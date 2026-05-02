#define _WIN32_WINNT 0x0601
#include "commands.h"
#include "inject.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_BLOCKDLLS

static int blockdlls_extract_bool(const char *json, const char *key, int defval) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *kp = strstr(json, pattern);
    if (!kp) return defval;
    const char *vp = strchr(kp, ':');
    if (!vp) return defval;
    vp++;
    while (*vp == ' ' || *vp == '\t') vp++;
    if (strncmp(vp, "true", 4) == 0) return 1;
    if (strncmp(vp, "false", 5) == 0) return 0;
    return defval;
}

void command_blockdlls(char *task_id, char *params) {
    int block = blockdlls_extract_bool(params, "block", -1);
    if (block == -1) {
        send_task_response(task_id, "Error: missing 'block' parameter");
        return;
    }

    g_blockdlls = block;

    char msg[64];
    snprintf(msg, sizeof(msg), "BlockDLLs %s", block ? "enabled" : "disabled");
    send_task_response(task_id, msg);
}

#endif /* INCLUDE_CMD_BLOCKDLLS */
