#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <windows.h>

#ifdef INCLUDE_CMD_GETUID

void command_getuid(char *task_id, char *params) {
  char username[256] = {0};
  DWORD len = sizeof(username);
  if (GetUserName(username, &len)) {
    send_task_response(task_id, username);
  } else {
    send_task_response(task_id, "Failed to get username");
  }
}

#endif
