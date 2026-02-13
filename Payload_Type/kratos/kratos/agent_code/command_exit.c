#define _WIN32_WINNT 0x0600
#include "commands.h"
#include <stdlib.h>

#ifdef INCLUDE_CMD_EXIT

void command_exit(char *task_id, char *params) { exit(0); }

#endif
