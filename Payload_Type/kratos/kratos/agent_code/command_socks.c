#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_SOCKS

// The "socks" command is script_only on the Mythic side:
// Python calls SendMythicRPCProxyStartCommand/StopCommand.
// The agent has no task to execute - real work happens in socks.c
// via socks_handle_incoming() / socks_send_pending() in the main loop.
//
// This function exists only for dispatch in main.c.
void command_socks(char *task_id, char *params) {
    (void)params;
    send_task_response(task_id, "SOCKS5 proxy managed by Mythic server.");
}

#endif
