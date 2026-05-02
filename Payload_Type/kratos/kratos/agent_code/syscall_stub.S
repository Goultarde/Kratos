/* syscall_stub.S  --  compiled only when EVASION_SYSCALLS is defined
 *
 * wSystemCall lives in .data  (plain write, no code patching)
 * do_syscall   lives in .text (syscall instruction in RX section)
 *
 * No VirtualAlloc, no VirtualProtect, no heap trampoline, no RWX.
 */

    .section .data
    .align 4
    .globl wSystemCall
wSystemCall:
    .long 0

    .section .text
    .align 16
    .globl do_syscall
    .def do_syscall; .scl 2; .type 32; .endef
do_syscall:
    movq    %rcx, %r10          /* Windows x64: copy first arg to r10 for kernel */
    movl    wSystemCall(%rip), %eax
    syscall
    ret
