+++
title = "runas"
chapter = false
weight = 5
+++

## Summary
Spawn a process under alternate credentials via `LogonUser` + `CreateProcessAsUser` (RunasCS-style). Captures stdout/stderr via anonymous pipes.

Supports Mythic credential store or manual username/password input.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `username` | Yes | DOMAIN\user, user@domain, or user |
| `password` | Yes | Plaintext password |
| `logon_type` | No | 2=Interactive, 3=Network, 8=NetworkCleartext, 9=NewCredentials (default) |
| `application` | Yes | Executable to run (default: cmd.exe) |
| `arguments` | No | Arguments (default: /c whoami /all) |

## Usage
```
runas -username DOMAIN\user -password Password123! -application cmd.exe -arguments "/c whoami /all"
runas -username DOMAIN\user -password Password123! -logon_type "3 - Network" -application cmd.exe
```

## Notes
- Logon type 9 (NewCredentials) inherits local token but uses alternate credentials for network auth. Ideal for lateral movement.
- Logon type 2 (Interactive) requires `SeAssignPrimaryTokenPrivilege`.
