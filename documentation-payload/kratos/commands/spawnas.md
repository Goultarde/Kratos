+++
title = "spawnas"
chapter = false
weight = 22
+++

## Summary
Spawn a new Kratos session inside the spawnto process under another user's credentials via `CreateProcessWithLogonW` then Early Bird APC injection.

Supports Mythic credential store or manual username/password input.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `Payload` | Yes | Kratos shellcode payload (output_format = shellcode) |
| `Username` | Yes | Account username (manual group) |
| `Password` | Yes | Account password (manual group) |
| `Domain` | No | NetBIOS domain name. Leave empty for auto-resolution (domain accounts) or `.` for local accounts |
| `LogonType` | No | 2=Interactive, 3=Network, 8=NetworkCleartext, 9=NewCredentials (default: 2) |
| `PushMode` | No | Send shellcode in one chunk instead of pulling in chunks (default: false) |
| `ChunkSizeMB` | No | Pull mode chunk size in MB (default: 4) |
| `bypass_uac` | No | UAC bypass: LogonUser (non-filtered type) + copy IL + strip DACL + ImpersonateLoggedOnUser + CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY). Only effective for logon types 2/9. |

## Usage
Select via modal popup in the Mythic UI.

## Notes
- Types 2/9: `CreateProcessWithLogonW`. Type 2 = full token, type 9 = netonly.
- Types 3/4/5/8: `LogonUser` + `DuplicateTokenEx` + `CreateProcessW(SUSPENDED)` + `SetThreadToken`. Requires `SeImpersonatePrivilege`.
- Type 4 requires `SeBatchLogonRight`, type 5 requires `SeServiceLogonRight` on the target account.
- Window station DACL is patched before spawning so the target user can access WinSta0/Default.
- Injection technique: Early Bird APC - shellcode queued before process entry point.
- Memory is `RW` during write then flipped to `RX` before APC fires. No `RWX` page.
- A fresh payload copy is built per task (unique UUID/callback).
- `bypass_uac`: same technique as `runas -b` (RunasCS `--bypass-uac`). Fails with err 1326 on hardened Windows 10/11 without permissive LSA policy.
- ATT&CK: T1055 (Process Injection), T1055.004 (APC), T1134.002 (Token Impersonation - CreateProcessWithLogon)
