+++
title = "spawnas"
chapter = false
weight = 22
+++

## Summary
Spawn a new Kratos session inside the spawnto process under another user's credentials.

Uses `CreateProcessWithLogonW` with `LOGON_NETCREDENTIALS_ONLY` (network token only, no local profile load) then injects via Early Bird APC - identical technique to `spawn`.

Useful when plaintext credentials are known but no impersonation token is available (complements `make_token` + `spawn`).

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `Payload` | Yes | Kratos shellcode payload (output_format = shellcode) |
| `Username` | Yes | Account username |
| `Domain` | No | NetBIOS domain or `.` for local accounts (default: `.`) |
| `Password` | Yes | Account password |
| `PushMode` | No | Send shellcode in one chunk instead of pulling in chunks (default: false) |
| `ChunkSizeMB` | No | Pull mode chunk size in MB (default: 4) |

## Usage
Select via modal popup in the Mythic UI.

## Notes
- `LOGON_WITH_PROFILE`: spawned process runs fully as the target user (getuid = target user). Loads the user profile. Requires the account to have a local profile on the machine.
- Injection technique: **Early Bird APC** - same as `spawn`. No PPID spoofing (incompatible with `CreateProcessWithLogonW`).
- Memory is `RW` during write then flipped to `RX` before APC fires. No `RWX` page.
- A fresh payload copy is built per task (unique UUID/callback).
- ATT&CK: T1055 (Process Injection), T1055.004 (APC), T1134.002 (Token Impersonation - CreateProcessWithLogon)
