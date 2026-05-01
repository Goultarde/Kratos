+++
title = "spawn"
chapter = false
weight = 21
+++

## Summary
Fork+Run: spawns the spawnto process, waits for its DLL loader to finish, then injects a Kratos shellcode payload via `CreateRemoteThread`. A fresh copy of the selected payload template is built by Mythic before injection.

Use `spawnto` to change the target process (default: `C:\Windows\System32\notepad.exe`).

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `Payload` | Yes | Kratos shellcode payload, selected from a dynamic dropdown showing only shellcode builds in creation order |

## Usage
Select via modal popup in the Mythic UI. The dropdown lists only Kratos payloads built with `output_format = shellcode`, numbered `[01]`, `[02]`, ... in creation order.

## Notes
- Shellcode is downloaded from Mythic in chunks and never written to disk.
- Injection technique: **Early Bird APC** - process spawned suspended (`CREATE_SUSPENDED`), APC queued to main thread, then resumed. The APC fires inside `ntdll!LdrInitializeThunk` before CFG is active, bypassing Control Flow Guard on the shellcode address.
- Memory is `RW` during write then flipped to `RX` (`PAGE_EXECUTE_READ`) before the APC fires. No `RWX` page.
- PPID is spoofed to `explorer.exe`.
- A fresh copy of the payload template is built per task (unique UUID/callback).
- ATT&CK: T1055 (Process Injection), T1055.004 (Asynchronous Procedure Call)
