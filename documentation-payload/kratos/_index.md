+++
title = "Kratos"
chapter = true
weight = 5
+++

![logo](/agents/kratos/kratos.svg?width=200px)

## Summary

Kratos is a minimal C99 agent for Windows x64, compiled with MinGW-w64 from Linux.

### Highlighted Features

- AES-256-CBC encrypted communications (tiny-AES or BCrypt backend)
- EDR evasion: ntdll unhooking, ETW patching, AMSI bypass, Hell's Gate direct syscalls
- SOCKS5 proxy (via Mythic server)
- Reverse port forwarding (rportfwd + relay.py)
- Ligolo-ng agent embedding and session management
- Token manipulation: steal_token, make_token, runas, rev2self
- Process injection: spawn (Fork & Run, PPID spoof)
- Shellcode output via Donut (position-independent, x64)
- Wrapped by Atreus (Early Bird injection loader)

### Build Options

| Parameter | Description |
|-----------|-------------|
| `debug` | Enable debug output |
| `crypto_backend` | `tiny_aes` (no bcrypt.dll) or `bcrypt` (Windows API) |
| `output_format` | `exe` or `shellcode` (via Donut) |
| `evasion_unhook` | Remap ntdll from disk to remove userland hooks |
| `evasion_etw` | Patch EtwEventWrite* to silence ETW |
| `evasion_amsi` | Patch AmsiScanBuffer/String |
| `evasion_syscalls` | Hell's Gate direct syscalls |
| `embedded_binary` | Optional binary to embed (e.g. ligolo-ng agent) |

### C2 Profile

HTTP only. Supports encrypted_exchange (AES-256-CBC + HMAC-SHA256) or plaintext.

## Authors

@goultarde
