<p align="center">
  <img src="Payload_Type/kratos/kratos/mythic/agent_functions/kratos.svg" alt="Kratos Logo" height="200" width="200">
  <h1 align="center">Kratos</h1>
</p>

Kratos is a minimalist C2 agent written in C (C99) for Mythic, targeting Windows x64. Compiled via MinGW-w64 on Linux. Designed to be lightweight, modular, and evasion-capable.

## Installation

```bash
sudo ./mythic-cli install folder Kratos
```

## Features

- **Language**: C99, compiled with MinGW-w64 (cross-compile from Linux)
- **Target**: Windows x64
- **Communication**: HTTP/HTTPS via WinHTTP
- **Encryption**: AES-256-CBC (tiny-AES embedded or Windows BCrypt API)
- **Output formats**: PE executable or raw shellcode (via Donut)
- **Modular commands**: only selected commands are compiled into the payload
- **Wrapper support**: can be wrapped by Atreus for shellcode injection

## Build Parameters

| Parameter | Options | Description |
|-----------|---------|-------------|
| `crypto_backend` | `tiny_aes`, `bcrypt` | `tiny_aes` = embedded AES, no `bcrypt.dll` import (better OPSEC) |
| `output_format` | `exe`, `shellcode` | `shellcode` uses Donut to produce PIC x64 shellcode |
| `evasion_unhook` | bool | Remap ntdll `.text` from disk to remove EDR userland hooks |
| `evasion_etw` | bool | Patch `EtwEventWrite*` to silence ETW telemetry |
| `evasion_amsi` | bool | Patch `AmsiScanBuffer/String` to bypass AMSI |
| `evasion_syscalls` | bool | Hell's Gate: direct syscalls bypassing hooked Nt* functions |
| `debug` | bool | Enable verbose debug output (do not use in production) |

## Commands

| Command | Description |
|---------|-------------|
| `shell` | Execute command via `cmd.exe /c` |
| `run` | Execute a binary with arguments |
| `cd` | Change working directory |
| `pwd` | Print working directory |
| `ls` | List directory contents |
| `cat` | Read a file |
| `cp` | Copy a file |
| `mv` | Move/rename a file |
| `rm` | Delete a file |
| `mkdir` | Create a directory |
| `download` | Download a file from the target |
| `upload` | Upload a file to the target |
| `ps` | List running processes |
| `kill` | Kill a process by PID |
| `getuid` | Get current username |
| `whoami` | Get user + domain + privileges |
| `sleep` | Get or set callback interval/jitter |
| `ifconfig` | List network interfaces and IPs |
| `make_token` | Create impersonation token (user/pass/domain) |
| `steal_token` | Steal token from another process |
| `rev2self` | Revert to original token |
| `runas` | Run a command as another user |
| `spawnas` | Spawn a process as another user |
| `spawn` | Fork & run shellcode in a sacrificial process |
| `spawnto` | Set the default sacrificial process for spawn |
| `execute_assembly` | Run a .NET assembly in memory |
| `blockdlls` | Enable BlockDLLs policy on spawned processes |
| `socks` | SOCKS5 proxy via Mythic |
| `rportfwd` | Reverse port forward via Mythic |
| `ligolo_start` | Start a Ligolo-ng tunnel (fork & run or external binary) |
| `ligolo_stop` | Stop a Ligolo-ng tunnel session |
| `ligolo_status` | List active Ligolo-ng tunnel sessions |
| `exit` | Terminate the agent |

## Usage with Atreus

1. Build Kratos with `output_format = shellcode`.
2. Select **Atreus** as the wrapper payload.
3. Configure Atreus injection technique and evasion options.
4. Deploy the resulting `.exe`.
