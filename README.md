<p align="center">
  <img src="Payload_Type/kratos/kratos/mythic/agent_functions/kratos.svg" alt="Kratos Logo" height="200" width="200">
  <h1 align="center">Kratos</h1>
</p>

Kratos is a minimalist C2 agent written in C for Mythic, targeting Windows environments. It is designed to be lightweight, modular, and easily extensible.

## Features

- **Language**: C (C99 compatible)
- **Target Architecture**: Windows x64 (compiled via MinGW-w64 on Linux)
- **Communication**: HTTP (via WinHTTP)
- **Modular**: Dynamic compilation system allowing inclusion of only selected commands during payload generation.
- **Lightweight**: No heavy dependencies, direct Windows API usage.

## Supported C2 Profiles

- **http**: Uses standard HTTP/HTTPS for communication.

## Encryption Support

⚠️ **Important**: AES encryption is **NOT supported** in the current version. 
- When creating a payload, set `AESPSK` to **`none`**
- All communication is transmitted in **plaintext** (Base64-encoded)
- This agent is intended for testing and educational purposes only

## Supported Commands

The agent supports dynamic command selection. If a command is not selected during payload creation, its code will not be compiled into the final executable.

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **shell** | `shell <command>` | Executes command via the system shell (cmd.exe). |
| **run** | `run <binary> <args>` | Executes specific binary or command. |
| **cd** | `cd <path>` | Changes the current working directory. |
| **ls** | `ls [path]` | Lists files and directories (wrapper around dir). |
| **pwd** | `pwd` | Displays the current working directory path. |
| **getuid** | `getuid` | Retrieves the current user name. |
| **sleep** | `sleep [interval]` | Get or set callback interval in seconds. No args = show current value. |
| **exit** | `exit` | Terminates the agent cleanly. |

