# Kratos

Kratos is a minimalist C2 agent written in C for Mythic, targeting Windows environments. It is designed to be lightweight, modular, and easily extensible.

## Features

- **Language**: C (C99 compatible)
- **Target Architecture**: Windows x64 (compiled via MinGW-w64 on Linux)
- **Communication**: HTTP (via WinHTTP)
- **Modular**: Dynamic compilation system allowing inclusion of only selected commands during payload generation.
- **Lightweight**: No heavy dependencies, direct Windows API usage.

## Supported C2 Profiles

- **http**: Uses standard HTTP/HTTPS for communication.

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
| **exit** | `exit` | Terminates the agent cleanly. |

