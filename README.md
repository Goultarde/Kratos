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

## Installation in Mythic

1. Ensure Mythic is installed and running.
2. Clone or copy this folder into the `InstalledServices` directory or use the Mythic agent installation command.
3. The agent uses a Docker container for compilation (MinGW).

## Build and Usage

When creating a payload in the Mythic UI:

1. Select Target OS (Windows).
2. Configure build parameters (output filename, etc.).
3. **Command Selection**: Check the commands you wish to include. The `builder.py` will automatically generate the necessary compilation flags to exclude unused code.
4. Configure C2 Profile (HTTP).

## Project Structure

- **agent_code/**: Contains the agent's C source code.
  - `main.c`: Entry point, main loop, and C2 handling.
  - `Checkin.c`: Initial check-in logic.
  - `config.h`: Generated configuration (UUID, C2 parameters).
  - `Makefile`: Compilation script.
- **mythic/**: Python scripts for Mythic integration.
  - `agent_functions/`: Command definitions and build script (`builder.py`).
- **Dockerfile**: Agent build environment.

## Development

To add a new command:

1. Create a python file in `mythic/agent_functions/` to define the command on the Mythic side.
2. Implement the C logic in `agent_code/main.c` (or a new file).
3. Wrap the C implementation with `#ifdef INCLUDE_CMD_YOUR_COMMAND` to support modular compilation.
