+++
title = "execute_assembly"
chapter = false
weight = 24
+++

## Summary
Execute a .NET assembly in the spawnto sacrifice process and return its output.

The Python-side builder converts the assembly to Donut PIC shellcode (with arguments embedded) at task time. The C agent injects it into the spawnto process via Early Bird APC with stdout/stderr capture. Output is returned once the process exits or the timeout is reached.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `Assembly` | Yes | .NET assembly file (.exe or .dll) |
| `Arguments` | No | Command-line arguments passed to the assembly (embedded in Donut) |
| `TimeoutSeconds` | No | Max wait time in seconds (default: 30) |
| `PushMode` | No | Send shellcode in one chunk instead of pulling in chunks (default: false) |
| `ChunkSizeMB` | No | Pull mode chunk size in MB (default: 4) |
| `AmsiBypass` | No | AMSI/ETW bypass technique: `donut` (default) or `none` |

## Usage
Select via modal popup in the Mythic UI.

## Notes
- Donut parameters: `arch=2` (x64), `format=1` (raw shellcode). `bypass=3` (AMSI+ETW) si `AmsiBypass=donut`, `bypass=1` (aucun) si `AmsiBypass=none`.
- Arguments are embedded at Donut build time, not passed as separate shellcode params.
- Injection technique: **Early Bird APC** into a suspended spawnto process. stdout/stderr are redirected via pipes before the APC fires.
- BlockDLLs policy applied if enabled via `blockdlls` command.
- The sacrifice process exits after the CLR finishes. Output is captured from pipes.
- A fresh Donut shellcode is generated per task (unique per assembly + arguments combination).
- ATT&CK: T1055 (Process Injection), T1055.004 (APC), T1059.001 (.NET assembly execution)
