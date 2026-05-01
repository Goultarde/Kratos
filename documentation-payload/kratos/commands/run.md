+++
title = "run"
chapter = false
weight = 5
+++

## Summary
Execute a program directly (no cmd.exe wrapper). Arguments are passed directly to the process.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `executable` | Yes | Path to the executable |
| `arguments` | No | Arguments to pass |

## Usage
```
run C:\Windows\System32\whoami.exe /all
run powershell.exe -enc <base64>
```
