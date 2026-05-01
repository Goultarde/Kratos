+++
title = "spawnto"
chapter = false
weight = 20
+++

## Summary
Change the process used for fork+run injection. Applies to the `spawn` command. The setting persists for the lifetime of the agent. Default: `C:\Windows\System32\svchost.exe`.

If a bare name is provided (no backslash), it is resolved from `C:\Windows\System32\`.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `path` | Yes | Target process name (e.g. `svchost.exe`) or full path (e.g. `C:\Windows\System32\RuntimeBroker.exe`) |

## Usage
```
spawnto svchost.exe
spawnto C:\Windows\System32\RuntimeBroker.exe
```
