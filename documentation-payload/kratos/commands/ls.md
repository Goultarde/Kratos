+++
title = "ls"
chapter = false
weight = 5
+++

## Summary
List files and directories using Win32 `FindFirstFileA/FindNextFileA`. Results are sent to the Mythic file browser. Supports recursive listing.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `path` | No | Directory to list (default: current directory) |
| `recursive` | No | Recursively list all subdirectories (-r) |

## Usage
```
ls
ls C:\Users
ls C:\Users -r
```

## Notes
- No `cmd.exe` spawn - uses Win32 file APIs directly.
- Results appear in the Mythic file browser (Files tab).
- Recursive mode sends one file_browser response per subdirectory.
