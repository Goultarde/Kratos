+++
title = "upload"
chapter = false
weight = 5
+++

## Summary
Upload a file from Mythic to the target. The file is chunked and transferred over the C2 channel.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `file` | Yes | File to upload (select from Mythic file browser) |
| `remote_path` | Yes | Destination path on the target |

## Usage
```
upload (select file in UI) -> C:\Windows\Temp\tool.exe
```
