+++
title = "ligolo_status"
chapter = false
weight = 5
+++

## Summary
List all active ligolo-ng sessions. Displays a table with slot, PID, status, connect address, and binary path. Each row has a **Stop session** button that calls `ligolo_stop` directly.

## Arguments
None.

## Usage
```
ligolo_status
```

## Output
| Column | Description |
|--------|-------------|
| slot | Session index (0-3) |
| pid | Process ID of the ligolo-ng agent |
| status | `running` or `dead` |
| connect | Proxy address or bind address |
| path | Drop path of the binary on target |

## Notes
- Up to 4 concurrent sessions (slots 0-3).
- Dead sessions are automatically cleaned up on next `ligolo_status` call.
