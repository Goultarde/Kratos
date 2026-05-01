+++
title = "ligolo_stop"
chapter = false
weight = 5
+++

## Summary
Stop one or all active ligolo-ng sessions.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `remote_path` | No | Path of the session to stop. Leave blank to kill all sessions. |

## Usage

**Stop all sessions:**
```
ligolo_stop
```

**Stop a specific session:**
```
ligolo_stop C:\Windows\Temp\svchost32.exe
```

## Notes
- `remote_path` matches the drop path used when the session was started.
- The stop button in the `ligolo_status` panel automatically fills the correct path.
