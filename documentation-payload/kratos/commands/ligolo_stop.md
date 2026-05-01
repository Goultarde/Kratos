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
| `pid` | No | PID of the session to stop. 0 (default) kills all sessions. |

## Usage

**Stop all sessions:**
```
ligolo_stop
```

**Stop a specific session by PID:**
```
ligolo_stop -PID 1234
```

## Notes
- The stop button in the `ligolo_status` panel automatically passes the correct PID.
- PID 0 terminates all tracked sessions.
