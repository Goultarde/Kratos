+++
title = "steal_token"
chapter = false
weight = 5
+++

## Summary
Steal the primary token from a running process and use it for subsequent commands. Requires `SeDebugPrivilege` for processes owned by other users.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `pid` | Yes | PID of the process to steal the token from |

## Usage
```
steal_token 1234
```

## Notes
- Use `rev2self` to revert to the original token.
- `getuid` will show the impersonated identity.
