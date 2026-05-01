+++
title = "make_token"
chapter = false
weight = 5
+++

## Summary
Create a new logon token with the provided credentials (LOGON32_LOGON_NEW_CREDENTIALS). Useful for network authentication without changing the local process identity.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `username` | Yes | Username (DOMAIN\user or user) |
| `password` | Yes | Plaintext password |
| `domain` | No | Domain (optional if included in username) |

## Usage
```
make_token DOMAIN\user Password123!
```

## Notes
- Equivalent to `runas /netonly`.
- Use `rev2self` to revert.
