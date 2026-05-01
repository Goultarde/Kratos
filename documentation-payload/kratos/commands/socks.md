+++
title = "socks"
chapter = false
weight = 5
+++

## Summary
Enable a SOCKS5 proxy through the agent. Mythic opens a local port on the operator's machine; all traffic is tunneled through the target via the C2 channel.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `port` | Yes | Local port on the Mythic server |
| `action` | No | `start` or `stop` (default: start) |

## Usage
```
socks -Port 7000 -Action start
proxychains -q nmap -sV 10.0.0.1
socks -Port 7000 -Action stop
```

## Notes
- Agent sleep is automatically set to 0 on start for low-latency polling.
- Sleep is restored to 5s on stop.
- Configure proxychains: `socks5 127.0.0.1 7000`
