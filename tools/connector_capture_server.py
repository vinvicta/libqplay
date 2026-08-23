#!/usr/bin/env python3
"""Capture legacy Graal connector requests on a local forwarded port.

The server is intentionally tiny and local-only.  It records each request,
then returns the corresponding previously captured connector body from /tmp
so the native client can be tested against the current service payload.
"""

from pathlib import Path
import argparse
import socket
from urllib.parse import urlsplit


BODY_FILES = {
    "/con.png": Path("/tmp/con.png"),
    "/con.gs": Path("/tmp/con.gs"),
    "/conf.gs": Path("/tmp/conf.gs"),
}


def read_request(conn: socket.socket) -> bytes:
    conn.settimeout(10)
    data = bytearray()
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--count", type=int, default=8)
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp"))
    parser.add_argument("--accept-timeout", type=float, default=120.0)
    parser.add_argument(
        "--con-png",
        type=Path,
        default=BODY_FILES["/con.png"],
        help="captured response body to return for /con.png",
    )
    args = parser.parse_args()

    with socket.create_server(("127.0.0.1", args.port), reuse_port=False) as server:
        server.settimeout(args.accept_timeout)
        print(f"listening 127.0.0.1:{args.port}", flush=True)
        for index in range(args.count):
            try:
                conn, peer = server.accept()
            except TimeoutError:
                break
            with conn:
                request = read_request(conn)
                output = args.output_dir / f"graal-captured-request-{index + 1}.bin"
                output.write_bytes(request)
                first_line = request.split(b"\r\n", 1)[0] if request else b""
                print(f"{index + 1}: {peer} {first_line!r}", flush=True)

                path = "/"
                if first_line:
                    parts = first_line.split(maxsplit=2)
                    if len(parts) >= 2:
                        path = urlsplit(parts[1].decode("latin1", "replace")).path
                body_path = args.con_png if path == "/con.png" else BODY_FILES.get(path)
                body = body_path.read_bytes() if body_path and body_path.exists() else b""
                response = (
                    b"HTTP/1.0 200 OK\r\n"
                    b"server: Graal-Capture\r\n"
                    b"content-type: application/octet-stream\r\n"
                    + f"content-length: {len(body)}\r\n".encode("ascii")
                    + b"connection: keep-alive\r\n\r\n"
                    + body
                )
                conn.sendall(response)
                conn.shutdown(socket.SHUT_WR)


if __name__ == "__main__":
    main()
