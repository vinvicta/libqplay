#!/usr/bin/env python3
"""Capture legacy Graal connector requests on a local forwarded port.

The server is intentionally tiny and local-only.  It records each request,
then returns the corresponding previously captured connector body from /tmp
so the native client can be tested against the current service payload.
"""

from pathlib import Path
import argparse
import socket
import time
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


def response_header(name: str, value: str, style: str) -> bytes:
    if style == "title":
        name = "-".join(part.capitalize() for part in name.split("-"))
    return f"{name}: {value}\r\n".encode("ascii")


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
    parser.add_argument(
        "--linger",
        type=float,
        default=0.0,
        help="seconds to keep each response socket open after sending",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="seconds to wait after reading a request and before sending",
    )
    parser.add_argument(
        "--omit-content-length",
        action="store_true",
        help="leave out Content-Length to exercise the old stream parser",
    )
    parser.add_argument(
        "--http-version",
        choices=("1.0", "1.1"),
        default="1.0",
        help="HTTP version used in the response status line",
    )
    parser.add_argument(
        "--header-case",
        choices=("lower", "title"),
        default="lower",
        help="case used for built-in response header names",
    )
    parser.add_argument(
        "--connection-value",
        choices=("keep-alive", "close"),
        default="keep-alive",
        help="value used for the built-in Connection response header",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="additional response header, repeatable",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

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
                extra_headers = b"".join(
                    header.encode("latin1") + b"\r\n" for header in args.header
                )
                response = (
                    f"HTTP/{args.http_version} 200 OK\r\n".encode("ascii")
                    + response_header("server", "Graal-Capture", args.header_case)
                    + response_header(
                        "content-type", "application/octet-stream", args.header_case
                    )
                    + (
                        b""
                        if args.omit_content_length
                        else response_header(
                            "content-length", str(len(body)), args.header_case
                        )
                    )
                    + response_header(
                        "connection", args.connection_value, args.header_case
                    )
                    + extra_headers
                    + b"\r\n"
                    + body
                )
                if args.delay > 0:
                    time.sleep(args.delay)
                conn.sendall(response)
                conn.shutdown(socket.SHUT_WR)
                if args.linger > 0:
                    time.sleep(args.linger)


if __name__ == "__main__":
    main()
