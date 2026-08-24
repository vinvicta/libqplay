#!/usr/bin/env python3
"""Serve an archived connector response over loopback-only TLS.

This helper is for a bounded local replay. It binds only to 127.0.0.1,
serves one or more copies of an archived response, and prints each request
without writing credentials or response bodies to a repository path.
"""

from __future__ import annotations

import argparse
import pathlib
import socket
import ssl


def serve_once(
    listener: socket.socket,
    context: ssl.SSLContext,
    body: bytes,
    connection_timeout: float,
) -> None:
    raw, peer = listener.accept()
    with context.wrap_socket(raw, server_side=True) as connection:
        connection.settimeout(connection_timeout)
        request = bytearray()
        while b"\r\n\r\n" not in request and len(request) < 65536:
            chunk = connection.recv(4096)
            if not chunk:
                break
            request.extend(chunk)
        print(f"TLS_CAPTURE_REQUEST {peer!r} {bytes(request)!r}", flush=True)
        header = (
            b"HTTP/1.0 200 OK\r\n"
            b"Content-Type: image/png\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
        )
        connection.sendall(header + body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", type=pathlib.Path, required=True)
    parser.add_argument("--private-key", type=pathlib.Path, required=True)
    parser.add_argument("--response", type=pathlib.Path, required=True)
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--accept-timeout", type=float, default=180.0)
    parser.add_argument("--connection-timeout", type=float, default=10.0)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise SystemExit("port must be between 1 and 65535")
    if args.count < 1:
        raise SystemExit("count must be positive")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    context.load_cert_chain(
        certfile=args.certificate,
        keyfile=args.private_key,
    )
    body = args.response.read_bytes()

    with socket.create_server(("127.0.0.1", args.port), reuse_port=False) as listener:
        listener.settimeout(args.accept_timeout)
        print("TLS_CAPTURE_READY", flush=True)
        for _ in range(args.count):
            serve_once(listener, context, body, args.connection_timeout)


if __name__ == "__main__":
    main()
