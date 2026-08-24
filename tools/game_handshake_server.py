#!/usr/bin/env python3
"""Loopback-only NewGraal handshake responder.

The decoded connector script contains a DES-wrapped RSA private key used by
the client to parse the server's encryption setup packet.  This diagnostic
server uses the matching public key to send a synthetic packet 0xfc after it
sees the client's 0xfd key-exchange packet.  It never opens a non-loopback
socket.
"""

from __future__ import annotations

import argparse
import base64
import re
import socket
import struct
import time
import zlib
from pathlib import Path

from Cryptodome.Cipher import DES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key


DEFAULT_SCRIPT = Path("analysis/StartScript_Connector.dec.bin")


def reverse_bits_each_byte(data: bytes) -> bytes:
    return bytes(int(f"{byte:08b}"[::-1], 2) for byte in data)


def native_des_decrypt_memory(data: bytes, key: bytes) -> bytes:
    full_length = len(data) - (len(data) % 8)
    cipher = DES.new(reverse_bits_each_byte(key), DES.MODE_ECB)
    return cipher.decrypt(data[:full_length]) + data[full_length:]


def load_parse_private_key(script: bytes):
    # The connector has several long base64 strings.  The parse-key blob is
    # the one which becomes a DER RSA private key under DOQLHRbY.
    for match in re.finditer(rb"[A-Za-z0-9+/=]{200,}", script):
        encoded = base64.b64decode(match.group())
        decoded = native_des_decrypt_memory(encoded, b"DOQLHRbY")
        try:
            return load_der_private_key(decoded, password=None)
        except ValueError:
            continue
    raise ValueError("embedded parse private key not found")


def read_newgraal_frames(buffer: bytearray):
    """Yield complete (header, payload) frames while retaining partial data."""

    frames = []
    while len(buffer) >= 6:
        compression = buffer[0] & 0x0F
        length = int.from_bytes(buffer[2:5], "big")
        if length < 6 or length > 0xFFFFFF:
            # The banner or an unexpected stream prefix is retained for the
            # caller to diagnose rather than discarded silently.
            break
        if len(buffer) < length:
            break
        frame = bytes(buffer[:length])
        del buffer[:length]
        body = frame[6:]
        if compression == 1:
            body = zlib.decompress(body)
        elif compression != 0:
            body = b"<unsupported compression>" + body
        frames.append(
            {
                "compression": compression,
                "sequence": frame[1],
                "length": length,
                "type": frame[5],
                "body": body,
                "raw": frame,
            }
        )
    return frames


def make_frame(packet_type: int, body: bytes, sequence: int = 0) -> bytes:
    length = 6 + len(body)
    if length > 0xFFFFFF:
        raise ValueError("NewGraal frame too large")
    return bytes((0, sequence & 0xFF)) + length.to_bytes(3, "big") + bytes((packet_type,)) + body


def rc4(data: bytes, key: bytes) -> bytes:
    """RC4 with the same stream construction used by libqplay."""

    return RC4Stream(key).process(data)


class RC4Stream:
    """Small stateful RC4 implementation for one NewGraal direction."""

    def __init__(self, key: bytes):
        if not key:
            raise ValueError("RC4 key must not be empty")
        self.state = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.state[i] + key[i % len(key)]) & 0xFF
            self.state[i], self.state[j] = self.state[j], self.state[i]
        self.i = 0
        self.j = 0

    def process(self, data: bytes) -> bytes:
        output = bytearray()
        for value in data:
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.state[self.i]) & 0xFF
            self.state[self.i], self.state[self.j] = (
                self.state[self.j],
                self.state[self.i],
            )
            output.append(value ^ self.state[(self.state[self.i] + self.state[self.j]) & 0xFF])
        return bytes(output)


def encode_file_size(value: int) -> bytes:
    """Encode the five 7-bit fields consumed by the packet-102 handler."""

    if value < 0 or value > 0x0FFFFFFF:
        raise ValueError("file size is outside the NewGraal five-byte range")
    return bytes(
        (
            ((value >> 28) & 0xFF) + 32,
            ((value >> 21) & 0x7F) + 32,
            ((value >> 14) & 0x7F) + 32,
            ((value >> 7) & 0x7F) + 32,
            (value & 0x7F) + 32,
        )
    )


def make_file_chunk_body(filename: bytes, data: bytes) -> bytes:
    """Build the packet-102 body: size, name length, name, and file bytes."""

    if not filename or len(filename) > 223:
        raise ValueError("filename length must fit the one-byte Graal string field")
    return encode_file_size(len(data)) + bytes((32 + len(filename),)) + filename + data


def make_minimal_nw(level_name: str) -> bytes:
    """Create a valid, empty 64x64 GLEVNW01 level for local protocol tests."""

    tile_row = b"AA" * 64
    rows = [
        f"BOARD 0 {row} 64 0 ".encode("ascii") + tile_row + b"\n"
        for row in range(64)
    ]
    return b"GLEVNW01\n" + b"".join(rows)


def resolve_test_file(
    file_root: Path | None,
    requested: bytes,
    level_code_root: Path | None = None,
    server_port: int = 14900,
) -> tuple[bytes, bytes] | None:
    """Resolve a requested resource from the loopback test asset tree."""

    if file_root is None:
        return None
    name = requested.decode("utf-8", "replace").strip()
    if not name:
        return None
    normalized = name.lower()
    root = file_root.resolve()

    if normalized.endswith(".nw") and level_code_root is not None:
        # A NewGraal level transition requests the level name, while the
        # native loader consumes the encrypted ``level-port.code`` container
        # under ``weblevels/<serveripstr>/``.  Return the container filename
        # in packet 102 so TCachedStream stores it in the .code cache.
        code_root = level_code_root.resolve()
        code_name = f"{Path(name).name}-{server_port}.code"
        code_candidate = code_root / code_name
        try:
            resolved = code_candidate.resolve()
            if resolved.is_relative_to(code_root) and resolved.is_file():
                return code_name.encode("utf-8"), resolved.read_bytes()
        except (OSError, ValueError):
            pass

    candidates = [root / name, root / "maps" / name, root / "levels" / name]
    if normalized == "pics1.png":
        # The APK carries a compatible classic tile sheet under this name;
        # serving it as pics1.png is enough to exercise the resource path.
        candidates.insert(0, root / "classiciphone_pics4.png")
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if resolved.is_relative_to(root) and resolved.is_file():
                return name.encode("utf-8"), resolved.read_bytes()
        except (OSError, ValueError):
            continue
    if normalized.endswith(".nw"):
        return name.encode("utf-8"), make_minimal_nw(name)
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=14900)
    parser.add_argument("--script", type=Path, default=DEFAULT_SCRIPT)
    parser.add_argument("--output", type=Path, default=Path("/tmp/graal-handshake"))
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--accept-timeout", type=float, default=120.0)
    parser.add_argument("--connection-timeout", type=float, default=10.0)
    parser.add_argument("--login-type", type=lambda value: int(value, 0), default=0x36)
    parser.add_argument(
        "--output-key-hex",
        default="30313233343536373839616263646566",
        help="RC4 key used by the diagnostic x86_64 and ARM64 APKs for client-to-server frames",
    )
    parser.add_argument(
        "--package-file",
        type=Path,
        help="optional raw basepackage.gupd text to return after packet 23",
    )
    parser.add_argument(
        "--no-basepackage",
        action="store_true",
        help="keep the responder at the handshake stage without returning packet 102",
    )
    parser.add_argument(
        "--file-root",
        type=Path,
        help="optional local asset tree used to answer map/level/image requests",
    )
    parser.add_argument(
        "--level-code-root",
        type=Path,
        help="optional directory of encrypted <level>-<port>.code test containers",
    )
    parser.add_argument(
        "--server-signature",
        type=int,
        default=0,
        help="synthetic server signature placed in packet 54 (default: 0)",
    )
    parser.add_argument(
        "--probe-file",
        help="send one unsolicited packet-102 probe file after the login frame",
    )
    parser.add_argument(
        "--file-transfer-mode",
        choices=("big", "single"),
        default="big",
        help="use the native multi-packet file-transfer sequence or one packet 102",
    )
    parser.add_argument(
        "--login-delay",
        type=float,
        default=0.0,
        help="seconds to wait after sending fc before sending the login frame",
    )
    parser.add_argument(
        "--post-login-delay",
        type=float,
        default=0.0,
        help="seconds to wait after the encrypted login before the first ordinary response",
    )
    parser.add_argument(
        "--no-login-encryption",
        action="store_true",
        help="send the synthetic login frame as plaintext instead of RC4",
    )
    parser.add_argument(
        "--extra-frame",
        action="append",
        default=[],
        metavar="TYPE:HEXBODY",
        help="send an additional encrypted server frame after login; repeatable",
    )
    parser.add_argument(
        "--extra-frame-once",
        action="append",
        default=[],
        metavar="TYPE:HEXBODY",
        help="send an additional encrypted frame only on the first connection",
    )
    parser.add_argument(
        "--extra-frame-after-first",
        action="append",
        default=[],
        metavar="TYPE:HEXBODY",
        help="send an additional encrypted frame on every connection after the first",
    )
    parser.add_argument(
        "--frame-after-client",
        action="append",
        default=[],
        metavar="CLIENTTYPE[@OCCURRENCE]:TYPE:HEXBODY",
        help=(
            "send one encrypted server frame after a matching client packet "
            "type on each connection; OCCURRENCE is 1-based and defaults to 1"
        ),
    )
    parser.add_argument(
        "--frame-after-map",
        action="append",
        default=[],
        metavar="TYPE:HEXBODY",
        help="send an additional encrypted server frame after each .gmap response",
    )
    args = parser.parse_args()

    if not 0 <= args.server_signature <= 223:
        parser.error("--server-signature must fit the one-byte net-string field")

    private_key = load_parse_private_key(args.script.read_bytes())
    public_key = private_key.public_key()
    # Fixed values make the capture reproducible and are sufficient for this
    # parser test; they are not production credentials.
    cipher_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    init_vector = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    output_key = bytes.fromhex(args.output_key_hex)
    extra_frames = []
    def parse_extra_frame(spec: str):
        try:
            type_text, body_text = spec.split(":", 1)
            return int(type_text, 0), bytes.fromhex(body_text)
        except ValueError as exc:
            raise SystemExit(f"invalid --extra-frame {spec!r}: expected TYPE:HEXBODY") from exc
    for spec in args.extra_frame:
        extra_frames.append(parse_extra_frame(spec))
    extra_frames_once = [parse_extra_frame(spec) for spec in args.extra_frame_once]
    extra_frames_after_first = [
        parse_extra_frame(spec) for spec in args.extra_frame_after_first
    ]
    frames_after_map = [parse_extra_frame(spec) for spec in args.frame_after_map]
    frame_after_client = []
    for spec in args.frame_after_client:
        try:
            client_spec, server_spec = spec.split(":", 1)
            server_type, body_text = server_spec.split(":", 1)
            if "@" in client_spec:
                client_text, occurrence_text = client_spec.rsplit("@", 1)
                occurrence = int(occurrence_text, 0)
            else:
                client_text = client_spec
                occurrence = 1
            if occurrence < 1:
                raise ValueError("occurrence must be positive")
            frame_after_client.append(
                (
                    int(client_text, 0),
                    occurrence,
                    int(server_type, 0),
                    bytes.fromhex(body_text),
                )
            )
        except ValueError as exc:
            raise SystemExit(
                f"invalid --frame-after-client {spec!r}: "
                "expected CLIENTTYPE[@OCCURRENCE]:TYPE:HEXBODY"
            ) from exc
    if args.package_file:
        package_data = args.package_file.read_bytes()
    else:
        package_data = b"GRPKG001\nNAME basepackage\nVERSION 1\nPLATFORM any\n"
    package_body = make_file_chunk_body(b"basepackage.gupd", package_data)
    probe_body = None
    if args.probe_file:
        probe_body = make_file_chunk_body(args.probe_file.encode("ascii"), b"GRAAL-PROBE\n")
    # get1PlusTextNetString emits 32 + length.  The native parser subtracts
    # 31 and then uses that value as the substring end index, so this is the
    # exact marker that yields the complete field.
    rsa_plaintext = b"!" + bytes((32 + len(cipher_key),)) + cipher_key
    rsa_plaintext += bytes((32 + len(init_vector),)) + init_vector
    rsa_ciphertext = public_key.encrypt(rsa_plaintext, padding.PKCS1v15())
    response_frame = make_frame(0xFC, rsa_ciphertext, sequence=0)
    # The native table maps packet type 0x36 (decimal 54) to the handler that
    # stores the server signature and invokes StartScript_Connector::onServerLogin.
    # NewGraal encrypts the complete frame (header included) after setEncryptionIn.
    # A one-byte net-string value of 0 is enough to exercise that transition.
    # setProtocol_NewGraal initializes the receive sequence to -1, so the
    # first server frame carries sequence 0; the encrypted login follows it
    # in the same receive sequence and therefore carries sequence 1.
    login_body = bytes((32 + args.server_signature,))
    login_plain_frame = make_frame(args.login_type, login_body, sequence=1)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with socket.create_server(("127.0.0.1", args.port), reuse_port=False) as server:
        server.settimeout(args.accept_timeout)
        print(
            f"listening 127.0.0.1:{args.port}; response=fc/{len(response_frame)} bytes",
            flush=True,
        )
        for index in range(args.count):
            try:
                conn, peer = server.accept()
            except TimeoutError:
                break
            with conn:
                conn.settimeout(args.connection_timeout)
                incoming = bytearray()
                client_plain = bytearray()
                captured = bytearray()
                outgoing = bytearray()
                responded = False
                basepackage_sent = False
                served_files = set()
                sent_after_client = set()
                client_type_occurrences = {}
                client_stream = RC4Stream(output_key)
                server_stream = RC4Stream(cipher_key)
                server_sequence = 1

                def send_server_frame(packet_type: int, body: bytes) -> None:
                    nonlocal server_sequence
                    plain = make_frame(packet_type, body, sequence=server_sequence)
                    wire = (
                        plain
                        if args.no_login_encryption
                        else server_stream.process(plain)
                    )
                    conn.sendall(wire)
                    outgoing.extend(wire)
                    server_sequence += 1

                def process_client_plain() -> None:
                    nonlocal basepackage_sent
                    frames = read_newgraal_frames(client_plain)

                    def flatten(frame, depth=0):
                        """Expose packets nested inside compressed 0xfd batches."""

                        yield frame, depth
                        if frame["type"] != 0xFD:
                            return
                        nested_buffer = bytearray(frame["body"])
                        nested = read_newgraal_frames(nested_buffer)
                        if nested and not nested_buffer:
                            for child in nested:
                                yield from flatten(child, depth + 1)

                    for outer_frame in frames:
                        for frame, depth in flatten(outer_frame):
                            body = frame["body"]
                            nested_label = " nested" if depth else ""
                            print(
                                f"{index + 1}: client{nested_label} frame "
                                f"seq={frame['sequence']} type={frame['type']} body={len(body)}",
                                flush=True,
                            )
                            client_type_occurrences[frame["type"]] = (
                                client_type_occurrences.get(frame["type"], 0) + 1
                            )

                            requested_filename = None
                            if frame["type"] == 23:
                                requested_filename = body
                            elif frame["type"] in (35, 47) and len(body) >= 5:
                                # Resource update requests carry five encoded
                                # timestamp/checksum bytes before the filename.
                                requested_filename = body[5:]

                            if (
                                not args.no_basepackage
                                and not basepackage_sent
                                and requested_filename is not None
                                and requested_filename.lower() == b"basepackage.gupd"
                            ):
                                filename = b"basepackage.gupd"
                                if args.file_transfer_mode == "big":
                                    # This is the sequence represented by the
                                    # native packet handlers: begin a named large
                                    # file, announce its five-byte size, append a
                                    # packet-102 chunk, then finalize the cache.
                                    send_server_frame(68, filename)
                                    send_server_frame(84, encode_file_size(len(package_data)))
                                    send_server_frame(102, package_body)
                                    send_server_frame(69, filename)
                                else:
                                    send_server_frame(102, package_body)
                                basepackage_sent = True
                                served_files.add("basepackage.gupd")
                                print(
                                    f"{index + 1}: sent {args.file_transfer_mode} basepackage.gupd "
                                    f"data={len(package_data)} total-body={len(package_body)}",
                                    flush=True,
                                )
                            elif (
                                requested_filename is not None
                                and args.file_root is not None
                            ):
                                requested_name = requested_filename.decode(
                                    "utf-8", "replace"
                                ).strip()
                                requested_key = requested_name.lower()
                                if requested_key == "basepackage.gupd":
                                    continue
                                if requested_key in served_files:
                                    continue
                                resolved = resolve_test_file(
                                    args.file_root,
                                    requested_filename,
                                    args.level_code_root,
                                    args.port,
                                )
                                if resolved is None:
                                    print(
                                        f"{index + 1}: no local response for "
                                        f"{requested_name!r}",
                                        flush=True,
                                    )
                                    continue
                                response_name, response_data = resolved
                                send_server_frame(
                                    102,
                                    make_file_chunk_body(response_name, response_data),
                                )
                                if requested_key.endswith(".gmap"):
                                    for map_type, map_body in frames_after_map:
                                        if args.post_login_delay > 0:
                                            time.sleep(args.post_login_delay)
                                        send_server_frame(map_type, map_body)
                                        print(
                                            f"{index + 1}: sent frame type={map_type} "
                                            "after gmap response",
                                            flush=True,
                                        )
                                served_files.add(requested_key)
                                print(
                                    f"{index + 1}: sent file {requested_name!r} "
                                    f"as {response_name.decode('utf-8', 'replace')!r} "
                                    f"data={len(response_data)}",
                                    flush=True,
                                )
                            for milestone, (
                                client_type,
                                occurrence,
                                server_type,
                                server_body,
                            ) in enumerate(frame_after_client):
                                if milestone in sent_after_client:
                                    continue
                                if (
                                    frame["type"] == client_type
                                    and client_type_occurrences[client_type] == occurrence
                                ):
                                    send_server_frame(server_type, server_body)
                                    sent_after_client.add(milestone)
                                    print(
                                        f"{index + 1}: sent frame type={server_type} "
                                        f"after client type={client_type} "
                                        f"occurrence={occurrence} "
                                        f"body={len(server_body)}",
                                        flush=True,
                                    )
                while len(captured) < 65536:
                    try:
                        chunk = conn.recv(4096)
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    captured.extend(chunk)
                    incoming.extend(chunk)
                    if not responded and b"GNP1905C" in incoming:
                        banner_end = incoming.find(b"GNP1905C") + 8
                        del incoming[:banner_end]
                    if not responded:
                        frames = read_newgraal_frames(incoming)
                        for frame in frames:
                            if frame["type"] == 0xFD:
                                # Deliver the key setup first.  A nonzero
                                # delay lets the connector script finish
                                # installing its handler table before the
                                # first ordinary server packet arrives.
                                conn.sendall(response_frame)
                                outgoing.extend(response_frame)
                                if args.login_delay > 0:
                                    time.sleep(args.login_delay)
                                login_plain_frame = make_frame(
                                    args.login_type,
                                    login_body,
                                    sequence=server_sequence,
                                )
                                if args.no_login_encryption:
                                    login_wire = login_plain_frame
                                else:
                                    login_wire = server_stream.process(login_plain_frame)
                                conn.sendall(login_wire)
                                outgoing.extend(login_wire)
                                server_sequence += 1
                                if probe_body is not None:
                                    if args.post_login_delay > 0:
                                        time.sleep(args.post_login_delay)
                                    send_server_frame(102, probe_body)
                                    print(
                                        f"{index + 1}: sent probe packet 102 file={args.probe_file}",
                                        flush=True,
                                    )
                                frames_to_send = list(extra_frames)
                                if index == 0:
                                    frames_to_send.extend(extra_frames_once)
                                else:
                                    frames_to_send.extend(extra_frames_after_first)
                                for extra_type, extra_body in frames_to_send:
                                    if args.post_login_delay > 0:
                                        time.sleep(args.post_login_delay)
                                    send_server_frame(extra_type, extra_body)
                                    print(
                                        f"{index + 1}: sent extra frame type={extra_type} "
                                        f"body={len(extra_body)}",
                                        flush=True,
                                    )
                                responded = True
                                print(
                                    f"{index + 1}: {peer} saw fd body={len(frame['body'])}; "
                                    f"sent fc then {'plaintext' if args.no_login_encryption else 'encrypted'} "
                                    f"login type={args.login_type}/{len(login_wire)} "
                                    f"after {args.login_delay:g}s",
                                    flush=True,
                                )
                                break
                        if responded and incoming:
                            if args.no_login_encryption:
                                client_plain.extend(incoming)
                            else:
                                client_plain.extend(client_stream.process(bytes(incoming)))
                            incoming.clear()
                            process_client_plain()
                    elif chunk:
                        if args.no_login_encryption:
                            client_plain.extend(chunk)
                        else:
                            client_plain.extend(client_stream.process(chunk))
                        process_client_plain()
                    if len(chunk) < 4096 and responded:
                        # Give the client a short opportunity to send the next
                        # encrypted login record, then let the socket timeout.
                        continue
                in_path = args.output.with_name(f"{args.output.name}-{index + 1}.in.bin")
                out_path = args.output.with_name(f"{args.output.name}-{index + 1}.out.bin")
                in_path.write_bytes(captured)
                out_path.write_bytes(outgoing)
                print(
                    f"{index + 1}: captured in={len(captured)} out={len(outgoing)} "
                    f"files={in_path},{out_path}",
                    flush=True,
                )


if __name__ == "__main__":
    main()
