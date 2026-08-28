#!/usr/bin/env python3
"""Decode and compare the embedded 1.8 and Spectron connector endpoints.

The connector stores short URL fragments in the same reversible byte format
used by the script-name tables.  This audit applies the recovered
``codesimplefix0`` sentinel repair and ``decodesimple`` transform to the
fragments referenced by the two connector-mode functions.  It reads files
only, writes a JSON record, and never opens a socket.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SOURCE_FRAGMENTS = {
    "http_scheme": {"offset": 0x2DC4E0, "length": 7},
    "https_scheme": {"offset": 0x2DC4E8, "length": 8},
    "first_host": {"offset": 0x2DC500, "length": 3},
    "retry_host": {"offset": 0x2DC4F8, "length": 4},
    "domain": {"offset": 0x2DC508, "length": 16},
    "png_path": {"offset": 0x2DC520, "length": 8},
    "conf_path": {"offset": 0x2DC538, "length": 8},
}

TARGET_FRAGMENTS = {
    "http_scheme": {"offset": 0x2E9E88, "length": 7},
    "https_scheme": {"offset": 0x2E9E90, "length": 8},
    "first_host": {"offset": 0x2E9EA8, "length": 4},
    "retry_host": {"offset": 0x2E9EA0, "length": 5},
    "domain": {"offset": 0x2E9EB0, "length": 16},
    "png_path": {"offset": 0x2E9EC8, "length": 8},
    "conf_path": {"offset": 0x2E9EE0, "length": 8},
}


MODE2_PATH = b"2]))&=\t"


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode_fragment(raw: bytes) -> tuple[str, list[int]]:
    """Apply the native sentinel repair and simple decoder to one fragment."""

    length = len(raw)
    decoded = []
    repaired_indexes = []
    for index, encoded in enumerate(raw):
        signed_encoded = encoded if encoded < 0x80 else encoded - 0x100
        value = -11 - signed_encoded - length
        sentinel_test = ((value >> 2) & 0x3F) | ((value & 3) << 6)
        if sentinel_test == index:
            signed_encoded = 0
            repaired_indexes.append(index)
        value = -11 - signed_encoded - length
        decoded.append(((value << 6) - index + ((value >> 2) & 0x3F)) & 0xFF)
    try:
        return bytes(decoded).decode("ascii"), repaired_indexes
    except UnicodeDecodeError as error:
        raise ValueError("decoded connector fragment is not ASCII") from error


def fragment_record(binary: bytes, spec: dict[str, int], origin: str) -> dict:
    offset = spec["offset"]
    length = spec["length"]
    if offset < 0 or offset + length > len(binary):
        raise ValueError("connector fragment is outside the input binary")
    raw = binary[offset : offset + length]
    decoded, repaired_indexes = decode_fragment(raw)
    return {
        "origin": origin,
        "offset": "0x%x" % offset,
        "length": length,
        "raw_hex": raw.hex(),
        "decoded": decoded,
        "sentinel_repaired_indexes": repaired_indexes,
    }


def literal_record(raw: bytes, origin: str) -> dict:
    decoded, repaired_indexes = decode_fragment(raw)
    return {
        "origin": origin,
        "offset": None,
        "length": len(raw),
        "raw_hex": raw.hex(),
        "decoded": decoded,
        "sentinel_repaired_indexes": repaired_indexes,
    }


def build_record(path: Path, fragments: dict[str, dict[str, int]], build: str) -> dict:
    binary = path.read_bytes()
    decoded = {
        name: fragment_record(binary, spec, "%s connector data" % build)
        for name, spec in fragments.items()
    }
    decoded["mode2_path_literal"] = literal_record(
        MODE2_PATH, "%s connector inline literal" % build
    )

    endpoint_rows = []
    schemes = {
        1: decoded["https_scheme"]["decoded"],
        2: decoded["https_scheme"]["decoded"],
        3: decoded["http_scheme"]["decoded"],
    }
    paths = {
        1: decoded["png_path"]["decoded"],
        2: decoded["mode2_path_literal"]["decoded"],
        3: decoded["conf_path"]["decoded"],
    }
    first_host = decoded["first_host"]["decoded"]
    retry_host = decoded["retry_host"]["decoded"]
    domain = decoded["domain"]["decoded"]
    for mode in (1, 2, 3):
        scheme = schemes[mode]
        path_part = paths[mode]
        endpoint_rows.append(
            {
                "mode": mode,
                "scheme": scheme,
                "host": first_host + domain,
                "retry_host": retry_host + domain,
                "path": path_part,
                "first": scheme + first_host + domain + path_part,
                "retry": scheme + retry_host + domain + path_part,
                "transport": "HTTPS" if scheme == "https://" else "HTTP",
            }
        )

    return {
        "input": {
            "path": path.name,
            "size": len(binary),
            "sha256": sha256_path(path),
        },
        "connector_function": {
            "name": "TServerList_enterNextConnectorMode_int",
            "address": "0x203df4" if build == "original_1.8" else "0x2094c0",
        },
        "fragments": decoded,
        "endpoints": endpoint_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--spectron", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    original = build_record(args.original, SOURCE_FRAGMENTS, "original_1.8")
    spectron = build_record(args.spectron, TARGET_FRAGMENTS, "spectron_2.2")

    original_hosts = {
        host
        for row in original["endpoints"]
        for host in (row["host"], row["retry_host"])
    }
    spectron_hosts = {
        host
        for row in spectron["endpoints"]
        for host in (row["host"], row["retry_host"])
    }
    original_schemes = [row["scheme"] for row in original["endpoints"]]
    spectron_schemes = [row["scheme"] for row in spectron["endpoints"]]
    original_paths = [row["path"] for row in original["endpoints"]]
    spectron_paths = [row["path"] for row in spectron["endpoints"]]

    result = {
        "artifact": "spectron_connector_endpoint_audit_20260827",
        "analysis": "offline connector URL fragment decode and cross-build comparison",
        "network_contacted": False,
        "decoder": {
            "source_functions": {
                "codesimplefix0": "0xea2c0",
                "decodesimple": "0xea100",
            },
            "sentinel_repair": "If the recovered encoded index equals the loop index, the native fix helper supplies a zero byte before decodesimple runs.",
            "formula": "value = -11 - signed_encoded - length; decoded = ((value << 6) - index + ((value >> 2) & 0x3f)) & 0xff",
        },
        "native_evidence": {
            "original": {
                "connector_mode": "0x203df4",
                "requestURLAsGameFile": "0x2013d4",
                "sendRequest": "0x1ffde8",
            },
            "spectron": {
                "connector_mode": "0x2094c0",
                "requestURLAsGameFile": "0x206bc4",
                "sendRequest": "0x205730",
            },
        },
        "build_literals": {
            "original_1.8": {
                "version": "6.15401",
                "build": "Jul  4 2019 09:35:48",
            },
            "spectron_2.2": {
                "version": "6.171",
                "build": "Oct 30 2022 12:58:55",
                "revision_parameter": "2.22",
            },
        },
        "comparison": {
            "domain_unchanged": original["fragments"]["domain"]["decoded"]
            == spectron["fragments"]["domain"]["decoded"],
            "paths_unchanged": original_paths == spectron_paths,
            "scheme_by_mode_unchanged": original_schemes == spectron_schemes,
            "original_hosts": sorted(original_hosts),
            "spectron_hosts": sorted(spectron_hosts),
            "target_first_host": spectron["fragments"]["first_host"]["decoded"],
            "target_retry_host": spectron["fragments"]["retry_host"]["decoded"],
            "target_host_change": (
                "The Spectron build changes the connector host pair from "
                + original["fragments"]["first_host"]["decoded"]
                + "/"
                + original["fragments"]["retry_host"]["decoded"]
                + " to "
                + spectron["fragments"]["first_host"]["decoded"]
                + "/"
                + spectron["fragments"]["retry_host"]["decoded"]
                + "."
            ),
        },
        "original": original,
        "spectron": spectron,
        "interpretation": [
            "The 1.8 build decodes con.quattroplay.com and con2.quattroplay.com.",
            "The Spectron build decodes cong.quattroplay.com and cong2.quattroplay.com.",
            "Modes 1 and 2 still use HTTPS, while mode 3 still uses HTTP.",
            "The host change is a static finding. This audit does not resolve DNS, contact a service, or prove that either hostname is currently live.",
            "The target's unchanged native trust material remains a separate compatibility concern for its HTTPS modes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "original_endpoints": [row["first"] for row in original["endpoints"]],
                "spectron_endpoints": [row["first"] for row in spectron["endpoints"]],
                "network_contacted": False,
            }
        )
    )


if __name__ == "__main__":
    main()
