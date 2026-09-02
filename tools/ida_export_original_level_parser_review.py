#!/usr/bin/env python3
"""Export a focused parser and allocation review for the original ARM64 IDB.

The exporter is read-only. It preserves the Hex-Rays text for the encrypted
level loader, coded-file reader, stream helpers, board decoder, and line-based
entity readers. Manual notes distinguish visible bounds from availability and
parser-state risks. It does not execute the library, fuzz a parser, or contact
a service.

Set ``IDA_LEVEL_PARSER_REVIEW_OUT`` to choose another output path. The default
is the compact JSON artifact in the repository's artifacts directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import ida_funcs
import ida_hexrays
import ida_kernwin
import idaapi
import idautils
import idc


TARGETS = [
    ("0x1aa198", "TServerLevel_LoadEncrypted_void", "encrypted level loader"),
    ("0xe62ec", "TEncryption_loadCodedFile_TString_const", "coded file reader"),
    ("0xf0790", "TStream_LoadFromFile_TString_const", "file to stream loader"),
    ("0xf0684", "TStream_read_void_int", "bounded stream read"),
    ("0xf11bc", "TString_addbuffer_char_const_int", "dynamic string append"),
    ("0xf0ce0", "TStream_readLine_void", "line reader"),
    ("0xf1d74", "TString_operator_index_int__2", "bounded string index"),
    ("0xf2da4", "TString_subString_int_int", "substring helper"),
    ("0x1aa0a0", "TServerLevel_setTileLayerCount_int", "tile-layer count"),
    ("0x1a0ea4", "TTilesLayer_TTilesLayer_TServerLevel_int", "tile-layer allocation"),
    ("0x22ed90", "TLevelLoader_loadBoard_TStream_short_int_bool", "board decoder"),
    ("0x1a2924", "TServerLevel_readLinks_TStream", "link reader"),
    ("0x1a29d0", "TServerLevel_readBaddies_TStream_bool", "baddie reader"),
    ("0x1a2a9c", "TServerLevel_readNPCs_TStream_bool", "NPC reader"),
    ("0x1a2cbc", "TServerLevel_readChests_TStream_bool", "chest reader"),
    ("0x1a2f08", "TServerLevel_readSigns_TStream", "sign reader"),
    ("0x1a1d00", "getSignText_TString_const", "keyboard-code expansion"),
    ("0x183414", "replaceKeyCodes_TString_const", "key-code replacement"),
    ("0x183320", "findBracketsEnd_TString_const", "replacement bracket scan"),
]


MANUAL_REVIEWS = [
    {
        "address": "0xe62ec",
        "function": "TEncryption_loadCodedFile_TString_const",
        "classification": "declared-length-availability-risk",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The four-byte outer length is loaded into a 32-bit W register and the check at 0xe63a8 uses signed B.GE after adding three; there is no explicit lower bound for the stored value.",
            "The code subtracts eight in 32-bit arithmetic and passes the result to TString_setSize_int_bool without checking the allocator result.",
            "For a stored value of 0x80000000, the W-register subtraction produces 0x7ffffff8. TString_setSize then adds nine in W arithmetic, sign-extends the wrapped value for malloc, and immediately dereferences the returned pointer without an allocation-failure check.",
            "Ciphertext and checksum reads use TStream_read_void_int, which clamps to the available bytes, but their return values are ignored. The decoded output is accepted only after an eight-byte additive column checksum, not a cryptographic authenticity check.",
        ],
        "interpretation": "A small malformed cached file can therefore drive a very large allocation request or a null dereference before the level header is checked. This is a confirmed static denial-of-service path for a locally writable cache. Reaching it through a game-server response depends on the file-download and cache path, but the normal level flow does load server-supplied .code data.",
    },
    {
        "address": "0x1aa198",
        "function": "TServerLevel_LoadEncrypted_void",
        "classification": "unchecked-short-header-reads",
        "confidence": "confirmed-static",
        "severity": "parser-robustness-risk",
        "evidence": [
            "The loader ignores the return value of fixed reads for the GWEBL001 marker, one-byte lengths, the two-byte signature, five-byte modification time, and eight-byte version.",
            "TStream_read_void_int returns a short count at end of stream, while the loader immediately compares or appends the requested byte count. The destination arrays are fixed at eight and 256 bytes, so the visible issue is stale or uninitialized stack data and parser-state confusion rather than a direct copy past those arrays.",
            "Length bytes are interpreted as byte minus 32. A negative result is ignored by the stream and string helpers, while positive values are bounded by the 256-byte temporary buffer.",
            "The server identity and signature checks happen before board decoding, but the outer coded-file checksum is additive and does not authenticate the level contents.",
        ],
        "interpretation": "Truncated containers should be rejected on each field read. The current code often reaches a later comparison with stale stack bytes, which can cause inconsistent rejection or accidental continuation. A reproducer should vary truncation points and stack history before assigning a code-execution severity.",
    },
    {
        "address": "0xf0684",
        "function": "TStream_read_void_int",
        "classification": "bounded-short-read-helper",
        "confidence": "confirmed-static",
        "severity": "context-dependent",
        "evidence": [
            "Negative requested lengths return zero.",
            "Positive reads are capped to the available stream length and return the actual count copied.",
            "The helper does not report an error separately, so callers must compare the return count before consuming a fixed-size field.",
        ],
        "interpretation": "The helper itself prevents a requested read from overrunning the in-memory stream. Its callers can still mishandle truncated input when they ignore the returned count.",
    },
    {
        "address": "0xf11bc",
        "function": "TString_addbuffer_char_const_int",
        "classification": "allocation-failure-and-size-overflow-risk",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The append length is an int and the new allocation size is formed with 32-bit ADD instructions before sign extension to malloc.",
            "The realloc and malloc results are stored and then dereferenced without null checks.",
            "Normal one-byte header fields and the fixed formatter wrappers stay far below this boundary, while line readers can grow a string in proportion to an entire input line.",
        ],
        "interpretation": "This is primarily an out-of-memory and integer-wrap concern for oversized level data. It is not evidence that ordinary short level records overflow the string object.",
    },
    {
        "address": "0xf0ce0",
        "function": "TStream_readLine_void",
        "classification": "unbounded-line-allocation",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The reader scans until LF or the end of the in-memory stream and appends the entire line to a dynamic TString.",
            "It removes a preceding CR when a line terminator is found, but has no maximum line length and no explicit malformed-line error.",
            "An unterminated final line is returned as a valid nonempty string when the stream ends.",
        ],
        "interpretation": "The outer coded-file length still limits the total input, but a large line can consume a large allocation and make every entity reader process attacker-sized text. A modern parser should set both per-line and total-object budgets.",
    },
    {
        "address": "0x22ed90",
        "function": "TLevelLoader_loadBoard_TStream_short_int_bool",
        "classification": "bounded-board-decoder",
        "confidence": "confirmed-static",
        "severity": "reviewed-safe-bound",
        "evidence": [
            "The normal caller passes a fixed 13-bit value. The call-site immediate is byte_9 + 4, and IDA defines byte_9 as the constant address value 9, giving 13.",
            "The decoder writes at most 4096 cells. Literal and run-length branches stop when the cell counter reaches 4096.",
            "TTilesLayer allocates exactly 0x2000 bytes, or 4096 16-bit cells, for each board.",
            "The decoder returns false when the stream is exhausted before the cell counter reaches 4096.",
        ],
        "interpretation": "No board-buffer overrun is visible for the normal fixed caller. The function would need a separate audit if another caller supplied an unchecked bit depth, but the current IDA xrefs do not show one.",
    },
    {
        "address": "0x1aa0a0",
        "function": "TServerLevel_setTileLayerCount_int",
        "classification": "clamped-layer-count",
        "confidence": "confirmed-static",
        "severity": "resource-amplification",
        "evidence": [
            "Layer counts at or below zero are changed to one and counts above 100 are changed to 100.",
            "Each new TTilesLayer allocates a 0x2000-byte board plus its object and list state.",
            "The function also applies the count across the linked-level chain when one is present.",
        ],
        "interpretation": "The one-byte network field cannot directly request an unbounded layer count, but the maximum still represents roughly 800 KiB of board storage per level before object and list overhead. The linked-level chain deserves a separate total-budget check.",
    },
    {
        "address": "0x1a2924",
        "function": "TServerLevel_readLinks_TStream",
        "classification": "unbounded-link-list",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The reader accepts records until a line exactly equal to #, allocates 0xA8 bytes for every accepted line, tokenizes it, and appends the object to the level list.",
            "There is no record count, line-length limit, or total link budget in this function.",
            "The link tokenizer requires more than four fields before assigning the object, but malformed short lines still pass through dynamic string and token-list work.",
        ],
        "interpretation": "A syntactically valid but very large link section can consume memory and CPU. The impact is a denial of service unless another caller gives the records a more privileged effect.",
    },
    {
        "address": "0x1a2f08",
        "function": "TServerLevel_readSigns_TStream",
        "classification": "unbounded-sign-list-and-expansion",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The normal loader calls this reader without a boolean gate. It allocates a 0xF8-byte sign for each line longer than one byte and continues until the stream ends or readLine returns empty.",
            "Unlike the link reader, it does not stop on a # sentinel.",
            "Each sign passes through getSignText and replaceKeyCodes, which can expand text and repeatedly rebuild the string when several #K(...) sequences are present.",
            "The coordinate accessor returns a safe fallback byte for short records, but there is no count or text-length budget.",
        ],
        "interpretation": "Signs are the clearest normal-path resource-exhaustion surface in the level parser. A hostile level can supply many records or expensive key-code text without reaching an obvious fixed-buffer overwrite.",
    },
    {
        "address": "0x1a2a9c",
        "function": "TServerLevel_readNPCs_TStream_bool",
        "classification": "normal-path-discard-with-gated-allocation",
        "confidence": "confirmed-static",
        "severity": "context-dependent",
        "evidence": [
            "The normal encrypted-level loader passes boolean zero, so this reader consumes and clears lines without allocating NPC objects.",
            "When its boolean is true and the global client pointer is null, it allocates 0x4D0 bytes per record, reads short fields through the bounded string accessor, and calls loadImage with the parsed image name.",
            "No record count or line-length limit is visible.",
        ],
        "interpretation": "The object-building branch is not active in the stock LoadEncrypted callsite reviewed here. It remains a gated resource and image-loading risk for other callers or modified modes.",
    },
    {
        "address": "0x1a2cbc",
        "function": "TServerLevel_readChests_TStream_bool",
        "classification": "normal-path-discard-with-gated-allocation",
        "confidence": "confirmed-static",
        "severity": "context-dependent",
        "evidence": [
            "The normal encrypted-level loader passes boolean zero, so this reader consumes and clears lines without allocating chest objects.",
            "When enabled, it allocates 0x108 bytes per record, clamps the first two coordinates to 0 through 62, and reads additional byte fields without a count or record budget.",
            "Short coordinate fields use the bounded string accessor and therefore receive its fallback byte rather than an obvious out-of-bounds read.",
        ],
        "interpretation": "The stock level-load path does not build these objects. Other callers should still impose record and line budgets before enabling the branch.",
    },
    {
        "address": "0x1a29d0",
        "function": "TServerLevel_readBaddies_TStream_bool",
        "classification": "unbounded-line-consumer",
        "confidence": "confirmed-static",
        "severity": "parser-robustness-risk",
        "evidence": [
            "The reader consumes one byte at a time into a dynamic TString until LF or end of stream.",
            "It stops or returns on short records based on the line length and second byte, but it does not impose a line-length limit.",
            "This function does not allocate a baddie object in the reviewed body, so its direct impact is dynamic-string work rather than per-record object growth.",
        ],
        "interpretation": "The missing line budget is still a denial-of-service concern for oversized input, but the reviewed function has less object amplification than the link and sign readers.",
    },
    {
        "address": "0x183414",
        "function": "replaceKeyCodes_TString_const",
        "classification": "repeated-rebuild-complexity",
        "confidence": "confirmed-static",
        "severity": "availability-risk",
        "evidence": [
            "The function searches for #K(, finds a matching bracket, parses the number, constructs prefix and suffix strings, and assigns a rebuilt result in a loop.",
            "Each replacement can copy most of the current string, so a long sign containing many replacement sequences can cause repeated whole-string allocation and copying.",
            "Unmatched brackets stop the loop, and the numeric conversion returns a fallback value when parsing fails.",
        ],
        "interpretation": "This is an algorithmic complexity concern layered on top of the sign reader. It is not a direct fixed-buffer overwrite in the reviewed code.",
    },
]


DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_level_parser_review_20260830.json")


def sha256_file(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def effective_callers(address: int) -> list[dict]:
    queue = [address]
    visited = set()
    callers = []
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        for reference in idautils.XrefsTo(current, 0):
            caller = ida_funcs.get_func(reference.frm)
            if caller is None or caller.start_ea == current:
                continue
            name = idc.get_func_name(caller.start_ea) or ""
            segment = idc.get_segm_name(caller.start_ea) or ""
            if name.startswith(".") or segment.startswith(".plt"):
                queue.append(caller.start_ea)
                continue
            callers.append(
                {
                    "callsite": "0x%x" % reference.frm,
                    "caller": "0x%x" % caller.start_ea,
                    "caller_name": name,
                }
            )
    unique = {(row["caller"], row["callsite"]): row for row in callers}
    return sorted(
        unique.values(),
        key=lambda row: (int(row["caller"], 16), int(row["callsite"], 16)),
    )


def export_function(address: int, expected_name: str, role: str) -> dict:
    current_name = idc.get_func_name(address) or ""
    if current_name != expected_name:
        raise RuntimeError(
            "unexpected function name at %s: %s (expected %s)"
            % (hex(address), current_name, expected_name)
        )
    function = ida_hexrays.decompile(address)
    if function is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % hex(address))
    code = str(function)
    function_info = ida_funcs.get_func(address)
    literals = sorted(set(re.findall(r'"(?:\\.|[^"\\])*"', code)))
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": (
            "0x%x" % function_info.start_ea if function_info is not None else None
        ),
        "function_end": (
            "0x%x" % function_info.end_ea if function_info is not None else None
        ),
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "string_literals": literals[:200],
        "callers": effective_callers(address)[:250],
        "code": code,
    }


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = [
        export_function(int(address, 16), name, role)
        for address, name, role in TARGETS
    ]
    result = {
        "schema": "libqplay.original-level-parser-review.v1",
        "artifact": "original_level_parser_review_20260830",
        "scope": (
            "read-only Hex-Rays export of original 1.8 ARM64 encrypted level "
            "and line-oriented entity parsing"
        ),
        "network_contacted": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": sha256_file(idaapi.get_input_file_path()),
        },
        "validated_constants": {
            "gwebl_header_bytes": 8,
            "encoded_string_max_bytes": 223,
            "board_cells": 4096,
            "board_bytes": 8192,
            "board_bit_depth_at_normal_callsite": 13,
            "minimum_tile_layers": 1,
            "maximum_tile_layers": 100,
            "tile_layer_allocation_bytes": 8192,
        },
        "manual_reviews": MANUAL_REVIEWS,
        "functions": functions,
        "interpretation": [
            "The outer coded-file reader bounds ordinary copies to the in-memory stream, but trusts a signed 32-bit interpretation of the stored length and does not check allocation failure.",
            "The encrypted level loader checks the server identity, signature, and accepted version before decoding the board, but fixed-field read counts are ignored and the additive checksum is not an authenticity mechanism.",
            "The normal board caller uses a fixed 13-bit decoder with a 4096-cell destination allocated as 8192 bytes. Its run-length branches stop at the destination capacity.",
            "The layer count is clamped to 1 through 100. The link and sign readers have no comparable total record budget, and signs are processed through expansion helpers until end of stream.",
            "NPC and chest object creation is gated off by the boolean used in the normal encrypted-level loader. Their alternative branches still need budgets if other callers enable them.",
            "The report identifies denial-of-service and parser-robustness risks from static evidence. It does not claim remote exploitability without tracing the complete file-download path or running a disposable fuzz harness.",
        ],
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output = os.environ.get("IDA_LEVEL_PARSER_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(encoded, encoding="utf-8")
    ida_kernwin.msg("wrote %s\n" % output)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
