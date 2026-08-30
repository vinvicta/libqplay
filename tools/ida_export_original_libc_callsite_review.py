#!/usr/bin/env python3
"""Export a focused libc call-site review for the original ARM64 IDB.

The exporter is read-only. It records direct references to selected imported
libc entry points and preserves the manual classifications for the small set
of call sites where a buffer or path boundary is visible in Hex-Rays. It does
not execute the library, fuzz a parser, or contact a service.

Set ``IDA_LIBC_REVIEW_OUT`` to choose another output path. The default output
is the compact JSON artifact in the repository's artifacts directory.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import ida_funcs
import ida_kernwin
import ida_name
import idaapi
import idautils
import idc


# These are the PLT entry points in the original 1.8 ARM64 library. Keeping
# the addresses fixed makes a wrong IDB fail loudly instead of producing a
# report that silently describes another revision.
PLT_TARGETS = {
    "memcpy": 0xD2340,
    "strncpy": 0xD2E00,
    "sprintf": 0xD5880,
    "memmove": 0xD62A0,
    "strcpy": 0xDA310,
    "strncat": 0xDA8D0,
    "memset": 0xDAE40,
    "chmod": 0xD5CB0,
    "fork": 0xDAFC0,
    "connect": 0xD8DA0,
    "execvp": 0xD2940,
    "stat": 0xDB3F0,
    "recv": 0xDDE50,
    "send": 0xD6170,
    "socket": 0xDE9A0,
    "unlink": 0xDEB90,
    "read": 0xD6290,
    "open": 0xDFB50,
}


MANUAL_REVIEWS = [
    {
        "address": "0x292b34",
        "function": "sub_292B34",
        "identified_role": "bundled libjpeg format_message callback",
        "api": "sprintf",
        "classification": "unbounded-callsite-unreachable-string-format",
        "confidence": "confirmed-static",
        "behavior": (
            "jpeg_std_error installs this function as the bundled libjpeg "
            "format_message callback. It selects one of 124 fixed message "
            "strings and writes into the caller-provided char buffer with "
            "sprintf at 0x292bd0 and 0x292c08. No destination length is "
            "passed by this function."
        ),
        "security_note": (
            "The 200-byte destination is TBitmap_JPEG_outputMessage's local "
            "JMSG_LENGTH_MAX buffer. The only three %s entries in the table "
            "describe temporary-file messages, but this build's "
            "jpeg_open_backing_store implementation reports the fixed "
            "JERR_NO_BACKING_STORE error instead of creating a temporary file. "
            "The TBitmap JPEG path supplies a stream source and reaches this "
            "formatter through numeric JPEG diagnostics. No write of a "
            "caller-controlled string into msg_parm.s was found in the bundled "
            "JPEG call path. The unbounded call remains a source-level hazard "
            "if the library is reused with a different backing-store or error "
            "path, but this APK does not establish a reachable string-format "
            "overflow."
        ),
    },
    {
        "address": "0x2afcec",
        "function": "yajl_gen_integer",
        "api": "sprintf",
        "classification": "bounded",
        "confidence": "confirmed-static",
        "behavior": (
            "Formats a signed 64-bit integer with the literal %lld into a "
            "32-byte local buffer before appending it to the YAJL output."
        ),
        "security_note": (
            "A signed 64-bit decimal value needs at most 20 digits plus a "
            "sign and terminator, so the local buffer is sufficient for this "
            "format."
        ),
    },
    {
        "address": "0x2aff04",
        "function": "yajl_gen_double",
        "api": "sprintf",
        "classification": "bounded",
        "confidence": "confirmed-static",
        "behavior": (
            "Formats a double with the literal %.20g into a 32-byte local "
            "buffer before appending it to the YAJL output."
        ),
        "security_note": (
            "The fixed format bounds the rendered value well below the local "
            "buffer size, including the exponent and terminator."
        ),
    },
    {
        "address": "0x2b2724",
        "function": "yajl_render_error_string_yajl_handle_t_uchar_const_ulong_int",
        "api": "strcpy/stpcpy",
        "classification": "length-precomputed",
        "confidence": "confirmed-static",
        "behavior": (
            "Builds a YAJL parser error string. It computes the variable "
            "error length, asks the parser allocator for the complete result, "
            "then copies fixed labels and the bounded parser error text."
        ),
        "security_note": (
            "The copies are not individually length-limited, but the output "
            "allocation is sized from the same strings before the copies. "
            "This review does not establish an allocation overflow in the "
            "surrounding parser allocator."
        ),
    },
    {
        "address": "0x2c50ac",
        "function": "CyaInt_ProcessVerifyPath",
        "identified_role": "CyaSSL certificate-directory loader",
        "api": "strncpy/strncat/stat",
        "classification": "bounded-dormant-path-api",
        "confidence": "confirmed-static",
        "behavior": (
            "Enumerates a certificate directory, clears a 256-byte local "
            "path buffer, copies at most 126 bytes of the directory name, "
            "adds a slash, and appends at most 128 bytes of each dirent name "
            "before stat and certificate processing."
        ),
        "security_note": (
            "The visible arithmetic keeps the constructed path within the "
            "256-byte local buffer, including its terminator. stat follows "
            "links and no canonicalization or no-follow operation is visible, "
            "so a caller that invokes this dormant API with an untrusted "
            "directory still has symlink risk. This helper is only called by "
            "CyaInt_CyaSSL_CTX_load_verify_locations, which is only reached "
            "by the exported CyaInt_CyaSSL_CertManagerLoadCA wrapper. The "
            "application connector instead calls "
            "CyaInt_CyaSSL_CTX_load_verify_buffer with its embedded trust "
            "bundle, and no internal application caller of the directory path "
            "API was found."
        ),
    },
    {
        "address": "0x2cbe2c",
        "function": "CyaInt_SetCipherList_CyaInt_Suites_char_const",
        "api": "strncpy",
        "classification": "bounded-parser",
        "confidence": "confirmed-static",
        "behavior": (
            "Splits the colon-separated cipher list into a 48-byte local "
            "buffer, always terminates it, and maps recognized legacy suite "
            "names to internal cipher identifiers."
        ),
        "security_note": (
            "The short and long input paths both write a terminator within "
            "the local buffer. The supported NULL and RC4 names are a legacy "
            "cryptographic policy concern, not a string overflow finding."
        ),
    },
    {
        "address": "0xec158",
        "function": "TIdentification_getMacAddressBuffer_void",
        "api": "socket/ioctl/close",
        "classification": "fixed-input",
        "confidence": "confirmed-static",
        "behavior": (
            "Writes the fixed interface name eth0 with ordinary ARM64 stores, "
            "then calls socket and SIOCGIFHWADDR to obtain the hardware "
            "address. The apparent strcpy in the decompiler is compiler "
            "inlining, not an imported strcpy call."
        ),
        "security_note": (
            "There is no attacker-sized string copy at this site. The privacy "
            "impact of collecting and hashing the MAC address is documented in "
            "SECURITY.md."
        ),
    },
    {
        "address": "0xf2870",
        "function": "TString_snprintf_char_int_char_const",
        "api": "strncpy",
        "classification": "bounded-wrapper",
        "confidence": "confirmed-static",
        "behavior": (
            "Renders through the internal formatter, caps the copy to the "
            "caller-supplied size minus one, and writes a terminating byte."
        ),
        "security_note": "The wrapper preserves the visible size boundary.",
    },
    {
        "address": "0xf2990",
        "function": "TString_vsnprintf_char_int_char_const_std_va_list",
        "api": "strncpy",
        "classification": "bounded-wrapper",
        "confidence": "confirmed-static",
        "behavior": (
            "The va_list variant follows the same size-minus-one copy and "
            "terminator pattern as TString_snprintf."
        ),
        "security_note": "The wrapper preserves the visible size boundary.",
    },
    {
        "address": "0x2bf378",
        "function": "GenerateSeed_OS_Seed_uchar_uint",
        "api": "open/read",
        "classification": "system-randomness",
        "confidence": "confirmed-static",
        "behavior": (
            "Opens /dev/urandom, falls back to /dev/random, reads the exact "
            "requested byte count, closes the descriptor, and returns an "
            "error code for an incomplete read."
        ),
        "security_note": "The path is a fixed device name, not caller-controlled.",
    },
    {
        "address": "0x2ad5e4",
        "function": "DGifOpenFileName",
        "api": "open",
        "classification": "path-input",
        "confidence": "confirmed-static",
        "behavior": (
            "Opens a caller-supplied GIF filename read-only and passes the "
            "descriptor to the bundled GIF decoder."
        ),
        "security_note": (
            "The path provenance is supplied by the resource and image "
            "loaders. This site alone does not prove arbitrary file access."
        ),
    },
]


DEFAULT_OUTPUT = (
    "/home/v/Desktop/graal-decomp/libqplay/artifacts/"
    "original_libc_callsite_review_20260830.json"
)


def sha256_file(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def caller_rows(address: int) -> list[dict]:
    rows = []
    for reference in idautils.XrefsTo(address, 0):
        function = ida_funcs.get_func(reference.frm)
        if function is None or function.start_ea == address:
            continue
        name = idc.get_func_name(function.start_ea) or ""
        segment = idc.get_segm_name(function.start_ea) or ""
        if name.startswith(".") or segment.startswith(".plt"):
            continue
        rows.append(
            {
                "callsite": "0x%x" % reference.frm,
                "caller": "0x%x" % function.start_ea,
                "caller_name": name,
                "xref_type": int(reference.type),
            }
        )
    unique = {(row["callsite"], row["caller"]): row for row in rows}
    return sorted(
        unique.values(),
        key=lambda row: (int(row["caller"], 16), int(row["callsite"], 16)),
    )


def main() -> None:
    targets = []
    for name, address in sorted(PLT_TARGETS.items()):
        actual = idc.get_name(address, idc.GN_VISIBLE) or ""
        if actual not in {"." + name, name}:
            raise RuntimeError(
                "unexpected PLT name at 0x%x: %s (expected .%s)"
                % (address, actual, name)
            )
        targets.append(
            {
                "name": name,
                "address": "0x%x" % address,
                "ida_name": actual,
                "callers": caller_rows(address),
            }
        )

    input_path = idaapi.get_input_file_path()
    result = {
        "schema": "libqplay.original-libc-callsite-review.v1",
        "artifact": "original_libc_callsite_review_20260830",
        "scope": (
            "read-only direct PLT call-site inventory and manual buffer review "
            "for the original 1.8 ARM64 library"
        ),
        "network_contacted": False,
        "database": {
            "path": input_path,
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": sha256_file(input_path),
        },
        "import_targets": targets,
        "manual_reviews": MANUAL_REVIEWS,
        "interpretation": [
            "Imported libc functions show capability, not exploitability.",
            "The selected direct call sites contain one unbounded sprintf call in the bundled JPEG formatter; its fixed-table string path and backing-store reachability were reviewed separately.",
            "The reviewed fixed-size formatter, YAJL integer formatter, certificate-directory path builder, cipher parser, and MAC-interface setup have visible local bounds or fixed inputs.",
            "The report does not prove that a network peer can reach any manual-review site or control its destination buffer.",
            "The report does not replace parser fuzzing in a disposable process.",
        ],
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    output = os.environ.get("IDA_LIBC_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(encoded, encoding="utf-8")
    ida_kernwin.msg("wrote %s\n" % output)
    print(json.dumps({"target_count": len(targets), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
