#!/usr/bin/env python3
"""Export the original image-resource loading and decoder boundaries.

The exporter is read-only. It records the resource-to-decoder path and the
dimension, compressed-chunk, and animation allocation checks visible in the
ARM64 IDA database. It does not fuzz a decoder or contact a server.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import ida_funcs
import ida_hexrays
import idaapi
import idautils
import idc


TARGETS = [
    ("0x115464", "TBitmapLoader_load_TResourceObject", "resource to bitmap loader"),
    ("0x114be8", "TBitmap_loadBitmap_TStream_TString_const", "decoder selection by extension"),
    ("0x1140b0", "TBitmap_allocateBitmap_uint_uint_bool_TBitmap_BitmapFormat", "bitmap allocation"),
    ("0x116fa0", "TBitmap_readPNG_TStream", "PNG and MNG frame reader"),
    ("0x11f9d8", "TMNGAnimation_parsePicture_void", "PNG/MNG chunk parser and decompressor"),
    ("0x150a38", "TBitmap_readGIF_TStream", "GIF frame reader"),
    ("0x150fa8", "TBitmap_readJPEG_TStream", "JPEG reader"),
    ("0x115e28", "TBitmap_readMSBmp_TStream", "BMP reader"),
    ("0x152110", "TBitmap_readTGA_TStream", "TGA reader"),
]

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_image_parser_review_20260830.json")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def effective_callers(address: int) -> list[dict]:
    callers = []
    for reference in idautils.XrefsTo(address, 0):
        caller = ida_funcs.get_func(reference.frm)
        if caller is None:
            continue
        callers.append(
            {
                "callsite": "0x%x" % reference.frm,
                "caller": "0x%x" % caller.start_ea,
                "caller_name": idc.get_func_name(caller.start_ea) or "",
            }
        )
    unique = {(item["caller"], item["callsite"]): item for item in callers}
    return sorted(
        unique.values(),
        key=lambda item: (int(item["caller"], 16), int(item["callsite"], 16)),
    )[:250]


def export_function(address: int, expected_name: str, role: str) -> dict:
    current_name = idc.get_func_name(address) or ""
    if current_name != expected_name:
        raise RuntimeError(
            "unexpected function name at %s: %s (expected %s)"
            % (hex(address), current_name, expected_name)
        )
    decompiled = ida_hexrays.decompile(address)
    if decompiled is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % hex(address))
    code = str(decompiled)
    function = ida_funcs.get_func(address)
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": "0x%x" % function.start_ea if function else None,
        "function_end": "0x%x" % function.end_ea if function else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "callers": effective_callers(address),
        "code": code,
    }


MANUAL_REVIEWS = [
    {
        "address": "0x115464",
        "classification": "server-resource-image-entrypoint",
        "confidence": "confirmed-static",
        "evidence": [
            "The loader obtains a resource stream and sends it to TBitmap_loadBitmap.",
            "A failed decode calls forceRedownload on the same resource.",
            "The local runtime trace loads server-delivered image resources through this resource and cache family.",
        ],
        "interpretation": "Image decoder input is part of the downloaded game-resource trust boundary, not only a local developer asset path.",
    },
    {
        "address": "0x114be8",
        "classification": "format-dispatch",
        "confidence": "confirmed-static",
        "evidence": [
            "The function dispatches .png and .mng to the PNG reader, .gif to the GIF reader, .jpg and .jpeg to the JPEG reader, and .bmp, .dib, and .tga to native readers.",
            "The extension is selected before the format-specific parser runs.",
        ],
        "interpretation": "A filename extension controls which native parser receives a downloaded stream. The parser itself must still validate dimensions and lengths.",
    },
    {
        "address": "0x116fa0",
        "classification": "png-frame-allocation",
        "confidence": "confirmed-static",
        "evidence": [
            "The reader creates one animation step per decoded frame and allocates pixel storage from width, height, and pixel depth arithmetic.",
            "The allocation expression is formed from integer fields before the result reaches malloc.",
            "There is no visible application-wide pixel or animation-frame budget in this wrapper.",
        ],
        "interpretation": "Malformed or unusually large image dimensions can create memory-pressure and integer-wrap test cases before the texture layer is reached.",
    },
    {
        "address": "0x11f9d8",
        "classification": "png-chunk-parser",
        "confidence": "confirmed-static",
        "evidence": [
            "IHDR dimensions are copied into animation-step fields without a small maximum.",
            "IDAT data is accumulated with realloc(p, old_size + chunk_length), with no visible aggregate compressed-data cap.",
            "Chunk lengths and size expressions use signed or 32-bit intermediates in the reviewed decompilation, and decompressed output is resized from those values.",
            "PNG and MNG chunk parsing stops at end markers but does not impose a total resource budget.",
        ],
        "interpretation": "This is a static memory-safety and availability boundary. It needs a bounded local malformed-PNG harness before being called an exploitable issue.",
    },
    {
        "address": "0x150a38",
        "classification": "gif-frame-allocation",
        "confidence": "confirmed-static",
        "evidence": [
            "Each GIF image descriptor allocates a source buffer from width times height and a destination buffer from frame dimensions and pixel depth.",
            "Interlaced rows are copied into the destination with arithmetic derived from the image dimensions.",
            "Every frame is appended to the animation list and there is no visible aggregate frame or pixel limit.",
        ],
        "interpretation": "A multi-frame GIF can consume memory across the animation list, while large dimensions create multiplication-wrap and allocation-size test cases.",
    },
    {
        "address": "0x150fa8",
        "classification": "jpeg-decoder-boundary",
        "confidence": "confirmed-static",
        "evidence": [
            "The reader delegates parsing to the bundled JPEG library and then allocates the bitmap from the decoder-reported output dimensions.",
            "The wrapper has no separate pixel-budget check before TBitmap allocation.",
            "The error path uses setjmp and destroys the decompressor on a decoder failure.",
        ],
        "interpretation": "The bundled JPEG library provides the primary malformed-input checks, but the application wrapper still lacks an explicit resource-size policy.",
    },
]


SECURITY_FINDINGS = [
    {
        "id": "IMG-001",
        "severity": "high",
        "confidence": "confirmed-static",
        "title": "PNG and GIF dimensions reach 32-bit allocation arithmetic without a small pixel cap",
        "evidence": [
            "PNG animation steps store IHDR dimensions and later compute pixel allocation sizes from integer fields.",
            "GIF frames compute source and destination sizes from image dimensions and pixel depth.",
            "The reviewed loaders do not reject large dimensions before allocation or impose an aggregate animation budget.",
        ],
        "impact": "A malformed or intentionally oversized downloaded image can cause excessive allocation, integer-wrap test cases, or decoder instability. A modern client should reject dimensions and total decoded pixels before allocation.",
        "limits": "The static pass did not fuzz the bundled decoders or establish a stock live-server path for arbitrary image bytes. The severity reflects the native arithmetic and trust boundary, not a demonstrated remote exploit.",
    },
    {
        "id": "IMG-002",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "PNG IDAT and GIF animation data have no visible aggregate resource budget",
        "evidence": [
            "The PNG/MNG parser grows accumulated IDAT data with realloc for each chunk.",
            "The GIF reader appends every decoded frame to the animation list.",
            "The image-resource wrapper has no total compressed, decompressed, frame-count, or pixel-count limit.",
        ],
        "impact": "A signed or otherwise accepted resource can consume memory and stall or terminate the client during decode. Resource budgets should be enforced before accumulation and again before texture creation.",
        "limits": "Reachability depends on the existing connector, game protocol, cache, and resource trust gates. No live endpoint was contacted.",
    },
    {
        "id": "IMG-003",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Extension-selected native decoders do not share one explicit size policy",
        "evidence": [
            "TBitmap_loadBitmap dispatches five image families to separate readers.",
            "The JPEG wrapper relies mainly on the bundled library and output dimensions, while PNG and GIF have their own integer allocation paths.",
            "No common maximum pixel count or decoded-byte budget is visible at the dispatch boundary.",
        ],
        "impact": "Different file formats have different allocation and failure behavior, making resource exhaustion harder to reason about and test. A single preflight budget should cover all decoders.",
        "limits": "The BMP and TGA readers were included for boundary coverage but were not independently fuzzed in this pass.",
    },
]


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = [
        export_function(int(address, 16), name, role)
        for address, name, role in TARGETS
    ]
    result = {
        "schema": "libqplay.original-image-parser-review.v1",
        "artifact": "original_image_parser_review_20260830",
        "scope": "read-only Hex-Rays export of original 1.8 downloaded image-resource and decoder paths",
        "network_contacted": False,
        "fuzzing_performed": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "resource_entrypoints": {
            "loader": "0x115464",
            "dispatch": "0x114be8",
            "downloaded_file_packet": 102,
        },
        "manual_reviews": MANUAL_REVIEWS,
        "security_findings": SECURITY_FINDINGS,
        "functions": functions,
        "interpretation": [
            "Downloaded image bytes reach native format-specific readers through the resource cache path.",
            "The highest-value local test is a bounded malformed-image corpus with dimension, chunk, frame-count, and multiplication-wrap cases.",
        ],
    }
    output = os.environ.get("IDA_IMAGE_PARSER_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
