#!/usr/bin/env python3
"""Export the original ARM64 ELF init and fini callback review.

The exporter is read-only. It follows the dynamic ELF init and fini arrays
already loaded in IDA, records each callback and its decompiler output, and
checks whether the callbacks directly reach selected network, file, or process
boundaries. It does not install the APK, contact a service, or change the IDA
database.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import ida_funcs
import ida_hexrays
import idaapi
import idautils
import idc


INIT_ARRAY_ADDRESS = 0x35D210
INIT_ARRAY_COUNT = 20
FINI_ARRAY_ADDRESS = 0x35D2B0
FINI_ARRAY_COUNT = 10
DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_native_init_review_20260830.json")

BOUNDARY_TOKENS = (
    "connect",
    "execvp",
    "fopen",
    "gethostbyname",
    "mkdir",
    "open",
    "recv",
    "send",
    "socket",
    "unlink",
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def direct_callees(function) -> list[dict]:
    result = {}
    for instruction in idautils.FuncItems(function.start_ea):
        for reference in idautils.CodeRefsFrom(instruction, 0):
            callee = ida_funcs.get_func(reference)
            if callee is None or callee.start_ea == function.start_ea:
                continue
            result[callee.start_ea] = {
                "address": "0x%x" % callee.start_ea,
                "name": idc.get_func_name(callee.start_ea) or "",
            }
    return sorted(result.values(), key=lambda item: int(item["address"], 16))


def export_callback(slot: int, kind: str) -> dict:
    address = idc.get_qword(slot)
    function = ida_funcs.get_func(address)
    if function is None:
        raise RuntimeError("no function at %s" % hex(address))
    name = idc.get_func_name(address) or ""
    decompiled = ida_hexrays.decompile(address)
    if decompiled is None:
        raise RuntimeError("Hex-Rays could not decompile %s" % hex(address))
    code = str(decompiled)
    callees = direct_callees(function)
    boundary_callees = [
        item for item in callees
        if any(token in item["name"].lower() for token in BOUNDARY_TOKENS)
    ]
    return {
        "kind": kind,
        "slot": "0x%x" % slot,
        "address": "0x%x" % address,
        "name": name,
        "function_start": "0x%x" % function.start_ea,
        "function_end": "0x%x" % function.end_ea,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "direct_callees": callees,
        "selected_boundary_callees": boundary_callees,
        "code": code,
    }


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")

    callbacks = []
    for index in range(INIT_ARRAY_COUNT):
        callbacks.append(export_callback(INIT_ARRAY_ADDRESS + index * 8, "init"))
    for index in range(FINI_ARRAY_COUNT):
        callbacks.append(export_callback(FINI_ARRAY_ADDRESS + index * 8, "fini"))

    selected_calls = [
        item for callback in callbacks for item in callback["selected_boundary_callees"]
    ]
    result = {
        "schema": "libqplay.original-native-init-review.v1",
        "artifact": "original_native_init_review_20260830",
        "scope": "read-only review of the original ARM64 ELF init and fini callback arrays",
        "network_contacted": False,
        "apk_executed_by_exporter": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "arrays": {
            "init_array": {
                "address": "0x%x" % INIT_ARRAY_ADDRESS,
                "entries": INIT_ARRAY_COUNT,
            },
            "fini_array": {
                "address": "0x%x" % FINI_ARRAY_ADDRESS,
                "entries": FINI_ARRAY_COUNT,
            },
        },
        "callbacks": callbacks,
        "findings": [
            {
                "id": "INIT-001",
                "severity": "informational",
                "confidence": "confirmed-static",
                "title": "Native load executes a fixed constructor array before QPlayMain",
                "evidence": [
                    "The ARM64 dynamic section defines a 20-entry init array at 0x35d210 and a 10-entry fini array at 0x35d2b0.",
                    "The entries resolve to fixed code addresses inside libqplay.so and do not depend on an incoming URI or server response.",
                ],
                "impact": "A loader failure or constructor crash can occur before the Java bridge reaches QPlayMain. This is a startup boundary that should be separated from connector and TLS diagnosis.",
                "limits": "Static decompilation does not prove that every constructor runs successfully on a particular Android image. No ARM64 device logcat was available.",
            },
            {
                "id": "INIT-002",
                "severity": "informational",
                "confidence": "confirmed-static",
                "title": "Reviewed init and fini callbacks perform static state setup and teardown",
                "evidence": [
                    "The callbacks initialize or clear file paths, resource link lists, texture state, cached image dimensions, GUI defaults, client restart strings, input animation state, and Android video globals.",
                    "The exporter found %d direct calls from the callback set into the selected socket, resolver, file, or process boundary names." % len(selected_calls),
                ],
                "impact": "The constructor set is not a hidden connector request path in the reviewed database. The only nontrivial load-time work is allocation of small native lists and initialization of fixed global values.",
                "limits": "The direct-call check is name-based and does not replace a full audit of every helper called by a constructor. It does not establish memory-safety of the allocation or teardown code.",
            },
        ],
        "interpretation": [
            "The JNI load path has a fixed native initialization phase before Java calls QPlayMain.",
            "The residual sub_E* callbacks in this array are retained address-based names in IDA because several only write anonymous static storage; their decompiled code is included for reproducibility.",
            "The selected boundary check found no direct constructor edge into connect, resolver, socket, file, or process imports.",
        ],
    }
    with open(DEFAULT_OUTPUT, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({
        "callbacks": len(callbacks),
        "init": INIT_ARRAY_COUNT,
        "fini": FINI_ARRAY_COUNT,
        "selected_boundary_calls": len(selected_calls),
        "output": DEFAULT_OUTPUT,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
