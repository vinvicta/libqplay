#!/usr/bin/env python3
"""Export bundled compression and font-library provenance from the ARM64 IDB.

The exporter is read-only. It records exact version literals, the wrapper
functions that reach the bundled libraries, and the local resource paths that
feed those wrappers. It does not contact a server or fuzz a decoder.
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
    ("0xe4dd4", "TCompression_getCompressionBuffer_int", "shared decompression buffer growth"),
    (
        "0xe4fc8",
        "TCompression_DecompressBuf_void_const_int_uchar_uint",
        "zlib decompression wrapper",
    ),
    (
        "0xe5270",
        "TCompression_DecompressBuf2_void_const_int_uchar_uint",
        "bzip2 decompression wrapper",
    ),
    (
        "0xe50d8",
        "TCompression_DecompressBuf_TString_const_uchar_uint",
        "zlib string wrapper",
    ),
    (
        "0xe5388",
        "TCompression_DecompressBuf2_TString_const_uchar_uint",
        "bzip2 string wrapper",
    ),
    ("0x275070", "BZ2_bzBuffToBuffDecompress", "bundled bzip2 buffer API"),
    ("0x2751ac", "BZ2_bzlibVersion", "bundled bzip2 version API"),
    ("0x289a70", "uncompress", "bundled zlib buffer API"),
    ("0x289b50", "zlibVersion", "bundled zlib version API"),
    ("0x110ca0", "TFontData_load_void", "font resource and file loader"),
    ("0x1110a8", "TFontData_getFontData_TString_const", "font cache entrypoint"),
    ("0x253f1c", "FT_Init_FreeType", "bundled FreeType initialization"),
]

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_dependency_provenance_20260830.json")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
                "xref_type": reference.type,
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


DEPENDENCIES = [
    {
        "name": "zlib",
        "version": "1.2.5",
        "linkage": "static code embedded in libqplay.so",
        "version_evidence": {
            "function": "zlibVersion",
            "address": "0x289b50",
            "return_literal": "1.2.5",
            "also_passed_to": [
                "inflateInit_ at 0x289ac0",
                "inflateInit2_ at 0x120428",
            ],
        },
        "inbound_paths": [
            "TMNGAnimation_parsePicture_void at 0x11f9d8 inflates PNG or MNG data.",
            "unzReadCurrentFile at 0x24b174 uses inflate for ZIP entries.",
            "TCompression_DecompressBuf at 0xe4fc8 is selected by protocol compression mode 1, and by legacy modes 3 and 4.",
        ],
    },
    {
        "name": "bzip2",
        "version": "1.0.4, 20-Dec-2006",
        "linkage": "static code embedded in libqplay.so",
        "version_evidence": {
            "function": "BZ2_bzlibVersion",
            "address": "0x2751ac",
            "return_literal": "1.0.4, 20-Dec-2006",
        },
        "inbound_paths": [
            "TCompression_DecompressBuf2 at 0xe5270 calls BZ2_bzBuffToBuffDecompress.",
            "The NewGraal protocol selects this wrapper for compression selector 2.",
            "The legacy protocol selects this wrapper for modes 5 and 6.",
        ],
    },
    {
        "name": "FreeType",
        "version": "2.3.6",
        "linkage": "static code embedded in libqplay.so",
        "version_evidence": {
            "function": "FT_Init_FreeType",
            "address": "0x253f1c",
            "library_version_fields": [2, 3, 6],
        },
        "inbound_paths": [
            "TFontData_load_void at 0x110ca0 loads system fonts through FT_New_Face.",
            "The same loader uses FT_New_Memory_Face for resource-backed font streams.",
            "A missing relative font resource reaches TFileDownload_download, so the resource-backed path is a conditional downloaded-input boundary.",
        ],
    },
    {
        "name": "libjpeg",
        "version": None,
        "linkage": "static code embedded in libqplay.so",
        "version_evidence": {
            "known_symbols": [
                "jpeg_std_error at 0x292c8c",
                "jpeg_CreateDecompress at 0x28ad98",
            ],
            "note": "The exact libjpeg release was not recovered in this pass. ABI constants in jpeg_CreateCompress are not treated as a release identifier.",
        },
        "inbound_paths": [
            "TBitmap_readJPEG_TStream at 0x150fa8 receives extension-selected image resources.",
        ],
    },
]


CALLSITE_EVIDENCE = [
    {
        "caller": "0x1fc598",
        "caller_name": "TGraalConnection_parseProtocol_OldGraal_void",
        "callsite": "0x1fc680",
        "callee": "TCompression_DecompressBuf_void_const_int_uchar_uint",
        "selector": "legacy compression modes 3 and 4",
    },
    {
        "caller": "0x1fc598",
        "caller_name": "TGraalConnection_parseProtocol_OldGraal_void",
        "callsite": "0x1fc8a4",
        "callee": "TCompression_DecompressBuf2_void_const_int_uchar_uint",
        "selector": "legacy compression modes 5 and 6",
    },
    {
        "caller": "0x1fe31c",
        "caller_name": "TGraalConnection_parseProtocol_NewGraal_void",
        "callsite": "0x1fe880",
        "callee": "TCompression_DecompressBuf_void_const_int_uchar_uint",
        "selector": "NewGraal compression selector 1",
    },
    {
        "caller": "0x1fe31c",
        "caller_name": "TGraalConnection_parseProtocol_NewGraal_void",
        "callsite": "0x1fe868",
        "callee": "TCompression_DecompressBuf2_void_const_int_uchar_uint",
        "selector": "NewGraal compression selector 2",
    },
    {
        "caller": "0x11f9d8",
        "caller_name": "TMNGAnimation_parsePicture_void",
        "callsite": "0x1204a8",
        "callee": "inflate",
        "selector": "PNG or MNG IDAT output",
    },
    {
        "caller": "0x11f9d8",
        "caller_name": "TMNGAnimation_parsePicture_void",
        "callsite": "0x1204f4",
        "callee": "uncompress",
        "selector": "PNG or MNG compressed block path",
    },
    {
        "caller": "0x24b174",
        "caller_name": "unzReadCurrentFile",
        "callsite": "0x24b458",
        "callee": "inflate",
        "selector": "ZIP entry decompression",
    },
    {
        "caller": "0x110ca0",
        "caller_name": "TFontData_load_void",
        "callsite": "0x110d6c",
        "callee": "FT_New_Memory_Face",
        "selector": "resource-backed font stream",
    },
    {
        "caller": "0x110ca0",
        "caller_name": "TFontData_load_void",
        "callsite": "0x110f14",
        "callee": "FT_New_Face",
        "selector": "filesystem font path",
    },
]


SECURITY_FINDINGS = [
    {
        "id": "DEP-001",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Inbound decompression uses old statically bundled zlib and bzip2 releases",
        "evidence": [
            "zlibVersion returns 1.2.5 and BZ2_bzlibVersion returns 1.0.4, 20-Dec-2006.",
            "The protocol parsers select the zlib and bzip2 wrappers from fields in incoming frames.",
            "PNG, MNG, and ZIP resource paths also reach bundled zlib code.",
            "DT_NEEDED contains no libz or libbz2 entry, so a host-library update cannot replace these implementations without rebuilding or repackaging the native library.",
        ],
        "impact": "These versions predate many later parser and resource-handling fixes. An attacker who can supply accepted protocol or resource bytes may have more malformed-input exposure than a current library would. Updating the dependency or proving vendor backports is appropriate before relying on the old client for hostile inputs.",
        "limits": "The exact bundled source revisions and vendor backports were not reconstructed here. This is dependency exposure, not a claim that a particular CVE is exploitable in this binary. No decoder fuzzing or live-server test was performed.",
    },
    {
        "id": "DEP-002",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Resource-backed font data reaches bundled FreeType 2.3.6",
        "evidence": [
            "FT_Init_FreeType writes version fields 2, 3, and 6 into the library object.",
            "TFontData_load uses FT_New_Memory_Face for resource streams and FT_New_Face for filesystem paths.",
            "A relative font that is absent locally is handed to the file-download/resource lookup path before the font face is created.",
        ],
        "impact": "Font parsing is native code with a large historical input surface. A malformed accepted font can create parser, memory, or availability test cases, especially because no application-level font byte or glyph budget was established in this pass.",
        "limits": "The review did not prove that an untrusted server can choose the font option or supply arbitrary font bytes in the stock game flow. No font fuzzing was performed.",
    },
    {
        "id": "DEP-003",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Automatic decompression buffer growth is shared and only partially bounded",
        "evidence": [
            "The automatic TCompression wrappers start at least 64 KiB and retry after output-buffer-full results.",
            "The retry loop accepts capacities through 4 MiB, then returns an empty result when another growth would exceed that threshold.",
            "TCompression_getCompressionBuffer_int itself rounds requests to powers of two and has no independent upper bound.",
            "The input stream and packet accumulator have separate limits and are not covered by this output-buffer ceiling.",
        ],
        "impact": "A compressed frame can force repeated global reallocations and consume memory before the wrapper rejects it. The cap limits one automatic output path but is not a complete compressed-input or total-resource budget.",
        "limits": "The exact behavior for every explicit-output-buffer caller was not exhaustively traced. This finding is a static resource-policy observation, not a demonstrated memory corruption.",
    },
]


def main() -> None:
    if not idaapi.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is not available")
    functions = [
        export_function(int(address, 16), name, role)
        for address, name, role in TARGETS
    ]
    input_path = Path(idaapi.get_input_file_path())
    result = {
        "schema": "libqplay.original-dependency-provenance.v1",
        "artifact": "original_dependency_provenance_20260830",
        "scope": "read-only Hex-Rays export of original 1.8 bundled compression and font-library boundaries",
        "network_contacted": False,
        "fuzzing_performed": False,
        "database": {
            "path": str(input_path),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": sha256_file(input_path),
            "binary_bytes": input_path.stat().st_size,
        },
        "dynamic_needed_libraries": [
            "libGLESv1_CM.so",
            "libc.so",
            "libstdc++.so",
            "libm.so",
            "liblog.so",
        ],
        "missing_dynamic_replacements": ["libz.so", "libbz2.so", "libfreetype.so"],
        "dependencies": DEPENDENCIES,
        "callsite_evidence": CALLSITE_EVIDENCE,
        "security_findings": SECURITY_FINDINGS,
        "functions": functions,
        "references": [
            {
                "title": "zlib 1.2.x ChangeLog",
                "url": "https://raw.githubusercontent.com/madler/zlib/v1.2.12/ChangeLog",
                "use": "upstream release-history comparison; not a binary provenance claim",
            },
            {
                "title": "zlib development ChangeLog",
                "url": "https://github.com/madler/zlib/blob/develop/ChangeLog",
                "use": "upstream parser-fix history; exact vendor backports remain unknown",
            },
            {
                "title": "bzip2 historical source archive",
                "url": "https://www.sourceware.org/pub/bzip2/",
                "use": "historical source comparison for the exact 1.0.4 release",
            },
        ],
        "interpretation": [
            "The native library statically embeds the decompression and font implementations, so Android system updates cannot independently patch these code paths.",
            "The highest-value follow-up is a disposable local harness for protocol compression, PNG or ZIP input, and font parsing with explicit byte and allocation budgets.",
        ],
    }
    output = os.environ.get("IDA_DEPENDENCY_PROVENANCE_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
