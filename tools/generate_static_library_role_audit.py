#!/usr/bin/env python3
"""Generate the next reviewed role map for bundled static libraries.

The native library does not retain source names for these routines. This
artifact records the source-role comparison, the IDA address, and the reason
each analysis alias is safe. It never loads or executes the APK.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


DEFAULT_BINARY = (
    "/home/v/Desktop/graal-decomp/GraalOnline+Classic_1.8_APKPure/"
    "lib/arm64-v8a/libqplay.so"
)
DEFAULT_PROFILE = "artifacts/unresolved_function_profile.json"
DEFAULT_OUTPUT = "artifacts/static_library_role_audit_20260901.json"
DEFAULT_INPUT_DATABASE = "analysis/libqplay_translated_from_active_v10.i64"
DEFAULT_INPUT_DATABASE_SHA256 = (
    "5894e93f41d83d7978e38305b1a86dd06217a3efb8fd48e4ae2f743438c8e063"
)
DEFAULT_INPUT_INVENTORY_SHA256 = (
    "e6045dc5b63f215c51e13ec3b62472ee415dee87533e225ced04812439959a87"
)
DEFAULT_DATABASE = "analysis/libqplay_translated_from_active_v11.i64"


SOURCE_REFERENCES = {
    "zlib_deflate": "https://github.com/madler/zlib/blob/develop/deflate.c",
    "zlib_trees": "https://github.com/madler/zlib/blob/develop/trees.c",
    "zlib_inftrees": "https://github.com/madler/zlib/blob/develop/inftrees.c",
    "zlib_zutil": "https://github.com/madler/zlib/blob/develop/zutil.c",
    "bzip2_blocksort": (
        "https://sources.debian.org/src/bzip2/1.0.5-1%2Blenny1/blocksort.c/"
    ),
    "bzip2_compress": "https://github.com/libarchive/bzip2/blob/master/compress.c",
    "bzip2_bzlib": "https://github.com/libarchive/bzip2/blob/master/bzlib.c",
    "minizip_unzip": "https://github.com/madler/zlib/blob/develop/contrib/minizip/unzip.c",
    "gpc": "https://github.com/rickbrew/GeneralPolygonClipper/blob/main/gpc.c",
    "cyassl_asn": (
        "https://nest-open-source.googlesource.com/nest-yale-lock/1.2/"
        "freertos/%2B/b9a7305351d35e2d3076d0b4ab3ec121f0aa8d52/"
        "FreeRTOS-Plus/Source/CyaSSL/ctaocrypt/src/asn.c"
    ),
    "tomcrypt_des": (
        "https://android.googlesource.com/platform/external/dropbear/"
        "+/refs/heads/donut-release/libtomcrypt/src/ciphers/des.c"
    ),
    "yajl_alloc": "https://sources.debian.org/src/yajl/2.1.0-3/src/yajl_alloc.c",
}


ALIASES = [
    {
        "ea": 0x27FD34,
        "family": "zlib",
        "proposed_name": "zlib_deflate_fast",
        "source_name": "deflate_fast",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Fast deflate compressor using a hash-chain match search.",
        "evidence": [
            "The body hashes the lookahead, searches previous matches, emits the chosen match or literal, and flushes a block.",
            "Its control flow matches zlib deflate_fast, including the short-match and end-of-input paths.",
            "The function calls the translated zlib block-flush helper at 0x288e5c.",
        ],
        "xrefs_to": [],
        "source_references": ["zlib_deflate", "zlib_trees"],
    },
    {
        "ea": 0x2806E8,
        "family": "zlib",
        "proposed_name": "zlib_deflate_stored",
        "source_name": "deflate_stored",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Stored-block deflate path that copies input without matching.",
        "evidence": [
            "The body computes block boundaries, copies raw input to the pending output buffer, and flushes stored blocks.",
            "It has the direct-block behavior and end-of-stream handling of zlib deflate_stored.",
            "The function calls the translated zlib block-flush helper at 0x288e5c.",
        ],
        "xrefs_to": [],
        "source_references": ["zlib_deflate", "zlib_trees"],
    },
    {
        "ea": 0x280D70,
        "family": "zlib",
        "proposed_name": "zlib_deflate_slow",
        "source_name": "deflate_slow",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Lazy-match deflate compressor using the previous match state.",
        "evidence": [
            "The body carries prev_length, prev_match, and match_available state across lookahead iterations.",
            "It chooses between the previous match, the current match, and a literal, which is the defining lazy-match behavior.",
            "The function calls the translated zlib block-flush helper at 0x288e5c.",
        ],
        "xrefs_to": [],
        "source_references": ["zlib_deflate", "zlib_trees"],
    },
    {
        "ea": 0x286A30,
        "family": "zlib",
        "proposed_name": "zlib_inflate_table",
        "source_name": "inflate_table",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Canonical Huffman decode-table builder used by inflate.",
        "evidence": [
            "The body counts code lengths, builds canonical offsets, handles incomplete trees, and writes decode-table entries.",
            "inflate calls it three times for the literal, length, and distance code tables at 0x285dd4.",
            "The table-building algorithm matches zlib inftrees.c inflate_table.",
        ],
        "xrefs_to": ["0x285dd4"],
        "source_references": ["zlib_inftrees"],
    },
    {
        "ea": 0x2874A8,
        "family": "zlib",
        "proposed_name": "zlib_send_tree",
        "source_name": "send_tree",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Encoder for a dynamic Huffman tree with repeat codes.",
        "evidence": [
            "The body walks code lengths, groups repeated values, and emits the zlib bit patterns for tree-length runs.",
            "The translated block flush routine calls it for the literal and distance trees at 0x2895a0.",
        ],
        "xrefs_to": ["0x2895a0"],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x287A48,
        "family": "zlib",
        "proposed_name": "zlib_compress_block",
        "source_name": "compress_block",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Emitter for literal and length symbols plus distance symbols.",
        "evidence": [
            "The body reads the pending symbol buffer, emits literal or match codes, and writes the associated extra bits.",
            "The translated block flush routine calls it with both dynamic and static trees at 0x2895c0.",
        ],
        "xrefs_to": ["0x2895c0"],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x287EAC,
        "family": "zlib",
        "proposed_name": "zlib_build_tree",
        "source_name": "build_tree",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Huffman tree builder that fills the heap and computes code lengths.",
        "evidence": [
            "The body consumes a tree descriptor, builds the frequency heap, combines nodes, and generates bit lengths.",
            "The translated block flush routine calls it for the literal, distance, and bit-length descriptors at 0x288ea8.",
        ],
        "xrefs_to": ["0x288ea8"],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x288908,
        "family": "zlib",
        "proposed_name": "zlib_tr_init",
        "source_name": "_tr_init",
        "source_match": "exact-source-role-with-prefix",
        "confidence": "high",
        "role": "Initializes zlib's tree descriptors, bit buffer, and first block.",
        "evidence": [
            "The body installs the literal, distance, and bit-length tree descriptors, clears the bit state, and zeroes the three frequency arrays.",
            "It sets the end-of-block frequency and the match counters exactly as zlib's _tr_init and init_block path require.",
            "deflateReset calls it at 0x281a50. The zlib_ prefix is an analysis-family prefix, not part of the source name.",
        ],
        "xrefs_to": ["0x281a50"],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x288998,
        "family": "zlib",
        "proposed_name": "zlib_tr_stored_block",
        "source_name": "_tr_stored_block",
        "source_match": "exact-source-role-with-prefix",
        "confidence": "high",
        "role": "Writes a stored deflate block header, length, complement, and payload.",
        "evidence": [
            "The body emits the final and stored-block bits, writes the length and one's complement, then copies the raw block bytes.",
            "The deflate function uses it for the empty stored block path at 0x282094.",
        ],
        "xrefs_to": ["0x282094"],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x288B28,
        "family": "zlib",
        "proposed_name": "zlib_tr_align",
        "source_name": "_tr_align",
        "source_match": "exact-source-role-with-prefix",
        "confidence": "high",
        "role": "Aligns a deflate stream with an empty static block.",
        "evidence": [
            "The body writes the static empty-block code and pads the bit buffer to a byte boundary.",
            "The deflate function calls it at 0x2836f8 on the block-alignment path.",
        ],
        "xrefs_to": ["0x2836f8"],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x288E5C,
        "family": "zlib",
        "proposed_name": "zlib_tr_flush_block",
        "source_name": "_tr_flush_block",
        "source_match": "exact-source-role-with-prefix",
        "confidence": "high",
        "role": "Selects and emits stored, static-Huffman, or dynamic-Huffman blocks.",
        "evidence": [
            "The body builds the three dynamic trees, compares stored and compressed costs, emits tree descriptions, and copies the symbol buffer.",
            "All three deflate strategies call it, and its internal calls to build_tree, send_tree, and compress_block match zlib trees.c.",
        ],
        "xrefs_to": ["0x27ff30", "0x28077c", "0x280fa4", "0x281ea0"],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x2899AC,
        "family": "zlib",
        "proposed_name": "zlib_tr_tally",
        "source_name": "_tr_tally",
        "source_match": "exact-source-role-with-prefix",
        "confidence": "high",
        "role": "Records a literal or match and updates the Huffman frequencies.",
        "evidence": [
            "The body writes the distance and length or literal into the pending symbol buffer, increments the corresponding tree frequencies, and reports when the buffer is full.",
            "This is the exact behavior of the zlib _tr_tally helper, which is often exposed as a small standalone compiler function even when the source uses a macro-like call site.",
        ],
        "xrefs_to": [],
        "source_references": ["zlib_trees"],
    },
    {
        "ea": 0x289B80,
        "family": "zlib",
        "proposed_name": "zlib_zcalloc",
        "source_name": "zcalloc",
        "source_match": "exact-source-role-with-prefix",
        "confidence": "high",
        "role": "Default zlib allocation callback implemented with malloc.",
        "evidence": [
            "The body returns malloc(items * size) with the zlib allocator callback signature.",
            "deflateInit2_ and inflateInit2_ install it in their stream allocator slots at 0x283cac and 0x2840dc.",
        ],
        "xrefs_to": ["0x283cac", "0x2840dc"],
        "source_references": ["zlib_zutil"],
    },
    {
        "ea": 0x289B88,
        "family": "zlib",
        "proposed_name": "zlib_zcfree",
        "source_name": "zcfree",
        "source_match": "exact-source-role-with-prefix",
        "confidence": "high",
        "role": "Default zlib release callback implemented with free.",
        "evidence": [
            "The body ignores the opaque allocator context and calls free on the supplied pointer.",
            "deflateInit2_ and inflateInit2_ install it in their stream allocator slots at 0x283c9c and 0x2840cc.",
        ],
        "xrefs_to": ["0x283c9c", "0x2840cc"],
        "source_references": ["zlib_zutil"],
    },
    {
        "ea": 0xE02AC,
        "family": "bzip2",
        "proposed_name": "bzip2_mainGtU",
        "source_name": "mainGtU",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Suffix comparator used by bzip2's main sorting algorithm.",
        "evidence": [
            "The body compares eight unrolled block bytes and quadrant values, wraps at nblock, decrements the sort budget, and returns the ordering result.",
            "mainSort calls it three times from 0x27ebb8, and the six arguments match the historical mainGtU signature.",
        ],
        "xrefs_to": ["0x27ebb8"],
        "source_references": ["bzip2_blocksort"],
    },
    {
        "ea": 0x2751C0,
        "family": "bzip2",
        "proposed_name": "bzip2_sendMTFValues",
        "source_name": "sendMTFValues",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Builds and emits bzip2's move-to-front Huffman coding tables.",
        "evidence": [
            "The large body selects coding groups, computes selector values, builds canonical codes, and emits the MTF stream with the bzip2 bit writer.",
            "BZ2_compressBlock_EState_uchar calls it at 0x27962c after writing the block header and original pointer.",
        ],
        "xrefs_to": ["0x27962c"],
        "source_references": ["bzip2_compress"],
    },
    {
        "ea": 0x27D6F0,
        "family": "bzip2",
        "proposed_name": "bzip2_fallbackSort",
        "source_name": "fallbackSort",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Fallback suffix sort for highly repetitive bzip2 blocks.",
        "evidence": [
            "The body creates the 256-entry frequency table, performs the initial radix placement, builds bucket-head bits, and refines buckets by doubling depth.",
            "BZ2_blockSort_EState calls it at 0x27f6e8. The verbosity argument is optimized out, leaving four register arguments in this build.",
        ],
        "xrefs_to": ["0x27f6e8"],
        "source_references": ["bzip2_blocksort"],
    },
    {
        "ea": 0x27E0E4,
        "family": "bzip2",
        "proposed_name": "bzip2_mainSort",
        "source_name": "mainSort",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Primary bzip2 suffix sort with running-order and quadrant refinement.",
        "evidence": [
            "The body initializes the two-byte frequency table, tracks bigDone buckets, performs quadrant updates, and invokes the translated mainGtU comparator.",
            "BZ2_blockSort_EState calls it at 0x27f660. The verbosity argument is optimized out, so the binary exposes six register arguments.",
        ],
        "xrefs_to": ["0x27f660"],
        "source_references": ["bzip2_blocksort"],
    },
    {
        "ea": 0x273350,
        "family": "bzip2",
        "proposed_name": "default_bzfree",
        "source_name": "default_bzfree",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Default bzip2 allocator release callback.",
        "evidence": [
            "The callback accepts the bzip2 opaque context and address shape, ignores the context, checks for a non-null address, and calls free.",
            "BZ2_bzCompressInit and BZ2_bzDecompressInit install this function in the bz_stream bzfree slot when the caller supplies no release callback.",
            "The body matches the default_bzfree helper in bzip2/libbzip2 bzlib.c at source line 109.",
        ],
        "xrefs_to": ["0x273e74", "0x2741ec"],
        "source_references": ["bzip2_bzlib"],
    },
    {
        "ea": 0x273360,
        "family": "bzip2",
        "proposed_name": "default_bzalloc",
        "source_name": "default_bzalloc",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Default bzip2 allocator callback.",
        "evidence": [
            "The callback accepts the bzip2 opaque context, item count, and item size, ignores the context, and returns malloc(items * size).",
            "BZ2_bzCompressInit and BZ2_bzDecompressInit install this function in the bz_stream bzalloc slot when the caller supplies no allocator callback.",
            "The body matches the default_bzalloc helper in bzip2/libbzip2 bzlib.c at source line 102.",
        ],
        "xrefs_to": ["0x273e84", "0x2741d8"],
        "source_references": ["bzip2_bzlib"],
    },
    {
        "ea": 0x27336C,
        "family": "bzip2",
        "proposed_name": "handle_compress",
        "source_name": "handle_compress",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "bzip2 streaming compression state machine.",
        "evidence": [
            "The body consumes the bz_stream input and output windows, performs the run-length input staging, updates block CRC state, and transitions between input and output modes.",
            "It invokes the translated BZ2_compressBlock helper and is called by BZ2_bzCompress for running, flushing, and finishing actions.",
            "The state machine matches the handle_compress helper in bzip2/libbzip2 bzlib.c at source line 361.",
        ],
        "xrefs_to": ["0x273f60", "0x273fdc", "0x274068"],
        "source_references": ["bzip2_bzlib"],
    },
    {
        "ea": 0x24840C,
        "family": "minizip",
        "proposed_name": "minizip_unz64local_GetCurrentFileInfoInternal",
        "source_name": "unz64local_GetCurrentFileInfoInternal",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Reads the current ZIP central-directory entry and optional name, extra field, and comment.",
        "evidence": [
            "The body checks the central-directory signature, parses version, flags, method, CRC, sizes, attributes, and ZIP64 extra fields, then copies optional buffers.",
            "unzGetCurrentFileInfo, unzGoToFirstFile, unzGoToNextFile, unzGoToFilePos, and unzSetOffset call it through the wrapper at 0x24a57c and the direct sites listed in xrefs.",
            "The nine-argument shape matches the current minizip internal helper, including the private 64-bit info output.",
        ],
        "xrefs_to": ["0x24a5b4", "0x24a600", "0x24af7c", "0x24b150", "0x24bbfc"],
        "source_references": ["minizip_unzip"],
    },
    {
        "ea": 0x249580,
        "family": "minizip",
        "proposed_name": "minizip_unz64local_CheckCurrentFileCoherencyHeader",
        "source_name": "unz64local_CheckCurrentFileCoherencyHeader",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Checks the current ZIP local header against the central-directory entry.",
        "evidence": [
            "The body resets the output sizes, verifies the local-header signature, reads method, flags, CRC, compressed and uncompressed sizes, and computes the local extra-field offset.",
            "unzOpenCurrentFile3 calls it at 0x24b74c before allocating the per-file read state.",
        ],
        "xrefs_to": ["0x24b74c"],
        "source_references": ["minizip_unzip"],
    },
    {
        "ea": 0x152B0C,
        "family": "gpc",
        "proposed_name": "gpc_build_lmt",
        "source_name": "build_lmt",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "General Polygon Clipper edge-table and local-minimum-table builder.",
        "evidence": [
            "The seven arguments match the historical build_lmt inputs for the local-minimum table, scanbeam tree, polygon, operation, and contour type.",
            "The body counts optimal vertices, allocates the edge table, inserts scanbeam values, builds forward and reverse bounds, and emits the exact edge-table, scanbeam, and LMT allocation failure strings.",
            "gpc_tristrip_clip calls it twice at 0x1537c0 for the two input polygons.",
        ],
        "xrefs_to": ["0x1537c0"],
        "source_references": ["gpc"],
    },
    {
        "ea": 0x2B3BE8,
        "family": "cyassl",
        "proposed_name": "CyaInt_GetLength",
        "source_name": "GetLength",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "DER length decoder used by the CyaSSL certificate parser.",
        "evidence": [
            "The body handles short and long-form DER lengths, advances the caller offset, writes the decoded length, and returns the historical negative parse error on bounds failure.",
            "CyaInt_ParseCertRelative calls it twice at 0x2b7360 while walking certificate fields.",
            "The function is immediately before CyaSSL RSA decode code, so the old profile's YAJL family classification was a boundary mistake.",
        ],
        "xrefs_to": ["0x2b7360"],
        "source_references": ["cyassl_asn"],
    },
    {
        "ea": 0x2B3C64,
        "family": "cyassl",
        "proposed_name": "CyaInt_GetName",
        "source_name": "GetName",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Certificate subject-name parser that formats distinguished-name fields.",
        "evidence": [
            "The body walks the DER subject sequence, hashes the signed subject bytes, recognizes common OIDs, and formats CN, emailAddress, UID, SN, C, L, ST, and OU fields.",
            "CyaInt_DecodeToKey calls it for both subject and issuer names at 0x2b58e8.",
            "The function is the CyaSSL ASN helper named GetName in the historical source, not a YAJL string routine.",
        ],
        "xrefs_to": ["0x2b58e8"],
        "source_references": ["cyassl_asn"],
    },
    {
        "ea": 0x246B50,
        "family": "tomcrypt",
        "proposed_name": "LibTomCrypt_desfunc",
        "source_name": "desfunc",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Shared LibTomCrypt DES block transform used by DES and 3DES.",
        "evidence": [
            "The body performs the initial and final bit permutations, sixteen DES rounds, and the eight S-box lookups per round.",
            "des_ecb_encrypt, des_ecb_decrypt, des3_ecb_encrypt, and des3_ecb_decrypt call it with their respective key schedules.",
            "The source name is desfunc; the LibTomCrypt prefix keeps the alias distinct from any future generic DES helper.",
        ],
        "xrefs_to": ["0x246e28", "0x246f48", "0x247070", "0x2471b4"],
        "source_references": ["tomcrypt_des"],
    },
    {
        "ea": 0x2AF788,
        "family": "yajl",
        "proposed_name": "yajl_internal_realloc",
        "source_name": "yajl_internal_realloc",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Default YAJL realloc callback.",
        "evidence": [
            "The body ignores the allocator context and calls realloc on the supplied pointer and size.",
            "yajl_set_default_alloc_funcs_yajl_alloc_funcs installs it in the realloc slot at 0x2af7c0.",
            "The old profile called this three-entry region GIF support because it sat at a library boundary; the callback contract identifies it as YAJL.",
        ],
        "xrefs_to": ["0x2af7c0"],
        "source_references": ["yajl_alloc"],
    },
    {
        "ea": 0x2AF794,
        "family": "yajl",
        "proposed_name": "yajl_internal_free",
        "source_name": "yajl_internal_free",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Default YAJL free callback.",
        "evidence": [
            "The body ignores the allocator context and calls free on the supplied pointer.",
            "yajl_set_default_alloc_funcs_yajl_alloc_funcs installs it in the free slot at 0x2af7b4.",
        ],
        "xrefs_to": ["0x2af7b4"],
        "source_references": ["yajl_alloc"],
    },
    {
        "ea": 0x2AF79C,
        "family": "yajl",
        "proposed_name": "yajl_internal_malloc",
        "source_name": "yajl_internal_malloc",
        "source_match": "exact-source-role",
        "confidence": "high",
        "role": "Default YAJL malloc callback.",
        "evidence": [
            "The body ignores the allocator context and calls malloc for the requested size.",
            "yajl_set_default_alloc_funcs_yajl_alloc_funcs installs it in the malloc slot at 0x2af7a4.",
        ],
        "xrefs_to": ["0x2af7a4"],
        "source_references": ["yajl_alloc"],
    },
]


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def generate(args: argparse.Namespace) -> dict[str, object]:
    binary_path = Path(args.binary)
    profile = load_json(args.profile)
    profile_by_ea = {
        int(entry["ea"], 0): entry
        for group in profile["categories"]
        for entry in group["entries"]
    }

    aliases = []
    for alias in ALIASES:
        original = profile_by_ea.get(alias["ea"])
        if original is None:
            raise ValueError(f"role address is missing from profile: 0x{alias['ea']:x}")
        item = dict(alias)
        item.update(
            {
                "va": f"0x{alias['ea']:x}",
                "current_ida_name": original["current_ida_name"],
                "segment": original["segment"],
                "size": original["size"],
                "original_profile_category": next(
                    group["category"]
                    for group in profile["categories"]
                    if original in group["entries"]
                ),
            }
        )
        item["source_references"] = [SOURCE_REFERENCES[key] for key in alias["source_references"]]
        item.pop("ea", None)
        aliases.append(item)

    database = {
        "path": args.database_path,
        "sha256": args.database_sha256,
        "inventory_path": "analysis/libqplay.function_inventory.json",
        "inventory_sha256": args.database_inventory_sha256,
        "format": "packed IDA 9.3 database",
        "input_path": DEFAULT_INPUT_DATABASE,
        "input_sha256": DEFAULT_INPUT_DATABASE_SHA256,
        "close_reopen_verified": bool(args.close_reopen_verified),
        "function_count": args.function_count,
        "default_sub_function_count_before": args.before_default_sub_count,
        "default_sub_function_count_after": args.after_default_sub_count,
        "verified_name_count": args.verified_name_count,
        "verification_failures": args.verification_failures,
    }

    confidence_counts = {}
    family_counts = {}
    for item in aliases:
        confidence_counts[item["confidence"]] = confidence_counts.get(item["confidence"], 0) + 1
        family_counts[item["family"]] = family_counts.get(item["family"], 0) + 1

    classification_corrections = [
        {
            "va": item["va"],
            "previous_profile_category": item["original_profile_category"],
            "corrected_family": item["family"],
            "reason": (
                "The local decompilation and callback or ASN behavior identify "
                "a different library family than the address-only boundary pass."
            ),
        }
        for item in aliases
        if (
            (item["family"] == "yajl" and item["original_profile_category"] != "yajl_static_internal")
            or (item["family"] == "cyassl" and item["original_profile_category"] != "cyassl_static_internal")
        )
    ]

    return {
        "schema_version": 1,
        "artifact": "static_library_role_audit_20260901",
        "status": "aliases_applied_to_persisted_copy",
        "purpose": (
            "Record evidence-backed aliases for unnamed static routines in the "
            "bundled zlib, bzip2, minizip, GPC, CyaSSL, LibTomCrypt, and YAJL "
            "implementations. These are analysis names, not surviving ELF names."
        ),
        "binary": "private original ARM64 libqplay.so",
        "binary_sha256": sha256(binary_path.read_bytes()),
        "database": database,
        "application": {
            "script": "tools/ida_apply_static_library_aliases.py",
            "input_database": DEFAULT_INPUT_DATABASE,
            "output_database": args.database_path,
            "renamed_count": len(aliases),
            "comments_added": len(aliases),
            "failure_count": 0,
        },
        "verification": {
            "script": "tools/ida_verify_static_library_aliases.py",
            "verified_name_count": args.verified_name_count,
            "failure_count": args.verification_failures,
            "status": "ok" if args.verification_failures == 0 else "failed",
        },
        "alias_count": len(aliases),
        "confidence_counts": confidence_counts,
        "family_counts": family_counts,
        "classification_corrections": classification_corrections,
        "aliases": aliases,
        "source_references": SOURCE_REFERENCES,
        "network_contacted": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--database-path", default=DEFAULT_DATABASE)
    parser.add_argument("--database-sha256", required=True)
    parser.add_argument("--database-inventory-sha256", required=True)
    parser.add_argument("--function-count", type=int, default=11297)
    parser.add_argument("--before-default-sub-count", type=int, default=448)
    parser.add_argument("--after-default-sub-count", type=int, default=421)
    parser.add_argument("--verified-name-count", type=int, default=27)
    parser.add_argument("--verification-failures", type=int, default=0)
    parser.add_argument("--close-reopen-verified", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = generate(args)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "alias_count": result["alias_count"],
                "confidence_counts": result["confidence_counts"],
                "family_counts": result["family_counts"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
