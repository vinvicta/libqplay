#!/usr/bin/env python3
"""Build the documented role map for unnamed CyaSSL implementation code.

The ARM64 APK keeps the exported CyaSSL API names, but it does not keep source
names for several static helpers between those exports. This generator records
what the IDA decompilation proves, separates source-role matches from local
descriptive aliases, and emits an offline JSON record. It does not execute the
library or contact a network.
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
DEFAULT_OUTPUT = "artifacts/cyassl_static_role_audit_20260826.json"
DEFAULT_DATABASE_PATH = "analysis/libqplay_translated_all_v3.i64"
DEFAULT_DATABASE_SHA256 = "1db52b8b2169250852fcd1a5a2acfda859b81038e92b47158029ecc886356874"
DEFAULT_DATABASE_INVENTORY_SHA256 = "e6045dc5b63f215c51e13ec3b62472ee415dee87533e225ced04812439959a87"


SOURCE_REFERENCES = {
    "cya_ssl_asn": (
        "https://nest-open-source.googlesource.com/nest-yale-lock/1.2/"
        "freertos/%2B/b9a7305351d35e2d3076d0b4ab3ec121f0aa8d52/"
        "FreeRTOS-Plus/Source/CyaSSL/ctaocrypt/src/asn.c"
    ),
    "wolfssl_tls": "https://os.mbed.com/users/wolfSSL/code/wolfSSL/docs/tip/tls_8c_source.html",
    "wolfssl_internal": "https://os.mbed.com/users/wolfSSL/code/wolfSSL/docs/tip/internal_8c_source.html",
    "wolfssl_process_buffer": "https://code.brunner.ninja/wolfSSL/wolfssl/commit/c3c341913838ebcd3178977630772bdde4908211",
    "wolfssl_prf": "https://code.brunner.ninja/wolfSSL/wolfssl/blame/commit/ef72bae2ffe1a6b0ab7397488d0544a850ed3608/src/tls.c",
}


ALIASES = [
    {
        "ea": 0x2B6384,
        "proposed_name": "CyaInt_ConfirmSignature",
        "confidence": "high",
        "source_name": "ConfirmSignature",
        "source_match": "exact-source-role",
        "role": (
            "Certificate-signature verifier that selects MD5, SHA-1, or SHA-256, "
            "decodes an RSA public key, verifies the RSA signature, and compares "
            "the expected encoded digest."
        ),
        "evidence": [
            "The only call is from CyaInt_ParseCertRelative at 0x2b6888.",
            "The body selects the digest from the certificate algorithm, checks the RSA key OID value 645, calls InitRsaKey, RsaPublicKeyDecode, and RsaSSL_VerifyInline, then compares the encoded digest produced by CyaInt_EncodeSignature.",
            "The control flow and helper sequence match the old CyaSSL ConfirmSignature implementation role.",
        ],
        "xrefs_to": ["0x2b6888"],
        "source_references": [SOURCE_REFERENCES["cya_ssl_asn"]],
    },
    {
        "ea": 0x2BDC74,
        "proposed_name": "CyaInt_Md5Transform",
        "confidence": "high",
        "source_name": "Md5Transform",
        "source_match": "exact-algorithm-role",
        "role": "The 64-round MD5 compression transform used by Md5Update and Md5Final.",
        "evidence": [
            "The function lies between the bundled multiprecision helpers and the exported InitMd5, Md5Update, and Md5Final routines.",
            "Its 64 rounds, Boolean functions, rotation schedule, and MD5 constants operate on the four-word MD5 state.",
            "The callers at 0x2bf2b4 and 0x2bf2f8 are inside the bundled MD5 update and finalization code.",
        ],
        "xrefs_to": ["0x2bf2b4", "0x2bf2f8"],
        "source_references": [SOURCE_REFERENCES["wolfssl_internal"]],
    },
    {
        "ea": 0x2C0408,
        "proposed_name": "CyaInt_ShaTransform",
        "confidence": "high",
        "source_name": "ShaTransform",
        "source_match": "exact-algorithm-role",
        "role": "The 80-round SHA-1 compression transform used by ShaUpdate and ShaFinal.",
        "evidence": [
            "The function lies after the RSA helpers and before the exported InitSha, ShaUpdate, and ShaFinal routines.",
            "Its five-word state and 80-round schedule use the SHA-1 constants 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, and 0xca62c1d6.",
            "The callers at 0x2c2db8 and 0x2c2f08 are inside the bundled SHA-1 update and finalization code.",
        ],
        "xrefs_to": ["0x2c2db8", "0x2c2f08"],
        "source_references": [SOURCE_REFERENCES["wolfssl_internal"]],
    },
    {
        "ea": 0x2C2F1C,
        "proposed_name": "CyaInt_Sha256Transform",
        "confidence": "high",
        "source_name": "Sha256Transform",
        "source_match": "exact-algorithm-role",
        "role": "The 64-round SHA-256 compression transform used by Sha256Update and Sha256Final.",
        "evidence": [
            "The function uses ARM NEON operations, the eight-word SHA-256 state, and the 64 SHA-256 round constants and rotations.",
            "It lies immediately before the exported InitSha256, Sha256Update, and Sha256Final routines.",
            "The callers at 0x2c355c, 0x2c36f8, and 0x2c3858 are inside the bundled SHA-256 update and finalization code.",
        ],
        "xrefs_to": ["0x2c355c", "0x2c36f8", "0x2c3858"],
        "source_references": [SOURCE_REFERENCES["wolfssl_internal"]],
    },
    {
        "ea": 0x2C47E0,
        "proposed_name": "CyaInt_ProcessBuffer",
        "confidence": "high",
        "source_name": "ProcessBuffer",
        "source_match": "exact-source-role",
        "role": (
            "PEM or DER buffer processor that loads certificate chains, decodes "
            "private RSA keys, and adds certificates to the CyaSSL context."
        ),
        "evidence": [
            "The body calls CyaInt_PemToDer, handles multiple PEM certificate blocks, builds the three-byte-length chain format with c32to24, and calls CyaInt_AddCA.",
            "It also initializes decoded certificates and decodes RSA private keys for the certificate and key loading paths.",
            "The function is called by the certificate and key loading code at 0x2c5040 and the repeated 0x2c60xx sites.",
            "The buffer and chain behavior matches the historical CyaSSL ProcessBuffer role.",
        ],
        "xrefs_to": [
            "0x2c5040",
            "0x2c607c",
            "0x2c60b8",
            "0x2c60f8",
            "0x2c613c",
            "0x2c6150",
            "0x2c6168",
            "0x2c6180",
            "0x2c6198",
            "0x2c61b4",
        ],
        "source_references": [SOURCE_REFERENCES["wolfssl_process_buffer"]],
    },
    {
        "ea": 0x2C50AC,
        "proposed_name": "CyaInt_ProcessVerifyPath",
        "confidence": "medium",
        "source_name": None,
        "source_match": "descriptive-role",
        "role": "Directory or file-path helper for the CyaSSL verification-store loader.",
        "evidence": [
            "The body forwards a file path to CyaInt_ProcessFile when present.",
            "For a directory path it calls opendir, readdir, and stat, then sends regular files back through CyaInt_ProcessFile.",
            "The only caller is the path-loading branch at 0x2c5220, immediately below CyaInt_CyaSSL_CTX_load_verify_locations.",
        ],
        "xrefs_to": ["0x2c5220"],
        "source_references": [SOURCE_REFERENCES["wolfssl_process_buffer"]],
    },
    {
        "ea": 0x2C6514,
        "proposed_name": "CyaInt_PRF",
        "confidence": "high",
        "source_name": "PRF",
        "source_match": "exact-source-role",
        "role": (
            "TLS pseudo-random function that expands a secret, label, and seed "
            "with HMAC and supports both TLS 1.2 SHA-256 and legacy MD5/SHA-1."
        ),
        "evidence": [
            "The body performs the repeated HMAC A(i) and output blocks, XORing the legacy MD5 and SHA-1 results when the protocol is below TLS 1.2.",
            "CyaInt_BuildTlsFinished calls it for the client and server Finished labels, and the key-derivation code calls it for the master-secret and key-block paths.",
            "The inputs are the output buffer and size, secret, label, seed, digest mode, and protocol-version flags expected by the old CyaSSL PRF role.",
        ],
        "xrefs_to": ["0x2c700c", "0x2c7b34", "0x2c7be0"],
        "source_references": [SOURCE_REFERENCES["wolfssl_prf"]],
    },
    {
        "ea": 0x2C84BC,
        "proposed_name": "CyaInt_TLSRecordMac",
        "confidence": "medium",
        "source_name": None,
        "source_match": "descriptive-role",
        "role": "Legacy TLS record-MAC callback for the active CyaSSL cipher state.",
        "evidence": [
            "CyaInt_InitSSL stores this address in the context callback slot at offset 1128.",
            "The body builds the MAC input from the sequence counter, content type, protocol version, record length, and payload, then computes MD5 or SHA-1.",
            "The callback is used by the record-processing code at 0x2ccf54 and 0x2ccf64.",
        ],
        "xrefs_to": ["0x2ccf54", "0x2ccf64"],
        "source_references": [SOURCE_REFERENCES["wolfssl_internal"]],
    },
    {
        "ea": 0x2C8710,
        "proposed_name": "CyaInt_VerifyRecordMac",
        "confidence": "medium",
        "source_name": None,
        "source_match": "descriptive-role",
        "role": "TLS CBC record verifier that checks padding and the record MAC.",
        "evidence": [
            "The body validates the CBC padding bytes, invokes the MAC callback stored at context offset 1128, and compares the computed result with the record trailer.",
            "CyaInt_DoApplicationData calls it at 0x2ca858 before exposing application data to the caller.",
            "The body supports the bundled MD5, SHA-1, and SHA-256 digest paths selected by the cipher state.",
        ],
        "xrefs_to": ["0x2ca858"],
        "source_references": [SOURCE_REFERENCES["wolfssl_internal"]],
    },
    {
        "ea": 0x2C8A20,
        "proposed_name": "CyaInt_ComputeFinishedVerifyData",
        "confidence": "medium",
        "source_name": None,
        "source_match": "descriptive-role",
        "role": "Computes the TLS Finished verify-data bytes from the accumulated handshake state.",
        "evidence": [
            "The body snapshots the MD5 and SHA-1 handshake states, uses CyaInt_BuildTlsFinished for TLS 1.2, and otherwise builds the legacy client or server Finished value with the master secret and CLNT or SRVR labels.",
            "It is called from both the send-Finished path at 0x2c9c70 and 0x2c9d5c and the receive path at 0x2cb700 and 0x2cb770.",
            "This is a complete verify-data builder, not only the smaller handshake-state snapshot helper described by newer wolfSSL source.",
        ],
        "xrefs_to": ["0x2c9c70", "0x2c9d5c", "0x2cb700", "0x2cb770"],
        "source_references": [SOURCE_REFERENCES["wolfssl_tls"]],
    },
    {
        "ea": 0x2CA940,
        "proposed_name": "CyaInt_ProcessPeerCerts",
        "confidence": "high",
        "source_name": "ProcessPeerCerts",
        "source_match": "exact-source-role",
        "role": "TLS Certificate-handshake parser for the peer certificate chain.",
        "evidence": [
            "CyaInt_ProcessReply calls the function at 0x2cb974 for handshake message type 11.",
            "The body reads the three-byte certificate-list and certificate lengths, parses the chain with CyaInt_ParseCertRelative, and handles up to nine certificates.",
            "It checks signer relationships with CyaInt_AlreadySigner, adds certificates with CyaInt_AddCA, and stores the peer certificate and RSA key state.",
            "The role matches the historical CyaSSL and wolfSSL ProcessPeerCerts implementation name.",
        ],
        "xrefs_to": ["0x2cb974"],
        "source_references": [SOURCE_REFERENCES["wolfssl_internal"]],
    },
]


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def relative_to_repo(path: str) -> str:
    value = Path(path).resolve()
    repo = Path(__file__).resolve().parents[1]
    try:
        return str(value.relative_to(repo))
    except ValueError:
        return str(value)


def generate(args: argparse.Namespace) -> dict[str, object]:
    binary_path = Path(args.binary)
    profile = load_json(args.profile)
    by_ea = {
        int(entry["ea"], 0): entry
        for group in profile["categories"]
        for entry in group["entries"]
        if group["category"] == "cyassl_static_internal"
    }
    if set(by_ea) != {item["ea"] for item in ALIASES}:
        raise ValueError("CyaSSL role list does not cover the profiled static entries")

    aliases = []
    for alias in ALIASES:
        original = by_ea[alias["ea"]]
        item = dict(alias)
        item.update(
            {
                "va": f"0x{alias['ea']:x}",
                "current_ida_name": original["current_ida_name"],
                "segment": original["segment"],
                "size": original["size"],
            }
        )
        item.pop("ea", None)
        aliases.append(item)

    database = {
        "path": args.database_path,
        "sha256": args.database_sha256,
        "inventory_path": "analysis/libqplay.function_inventory.json",
        "inventory_sha256": args.database_inventory_sha256,
        "format": "packed IDA 9.3 database",
        "close_reopen_verified": bool(args.close_reopen_verified),
        "function_count": args.function_count,
        "default_sub_function_count_before": args.before_default_sub_count,
        "default_sub_function_count_after": args.after_default_sub_count,
        "verified_name_count": args.verified_name_count,
        "verification_failures": args.verification_failures,
    }

    confidence_counts = {}
    for item in aliases:
        value = item["confidence"]
        confidence_counts[value] = confidence_counts.get(value, 0) + 1

    return {
        "schema_version": 1,
        "artifact": "cyassl_static_role_audit_20260826",
        "status": "aliases_applied_to_persisted_copy",
        "purpose": (
            "Record behavior-based aliases for the unnamed static CyaSSL and "
            "bundled cryptographic helpers. High-confidence entries match "
            "historical source roles; medium-confidence entries are descriptive "
            "IDA aliases and are not claims about preserved source names."
        ),
        "binary": "private original ARM64 libqplay.so",
        "binary_sha256": sha256(binary_path.read_bytes()),
        "database": database,
        "application": {
            "script": "tools/ida_apply_cyassl_static_aliases.py",
            "input_database": "analysis/libqplay_translated_all_v2.i64",
            "output_database": args.database_path,
            "renamed_count": len(aliases),
            "comments_added": len(aliases),
            "failure_count": 0,
        },
        "verification": {
            "script": "tools/ida_verify_cyassl_static_aliases.py",
            "verified_name_count": args.verified_name_count,
            "failure_count": args.verification_failures,
            "status": "ok" if args.verification_failures == 0 else "failed",
        },
        "alias_count": len(aliases),
        "confidence_counts": confidence_counts,
        "aliases": aliases,
        "source_references": SOURCE_REFERENCES,
        "network_contacted": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument("--database-path", default=DEFAULT_DATABASE_PATH)
    parser.add_argument("--database-sha256", default=DEFAULT_DATABASE_SHA256)
    parser.add_argument(
        "--database-inventory-sha256",
        default=DEFAULT_DATABASE_INVENTORY_SHA256,
    )
    parser.add_argument("--function-count", type=int, default=11297)
    parser.add_argument("--before-default-sub-count", type=int, default=459)
    parser.add_argument("--after-default-sub-count", type=int, default=448)
    parser.add_argument("--verified-name-count", type=int, default=11)
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
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
