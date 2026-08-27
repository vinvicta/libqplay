#!/usr/bin/env python3
"""Create reviewed anchors for the residual CyaInt TLS methods."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    ("0x2bb418", "CyaInt_mp_dr_setup_CyaInt_mp_int_uint", "0x2c89a8", "_ZN6CyaInt11mp_dr_setupEPNS_6mp_intEPj", "MPI Montgomery-reduction setup"),
    ("0x2c3a04", "CyaInt_CyaSSL_set_using_nonblock_CyaInt_CYASSL_int", "0x2d0f94", "_ZN6CyaInt25CyaSSL_set_using_nonblockEPNS_6CYASSLEi", "nonblocking socket mode setter"),
    ("0x2c3d64", "CyaInt_CyaSSL_get_alert_history_CyaInt_CYASSL_CyaInt_CYASSL_ALERT_HISTORY", "0x2d12f4", "_ZN6CyaInt24CyaSSL_get_alert_historyEPNS_6CYASSLEPNS_20CYASSL_ALERT_HISTORYE", "TLS alert-history accessor"),
    ("0x2c3dd8", "CyaInt_CyaSSL_ERR_error_string_n_ulong_char_ulong", "0x2d1368", "_ZN6CyaInt25CyaSSL_ERR_error_string_nEmPcm", "TLS error-string formatter"),
    ("0x2c3de4", "CyaInt_CyaSSL_KeepArrays_CyaInt_CYASSL", "0x2d1374", "_ZN6CyaInt17CyaSSL_KeepArraysEPNS_6CYASSLE", "TLS array-retention helper"),
    ("0x2c520c", "CyaInt_CyaSSL_CTX_load_verify_locations_CyaInt_CYASSL_CTX_char_const_char_const", "0x2d279c", "_ZN6CyaInt32CyaSSL_CTX_load_verify_locationsEPNS_10CYASSL_CTXEPKcS3_", "TLS verification-path loader"),
    ("0x2c5354", "CyaInt_CyaSSL_CertManagerEnableCRL_CyaInt_CYASSL_CERT_MANAGER_int", "0x2d28e4", "_ZN6CyaInt27CyaSSL_CertManagerEnableCRLEPNS_19CYASSL_CERT_MANAGEREi", "certificate-revocation enable helper"),
    ("0x2c5368", "CyaInt_CyaSSL_CertManagerDisableCRL_CyaInt_CYASSL_CERT_MANAGER", "0x2d28f8", "_ZN6CyaInt28CyaSSL_CertManagerDisableCRLEPNS_19CYASSL_CERT_MANAGERE", "certificate-revocation disable helper"),
    ("0x2c5494", "CyaInt_CyaSSL_CTX_SetCACb_CyaInt_CYASSL_CTX_void_uchar_int_int", "0x2d2a24", "_ZN6CyaInt18CyaSSL_CTX_SetCACbEPNS_10CYASSL_CTXEPFvPhiiE", "certificate-authority callback setter"),
    ("0x2c5b78", "CyaInt_CyaSSL_get_session_CyaInt_CYASSL", "0x2d3108", "_ZN6CyaInt18CyaSSL_get_sessionEPNS_6CYASSLE", "TLS session getter"),
    ("0x2c5c20", "CyaInt_CyaSSL_set_session_CyaInt_CYASSL_CyaInt_CYASSL_SESSION", "0x2d31b0", "_ZN6CyaInt18CyaSSL_set_sessionEPNS_6CYASSLEPNS_14CYASSL_SESSIONE", "TLS session setter"),
    ("0x2c612c", "CyaInt_CyaSSL_CTX_use_certificate_buffer_CyaInt_CYASSL_CTX_uchar_const_long_int", "0x2d36bc", "_ZN6CyaInt33CyaSSL_CTX_use_certificate_bufferEPNS_10CYASSL_CTXEPKhli", "certificate-context buffer loader"),
    ("0x2c6140", "CyaInt_CyaSSL_CTX_use_PrivateKey_buffer_CyaInt_CYASSL_CTX_uchar_const_long_int", "0x2d36d0", "_ZN6CyaInt32CyaSSL_CTX_use_PrivateKey_bufferEPNS_10CYASSL_CTXEPKhli", "private-key context buffer loader"),
    ("0x2c6154", "CyaInt_CyaSSL_CTX_use_certificate_chain_buffer_CyaInt_CYASSL_CTX_uchar_const_long", "0x2d36e4", "_ZN6CyaInt39CyaSSL_CTX_use_certificate_chain_bufferEPNS_10CYASSL_CTXEPKhl", "certificate-chain context buffer loader"),
    ("0x2c616c", "CyaInt_CyaSSL_use_certificate_buffer_CyaInt_CYASSL_uchar_const_long_int", "0x2d36fc", "_ZN6CyaInt29CyaSSL_use_certificate_bufferEPNS_6CYASSLEPKhli", "certificate buffer loader"),
    ("0x2c6184", "CyaInt_CyaSSL_use_PrivateKey_buffer_CyaInt_CYASSL_uchar_const_long_int", "0x2d3714", "_ZN6CyaInt28CyaSSL_use_PrivateKey_bufferEPNS_6CYASSLEPKhli", "private-key buffer loader"),
    ("0x2c619c", "CyaInt_CyaSSL_use_certificate_chain_buffer_CyaInt_CYASSL_uchar_const_long", "0x2d372c", "_ZN6CyaInt35CyaSSL_use_certificate_chain_bufferEPNS_6CYASSLEPKhl", "certificate-chain buffer loader"),
    ("0x2c61b8", "CyaInt_CyaSSL_is_init_finished_CyaInt_CYASSL", "0x2d3748", "_ZN6CyaInt23CyaSSL_is_init_finishedEPNS_6CYASSLE", "TLS initialization-state query"),
    ("0x2c61d8", "CyaInt_CyaSSL_X509_get_subject_name_CyaInt_CYASSL_X509", "0x2d3768", "_ZN6CyaInt28CyaSSL_X509_get_subject_nameEPNS_11CYASSL_X509E", "X.509 subject-name accessor"),
    ("0x2c6270", "CyaInt_CyaSSL_get_peer_certificate_CyaInt_CYASSL", "0x2d3800", "_ZN6CyaInt27CyaSSL_get_peer_certificateEPNS_6CYASSLE", "peer-certificate accessor"),
    ("0x2c6284", "CyaInt_CyaSSL_get_shutdown_CyaInt_CYASSL_const", "0x2d3814", "_ZN6CyaInt19CyaSSL_get_shutdownEPKNS_6CYASSLE", "TLS shutdown-state query"),
    ("0x2c6344", "CyaInt_CyaSSL_get_current_cipher_suite_CyaInt_CYASSL", "0x2d38d4", "_ZN6CyaInt31CyaSSL_get_current_cipher_suiteEPNS_6CYASSLE", "active cipher-suite accessor"),
    ("0x2c703c", "CyaInt_MakeTLSv1_void", "0x2d45cc", "_ZN6CyaInt9MakeTLSv1Ev", "TLS 1.0 protocol selector"),
    ("0x2c7054", "CyaInt_MakeTLSv1_1_void", "0x2d45e4", "_ZN6CyaInt11MakeTLSv1_1Ev", "TLS 1.1 protocol selector"),
    ("0x2c8c84", "CyaInt_c32to24_uint_uchar", "0x2d6214", "_ZN6CyaInt7c32to24EjPh", "24-bit integer encoder"),
    ("0x2c8c9c", "CyaInt_InitSSL_Method_CyaInt_CYASSL_METHOD_CyaInt_ProtocolVersion", "0x2d622c", "_ZN6CyaInt14InitSSL_MethodEPNS_13CYASSL_METHODENS_15ProtocolVersionE", "SSL method initializer"),
    ("0x2c8d14", "CyaInt_InitCiphers_CyaInt_CYASSL", "0x2d62a4", "_ZN6CyaInt11InitCiphersEPNS_6CYASSLE", "cipher-state initializer"),
    ("0x2c9064", "CyaInt_MakeSSLv3_void", "0x2d65f4", "_ZN6CyaInt9MakeSSLv3Ev", "SSL 3.0 protocol selector"),
    ("0x2cbe18", "CyaInt_SetErrorString_int_char", "0x2d93a8", "_ZN6CyaInt14SetErrorStringEiPc", "TLS error-string setter"),
    ("0x2cdad0", "CyaInt_MakeMasterSecret_CyaInt_CYASSL", "0x2db060", "_ZN6CyaInt16MakeMasterSecretEPNS_6CYASSLE", "TLS master-secret derivation"),
]

METRIC_FIELDS = (
    "size",
    "instruction_count",
    "basic_block_count",
    "branch_count",
    "call_count",
    "mnemonic_hash",
    "opcode_shape_hash",
    "register_shape_hash",
    "shape_hash",
    "string_refs_hash",
)

COMMON_EVIDENCE = [
    "Every row has identical size, instruction count, basic-block count, branch count, call count, mnemonic hash, opcode-shape hash, register-shape hash, overall shape hash, and string-reference hash in the two feature exports.",
    "Every target address is the source address plus 0xd590. The constant relocation holds across the whole CyaInt block, while the target symbol name retains the same CyaInt method and parameter roles in its C++ mangling.",
    "The target methods are not guessed from a nearby address alone. Their retained CyaInt names, exact normalized fingerprints, and shared class-local relocation provide independent evidence for each role.",
    "Representative Hex-Rays checks show the same behavior: nonblocking mode writes the same state byte, certificate paths and buffers call the corresponding processing helpers, protocol selectors return the same constants, InitCiphers resets the same fields, and MakeMasterSecret preserves the same TLS key schedule.",
]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def by_ea(functions: list[dict]) -> dict[int, dict]:
    return {int(function["ea"], 16): function for function in functions}


def metrics(function: dict) -> dict:
    return {field: function.get(field) for field in METRIC_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for source_text, source_name, target_text, target_name, role in ANCHOR_SPECS:
        source_ea = int(source_text, 16)
        target_ea = int(target_text, 16)
        source = original.get(source_ea)
        target = spectron.get(target_ea)
        if source is None or target is None:
            raise ValueError("missing source or target feature at %s" % source_text)
        if source.get("name") != source_name:
            raise ValueError("unexpected source name at %s" % source_text)
        if target.get("name") != target_name:
            raise ValueError("unexpected target name at %s" % target_text)
        if source_ea in semantic_source_eas:
            raise ValueError("source is already present in the semantic map: %s" % source_text)
        if target_ea in semantic_target_eas:
            raise ValueError("target is already present in the semantic map: %s" % target_text)
        if target_ea - source_ea != 0xD590:
            raise ValueError("unexpected CyaInt relocation at %s" % source_text)
        shape_equal = metrics(source) == metrics(target)
        if not shape_equal:
            raise ValueError("CyaInt feature mismatch at %s" % source_text)
        anchors.append(
            {
                "original_ea": source["ea"],
                "original_name": source["name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "original_direct_call_names": source.get("direct_call_names", []),
                "spectron_ea": target["ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "spectron_direct_call_names": target.get("direct_call_names", []),
                "proposed_name": "v18_" + source["name"],
                "confidence": "high",
                "match_kind": "manual-cyaint-tls-residual-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": role,
                "context_group": "CyaInt TLS and cryptography residual methods",
                "target_delta": "+0xd590",
                "evidence": COMMON_EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    if len({row["original_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate source in CyaInt anchor set")
    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate target in CyaInt anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_cyaint_tls_residual_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for residual CyaInt TLS, certificate, session, cipher, and cryptographic methods",
        "network_contacted": False,
        "inputs": {
            "original_features": str(args.original_features),
            "original_features_sha256": sha256_path(args.original_features),
            "original_binary_sha256": args.original_binary_sha256,
            "spectron_features": str(args.spectron_features),
            "spectron_features_sha256": sha256_path(args.spectron_features),
            "spectron_binary_sha256": args.spectron_binary_sha256,
            "semantic_map": str(args.semantic_map),
            "semantic_map_sha256": sha256_path(args.semantic_map),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "constant_target_delta": "+0xd590",
        },
        "context": {
            "source_class": "CyaInt",
            "target_class": "CyaInt",
            "source_range": "0x2bb418 through 0x2cdad0",
            "target_range": "0x2c89a8 through 0x2db060",
            "relocation": "+0xd590",
            "representative_pseudocode_checks": [
                "CyaSSL_set_using_nonblock writes the same byte at CyaSSL offset 999.",
                "CyaSSL_CTX_load_verify_locations calls ProcessVerifyPath under the same null checks.",
                "CyaSSL_CTX_use_certificate_buffer calls ProcessBuffer with the same arguments.",
                "MakeTLSv1 returns 259 in both builds.",
                "InitCiphers clears the same six cipher-state fields.",
                "MakeMasterSecret preserves the same TLS master-secret derivation and key cleanup loops.",
            ],
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The target C++ names are retained as evidence, while the v18_ aliases make the readable 1.8 roles searchable in the translated IDB.",
            "All 30 rows are exact across the complete normalized feature set used by this artifact. No layout-change rows are hidden in the exact count.",
            "The constant relocation is specific to this hashed Spectron library and must not be reused for unrelated classes without independent checks.",
            "This batch covers native TLS plumbing and cryptographic helpers. It does not by itself prove that certificate verification is disabled or that a live server accepts the old client.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
