#!/usr/bin/env python3
"""Create the second reviewed anchor batch for the residual CyaInt block."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from generate_spectron_cyaint_tls_residual_anchors import (
    COMMON_EVIDENCE,
    by_ea,
    load,
    metrics,
    sha256_path,
)


ANCHOR_SPECS = [
    ("0x2b8bb0", "CyaInt_CheckRunTimeSettings_void", "0x2c6140", "_ZN6CyaInt20CheckRunTimeSettingsEv", "runtime settings check"),
    ("0x2bfbf0", "CyaInt_RsaPrivateDecrypt_uchar_const_uint_uchar_uint_CyaInt_RsaKey", "0x2cd180", "_ZN6CyaInt17RsaPrivateDecryptEPKhjPhjPNS_6RsaKeyE", "RSA private decrypt"),
    ("0x2bffa4", "CyaInt_RsaSSL_Verify_uchar_const_uint_uchar_uint_CyaInt_RsaKey", "0x2cd534", "_ZN6CyaInt13RsaSSL_VerifyEPKhjPhjPNS_6RsaKeyE", "RSA signature verification"),
    ("0x2c0404", "CyaInt_RsaEncryptSize_CyaInt_RsaKey", "0x2cd994", "_ZN6CyaInt14RsaEncryptSizeEPNS_6RsaKeyE", "RSA encrypted-size query"),
    ("0x2c386c", "CyaInt_CyaSSL_SetIORecv_CyaInt_CYASSL_CTX_int_CyaInt_CYASSL_char_int_void", "0x2d0dfc", "_ZN6CyaInt16CyaSSL_SetIORecvEPNS_10CYASSL_CTXEPFiPNS_6CYASSLEPciPvE", "TLS receive callback"),
    ("0x2c3874", "CyaInt_CyaSSL_SetIOSend_CyaInt_CYASSL_CTX_int_CyaInt_CYASSL_char_int_void", "0x2d0e04", "_ZN6CyaInt16CyaSSL_SetIOSendEPNS_10CYASSL_CTXEPFiPNS_6CYASSLEPciPvE", "TLS send callback"),
    ("0x2c387c", "CyaInt_CyaSSL_SetIOReadCtx_CyaInt_CYASSL_void", "0x2d0e0c", "_ZN6CyaInt19CyaSSL_SetIOReadCtxEPNS_6CYASSLEPv", "TLS read context"),
    ("0x2c3884", "CyaInt_CyaSSL_SetIOWriteCtx_CyaInt_CYASSL_void", "0x2d0e14", "_ZN6CyaInt20CyaSSL_SetIOWriteCtxEPNS_6CYASSLEPv", "TLS write context"),
    ("0x2c388c", "CyaInt_CyaSSL_SetIOReadFlags_CyaInt_CYASSL_int", "0x2d0e1c", "_ZN6CyaInt21CyaSSL_SetIOReadFlagsEPNS_6CYASSLEi", "TLS read flags"),
    ("0x2c3894", "CyaInt_CyaSSL_SetIOWriteFlags_CyaInt_CYASSL_int", "0x2d0e24", "_ZN6CyaInt22CyaSSL_SetIOWriteFlagsEPNS_6CYASSLEi", "TLS write flags"),
    ("0x2c395c", "CyaInt_CyaSSL_CTX_free_CyaInt_CYASSL_CTX", "0x2d0eec", "_ZN6CyaInt15CyaSSL_CTX_freeEPNS_10CYASSL_CTXE", "TLS context free"),
    ("0x2c39cc", "CyaInt_CyaSSL_free_CyaInt_CYASSL", "0x2d0f5c", "_ZN6CyaInt11CyaSSL_freeEPNS_6CYASSLE", "TLS object free"),
    ("0x2c39fc", "CyaInt_CyaSSL_get_fd_CyaInt_CYASSL_const", "0x2d0f8c", "_ZN6CyaInt13CyaSSL_get_fdEPKNS_6CYASSLE", "TLS file descriptor"),
    ("0x2c3a14", "CyaInt_CyaSSL_get_using_nonblock_CyaInt_CYASSL", "0x2d0fa4", "_ZN6CyaInt25CyaSSL_get_using_nonblockEPNS_6CYASSLE", "nonblocking mode getter"),
    ("0x2c3a1c", "CyaInt_CyaSSL_dtls_CyaInt_CYASSL", "0x2d0fac", "_ZN6CyaInt11CyaSSL_dtlsEPNS_6CYASSLE", "DTLS mode query"),
    ("0x2c3a24", "CyaInt_CyaSSL_dtls_set_peer_CyaInt_CYASSL_void_uint", "0x2d0fb4", "_ZN6CyaInt20CyaSSL_dtls_set_peerEPNS_6CYASSLEPvj", "DTLS peer setter"),
    ("0x2c3a2c", "CyaInt_CyaSSL_dtls_get_peer_CyaInt_CYASSL_void_uint", "0x2d0fbc", "_ZN6CyaInt20CyaSSL_dtls_get_peerEPNS_6CYASSLEPvPj", "DTLS peer getter"),
    ("0x2c3a34", "CyaInt_CyaSSL_GetObjectSize_void", "0x2d0fc4", "_ZN6CyaInt20CyaSSL_GetObjectSizeEv", "TLS object size"),
    ("0x2c3c34", "CyaInt_CyaSSL_send_CyaInt_CYASSL_void_const_int_int", "0x2d11c4", "_ZN6CyaInt11CyaSSL_sendEPNS_6CYASSLEPKvii", "TLS send"),
    ("0x2c3c64", "CyaInt_CyaSSL_recv_CyaInt_CYASSL_void_int_int", "0x2d11f4", "_ZN6CyaInt11CyaSSL_recvEPNS_6CYASSLEPvii", "TLS receive"),
    ("0x2c3d80", "CyaInt_CyaSSL_want_read_CyaInt_CYASSL", "0x2d1310", "_ZN6CyaInt16CyaSSL_want_readEPNS_6CYASSLE", "TLS read wait state"),
    ("0x2c3d90", "CyaInt_CyaSSL_want_write_CyaInt_CYASSL", "0x2d1320", "_ZN6CyaInt17CyaSSL_want_writeEPNS_6CYASSLE", "TLS write wait state"),
    ("0x2c3f14", "CyaInt_CyaSSL_pending_CyaInt_CYASSL", "0x2d14a4", "_ZN6CyaInt14CyaSSL_pendingEPNS_6CYASSLE", "pending TLS bytes"),
    ("0x2c3f1c", "CyaInt_CyaSSL_CTX_set_group_messages_CyaInt_CYASSL_CTX", "0x2d14ac", "_ZN6CyaInt29CyaSSL_CTX_set_group_messagesEPNS_10CYASSL_CTXE", "context message grouping"),
    ("0x2c3f3c", "CyaInt_CyaSSL_set_group_messages_CyaInt_CYASSL", "0x2d14cc", "_ZN6CyaInt25CyaSSL_set_group_messagesEPNS_6CYASSLE", "connection message grouping"),
    ("0x2c5380", "CyaInt_CyaSSL_CTX_check_private_key_CyaInt_CYASSL_CTX", "0x2d2910", "_ZN6CyaInt28CyaSSL_CTX_check_private_keyEPNS_10CYASSL_CTXE", "private-key check"),
    ("0x2c541c", "CyaInt_CyaSSL_CTX_set_verify_CyaInt_CYASSL_CTX_int_int_int_CyaInt_CYASSL_X509_STORE_CTX", "0x2d29ac", "_ZN6CyaInt21CyaSSL_CTX_set_verifyEPNS_10CYASSL_CTXEiPFiiPNS_21CYASSL_X509_STORE_CTXEE", "context verification mode"),
    ("0x2c5458", "CyaInt_CyaSSL_set_verify_CyaInt_CYASSL_int_int_int_CyaInt_CYASSL_X509_STORE_CTX", "0x2d29e8", "_ZN6CyaInt17CyaSSL_set_verifyEPNS_6CYASSLEiPFiiPNS_21CYASSL_X509_STORE_CTXEE", "connection verification mode"),
    ("0x2c54a8", "CyaInt_CyaSSL_load_error_strings_void", "0x2d2a38", "_ZN6CyaInt25CyaSSL_load_error_stringsEv", "TLS error strings"),
    ("0x2c5578", "CyaInt_CyaSSL_dtls_get_current_timeout_CyaInt_CYASSL", "0x2d2b08", "_ZN6CyaInt31CyaSSL_dtls_get_current_timeoutEPNS_6CYASSLE", "DTLS timeout getter"),
    ("0x2c5580", "CyaInt_CyaSSL_dtls_got_timeout_CyaInt_CYASSL", "0x2d2b10", "_ZN6CyaInt23CyaSSL_dtls_got_timeoutEPNS_6CYASSLE", "DTLS timeout notification"),
    ("0x2c5588", "CyaInt_CyaSSLv3_client_method_void", "0x2d2b18", "_ZN6CyaInt22CyaSSLv3_client_methodEv", "SSL 3.0 client method"),
    ("0x2c5950", "CyaInt_CyaSSL_flush_sessions_CyaInt_CYASSL_CTX_long", "0x2d2ee0", "_ZN6CyaInt21CyaSSL_flush_sessionsEPNS_10CYASSL_CTXEl", "session-cache flush"),
    ("0x2c5954", "CyaInt_CyaSSL_set_timeout_CyaInt_CYASSL_uint", "0x2d2ee4", "_ZN6CyaInt18CyaSSL_set_timeoutEPNS_6CYASSLEj", "connection timeout"),
    ("0x2c596c", "CyaInt_CyaSSL_CTX_set_timeout_CyaInt_CYASSL_CTX_uint", "0x2d2efc", "_ZN6CyaInt22CyaSSL_CTX_set_timeoutEPNS_10CYASSL_CTXEj", "context timeout"),
    ("0x2c5e4c", "CyaInt_CyaSSL_set_compression_CyaInt_CYASSL", "0x2d33dc", "_ZN6CyaInt22CyaSSL_set_compressionEPNS_6CYASSLE", "TLS compression setting"),
    ("0x2c61d4", "CyaInt_CyaSSL_X509_get_issuer_name_CyaInt_CYASSL_X509", "0x2d3764", "_ZN6CyaInt27CyaSSL_X509_get_issuer_nameEPNS_11CYASSL_X509E", "X.509 issuer"),
    ("0x2c629c", "CyaInt_CyaSSL_session_reused_CyaInt_CYASSL", "0x2d382c", "_ZN6CyaInt21CyaSSL_session_reusedEPNS_6CYASSLE", "session reuse query"),
    ("0x2c6360", "CyaInt_CyaSSL_get_current_cipher_CyaInt_CYASSL", "0x2d38f0", "_ZN6CyaInt25CyaSSL_get_current_cipherEPNS_6CYASSLE", "current cipher"),
    ("0x2c64d8", "CyaInt_CyaSSL_get_cipher_CyaInt_CYASSL", "0x2d3a68", "_ZN6CyaInt17CyaSSL_get_cipherEPNS_6CYASSLE", "cipher name"),
    ("0x2c64f0", "CyaInt_CyaSSL_X509_free_CyaInt_CYASSL_X509", "0x2d3a80", "_ZN6CyaInt16CyaSSL_X509_freeEPNS_11CYASSL_X509E", "X.509 free"),
    ("0x2c64f4", "CyaInt_CyaSSL_X509_get_subjectCN_CyaInt_CYASSL_X509", "0x2d3a84", "_ZN6CyaInt25CyaSSL_X509_get_subjectCNEPNS_11CYASSL_X509E", "X.509 subject common name"),
    ("0x2c6504", "CyaInt_CyaSSL_CTX_OCSP_set_options_CyaInt_CYASSL_CTX_long", "0x2d3a94", "_ZN6CyaInt27CyaSSL_CTX_OCSP_set_optionsEPNS_10CYASSL_CTXEl", "OCSP options"),
    ("0x2c650c", "CyaInt_CyaSSL_CTX_OCSP_set_override_url_CyaInt_CYASSL_CTX_char_const", "0x2d3a9c", "_ZN6CyaInt32CyaSSL_CTX_OCSP_set_override_urlEPNS_10CYASSL_CTXEPKc", "OCSP override URL"),
    ("0x2c706c", "CyaInt_MakeTLSv1_2_void", "0x2d45fc", "_ZN6CyaInt11MakeTLSv1_2Ev", "TLS 1.2 protocol selector"),
    ("0x2c7d44", "CyaInt_CyaTLSv1_client_method_void", "0x2d52d4", "_ZN6CyaInt22CyaTLSv1_client_methodEv", "TLS 1.0 client method"),
    ("0x2c7d7c", "CyaInt_CyaTLSv1_1_client_method_void", "0x2d530c", "_ZN6CyaInt24CyaTLSv1_1_client_methodEv", "TLS 1.1 client method"),
    ("0x2c7db4", "CyaInt_CyaTLSv1_2_client_method_void", "0x2d5344", "_ZN6CyaInt24CyaTLSv1_2_client_methodEv", "TLS 1.2 client method"),
    ("0x2c906c", "CyaInt_LowResTimer_void", "0x2d65fc", "_ZN6CyaInt11LowResTimerEv", "low-resolution timer"),
    ("0x2ccbc4", "CyaInt_InitMutex_int", "0x2da154", "_ZN6CyaInt9InitMutexEPi", "mutex initialization"),
    ("0x2cccbc", "CyaInt_FreeMutex_int", "0x2da24c", "_ZN6CyaInt9FreeMutexEPi", "mutex release"),
    ("0x2cccc4", "CyaInt_LockMutex_int", "0x2da254", "_ZN6CyaInt9LockMutexEPi", "mutex lock"),
    ("0x2ccccc", "CyaInt_UnLockMutex_int", "0x2da25c", "_ZN6CyaInt11UnLockMutexEPi", "mutex unlock"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-features", required=True, type=Path)
    parser.add_argument("--spectron-features", required=True, type=Path)
    parser.add_argument("--semantic-map", required=True, type=Path)
    parser.add_argument("--prior-anchors", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--original-binary-sha256")
    parser.add_argument("--spectron-binary-sha256")
    args = parser.parse_args()

    original_document = load(args.original_features)
    spectron_document = load(args.spectron_features)
    semantic_document = load(args.semantic_map)
    prior_document = load(args.prior_anchors)
    original = by_ea(original_document["functions"])
    spectron = by_ea(spectron_document["functions"])
    semantic_source_eas = {
        int(row["original_ea"], 16) for row in semantic_document.get("matches", [])
    }
    semantic_target_eas = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }
    prior_source_eas = {int(row["original_ea"], 16) for row in prior_document.get("anchors", [])}
    prior_target_eas = {int(row["spectron_ea"], 16) for row in prior_document.get("anchors", [])}

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
        if source_ea in semantic_source_eas or target_ea in semantic_target_eas:
            raise ValueError("CyaInt row is already in the semantic map at %s" % source_text)
        if source_ea in prior_source_eas or target_ea in prior_target_eas:
            raise ValueError("CyaInt row overlaps the prior batch at %s" % source_text)
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
                "match_kind": "manual-cyaint-tls-residual-v2-exact-anchor",
                "semantic_match_already_present": False,
                "source_basis": role,
                "context_group": "CyaInt TLS and cryptography residual methods, batch two",
                "target_delta": "+0xd590",
                "evidence": COMMON_EVIDENCE,
                "name_action": "rename-with-v18-prefix",
                "shape_equal": True,
            }
        )

    result = {
        "schema_version": 1,
        "artifact": "spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for the remaining CyaInt RSA, TLS I/O, verification, protocol, OCSP, and mutex methods",
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
            "prior_anchors": str(args.prior_anchors),
            "prior_anchors_sha256": sha256_path(args.prior_anchors),
        },
        "summary": {
            "anchor_count": len(anchors),
            "high_confidence_count": len(anchors),
            "already_in_semantic_map": 0,
            "already_in_prior_anchor": 0,
            "new_context_anchor_count": len(anchors),
            "exact_shape_anchor_count": len(anchors),
            "layout_change_anchor_count": 0,
            "target_default_name_count": sum(row["spectron_default_name"] for row in anchors),
            "constant_target_delta": "+0xd590",
        },
        "context": {
            "source_class": "CyaInt",
            "target_class": "CyaInt",
            "source_range": "0x2b8bb0 through 0x2ccccc",
            "target_range": "0x2c6140 through 0x2da25c",
            "relocation": "+0xd590",
            "coverage": [
                "RSA verification and decryption helpers",
                "TLS callback registration and I/O state",
                "verification modes and private-key checks",
                "DTLS and timeout helpers",
                "protocol method selectors through TLS 1.2",
                "OCSP options and X.509 accessors",
                "mutex wrappers used by the TLS implementation",
            ],
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The target C++ names are retained as evidence, while the v18_ aliases make the readable 1.8 roles searchable in the translated IDB.",
            "All 53 rows are exact across the complete normalized feature set used by this artifact, and none overlap the first CyaInt batch.",
            "The constant relocation is specific to this hashed Spectron library and must not be reused for unrelated classes without independent checks.",
            "The RSA and verification helpers identify the handshake decision points but do not establish that certificate verification is disabled or that a live server accepts the old client.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
