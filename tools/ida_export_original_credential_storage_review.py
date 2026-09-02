#!/usr/bin/env python3
"""Export the original credential and local-identity storage path from IDA.

The exporter is read-only. It records the options accessors, the virtual
registry file, the reversible simple encoding, and the script-facing account,
password, and cookie boundaries. No runtime credential is read by this tool.
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
    ("0x16b92c", "TOptions_loadPasswords_void", "load local option values"),
    ("0x16b8ec", "TOptions_getGraalNickName_void", "nickname getter"),
    ("0x16bb8c", "TOptions_setGraalNickName_TString_const", "nickname setter"),
    ("0x16bc24", "TOptions_getGraalAccountName_void", "account getter"),
    ("0x16bc68", "TOptions_setGraalAccountNameSimple_TString_const", "in-memory account setter"),
    ("0x16bcd8", "TOptions_setGraalAccountName_TString_const", "account setter and history update"),
    ("0x16be70", "TOptions_getGraalPassWord_void", "password getter"),
    ("0x16beb4", "TOptions_setGraalPassWord_TString_const", "in-memory password setter"),
    ("0x16a27c", "TOptions_get_pref__graal__dontsavepasswords", "do-not-save-passwords preference getter"),
    ("0x16a28c", "TOptions_set_pref__graal__dontsavepasswords", "do-not-save-passwords preference setter"),
    ("0x1eb93c", "TClient_getGraalPassword", "script-facing password getter"),
    ("0x1e9870", "TClient_setLoginAccountName", "active login account setter"),
    ("0x159af8", "GSFunctionsClient_script_getloginaccountname", "script-facing login account getter"),
    ("0x16a4b8", "TOptions_get_graalplugincookie", "script-facing plugin cookie getter"),
    ("0xe71bc", "TFiles_getVirtualRegistryFile_void", "virtual registry path"),
    ("0xe8414", "TFiles_getRegistryValue_TString_const", "virtual registry getter"),
    ("0xe84d0", "TFiles_setRegistryValue_TString_const_TString_const", "virtual registry setter"),
    ("0xe9f60", "THashList_encodesimple_TString_const", "simple option encoding"),
    ("0xea100", "THashList_decodesimple_TString_const", "simple option decoding"),
]

DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_credential_storage_review_20260830.json")


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
        "address": "0x16b92c",
        "classification": "local-options-load",
        "confidence": "confirmed-static",
        "evidence": [
            "The loader reads nickname and accountname from the virtual registry file.",
            "It decodes the first account-name entry into the in-memory options object and falls back to the default guest account when no entry exists.",
            "The password field is populated only by the guest fallback in this loader; no password registry key is read here.",
        ],
        "interpretation": "Normal account history and nickname persistence are separate from the in-memory password field. The name load routine does not establish durable password storage.",
    },
    {
        "address": "0xe71bc",
        "classification": "virtual-registry-location",
        "confidence": "confirmed-static",
        "evidence": [
            "The path is built from data_TFiles_basedatafolder followed by cache/registry.",
            "The same path is used by the registry getter and setter.",
        ],
        "interpretation": "The legacy options registry is a native flat-file store below the client data folder, not Android Keystore-backed storage.",
    },
    {
        "address": "0xe9f60",
        "classification": "reversible-obfuscation-encode",
        "confidence": "confirmed-static",
        "evidence": [
            "The function copies the input and transforms each byte using the total string length and the byte value.",
            "The inverse routine uses the same length-dependent state and is called by the option getters.",
            "No random salt, key lookup, cryptographic primitive, or integrity tag appears in this pair of functions.",
        ],
        "interpretation": "Stored option values are obfuscated for presentation, not protected as secrets. A reader of the registry file who has the client code can reverse them.",
    },
    {
        "address": "0x16bcd8",
        "classification": "account-history-persistence",
        "confidence": "confirmed-static",
        "evidence": [
            "The setter always updates the in-memory account value through the simple setter.",
            "It avoids persisting guest, guest_ prefixed, and cookie account names, while ordinary names are placed at the front of a list.",
            "The list is trimmed to five entries and saved under the accountname registry key.",
        ],
        "interpretation": "The client remembers up to five ordinary account names in the virtual registry. This is a privacy-relevant history even though the reviewed setter does not persist the password.",
    },
    {
        "address": "0x16beb4",
        "classification": "password-memory-boundary",
        "confidence": "confirmed-static",
        "evidence": [
            "The setter stores an encoded copy in the third TString slot of the global options object.",
            "The getter decodes that slot and returns the value to its caller.",
            "The setter itself does not call the virtual registry writer.",
        ],
        "interpretation": "The password persists in the process as reversible obfuscation, but this function does not show a durable password write. Memory inspection or a script caller remains enough to recover it while the client is running.",
    },
    {
        "address": "0x1eb93c",
        "classification": "script-password-exposure",
        "confidence": "confirmed-static",
        "evidence": [
            "The callback invokes TOptions_getGraalPassWord and returns through the script callback ABI.",
            "The script-table inventory maps the native boundary to the getpassword script function.",
        ],
        "interpretation": "Loaded password material is deliberately exposed to the embedded script runtime. A signed or otherwise activated script package should be treated as able to read it.",
    },
    {
        "address": "0x16a27c",
        "classification": "password-save-preference",
        "confidence": "confirmed-static",
        "evidence": [
            "The preference getter returns the global dontsavepasswords byte.",
            "The matching setter only changes that byte and does not itself erase the in-memory password or rewrite the registry.",
        ],
        "interpretation": "The preference is a script-visible policy value, but the reviewed native setter does not provide secure erasure or persistence semantics by itself.",
    },
    {
        "address": "0x16a4b8",
        "classification": "plugin-cookie-exposure",
        "confidence": "confirmed-static",
        "evidence": [
            "The getter copies data_TOptions_plugincookie into a script return string.",
            "The value is separate from creationtime.dat, which is the native cache identity file reviewed in the general security pass.",
        ],
        "interpretation": "The embedded script environment can read the plugin cookie. Its origin and persistence need a runtime value trace before treating it as an account credential.",
    },
]


SECURITY_FINDINGS = [
    {
        "id": "CRED-001",
        "severity": "high",
        "confidence": "confirmed-static",
        "title": "Stored option values use reversible obfuscation instead of secret protection",
        "evidence": [
            "nickname and accountname are read from cache/registry and passed through THashList_encodesimple or decodesimple.",
            "The transform is length-dependent arithmetic with no secret key or integrity check.",
        ],
        "impact": "Anyone who can read the client data folder and knows the published binary can recover remembered names and any value written through this option path. A modern client should use platform-backed secret storage for credentials and avoid persisting account history unless the user asks for it.",
        "limits": "The reviewed account setter does not write the password field. This finding concerns the protection strength of values that are stored through the virtual registry and the in-memory password representation.",
    },
    {
        "id": "CRED-002",
        "severity": "high",
        "confidence": "confirmed-static",
        "title": "Embedded scripts can request the current password",
        "evidence": [
            "TClient_getGraalPassword calls TOptions_getGraalPassWord.",
            "The script inventory maps that native callback to getpassword.",
        ],
        "impact": "Any script that reaches this callback can read the process-held password. The package-signing boundary therefore protects more than code execution: it also protects credential confidentiality.",
        "limits": "The static pass did not prove that an untrusted server response can activate a script package. The original signed-package review documents the separate RSA gate.",
    },
    {
        "id": "CRED-003",
        "severity": "medium",
        "confidence": "confirmed-static",
        "title": "Account history is retained in a shared native flat file",
        "evidence": [
            "Ordinary account names are inserted into a five-entry list and saved under cache/registry.",
            "The path is built from the native base data folder and is not Android Keystore storage.",
        ],
        "impact": "Other code or a local backup reader may learn which accounts have been used on the device. This is a privacy and account-correlation concern, especially on a legacy platform with broad storage behavior.",
        "limits": "The review did not inspect filesystem permissions after installation and did not recover a real user registry file.",
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
        "schema": "libqplay.original-credential-storage-review.v1",
        "artifact": "original_credential_storage_review_20260830",
        "scope": "read-only Hex-Rays export of original 1.8 option, credential, and local-identity boundaries",
        "network_contacted": False,
        "runtime_credentials_read": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": "9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8",
        },
        "manual_reviews": MANUAL_REVIEWS,
        "security_findings": SECURITY_FINDINGS,
        "functions": functions,
        "interpretation": [
            "The virtual registry remembers nickname and a bounded account-name history, while the reviewed password setter stores only an encoded in-memory value.",
            "The simple option transform is reversible obfuscation, not authenticated encryption.",
            "Script access to getpassword makes the signed script-package gate part of the credential trust boundary.",
        ],
    }
    output = os.environ.get("IDA_CREDENTIAL_STORAGE_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
