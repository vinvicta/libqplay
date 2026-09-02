#!/usr/bin/env python3
"""Export the original 1.8 update-package path boundary from IDA.

The exporter is read-only. It records the exact path helpers, update-package
parser, cache mapper, and file writers used by the original ARM64 library.
The report deliberately separates a confirmed static behavior from a proof
that a remote peer can reach that behavior. It does not execute the library,
modify the IDB, fuzz a parser, or contact a service.
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
    ("0x209020", "requestUpdatePackage_void", "base-package request"),
    ("0x2097c8", "TUpdatePackage_update_bool", "update scheduling"),
    ("0x208f4c", "getPackageFullFilename_TString_const", "package path builder"),
    ("0x209e68", "getUpdatePackage_TUpdatePackage_TString_const_bool", "package lookup"),
    ("0x209fa4", "TUpdatePackage_load_void", "package manifest parser"),
    ("0x209998", "TUpdatePackage_getFilePath_TString_const", "package file lookup"),
    ("0x209b28", "getUpdatePackageFilePath_TString_const", "base-package file lookup"),
    ("0x209b70", "TUpdatePackage_isProtected_TString_const", "protected-file lookup"),
    ("0x209d18", "TUpdatePackage_loadLocalVersion_void", "local version reader"),
    ("0x20a898", "TUpdatePackage_saveLocalVersion_void", "local version writer"),
    ("0x20a9cc", "TUpdatePackage_uninstall_void", "package uninstall"),
    ("0x1ec044", "TClient_handleUpdatePackageDownloaded", "update completion"),
    ("0xe8338", "TFiles_initStaticVars_void", "path separator policy"),
    ("0xe73b4", "TFiles_lowerCaseFilename_TString_const", "basename normalization"),
    ("0xe7304", "TFiles_extractFilename_TString_const", "filename extraction"),
    ("0xe7464", "TFiles_extractFilepath_TString_const", "directory extraction"),
    ("0xe7a50", "TFiles_escapedFilename_TString_const", "server-name escaping"),
    ("0xe8208", "TFiles_hasAbsolutePath_TString_const", "path-form test"),
    ("0xfd054", "TFileScripting_initStaticVars_void", "folder policy initialization"),
    ("0xfbf0c", "TFileScripting_AllowedFoldername_TString_const_bool", "folder policy"),
    ("0x1fa920", "TCachedStream_getDownloadFilename_TString_const", "cache filename mapping"),
    ("0x1fb5b8", "TCachedStream_resolveFilename_void", "cache path resolution"),
    ("0x1fb744", "TCachedStream_saveAndUpdate_TCachedStream_TString_const", "cache persistence policy"),
    ("0x1fa6e8", "TCachedStream_save_bool", "cache file writer"),
    ("0xf0aa8", "TStream_SaveToFile_TString_const_uint", "stream file writer"),
    ("0xf6580", "TStringList_SaveToFile_TString_const_uint", "line-list file writer"),
    ("0xe74d4", "TFiles_forceDirectories_TString_const", "directory creation"),
    ("0xe6dfc", "TFiles_deleteFile_TString_const", "file deletion"),
    ("0xedbcc", "TResourceFunctions_getLevelFileResource_TString_const", "resource lookup"),
    ("0xeec84", "TResourceFunctions_getGameFile_TString_const_bool", "resource file lookup"),
]


MANUAL_REVIEWS = [
    {
        "address": "0xfd054",
        "function": "TFileScripting_initStaticVars_void",
        "classification": "static-path-policy-constants",
        "confidence": "confirmed-static",
        "severity": "context",
        "evidence": [
            "The function initializes the broad folder character set to A-Z, a-z, 0-9, underscore, hyphen, slash, colon, and percent.",
            "It initializes the special dotted-directory suffix list to zip, gpak, app, nw, graal, and gmap.",
            "TFiles_initStaticVars separately defines slash and backslash as path separators, while the folder character set does not include backslash.",
        ],
        "interpretation": "The package FILE policy is a character and component policy, not a canonical filesystem policy. The constants reject common traversal spelling in the normal path, but they do not replace a canonical-root check.",
    },
    {
        "address": "0xfbf0c",
        "function": "TFileScripting_AllowedFoldername_TString_const_bool",
        "classification": "literal-traversal-filter",
        "confidence": "confirmed-static",
        "severity": "defense-in-depth-gap",
        "evidence": [
            "TUpdatePackage_load calls this function with W1 equal to zero for the directory portion of each FILE record.",
            "Characters outside the initialized folder set are rejected. Asterisk is only permitted when the boolean argument is enabled.",
            "A dot is accepted only when it follows an alphanumeric character and the following component matches one of the approved dotted directory suffixes with a path separator.",
            "A literal leading dot, a dot after a separator, and the second dot in a .. component therefore fail this check in the package path.",
            "There is no realpath, openat, O_NOFOLLOW, or equivalent canonical-root operation in this helper.",
        ],
        "interpretation": "The static helper blocks the usual ../ and ..\\ spellings for package FILE directories. It accepts slash-prefixed paths made only from allowed characters, so absolute syntax is not explicitly rejected here. That does not prove an escape because the reviewed cache mapper prefixes the stored result with the base user folder, but the acceptance is still weaker than a canonical root check.",
    },
    {
        "address": "0x209fa4",
        "function": "TUpdatePackage_load_void",
        "classification": "manifest-parser-and-path-registration",
        "confidence": "confirmed-static",
        "severity": "availability-and-trust-boundary",
        "evidence": [
            "The function loads a cached stream or a package file into a TStringList and accepts the GRPKG001 header.",
            "SUBPACKAGE records are trimmed to a basename by lowerCaseFilename, checked for a .gupd extension, and passed to getUpdatePackage before a download or update request is started.",
            "FILE records are split into a directory and basename. The directory is passed to AllowedFoldername, while the basename is subject to privileged-package and executable-extension checks before the combined string is stored.",
            "The manifest has no visible total record, description length, or subpackage count limit, and each accepted subpackage can add another package object and request.",
        ],
        "interpretation": "The parser has meaningful path and executable filters, but an accepted package can still amplify memory, list traversal, and download work. This is a stronger static availability finding than a claim of arbitrary file write.",
    },
    {
        "address": "0xe73b4",
        "function": "TFiles_lowerCaseFilename_TString_const",
        "classification": "basename-only-normalization",
        "confidence": "confirmed-static",
        "severity": "path-review-boundary",
        "evidence": [
            "The helper finds the last slash or backslash and returns a lowercased substring after it.",
            "When there is no separator, it lowercases the complete input.",
            "The helper is used for SUBPACKAGE names, cache keys, and package file matching.",
        ],
        "interpretation": "This explains why a SUBPACKAGE value containing a path does not reach the package filename builder as a path. It is normalization by basename extraction, not a general path sanitizer.",
    },
    {
        "address": "0x208f4c",
        "function": "getPackageFullFilename_TString_const",
        "classification": "rooted-package-path-concatenation",
        "confidence": "confirmed-static",
        "severity": "path-trust-boundary",
        "evidence": [
            "The builder starts with the base user folder and updatepackages.",
            "For nonprivileged servers it adds an escaped server-name directory.",
            "It then appends the supplied package string without applying its own extension, separator, or canonical-root validation.",
            "The main callers in the reviewed path pass a package name that has already been reduced to a basename, but the function itself depends on that caller contract.",
        ],
        "interpretation": "The function is safe only as part of its current caller chain. A modern repair should validate the final canonical path even when the caller appears to have sanitized the name.",
    },
    {
        "address": "0x209998",
        "function": "TUpdatePackage_getFilePath_TString_const",
        "classification": "stored-manifest-path-return",
        "confidence": "confirmed-static",
        "severity": "path-trust-boundary",
        "evidence": [
            "The function compares a lowercased lookup basename with package file entries and returns the complete stored entry, including its directory portion.",
            "It searches child packages after the current package when the current package has no matching file.",
            "It does not canonicalize or independently revalidate the returned path.",
        ],
        "interpretation": "A FILE record can influence the directory string returned here after the parser accepts it. The output must therefore be treated as untrusted metadata until the final writer proves it remains below the intended root.",
    },
    {
        "address": "0x1fa920",
        "function": "TCachedStream_getDownloadFilename_TString_const",
        "classification": "package-aware-cache-mapping",
        "confidence": "confirmed-static",
        "severity": "defense-in-depth-gap",
        "evidence": [
            "The function lowercases the basename and asks getUpdatePackageFilePath for a package-provided file path.",
            "When a package path is returned, it builds the result by starting with the base user folder and appending that stored string.",
            "If no package mapping applies, recognized extensions are routed to fixed directories such as updatepackages, levels, levels3d, sounds, and webfiles, with escaped final components in the fallback branches.",
        ],
        "interpretation": "The reviewed package mapping adds a base-user prefix even when the stored FILE directory begins with a slash, so the static result is not a demonstrated root escape. String prefixing is not equivalent to canonical containment, and symlink or future caller behavior remains relevant.",
    },
    {
        "address": "0x1fb5b8",
        "function": "TCachedStream_resolveFilename_void",
        "classification": "existing-path-or-fallback-selection",
        "confidence": "confirmed-static",
        "severity": "symlink-and-canonicalization-risk",
        "evidence": [
            "The resolver lowercases .gupd names, extracts the candidate directory, and uses TFiles_fileExists before retaining an existing path.",
            "TFiles_fileExists is based on stat, which follows symlinks.",
            "Missing or rejected candidates fall back to the extension directory mapper, but there is no visible realpath or no-follow creation step before a retained path is later written.",
        ],
        "interpretation": "This is a confirmed review gap. Exploitability depends on whether an attacker can create or influence a link inside an accepted application directory and whether the same path is later opened for writing.",
    },
    {
        "address": "0x1fa6e8",
        "function": "TCachedStream_save_bool",
        "classification": "persistent-write-and-executable-redirect",
        "confidence": "confirmed-static",
        "severity": "high-impact-capability",
        "evidence": [
            "The function creates parent directories and checks whether the candidate starts with the base user folder.",
            "A path outside that prefix, or a path matching the configured base executable, is redirected to the configured full executable path.",
            "The redirect deletes an existing target and sets the replacement flag. The ordinary path is then saved with TStream_SaveToFile.",
            "There is no package signature check, atomic rename, or no-follow open in this function.",
        ],
        "interpretation": "The executable replacement behavior is a confirmed capability already documented in SECURITY.md. The path and package trust chain determines whether a remote response can reach it; this function alone does not establish that reachability.",
    },
    {
        "address": "0xf0aa8",
        "function": "TStream_SaveToFile_TString_const_uint",
        "classification": "non-atomic-truncating-write",
        "confidence": "confirmed-static",
        "severity": "integrity-and-availability",
        "evidence": [
            "The normal write mode is wb and the append mode is ab.",
            "The function writes the whole TString buffer with one fwrite call and does not compare the returned count with the requested length.",
            "It logs an open failure but does not expose a structured write failure to the caller.",
        ],
        "interpretation": "A crash, storage-full condition, or interruption can leave a truncated cache file while the surrounding caller may continue. A modern repair should use a temporary file, checked writes, fsync where appropriate, and an atomic rename.",
    },
    {
        "address": "0x20a898",
        "function": "TUpdatePackage_saveLocalVersion_void",
        "classification": "server-scoped-local-state-write",
        "confidence": "confirmed-static",
        "severity": "integrity-boundary",
        "evidence": [
            "The path is baseuserfolder/updatepackages, followed by an escaped server-name component for nonprivileged servers, and localversions.txt.",
            "The function loads the existing line list, updates the package name key, and calls TStringList_SaveToFile with overwrite mode.",
            "The writer does not use a temporary file or check each fwrite result.",
        ],
        "interpretation": "The server-name component is escaped, which limits direct separator injection through that field. The local version file remains a mutable trust and integrity point because it is overwritten non-atomically and the package key is parsed from package metadata.",
    },
    {
        "address": "0x20a9cc",
        "function": "TUpdatePackage_uninstall_void",
        "classification": "package-driven-delete-capability",
        "confidence": "confirmed-static",
        "severity": "context-dependent",
        "evidence": [
            "The function iterates the package FILE list, reduces each entry to a basename with lowerCaseFilename, resolves it through getGameFile, and passes the resolved result to TFiles_deleteFile.",
            "The generic delete helper is a thin unlink wrapper and does not apply its own policy.",
            "The package name optional skips this path, but there is no canonical-root check inside the uninstall loop.",
        ],
        "interpretation": "The delete operation is real, but the current caller uses basename resolution rather than blindly unlinking the stored manifest string. A disposable local test should still verify resource-object and symlink behavior before assigning arbitrary deletion.",
    },
    {
        "address": "0x209b70",
        "function": "TUpdatePackage_isProtected_TString_const",
        "classification": "basename-protection-matching",
        "confidence": "confirmed-static",
        "severity": "policy-boundary",
        "evidence": [
            "PROTECTOVERWRITE causes the function to compare the lowercased basename of each FILE entry with the requested name.",
            "If no match exists in the current package, the check recurses into the parent package.",
            "The comparison is basename-based, so two different directories with the same filename share the protection decision.",
        ],
        "interpretation": "This is a policy correctness issue rather than a direct traversal finding. A modern implementation should compare canonical relative paths, not only basenames, when protecting files from overwrite.",
    },
]


DEFAULT_OUTPUT = str(Path(__file__).resolve().parents[1] / "artifacts" / "original_update_package_path_review_20260830.json")


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
    info = ida_funcs.get_func(address)
    literals = sorted(set(re.findall(r'"(?:\\.|[^"\\])*"', code)))
    return {
        "address": "0x%x" % address,
        "name": current_name,
        "role": role,
        "function_start": "0x%x" % info.start_ea if info else None,
        "function_end": "0x%x" % info.end_ea if info else None,
        "code_sha256": sha256_text(code),
        "code_bytes": len(code.encode("utf-8")),
        "string_literals": literals[:400],
        "callers": effective_callers(address)[:400],
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
        "schema": "libqplay.original-update-package-path-review.v1",
        "artifact": "original_update_package_path_review_20260830",
        "scope": (
            "read-only Hex-Rays export of original 1.8 ARM64 update-package "
            "path handling, cache mapping, and local file writers"
        ),
        "network_contacted": False,
        "database": {
            "path": idaapi.get_input_file_path(),
            "imagebase": "0x%x" % idaapi.get_imagebase(),
            "binary_sha256": sha256_file(idaapi.get_input_file_path()),
        },
        "static_policy_cases": [
            {
                "input": "../escape/",
                "expected_folder_policy": "reject",
                "reason": "The first dot is leading and the second dot follows a dot, so the dotted-component rule does not match.",
            },
            {
                "input": "levels/../escape/",
                "expected_folder_policy": "reject",
                "reason": "The first dot in the parent component follows a separator and is rejected.",
            },
            {
                "input": "levels\\..\\escape\\",
                "expected_folder_policy": "reject",
                "reason": "Backslash is a recognized separator for extraction but is not in the allowed folder character set, and the parent component also fails the dot rule.",
            },
            {
                "input": "packs/base.gpak/",
                "expected_folder_policy": "accept-if-other-state-allows",
                "reason": "The dotted directory suffix is one of the initialized approved forms and ends at a separator.",
            },
            {
                "input": "/tmp/",
                "expected_folder_policy": "accept-if-other-state-allows",
                "reason": "The helper permits slash-prefixed strings made from its allowed characters; it does not itself reject absolute syntax.",
            },
        ],
        "manual_reviews": MANUAL_REVIEWS,
        "functions": functions,
        "interpretation": [
            "The original package FILE directory policy blocks ordinary literal traversal spellings but does not perform canonical containment.",
            "SUBPACKAGE names are basename-normalized before package path construction, while FILE entries retain an accepted directory plus basename for later package lookup.",
            "The package-aware cache mapper prefixes package file paths with the base user folder, so an absolute-looking FILE directory is not by itself proof of a root escape.",
            "The remaining high-value filesystem questions are symlink following, canonical path containment, non-atomic writes, and the provenance of package metadata.",
            "Manifest records, subpackages, descriptions, and cached file responses have no single visible total budget in the reviewed path, creating a context-dependent availability risk.",
            "This artifact does not claim a remotely exploitable traversal or code execution path. Such a claim requires a controlled local package and filesystem test that observes the final open or unlink target.",
        ],
    }
    output = os.environ.get("IDA_UPDATE_PACKAGE_PATH_REVIEW_OUT", DEFAULT_OUTPUT)
    Path(output).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    ida_kernwin.msg("wrote %s\n" % output)
    print(json.dumps({"function_count": len(functions), "output": output}, sort_keys=True))


if __name__ == "__main__":
    main()
