#!/usr/bin/env python3
"""Build high-confidence role candidates for selected IDA default functions.

The ELF symbol import is complete, but some compiler-created functions still
have no source name. This small candidate set records roles proved by callers
and nearby exported methods. It does not claim that the proposed aliases were
present in the APK or already applied to IDA.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


DEFAULT_BINARY = "/home/v/Desktop/graal-decomp/GraalOnline+Classic_1.8_APKPure/lib/arm64-v8a/libqplay.so"
DEFAULT_INVENTORY = "symbols/libqplay.function_inventory.json"
DEFAULT_PROFILE = "artifacts/unresolved_function_profile.json"
DEFAULT_OUTPUT = "artifacts/unresolved_function_candidates.json"


CANDIDATES = [
    {
        "ea": 0xF9028,
        "proposed_name": "ProfilerRootData_compareNonSubTotalTime",
        "confidence": "high",
        "role": "TList comparator for profiler entries ordered by non-sub total time",
        "evidence": [
            "TProfiler::dumpToList passes 0xf9028 to TList::Sort at 0xfa4b4.",
            "The body reads the ProfilerRootData time fields at offsets 0x20 and 0x28 and returns their floating-point ordering.",
        ],
    },
    {
        "ea": 0xF9060,
        "proposed_name": "ProfilerRootData_dumpFunctionTree",
        "confidence": "high",
        "role": "Recursive profiler function-tree formatter",
        "evidence": [
            "TProfiler::dumpToList calls 0xf9060 at 0xfa6b0 immediately after emitting the Function tree header.",
            "The body walks child links, formats profiler time, invocation count, and names with the native format string, and appends rows to a TStringList.",
            "The body calls itself while traversing nested profiler entries.",
        ],
    },
    {
        "ea": 0xF9944,
        "proposed_name": "ProfilerRootData_resetTree",
        "confidence": "high",
        "role": "Recursive profiler tree reset helper",
        "evidence": [
            "TProfiler::dumpToList calls 0xf9944 at 0xfa8a8 after the function-tree output pass.",
            "The body clears active flags and timing fields for each node and recursively visits the child chain.",
        ],
    },
    {
        "ea": 0x213088,
        "proposed_name": "TGraalVar_loadFolderRecursive",
        "confidence": "high",
        "role": "Recursive folder-to-array loader used by TGraalVar::loadFolder",
        "evidence": [
            "The helper ends exactly at the exported TGraalVar::loadFolder entry at 0x21337c.",
            "TGraalVar::loadFolder calls it at 0x2134cc, and the helper calls itself at 0x213184 for nested folders.",
            "The body calls TFiles::getFolder and creates TGraalVar entries with filesize and isfolder properties.",
        ],
    },
]


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def generate(args: argparse.Namespace) -> dict[str, object]:
    binary = Path(args.binary).read_bytes()
    inventory = json.loads(Path(args.inventory).read_text(encoding="utf-8"))
    profile = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    by_ea = {int(item["ea"]): item for item in inventory}
    unresolved = {
        int(item["ea"], 0)
        for item in profile["categories"]
        for item in item["entries"]
    }

    candidates = []
    for candidate in CANDIDATES:
        item = dict(candidate)
        function = by_ea.get(candidate["ea"])
        if function is None:
            raise ValueError("candidate 0x%x is absent from the inventory" % candidate["ea"])
        if candidate["ea"] not in unresolved:
            raise ValueError("candidate 0x%x is no longer unresolved" % candidate["ea"])
        if not function["is_default_sub"]:
            raise ValueError("candidate 0x%x is no longer an IDA default sub" % candidate["ea"])
        item.update(
            {
                "va": "0x%x" % candidate["ea"],
                "current_ida_name": function["name"],
                "segment": function["segment"],
                "size": function["size"],
                "xrefs_to": function["xrefs_to"],
            }
        )
        item.pop("ea", None)
        candidates.append(item)

    return {
        "status": "candidates_not_yet_applied_to_ida",
        "purpose": "Record high-confidence roles for selected IDA default functions without claiming recovered ELF source names.",
        "binary": "private original ARM64 libqplay.so",
        "binary_sha256": sha256(binary),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "source_artifacts": {
            "function_inventory": "symbols/libqplay.function_inventory.json",
            "unresolved_profile": "artifacts/unresolved_function_profile.json",
        },
        "network_contacted": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
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
    print(json.dumps({"output": str(output), "candidates": result["candidate_count"]}, sort_keys=True))


if __name__ == "__main__":
    main()
