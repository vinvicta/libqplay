#!/usr/bin/env python3
"""Build behavior-based role candidates for selected IDA default functions.

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
    {
        "ea": 0x150A30,
        "proposed_name": "TBitmap_GIF_streamRead",
        "confidence": "high",
        "role": "GIF decoder read callback backed by a TStream",
        "evidence": [
            "TBitmap::readGIF passes 0x150a30 to DGifOpen at 0x150a68.",
            "The callback loads the TStream pointer from the GIF user-data field at offset 0x68 and tail-calls TStream::read.",
        ],
    },
    {
        "ea": 0x150EA0,
        "proposed_name": "TBitmap_JPEG_noopFlush",
        "confidence": "high",
        "role": "No-op JPEG flush callback",
        "evidence": [
            "TBitmap::writeJPEG assigns 0x150ea0 to the JFFLUSH global at 0x15125c.",
            "The body is the two-instruction callback that returns zero without changing the stream state.",
        ],
    },
    {
        "ea": 0x150EA8,
        "proposed_name": "TBitmap_JPEG_noopError",
        "confidence": "high",
        "role": "No-op JPEG error callback",
        "evidence": [
            "TBitmap::readJPEG assigns 0x150ea8 to the JFERROR global at 0x151008.",
            "TBitmap::writeJPEG assigns the same callback at 0x151268, and the body returns zero without changing the error state.",
        ],
    },
    {
        "ea": 0x150EB0,
        "proposed_name": "TBitmap_JPEG_outputMessage",
        "confidence": "high",
        "role": "JPEG error-manager output callback",
        "evidence": [
            "TBitmap::readJPEG installs 0x150eb0 in the JPEG error manager at 0x151048.",
            "The body obtains the manager's message text, formats it through TLog::printf, and returns through the libjpeg error callback convention.",
        ],
    },
    {
        "ea": 0x150F20,
        "proposed_name": "TBitmap_JPEG_errorExit",
        "confidence": "high",
        "role": "JPEG fatal-error callback that performs the saved jump",
        "evidence": [
            "TBitmap::readJPEG installs 0x150f20 as the first JPEG error-manager callback at 0x15103c.",
            "The body invokes the manager's error callback, then longjmps through the saved jump buffer with status two.",
        ],
    },
    {
        "ea": 0x150F44,
        "proposed_name": "TBitmap_JPEG_streamWrite",
        "confidence": "high",
        "role": "JPEG destination write callback backed by a TStream",
        "evidence": [
            "TBitmap::writeJPEG assigns 0x150f44 to the JFWRITE global at 0x151250.",
            "The callback appends the requested bytes with TString::addbuffer, updates the destination counters, and returns the number of bytes written.",
        ],
    },
    {
        "ea": 0x17B9BC,
        "proposed_name": "TPlayer_getDrawObjectListPredicate",
        "confidence": "high",
        "role": "Draw-object tree predicate used while building a player draw list",
        "evidence": [
            "TPlayer::getDrawObjectList passes 0x17b9bc to TBSPTree::findObject at 0x17dff4.",
            "The callback updates the object's draw-search marker at offset 0x388 and invokes the object virtual update slot at offset 0x138.",
        ],
    },
    {
        "ea": 0x1925E4,
        "proposed_name": "ani_lexer_fatalExit",
        "confidence": "high",
        "role": "Generated animation lexer fatal-exit helper",
        "evidence": [
            "The generated animation scanner APIs and loadGaniFromString call 0x1925e4 as their fatal path.",
            "The body calls exit with status two and has no independent application state or return path.",
        ],
    },
    {
        "ea": 0x19FC88,
        "proposed_name": "TServerLevel_getNPCTileTypePredicate",
        "confidence": "high",
        "role": "BSP-tree predicate for TServerLevel::getNPCTileType",
        "evidence": [
            "TServerLevel::getNPCTileType passes 0x19fc88 to TBSPTree::findObject at 0x1a420c.",
            "The callback reads the query coordinates from the shared level context, calls TServerNPC::getTileType, stores the result, and returns whether a type was found.",
        ],
    },
    {
        "ea": 0x19FCBC,
        "proposed_name": "TServerLevel_isOnNPCPredicate",
        "confidence": "high",
        "role": "BSP-tree predicate for TServerLevel::isOnNPC",
        "evidence": [
            "TServerLevel::isOnNPC passes 0x19fcbc to the object-tree search at 0x1a4d60.",
            "The callback loads the saved coordinates and flag from the shared level context and tail-calls TServerNPC::isOnNPC.",
        ],
    },
    {
        "ea": 0x19FE34,
        "proposed_name": "TServerLevel_collectOnNPCPredicate",
        "confidence": "high",
        "role": "BSP-tree predicate that collects NPCs matching TServerLevel::getOnNPC",
        "evidence": [
            "TServerLevel::getOnNPC passes 0x19fe34 to the object-tree search at 0x1a5030 and 0x1a505c.",
            "The callback tests each NPC with TServerNPC::isOnNPC and appends matching objects to the result list at the shared context offset 0x100.",
        ],
    },
    {
        "ea": 0x1C042C,
        "proposed_name": "GuiScrollCtrl_readScriptObjectProperties",
        "confidence": "high",
        "role": "Scroll-control helper that resolves a script object to TProperties",
        "evidence": [
            "GuiScrollCtrl::findHitControl calls 0x1c042c at four scrollbar-related sites.",
            "The helper reads a TGraalVar object and dynamic-casts it to TProperties before the caller reads the resulting property data.",
        ],
    },
    {
        "ea": 0x217E68,
        "proposed_name": "TScriptMachine_getActionNpcOrActivePlayerObject",
        "confidence": "high",
        "role": "Script-object resolver for actionnpc with activeplayer fallback",
        "evidence": [
            "TScriptMachine::resolveObjectMember calls 0x217e68 at 0x219610 and 0x219850.",
            "The helper returns the actionnpc object field, or the activeplayer object field when actionnpc is marked as using the active player context.",
        ],
    },
    {
        "ea": 0xE01D0,
        "proposed_name": "ani_lexer_getPreviousState",
        "confidence": "high",
        "role": "Flex-style animation lexer previous-state helper",
        "evidence": [
            "The generated lex_load routine calls 0xe01d0 at 0x194c8c, 0x194e4c, and 0x195efc after updating its scanner buffer state.",
            "The body walks the current animation input with the DFA tables near 0x2d6000 and 0x2d7000, updates scanner state globals, and returns the next lexer state.",
            "Its no-argument shape and table walk match the generated yy_get_previous_state helper used by flex scanners.",
        ],
    },
    {
        "ea": 0x20AC18,
        "proposed_name": "compareObjectsByDistance",
        "confidence": "medium",
        "role": "Object comparator using draw-distance and priority tie-breaks",
        "evidence": [
            "The body accepts two object pointers, calls each object's virtual position accessors at offsets 0x148 and 0x158, and computes squared distance from the shared draw reference at 0x390bd8.",
            "It returns -1, 0, or 1 and uses the object field at offset 0x2ec as a tie-breaker, which is consistent with a sort comparator.",
            "IDA recorded four incoming references, but the saved static scan did not recover a direct BL call site, so the alias intentionally avoids assigning a class owner.",
        ],
    },
    {
        "ea": 0x22D9FC,
        "proposed_name": "TGraalVar_jsonMapKeyCallback",
        "confidence": "high",
        "role": "YAJL map-key callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22d9fc in the map_key slot, and TGraalVar::readJSON passes that table to yajl_alloc at 0x22e2c0.",
            "The body builds a temporary key string, stores it in the current object entry, and handles the special scriptsslissuer key used by the client.",
        ],
    },
    {
        "ea": 0x22DAB4,
        "proposed_name": "TGraalVar_jsonStringCallback",
        "confidence": "high",
        "role": "YAJL string-value callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22dab4 in the string slot used by yajl_alloc.",
            "The body copies the incoming string into a temporary TString and writes it into the current TGraalVar object or array entry.",
        ],
    },
    {
        "ea": 0x22DBBC,
        "proposed_name": "TGraalVar_jsonNumberCallback",
        "confidence": "high",
        "role": "YAJL number callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22dbbc in the number slot used by yajl_alloc.",
            "The body copies the numeric text, checks it with isnumber2, converts it with strtofloat, and stores the value in the current TGraalVar entry while preserving a normalized string form.",
        ],
    },
    {
        "ea": 0x22DD94,
        "proposed_name": "TGraalVar_jsonBooleanCallback",
        "confidence": "high",
        "role": "YAJL boolean callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22dd94 in the boolean slot used by yajl_alloc.",
            "The body converts the boolean argument to a floating value and updates the current TGraalVar entry, returning one on completion.",
        ],
    },
    {
        "ea": 0x22DE60,
        "proposed_name": "TGraalVar_jsonStartArrayCallback",
        "confidence": "high",
        "role": "YAJL start-array callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22de60 in the start_array slot used by yajl_alloc.",
            "The body creates an array TGraalVar child, initializes its type marker, and links the new list node into the current parsing context.",
        ],
    },
    {
        "ea": 0x22DFA4,
        "proposed_name": "TGraalVar_jsonEndMapCallback",
        "confidence": "high",
        "role": "YAJL end-map callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22dfa4 in the end_map slot used by yajl_alloc.",
            "The body removes the current object node from the parsing chain, transfers its linked-string ownership, clears the temporary string, and deletes the completed node.",
        ],
    },
    {
        "ea": 0x22E000,
        "proposed_name": "TGraalVar_jsonEndArrayCallback",
        "confidence": "high",
        "role": "YAJL end-array callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22e000 in the end_array slot used by yajl_alloc.",
            "The body performs the corresponding array-node removal and ownership transfer, then clears and deletes the completed parser node.",
        ],
    },
    {
        "ea": 0x22E05C,
        "proposed_name": "TGraalVar_jsonNullCallback",
        "confidence": "high",
        "role": "YAJL null callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22e05c in the null slot used by yajl_alloc.",
            "The body handles the current object or array entry and writes the null value through the TGraalVar numeric or virtual-value path.",
        ],
    },
    {
        "ea": 0x22E12C,
        "proposed_name": "TGraalVar_jsonStartMapCallback",
        "confidence": "high",
        "role": "YAJL start-map callback for TGraalVar::readJSON",
        "evidence": [
            "The callback table at 0x387e20 stores 0x22e12c in the start_map slot used by yajl_alloc.",
            "The body creates an object TGraalVar child, initializes its type marker, and links the new list node into the current parsing context.",
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
    application_unknown = {
        int(item["ea"], 0)
        for item in profile["categories"]
        if item["category"] == "app_or_engine_unknown"
        for item in item["entries"]
    }
    candidate_addresses = {candidate["ea"] for candidate in CANDIDATES}
    if candidate_addresses != application_unknown:
        missing = sorted(application_unknown - candidate_addresses)
        extra = sorted(candidate_addresses - application_unknown)
        raise ValueError(
            "role candidate coverage mismatch: missing=%s extra=%s"
            % ([f"0x{ea:x}" for ea in missing], [f"0x{ea:x}" for ea in extra])
        )

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
        "purpose": "Record behavior-based roles for the unresolved application or engine functions without claiming recovered ELF source names; confidence is recorded per candidate.",
        "binary": "private original ARM64 libqplay.so",
        "binary_sha256": sha256(binary),
        "candidate_count": len(candidates),
        "role_candidate_coverage": {
            "profile_category": "app_or_engine_unknown",
            "profile_count": len(application_unknown),
            "candidate_count": len(candidate_addresses),
            "uncovered": [],
            "extra": [],
        },
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
