#!/usr/bin/env python3
"""Create reviewed 1.8-to-Spectron anchors for core client routines.

The target addresses are selected from clean Spectron IDA pseudocode and
feature metadata.  This file records evidence for resource loading, rendering,
GUI setup, scripting, and client support code without modifying an IDA
database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ANCHOR_SPECS = [
    {
        "original_ea": "0xed578",
        "original_name": "TResourceFunctions_updateGameObjectsForFile_TString_const",
        "spectron_ea": "0xee558",
        "source_basis": "resource extension dispatch, map-header checks, and game-object refresh",
        "required_target_strings": [
            ".enc",
            ".gani",
            ".gmap",
            ".po",
            ".ttf",
            ".wba",
            ".zip",
            "UpdateFile_Ganis",
            "khead",
            "zone_head",
        ],
        "evidence": [
            "The candidate strips the encrypted extension and dispatches the same zip, WBA, font, GANI, WAV, PO, image, and map resource cases.",
            "It preserves the khead and zone_head checks, the UpdateFile_Ganis event, and the resource-object refresh calls visible in the 1.8 body.",
            "Both builds retain 56 basic blocks and the same distinctive extension and map-header string set, while the rebuilt 2.2 body is modestly larger.",
        ],
    },
    {
        "original_ea": "0xee078",
        "original_name": "TResourceFunctions_updateResourceObject_TString_const_bool",
        "spectron_ea": "0xef090",
        "source_basis": "webfiles path construction, resource lookup, linked-object refresh, and update notification",
        "required_target_strings": ["webfiles"],
        "evidence": [
            "The candidate constructs the webfiles path, looks up or creates the resource object, and refreshes linked alternatives in the same class context.",
            "Its callers and callees include the translated updateGameObjectsForFile role, HTTP download lookup, resource creation, and the level-file update event path.",
            "Both builds retain 47 basic blocks and the same f6WHgaQkAF class-level relationship; the 2.2 function adds only rebuilt-body detail.",
        ],
    },
    {
        "original_ea": "0xeee48",
        "original_name": "TResourceFunctions_initStaticVars_void",
        "spectron_ea": "0xf0058",
        "source_basis": "resource extension table initialization",
        "required_target_strings": [".dds,.gif,.mng,.png,.jp2,.jpg,.jpeg,.tga,.bmp,.dib"],
        "evidence": [
            "The candidate initializes the same image-extension table as the 1.8 resource subsystem.",
            "It has the same one-block static-initializer shape and the same small-string and list-construction call pattern.",
            "The exact extension-table text is a stronger identifier here than the rebuilt address or mangled class name.",
        ],
    },
    {
        "original_ea": "0xfca80",
        "original_name": "TFileScripting_script_decompressFile",
        "spectron_ea": "0xff028",
        "source_basis": "archive extraction, resource iteration, and decompression status reporting",
        "required_target_strings": [" into ", "*", "Unzipped ", "files"],
        "evidence": [
            "The candidate walks the same file and resource-object lists, extracts matching entries, and updates resources after decompression.",
            "It owns the distinctive Unzipped, into, wildcard, and files messages and calls the same resource update and stream operations.",
            "The target was an IDA default sub_ name, so this anchor restores a reviewed v18_ role rather than relying on an existing Spectron symbol.",
        ],
    },
    {
        "original_ea": "0xfd054",
        "original_name": "TFileScripting_initStaticVars_void",
        "spectron_ea": "0xff65c",
        "source_basis": "file-scripting extension, path, and allowed-folder table initialization",
        "required_target_strings": [
            ".exe,.dll,.sh,.so,.bat,.cmd,.com,.inf,.lnk,.mdb,.msi,.ocx,.pif,.reg,.scr,.sys,.app",
            ".zip,.wba,.ods",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-/:%",
            "tileobjects/",
            "zip,gpak,app,nw,graal,gmap",
        ],
        "evidence": [
            "The candidate initializes the same executable deny-list, archive list, path character tables, tileobjects path, and supported package extensions.",
            "The exact six-string table is preserved in the rebuilt binary and the target has the same one-block static-initializer role.",
            "This is a static role anchor, not a claim that every helper called by the initializer has also been translated.",
        ],
    },
    {
        "original_ea": "0x15d224",
        "original_name": "TClientEnvironment_drawGame_bool",
        "spectron_ea": "0x16027c",
        "source_basis": "RenderGUI setup, frame clearing, display-state handling, and successful return",
        "required_target_strings": ["RenderGUI"],
        "evidence": [
            "The candidate initializes the RenderGUI profiler label, clears the rendering managers, and invokes the rebuilt GUI canvas frame path.",
            "It preserves the display-state cleanup and restart handling surrounding the render call and returns success on the same normal path.",
            "The target has the same unique RenderGUI string and nearly the same compact control flow despite one fewer basic block.",
        ],
    },
    {
        "original_ea": "0x167e88",
        "original_name": "TGUIScriptLoader_showGameGui_void",
        "spectron_ea": "0x16b848",
        "source_basis": "Graal GUI script creation and GUIContainer control-tree setup",
        "required_target_strings": ["GUIContainer", "GraalControl", "GraalControl3D", "StartScript_GraalGui"],
        "evidence": [
            "The candidate loads or creates StartScript_GraalGui, obtains GUIContainer, and installs the GraalControl and GraalControl3D controls.",
            "Its pseudocode follows the same script-universe and canvas-content setup as the 1.8 function.",
            "The four distinctive GUI strings are preserved, and both builds have the same compact 19-block versus 18-block setup role.",
        ],
    },
    {
        "original_ea": "0x1684f4",
        "original_name": "TGUIScriptLoader_hideConnectingWindow_void",
        "spectron_ea": "0x16bed8",
        "source_basis": "StartConnectMessage lookup and connecting-dialog hide operation",
        "required_target_strings": ["StartConnectMessage"],
        "evidence": [
            "The candidate looks up StartConnectMessage, resolves the same GUI control, and calls the dialog hide or close vtable operation when it is active.",
            "The target and source retain the same seven-block shape and the same single script-control identifier.",
            "This directly anchors the UI transition that should follow a completed connection or server warp.",
        ],
    },
    {
        "original_ea": "0x1685a0",
        "original_name": "TGUIScriptLoader_createMessageBoxDialog_void",
        "spectron_ea": "0x16bf80",
        "source_basis": "StartScript_MessageBoxDialog creation and script loading",
        "required_target_strings": ["StartScript_MessageBoxDialog"],
        "evidence": [
            "The candidate resolves or creates the StartScript_MessageBoxDialog object and loads the same embedded GUI script resource.",
            "It preserves the same script-universe registration, control initialization, and dialog activation sequence.",
            "The exact script name and matching five-block versus four-block wrapper shape make this a direct UI anchor.",
        ],
    },
    {
        "original_ea": "0x1686d0",
        "original_name": "TGUIScriptLoader_showMessageBox_TString_const_TString_const_bool",
        "spectron_ea": "0x16c0ac",
        "source_basis": "message-box text assignment, dialog display, and loading-state interaction",
        "required_target_strings": ["MessageBoxDialog", "MessageBoxDialog_Text"],
        "evidence": [
            "The candidate resolves MessageBoxDialog_Text, assigns the supplied text, resolves MessageBoxDialog, and pushes the dialog onto the GUI canvas.",
            "It retains the same optional loading-state and cursor interactions seen in the 1.8 pseudocode.",
            "The rebuilt target has the same 17 basic blocks and exact two-string dialog vocabulary, with only instruction-boundary changes.",
        ],
    },
    {
        "original_ea": "0x1689c4",
        "original_name": "TGUIScriptLoader_runFailedsafeConnector_void",
        "spectron_ea": "0x16c3a0",
        "source_basis": "StartScript_Connector creation and failed-safe connector activation",
        "required_target_strings": ["StartScript_Connector"],
        "evidence": [
            "The candidate resolves or creates StartScript_Connector and loads the same connector recovery script.",
            "The surrounding script-universe and GUI-control calls match the failed-safe connector role in the 1.8 build.",
            "The exact script name and matching five-block versus four-block wrapper shape support the correspondence.",
        ],
    },
    {
        "original_ea": "0x1690c8",
        "original_name": "TInput_graalControlHasFocus_bool",
        "spectron_ea": "0x16cac8",
        "source_basis": "focused-control lookup for ChatBar and ChatBar3D",
        "required_target_strings": ["ChatBar", "ChatBar3D"],
        "evidence": [
            "The candidate reads the current focused control name and compares it against ChatBar and ChatBar3D.",
            "It preserves the same early returns for missing GUI state and the same two-control fallback check.",
            "The target's larger rebuilt body still has the distinctive input-control strings and the same boolean result role.",
        ],
    },
    {
        "original_ea": "0x1e9068",
        "original_name": "TClient_uploadFile_TString_const",
        "spectron_ea": "0x1ed4c4",
        "source_basis": "upload-size validation, upload object creation, and folder-log event",
        "required_target_strings": [" bytes)", " is too big to upload (max ", "File "],
        "evidence": [
            "The candidate enforces the same 20,000,000-byte limit, queues an upload object on success, and reports oversized files through the game log path.",
            "It owns the same File, maximum-size, and bytes message fragments and retains the same list insertion role.",
            "The target's eight-block body and matching argument shape are consistent with a rebuilt client helper rather than an unrelated file routine.",
        ],
    },
    {
        "original_ea": "0x1f1d38",
        "original_name": "TClient_logGameEcho",
        "spectron_ea": "0x1f6538",
        "source_basis": "game-channel logging for each line in a client message",
        "required_target_strings": ["game"],
        "evidence": [
            "The candidate iterates the supplied line list and sends every line to the game log channel.",
            "It retains the same temporary string-list construction and per-line logging sequence.",
            "The target was a default sub_ name, so the reviewed alias supplies the missing client role without transferring the old address.",
        ],
    },
    {
        "original_ea": "0x2025a0",
        "original_name": "THTTPRequest_runScript_void",
        "spectron_ea": "0x207db8",
        "source_basis": "web-script response parsing, size guard, script execution, and completion",
        "required_target_strings": [
            " (size of ",
            " bytes)",
            "Web file is too huge, download skipped: ",
            "files",
        ],
        "evidence": [
            "The candidate reads the HTTP response, handles the same size guard, parses the returned script data, and invokes the script runner on successful completion.",
            "It owns the distinctive oversized-web-file message and calls the same read, pre-parse, save, request-removal, and script-execution helpers.",
            "Both builds retain 35 basic blocks and the same response-state fields, while the 2.2 function is expanded by the rebuilt implementation.",
        ],
    },
    {
        "original_ea": "0x203bd8",
        "original_name": "TServerList_showConnectingWindow_void",
        "spectron_ea": "0x2092a0",
        "source_basis": "server-list dialog setup, connecting-window transition, and game GUI handoff",
        "required_target_strings": ["GUIContainer", "ServerListGui"],
        "evidence": [
            "The candidate resolves ServerListGui, attaches it to the same GUI container, and changes the connecting state through the server-list environment.",
            "It calls the reviewed connecting-window and game-GUI routines in the same handoff sequence.",
            "The exact GUI identifiers and matching 13-block shape make this a direct bridge between network completion and rendered UI state.",
        ],
    },
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
    semantic_targets = {
        int(row["spectron_ea"], 16) for row in semantic_document.get("matches", [])
    }

    anchors = []
    for spec in ANCHOR_SPECS:
        original_ea = int(spec["original_ea"], 16)
        spectron_ea = int(spec["spectron_ea"], 16)
        source = original.get(original_ea)
        target = spectron.get(spectron_ea)
        if source is None:
            raise ValueError("missing original feature at %s" % spec["original_ea"])
        if target is None:
            raise ValueError("missing Spectron feature at %s" % spec["spectron_ea"])
        if source.get("name") != spec["original_name"]:
            raise ValueError(
                "original name mismatch at %s: %s"
                % (spec["original_ea"], source.get("name"))
            )
        target_strings = set(target.get("string_refs", []))
        missing_strings = sorted(set(spec["required_target_strings"]) - target_strings)
        if missing_strings:
            raise ValueError(
                "target %s is missing expected strings: %s"
                % (spec["spectron_ea"], ", ".join(missing_strings))
            )
        proposed_name = "v18_" + spec["original_name"]
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_size": source["size"],
                "original_instruction_count": source["instruction_count"],
                "original_basic_block_count": source["basic_block_count"],
                "original_strings": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_size": target["size"],
                "spectron_instruction_count": target["instruction_count"],
                "spectron_basic_block_count": target["basic_block_count"],
                "spectron_strings": target.get("string_refs", []),
                "proposed_name": proposed_name,
                "confidence": "high",
                "match_kind": "manual-core-context-anchor",
                "semantic_match_already_present": spectron_ea in semantic_targets,
                "source_basis": spec["source_basis"],
                "evidence": spec["evidence"],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in core anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_core_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for resources, rendering, GUI, scripting, and client support",
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
            "high_confidence_count": sum(row["confidence"] == "high" for row in anchors),
            "already_in_semantic_map": sum(
                row["semantic_match_already_present"] for row in anchors
            ),
            "new_context_anchor_count": sum(
                not row["semantic_match_already_present"] for row in anchors
            ),
            "target_default_name_count": sum(
                row["spectron_default_name"] for row in anchors
            ),
        },
        "anchors": anchors,
        "interpretation": [
            "These are reviewed semantic correspondences, not restored original debug symbols.",
            "The addresses are valid only in the exact hashed Spectron library named in this artifact.",
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated or default 2.2 name in the evidence row.",
            "Static initializer rows identify preserved tables and should not be read as proof that every referenced helper has also been translated.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
