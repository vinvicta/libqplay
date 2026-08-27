#!/usr/bin/env python3
"""Create reviewed anchors for the Gani object and animation lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


GROUP_EVIDENCE = {
    "gani_chat": [
        "Both functions read the Gani object's text-token child from the same field, remove its token list through the class helper, release the child when present, and clear the field.",
        "The target body has the same 64-byte, 16-instruction, five-block shape as the source. The obfuscated helper name is the only naming difference in this direct wrapper correspondence.",
    ],
    "gani_destructor": [
        "Both functions install the Gani object vtable, disable level visibility, remove the object from its owning animation, release object and script-variable lists, clear the ShowImg child and chat state, update the lookup tree, clear the same string fields, and call the level-object base destructor.",
        "The source display name is constructor-shaped, but IDA records the alternative mangled name `_ZN11TGaniObjectD1Ev`, and the pseudocode is a non-deleting destructor. The target has the corresponding D2 body and a separate D0 delete wrapper.",
    ],
    "inherited_accessors": [
        "The source and target are the three inherited level-object accessors in the same class-local slot sequence. They read local x and y from offsets 112 and 120, or store the attached-player pointer at offset 144.",
        "Each target body has the exact source size, instruction count, and block count. The target class is obfuscated, but the returned fields and store offset are unchanged.",
    ],
    "virtual_hooks": [
        "The six source virtual hooks occur immediately after the inherited accessors, and the target preserves that order. The no-op animation, attribute, step, and color hooks remain no-op bodies, while getdir and setdir read or write the same direction field at offset 260.",
        "The source and target bodies have identical metrics for every hook. This is a direct vtable-surface translation, not a name-only inference.",
    ],
    "gani_properties": [
        "The source and target property classes each install two vtable pointers, call the common properties base destructor, and use the same D1, D0, and non-virtual thunk layout.",
        "The target keeps the exact 28-byte or 56-byte body sizes and two-block control flow of the source. The class names are changed, but the paired destructor and thunk ordering is preserved.",
    ],
    "event_dispatch": [
        "Both event wrappers build the same empty event prefix, dispatch through the same virtual slot at offset 128, pass the script event or string argument unchanged, and clear the temporary string before returning.",
        "The three target functions have the same sizes and control-flow metrics as their source counterparts, including the one-instruction forwarding thunk.",
    ],
    "color_destructor": [
        "The source TColorVar pair and target color-variable pair are the same D1 and D0 destructor bodies. Both install the derived vtable, call the common Graal-variable base destructor, and let D0 delete the object.",
        "The two bodies retain exact source metrics, while the target's `_HTugbItBu` name identifies the obfuscated color-variable class.",
    ],
    "flags": [
        "The seven animation flag accessors remain in the same order and read or write the same byte offsets: continuous at 201, loop at 200, movie at 172, and singledirection at 202.",
        "Every target accessor has the exact eight-byte, two-instruction, one-block shape of the corresponding source function. IDA calls the target functions subroutines because the debug names were stripped.",
    ],
    "setback": [
        "Both functions access the setbackto string at object offset 208. The setter assigns the supplied string, and the getter copies the stored string into the hidden return object.",
        "The source and target metrics match exactly. The target's replacement string wrapper changes only the helper name, not the field or return behavior.",
    ],
    "graal_clear": [
        "Both TGraalAni clear methods reset the sprite and step arrays, clear the animation and script state, release the owner and child lists, and restore the same counters and flags.",
        "The source and target preserve the 25-block control-flow structure. The target body is smaller because its rebuilt container wrappers fold several source operations together, but the field order and reset sequence remain visible in pseudocode.",
    ],
    "graal_destructor": [
        "Both entries are the deleting-destructor wrapper for TGraalAni. Each forwards to the class teardown routine and then calls operator delete on the same object pointer.",
        "The source and target are exact 32-byte, eight-instruction, two-block wrappers. The target D0 name confirms the class-local destructor role.",
    ],
    "owner": [
        "The source and target owner helpers operate on the same owner list at object field 15. One calls the list Add method and the other calls Remove with the supplied Gani object.",
        "Both target bodies preserve the two-block wrapper shape and exact eight-byte size of the source functions.",
    ],
    "script_load": [
        "Both functions check the client and script state, derive the coded Gani filename, test the local file, load the encrypted script, build the `gani::` class name, add the class script to the universe, calculate the CRC, and send WantGaniScript when needed.",
        "The target retains the `gani::` literal and the source 14-block structure. Its 520-byte body is larger than the 432-byte source body because the target string and script-universe wrappers use expanded temporaries.",
    ],
    "script_save": [
        "Both functions derive the coded script filename, create the required directories, hash the script text, build the same 16-byte coded stream header, and save the encrypted Gani script.",
        "The target preserves the four-block structure and grows from 228 to 256 bytes through the target string and file wrappers. No network operation is involved in either routine.",
    ],
    "gani_type": [
        "Both methods classify the animation as def or bomy_walk before iterating the same 31 animation names and storing the resulting Gani type.",
        "The target retains both `def` and `bomy_walk` literals and the same 11-block structure. The nine extra instructions are wrapper expansion around the same classification loop.",
    ],
    "graal_constructor": [
        "Both constructors call the Graal-variable base constructor, initialize the same animation state, set the name, calculate the type, allocate the sprite and step lists, create the `sprites` and `steps` child arrays, and finish through clear.",
        "The target retains both `sprites` and `steps` literals and the same class-local position after the owner and filename helpers. Its seven-block body is one block shorter but preserves the initialization sequence directly.",
    ],
    "global_cache": [
        "Both functions clear the process-wide GraalAni cache list through the same global helper and return immediately.",
        "The source and target are exact 20-byte, five-instruction, two-block bodies. The target method name is obfuscated but remains in the same class-local tail.",
    ],
    "load_ani": [
        "Both functions trim and lowercase the requested animation name, look up the cached object, compare download or modification state, allocate and register a new TGraalAni when absent, load the `.gani` resource, request it from the server when necessary, reload the object, load its script, and calculate the visible rectangle.",
        "The target retains the `.gani` literal and the source 21-block structure. Its larger body reflects target wrapper calls and string temporaries, while the cache, download, reload, and visible-rectangle branches remain in the same order.",
    ],
    "static_init": [
        "Both static initializers allocate the same global hash-list or properties object and publish it to the class static state.",
        "The target bodies have the exact source size, instruction count, and block count, which makes these direct static-construction matches.",
    ],
    "graal_properties": [
        "The source and target TGraalAni property classes install two vtable pointers, call the common properties base destructor, and preserve the D1, D0, and non-virtual thunk arrangement.",
        "All four target functions retain the exact 28-byte, 56-byte, or eight-byte thunk metrics of their source counterparts. The target class name is obfuscated as Kc8uganwOuProperties.",
    ],
}


def make_spec(
    original_ea: str,
    original_name: str,
    spectron_ea: str,
    target_name: str,
    proposed_name: str,
    source_metrics: tuple[int, int, int],
    target_metrics: tuple[int, int, int],
    group: str,
    source_basis: str,
    required_string_refs: tuple[str, ...] = (),
) -> dict:
    return {
        "original_ea": original_ea,
        "original_name": original_name,
        "spectron_ea": spectron_ea,
        "target_name": target_name,
        "proposed_name": proposed_name,
        "source_metrics": source_metrics,
        "target_metrics": target_metrics,
        "group": group,
        "source_basis": source_basis,
        "required_string_refs": required_string_refs,
    }


ANCHOR_SPECS = [
    make_spec("0x16526c", "TGaniObject_clearChatWrapped_void", "0x168a5c", "_ZN10ieJzgaIFFy10j1qzgbHlqyEv", "v18_TGaniObject_clearChatWrapped_void", (64, 16, 5), (64, 16, 5), "gani_chat", "Gani text-token child cleanup"),
    make_spec("0x1652ac", "TGaniObject_TGaniObject", "0x168af8", "_ZN10ieJzgaIFFyD2Ev", "v18_TGaniObject_destructor_D1", (564, 141, 34), (592, 148, 38), "gani_destructor", "TGaniObject non-deleting destructor"),
    make_spec("0x1654e0", "TGaniObject_TGaniObject__2", "0x168d48", "_ZN10ieJzgaIFFyD0Ev", "v18_TGaniObject_destructor_D0", (32, 8, 2), (32, 8, 2), "gani_destructor", "TGaniObject deleting destructor wrapper"),
    make_spec("0x1656c0", "TLevelObject_getlocalx_void", "0x168ecc", "_ZNK10FY2VgaG6rR10Qi2VgaCyrREv", "v18_TLevelObject_getlocalx_void", (8, 2, 1), (8, 2, 1), "inherited_accessors", "inherited local-x accessor"),
    make_spec("0x1656c8", "TLevelObject_getlocaly_void", "0x168ed4", "_ZNK10FY2VgaG6rR10qCgWga1ADREv", "v18_TLevelObject_getlocaly_void", (8, 2, 1), (8, 2, 1), "inherited_accessors", "inherited local-y accessor"),
    make_spec("0x1656d0", "TLevelObject_setAttachedTo_TServerPlayer", "0x168edc", "_ZN10FY2VgaG6rR10QL5FfaVs1NEP10MpGzgariDy", "v18_TLevelObject_setAttachedTo_TServerPlayer", (8, 2, 1), (8, 2, 1), "inherited_accessors", "inherited attached-player setter"),
    make_spec("0x1656d8", "TGaniObject_onNewAnimation_void", "0x168ee4", "_ZN10ieJzgaIFFy10SCanwany6QEv", "v18_TGaniObject_onNewAnimation_void", (4, 1, 1), (4, 1, 1), "virtual_hooks", "Gani new-animation virtual hook"),
    make_spec("0x1656dc", "TGaniObject_onGaniAttributeChanged_int", "0x168ee8", "_ZN10ieJzgaIFFy10eGQmwacWPQEi", "v18_TGaniObject_onGaniAttributeChanged_int", (4, 1, 1), (4, 1, 1), "virtual_hooks", "Gani attribute-change virtual hook"),
    make_spec("0x1656e0", "TGaniObject_onGaniStepChanged_void", "0x168eec", "_ZN10ieJzgaIFFy10QVSqwakPdUEv", "v18_TGaniObject_onGaniStepChanged_void", (4, 1, 1), (4, 1, 1), "virtual_hooks", "Gani step-change virtual hook"),
    make_spec("0x1656e4", "TGaniObject_getdir_void", "0x168ef0", "_ZN10ieJzgaIFFy10JX6VLaUsvWEv", "v18_TGaniObject_getdir_void", (8, 2, 1), (8, 2, 1), "virtual_hooks", "Gani direction getter"),
    make_spec("0x1656ec", "TGaniObject_setdir_int", "0x168ef8", "_ZN10ieJzgaIFFy10sgdTJasM3cEi", "v18_TGaniObject_setdir_int", (8, 2, 1), (8, 2, 1), "virtual_hooks", "Gani direction setter"),
    make_spec("0x1656f4", "TGaniObject_onUpdateColors_void", "0x168f00", "_ZN10ieJzgaIFFy10rGmrwapHDUEv", "v18_TGaniObject_onUpdateColors_void", (4, 1, 1), (4, 1, 1), "virtual_hooks", "Gani color-update virtual hook"),
    make_spec("0x1656f8", "TGaniParamProperties_TGaniParamProperties", "0x168f04", "_ZN20J0CfgbmrLhPropertiesD1Ev", "v18_TGaniParamProperties_destructor_D1", (28, 7, 2), (28, 7, 2), "gani_properties", "TGaniParamProperties non-deleting destructor"),
    make_spec("0x165714", "non_virtual_thunk_to_TGaniParamProperties_TGaniParamProperties", "0x168f20", "_ZThn16_N20J0CfgbmrLhPropertiesD1Ev", "v18_TGaniParamProperties_destructor_D1_thunk", (8, 2, 2), (8, 2, 2), "gani_properties", "TGaniParamProperties D1 non-virtual thunk"),
    make_spec("0x16571c", "TGaniObjectProperties_TGaniObjectProperties", "0x168f28", "_ZN20ieJzgaIFFyPropertiesD2Ev", "v18_TGaniObjectProperties_destructor_D1", (28, 7, 2), (28, 7, 2), "gani_properties", "TGaniObjectProperties non-deleting destructor"),
    make_spec("0x165738", "non_virtual_thunk_to_TGaniObjectProperties_TGaniObjectProperties", "0x168f44", "_ZThn16_N20ieJzgaIFFyPropertiesD1Ev", "v18_TGaniObjectProperties_destructor_D1_thunk", (8, 2, 2), (8, 2, 2), "gani_properties", "TGaniObjectProperties D1 non-virtual thunk"),
    make_spec("0x165740", "TGaniParamProperties_TGaniParamProperties__2", "0x168f4c", "_ZN20J0CfgbmrLhPropertiesD0Ev", "v18_TGaniParamProperties_destructor_D0", (56, 14, 2), (56, 14, 2), "gani_properties", "TGaniParamProperties deleting destructor"),
    make_spec("0x165778", "non_virtual_thunk_to_TGaniParamProperties_TGaniParamProperties__2", "0x168f84", "_ZThn16_N20J0CfgbmrLhPropertiesD0Ev", "v18_TGaniParamProperties_destructor_D0_thunk", (8, 2, 2), (8, 2, 2), "gani_properties", "TGaniParamProperties D0 non-virtual thunk"),
    make_spec("0x165780", "TGaniObjectProperties_TGaniObjectProperties__2", "0x168f8c", "_ZN20ieJzgaIFFyPropertiesD0Ev", "v18_TGaniObjectProperties_destructor_D0", (56, 14, 2), (56, 14, 2), "gani_properties", "TGaniObjectProperties deleting destructor"),
    make_spec("0x1657b8", "non_virtual_thunk_to_TGaniObjectProperties_TGaniObjectProperties__2", "0x168fc4", "_ZThn16_N20ieJzgaIFFyPropertiesD0Ev", "v18_TGaniObjectProperties_destructor_D0_thunk", (8, 2, 2), (8, 2, 2), "gani_properties", "TGaniObjectProperties D0 non-virtual thunk"),
    make_spec("0x1657c0", "TGaniObject_receiveEvent_script_event", "0x168fcc", "_ZN10ieJzgaIFFy10rVjVga1mQQE10RiQ7IaxCcA", "v18_TGaniObject_receiveEvent_script_event", (100, 24, 1), (100, 24, 1), "event_dispatch", "Gani script-event forwarding wrapper"),
    make_spec("0x165824", "TColorVar_TColorVar", "0x169030", "_ZN10_HTugbItBuD1Ev", "v18_TColorVar_destructor_D1", (20, 5, 2), (20, 5, 2), "color_destructor", "TColorVar non-deleting destructor"),
    make_spec("0x165838", "TColorVar_TColorVar__2", "0x169044", "_ZN10_HTugbItBuD0Ev", "v18_TColorVar_destructor_D0", (48, 12, 2), (48, 12, 2), "color_destructor", "TColorVar deleting destructor"),
    make_spec("0x165868", "TGaniObject_receiveEvent_TString_const_TString_const_TGraalVar", "0x169074", "_ZN10ieJzgaIFFy10rVjVga1mQQERK10C8THgaTQxFS2_P10G0gxgajWBw", "v18_TGaniObject_receiveEvent_TString_const_TString_const_TGraalVar_thunk", (4, 1, 2), (4, 1, 2), "event_dispatch", "Gani event base forwarding thunk"),
    make_spec("0x16586c", "TGaniObject_receiveEvent_TString_const", "0x169078", "_ZN10ieJzgaIFFy10rVjVga1mQQERK10C8THgaTQxF", "v18_TGaniObject_receiveEvent_TString_const", (88, 22, 1), (88, 22, 1), "event_dispatch", "Gani string-event forwarding wrapper"),
    make_spec("0x1658c4", "TGraalAni_get_continuous", "0x1690d0", "sub_1690D0", "v18_TGraalAni_get_continuous", (8, 2, 1), (8, 2, 1), "flags", "TGraalAni continuous flag getter"),
    make_spec("0x1658cc", "TGraalAni_set_continuous", "0x1690d8", "sub_1690D8", "v18_TGraalAni_set_continuous", (8, 2, 1), (8, 2, 1), "flags", "TGraalAni continuous flag setter"),
    make_spec("0x1658d4", "TGraalAni_get_loop", "0x1690e0", "sub_1690E0", "v18_TGraalAni_get_loop", (8, 2, 1), (8, 2, 1), "flags", "TGraalAni loop flag getter"),
    make_spec("0x1658dc", "TGraalAni_set_loop", "0x1690e8", "sub_1690E8", "v18_TGraalAni_set_loop", (8, 2, 1), (8, 2, 1), "flags", "TGraalAni loop flag setter"),
    make_spec("0x1658e4", "TGraalAni_get_movie", "0x1690f0", "sub_1690F0", "v18_TGraalAni_get_movie", (8, 2, 1), (8, 2, 1), "flags", "TGraalAni movie flag getter"),
    make_spec("0x1658ec", "TGraalAni_set_movie", "0x1690f8", "sub_1690F8", "v18_TGraalAni_set_movie", (8, 2, 1), (8, 2, 1), "flags", "TGraalAni movie flag setter"),
    make_spec("0x1658f4", "TGraalAni_get_singledirection", "0x169100", "sub_169100", "v18_TGraalAni_get_singledirection", (8, 2, 1), (8, 2, 1), "flags", "TGraalAni singledirection flag getter"),
    make_spec("0x165954", "TGraalAni_set_setbackto", "0x169160", "sub_169160", "v18_TGraalAni_set_setbackto", (8, 2, 2), (8, 2, 2), "setback", "TGraalAni setbackto string setter"),
    make_spec("0x16595c", "TGraalAni_get_setbackto", "0x169168", "sub_169168", "v18_TGraalAni_get_setbackto", (48, 12, 1), (48, 12, 1), "setback", "TGraalAni setbackto string getter"),
    make_spec("0x165a8c", "TGraalAni_clear_void", "0x1692bc", "_ZN10Kc8uganwOu5clearEv", "v18_TGraalAni_clear_void", (552, 138, 25), (428, 107, 25), "graal_clear", "TGraalAni state reset and child-list cleanup"),
    make_spec("0x165db8", "TGraalAni_TGraalAni__2", "0x16956c", "_ZN10Kc8uganwOuD0Ev", "v18_TGraalAni_destructor_D0", (32, 8, 2), (32, 8, 2), "graal_destructor", "TGraalAni deleting destructor wrapper"),
    make_spec("0x1660f4", "TGraalAni_addOwner_TGaniObject", "0x1698a8", "_ZN10Kc8uganwOu10OZLUDaFZmbEP10ieJzgaIFFy", "v18_TGraalAni_addOwner_TGaniObject", (8, 2, 2), (8, 2, 2), "owner", "TGraalAni owner-list insertion"),
    make_spec("0x1660fc", "TGraalAni_removeOwner_TGaniObject", "0x1698b0", "_ZN10Kc8uganwOu10gyhUDavnYaEP10ieJzgaIFFy", "v18_TGraalAni_removeOwner_TGaniObject", (8, 2, 2), (8, 2, 2), "owner", "TGraalAni owner-list removal"),
    make_spec("0x1661b0", "TGraalAni_loadScriptEncrypted_void", "0x169964", "_ZN10Kc8uganwOu10pH_0fadms5Ev", "v18_TGraalAni_loadScriptEncrypted_void", (432, 107, 14), (520, 129, 14), "script_load", "TGraalAni encrypted script loading", ("gani::",)),
    make_spec("0x166360", "TGraalAni_saveScriptEncrypted_TString_const", "0x169b6c", "_ZN10Kc8uganwOu10NiGdgazc7fERK10C8THgaTQxF", "v18_TGraalAni_saveScriptEncrypted_TString_const", (228, 57, 4), (256, 64, 4), "script_save", "TGraalAni encrypted script saving"),
    make_spec("0x166444", "TGraalAni_calcGaniType_void", "0x169c6c", "_ZN10Kc8uganwOu10iG5UDaaoEbEv", "v18_TGraalAni_calcGaniType_void", (248, 60, 11), (280, 69, 11), "gani_type", "TGraalAni type classification", ("bomy_walk", "def")),
    make_spec("0x16653c", "TGraalAni_TGraalAni_TString_const", "0x169d84", "_ZN10Kc8uganwOuC2ERK10C8THgaTQxF", "v18_TGraalAni_TGraalAni_TString_const", (648, 159, 8), (756, 186, 7), "graal_constructor", "TGraalAni name constructor", ("sprites", "steps")),
    make_spec("0x166860", "TGraalAni_removeGraalAnis_void", "0x16a114", "_ZN10Kc8uganwOu10N2CgLa0sBnEv", "v18_TGraalAni_removeGraalAnis_void", (20, 5, 2), (20, 5, 2), "global_cache", "TGraalAni global-cache cleanup"),
    make_spec("0x1668a8", "TGraalAni_loadAni_TString_const_bool", "0x16a15c", "_ZN10Kc8uganwOu10HuavgazrQuERK10C8THgaTQxFb", "v18_TGraalAni_loadAni_TString_const_bool", (596, 149, 21), (724, 181, 21), "load_ani", "TGraalAni cache and resource loading", (".gani",)),
    make_spec("0x166cbc", "TGraalAni_initStaticVars_void", "0x16a5f0", "_Z10Q8WTDa6mGav", "v18_TGraalAni_initStaticVars_void", (48, 12, 1), (48, 12, 1), "static_init", "TGraalAni static hash-list initialization"),
    make_spec("0x166cec", "TGraalAni_initStaticScriptVars_void", "0x16a620", "_Z10sb6TDalPOav", "v18_TGraalAni_initStaticScriptVars_void", (68, 16, 2), (68, 16, 2), "static_init", "TGraalAni static property initialization"),
    make_spec("0x166d30", "TGraalAniProperties_TGraalAniProperties", "0x16a664", "_ZN20Kc8uganwOuPropertiesD1Ev", "v18_TGraalAniProperties_destructor_D1", (28, 7, 2), (28, 7, 2), "graal_properties", "TGraalAniProperties non-deleting destructor"),
    make_spec("0x166d4c", "non_virtual_thunk_to_TGraalAniProperties_TGraalAniProperties", "0x16a680", "_ZThn16_N20Kc8uganwOuPropertiesD1Ev", "v18_TGraalAniProperties_destructor_D1_thunk", (8, 2, 2), (8, 2, 2), "graal_properties", "TGraalAniProperties D1 non-virtual thunk"),
    make_spec("0x166d54", "TGraalAniProperties_TGraalAniProperties__2", "0x16a688", "_ZN20Kc8uganwOuPropertiesD0Ev", "v18_TGraalAniProperties_destructor_D0", (56, 14, 2), (56, 14, 2), "graal_properties", "TGraalAniProperties deleting destructor"),
    make_spec("0x166d8c", "non_virtual_thunk_to_TGraalAniProperties_TGraalAniProperties__2", "0x16a6c0", "_ZThn16_N20Kc8uganwOuPropertiesD0Ev", "v18_TGraalAniProperties_destructor_D0_thunk", (8, 2, 2), (8, 2, 2), "graal_properties", "TGraalAniProperties D0 non-virtual thunk"),
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
    return {
        field: function.get(field)
        for field in (
            "size",
            "instruction_count",
            "basic_block_count",
            "mnemonic_hash",
            "register_shape_hash",
            "shape_hash",
        )
    }


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
        if target.get("name") != spec["target_name"]:
            raise ValueError(
                "target name mismatch at %s: %s"
                % (spec["spectron_ea"], target.get("name"))
            )
        for side, function in (("source", source), ("target", target)):
            expected = spec["%s_metrics" % side]
            actual = (
                function.get("size"),
                function.get("instruction_count"),
                function.get("basic_block_count"),
            )
            if actual != expected:
                raise ValueError(
                    "unexpected %s metrics at %s: %s"
                    % (side, spec["%s_ea" % side], actual)
                )
        for literal in spec["required_string_refs"]:
            if literal not in source.get("string_refs", []):
                raise ValueError(
                    "source %s lacks required string reference %s"
                    % (spec["original_ea"], literal)
                )
            if literal not in target.get("string_refs", []):
                raise ValueError(
                    "target %s lacks required string reference %s"
                    % (spec["spectron_ea"], literal)
                )
        if spectron_ea in semantic_targets:
            raise ValueError(
                "target %s is already present in the semantic map" % spec["spectron_ea"]
            )
        anchors.append(
            {
                "original_ea": spec["original_ea"],
                "original_name": spec["original_name"],
                "original_metrics": metrics(source),
                "original_string_refs": source.get("string_refs", []),
                "spectron_ea": spec["spectron_ea"],
                "spectron_current_name": target["name"],
                "spectron_default_name": target.get("is_default_name", False),
                "spectron_metrics": metrics(target),
                "spectron_string_refs": target.get("string_refs", []),
                "proposed_name": spec["proposed_name"],
                "confidence": "high",
                "match_kind": "manual-gani-lifecycle-context-anchor",
                "semantic_match_already_present": False,
                "source_basis": spec["source_basis"],
                "evidence": GROUP_EVIDENCE[spec["group"]],
                "name_action": "rename-with-v18-prefix",
            }
        )

    if len({row["spectron_ea"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate Spectron target in Gani lifecycle anchor set")
    if len({row["proposed_name"] for row in anchors}) != len(anchors):
        raise ValueError("duplicate proposed name in Gani lifecycle anchor set")

    result = {
        "schema_version": 1,
        "artifact": "spectron_gani_lifecycle_manual_translation_anchors_20260826",
        "scope": "reviewed 1.8-to-Spectron ARM64 anchors for Gani object teardown, virtual surface, animation state, ownership, script caching, loading, and properties",
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
            "The proposed v18_ labels preserve the readable 1.8 role while keeping the obfuscated 2.2 name in the evidence row.",
            "Several source entries use constructor-shaped IDA display names for D1 destructors. The artifact names those functions as destructors because the alternative mangled names and pseudocode establish that role.",
            "The correspondence is supported by direct Hex-Rays pseudocode, exact field offsets, destructor pairing, virtual dispatch slots, class-local order, and preserved literals where applicable.",
            "Changed byte sizes, instruction counts, and block counts are recorded as version differences. No exact byte identity is claimed.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
