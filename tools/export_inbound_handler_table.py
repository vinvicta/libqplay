"""Export the native handler-index table from the active IDA database.

The table is not the wire packet table. The script records the internal
handler index selected by the serialized setInDataHandlers data and the
function pointer currently stored for that index. The output is written to
the private analysis directory first so it can be reviewed before it is
copied into the public archive.
"""

import json
import os

import ida_auto
import ida_bytes
import ida_idaapi
import ida_name
import ida_nalt


OUTPUT_PATH = "/home/v/Desktop/graal-decomp/analysis/inbound_handler_table.json"
TABLE_NAME = "off_369960"
TABLE_EA = 0x369960
ENTRY_STRIDE = 8
MAX_ENTRIES = 96
OBSERVED_PACKET_TO_HANDLER = {
    7: 31,
    9: 1,
    48: 8,
    49: 32,
    54: 10,
    68: 21,
    69: 23,
    84: 22,
    102: 24,
    178: 0,
    182: 15,
    190: 14,
}


def input_sha256():
    for name in ("retrieve_input_file_sha256", "get_input_file_sha256"):
        getter = getattr(ida_nalt, name, None)
        if getter is None:
            continue
        try:
            value = getter()
        except Exception:
            continue
        if isinstance(value, bytes):
            return value.hex()
        if value:
            return str(value)
    return None


ida_auto.auto_wait()
named_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, TABLE_NAME)
if named_ea != ida_idaapi.BADADDR:
    TABLE_EA = named_ea

entries = []
for index in range(MAX_ENTRIES):
    target = ida_bytes.get_qword(TABLE_EA + index * ENTRY_STRIDE)
    if not target:
        continue
    entries.append(
        {
            "handler_index": index,
            "va": hex(target),
            "name": ida_name.get_name(target),
        }
    )

artifact = {
    "binary": {
        "architecture": "arm64-v8a",
        "libqplay_sha256": input_sha256(),
        "idb": ida_nalt.get_input_file_path(),
    },
    "purpose": "Snapshot of the native handler-index table used by TClient packet dispatch.",
    "table_va": hex(TABLE_EA),
    "table_entry_stride": ENTRY_STRIDE,
    "table_entry_count": len(entries),
    "index_scope": "The handler index is the internal index selected by the serialized setInDataHandlers data. It is not the wire packet number.",
    "loader": {
        "va": "0x1ea6fc",
        "name": "TClient_setInDataHandlersFromArray",
        "action": "Reads pairs from a serialized array, stores the function pointer for each handler index, and handles the special setEncryptionIn, raw-length, and ping entries.",
    },
    "clear_function": {
        "va": "0x1eb91c",
        "name": "TClient_clearInDataHandlers",
        "action": "Clears the 256-entry inbound handler array.",
    },
    "observed_packet_to_handler_index": {
        str(packet): index
        for packet, index in sorted(OBSERVED_PACKET_TO_HANDLER.items())
    },
    "entries": entries,
    "network_contacted": False,
}

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
with open(OUTPUT_PATH, "w", encoding="utf-8") as handle:
    json.dump(artifact, handle, ensure_ascii=False, indent=2, sort_keys=True)
    handle.write("\n")

print(json.dumps({"path": OUTPUT_PATH, "table_va": hex(TABLE_EA), "entries": len(entries)}))
