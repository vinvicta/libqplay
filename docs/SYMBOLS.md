# Symbol translation

## Result

The original ARM64 database was processed with `tools/ida_translate_symbols.py`.
The script reads the symbol names that survived in the ELF, demangles the C++
names where possible, classifies the result, and applies the names back into
IDA. The run was configured with renaming enabled and finished with:

```json
{
  "apply_renames": true,
  "data": 505,
  "functions": 4714,
  "jump_thunks": 199,
  "plt_thunks": 3183,
  "rename_failures": [],
  "renamed": 8601,
  "translated_symbols": 8601
}
```

The full exports are in `symbols/`. The CSV is convenient for grep, a
spreadsheet, or a quick address lookup. The JSON preserves the same records
with explicit fields.

The translation count is the number of ELF symbol records handled by the
script. IDA's function survey also reports compiler-generated functions and
other analysis-created entries, so its total function count is not expected
to equal 8,601. After the follow-up semantic pass, the original ARM64
database reports 11,271 total functions, 9,243 with names, and 2,028 default
`sub_` names. Those figures describe the IDA database; the 8,601 count
describes the reproducible symbol import and rename pass. The 83 semantic labels
are recorded separately in `artifacts/ida_semantic_labels.json`, alongside
the earlier inferred `TClient_setSSLParameters_scriptCallback` label. None of
these semantic labels is part of the 8,601 original ELF symbol records.

## Naming policy

The native names are kept close to their demangled ELF form. Characters that
are inconvenient in an IDA identifier are converted to underscores, while
the original mangled symbol remains in the export. PLT entries receive a
`plt_` prefix and jump thunks receive a `j_` prefix so that a thunk is not
mistaken for the implementation it reaches.

Examples:

| Native role | Applied alias | Address in ARM64 database |
| --- | --- | ---: |
| Connector mode selection | `TServerList_enterNextConnectorMode_int` | `0x203df4` |
| Connector login | `TServerList_login` | `0x204420` |
| Game-server connect | `TClient_connectToGameServer` | `0x1e7058` |
| HTTP request creation | `THTTPRequest_sendRequest` | `0x1ffde8` |
| Incoming packet dispatch | `TClient_parse` | `0x1e7cd0` |
| Encrypted level loader | `TServerLevel_LoadEncrypted_void` | `0x1aa198` |

The exact address and alias for every symbol are in the CSV. These names are
analysis labels, not an assertion that every demangled signature was manually
verified. The important connector and packet functions were checked against
cross-references and emulator traces.

Some important callbacks have no surviving ELF symbol. The IDA database now
labels the game-server SSL method at `0x1eb964` as
`TClient_setSSLParameters_scriptCallback`. The `scriptCallback` suffix marks
it as an inferred semantic name, not part of the original symbol import. Its
method-table reference and native behavior are documented in
`artifacts/game_server_tls.json`.

The same database now has evidence-backed names for the login callback,
server-list completion, file-download, and script-window helpers that IDA
originally displayed as `sub_` functions. Examples include
`TClient_handleServerLoginPacket`, `TClient_finishFileDownload`, and
`TGUIScriptLoader_finishServerListConnect`. These remain separate from the
imported symbol CSV because they are semantic labels, not ELF names. The
complete list and the evidence behind each label are in
`artifacts/ida_semantic_labels.json`.

## Complete function inventory

The symbol table and the IDA function list are different sets. The ELF has
8,601 surviving records, including 505 data records. Of those records, 8,096
land on IDA functions. IDA's analysis adds 11,271 function starts in total:

| Function source | Count |
| --- | ---: |
| Backed by a translated ELF symbol | 8,096 |
| IDA default `sub_` names | 2,028 |
| Named by IDA but not backed by an ELF record | 1,147 |
| Total IDA functions | 11,271 |

The complete address-level inventory is in
`symbols/libqplay.function_inventory.csv` and
`symbols/libqplay.function_inventory.json`. Every row records the IDA name,
address, segment, size, incoming-reference count, thunk and library flags,
and the matching original ELF symbol when one exists. The summary file records
the input hash and counts. This is the honest limit of the available evidence:
the remaining default `sub_` entries are real functions identified by IDA, but
the APK does not contain source names for them. They remain addressable and
searchable without being given guesses that could mislead later protocol work.
The semantic pass names only the small set whose behavior was clear enough to
document.

The inventory was generated from the active ARM64 database by
`tools/export_function_inventory.py`. It waits for auto-analysis, joins each
function start against the translated symbol export, and writes the result in
address order. Running it again against a different library revision should
produce a different input hash and must be kept as a separate export.

## Repeating the pass

Run the IDAPython script from IDA's Python console or with the IDA batch
runner. The input must be the same library revision used to build the IDB.
The script deliberately reports a byte or address mismatch instead of
silently applying names to a different build.

The generated summary should have `rename_failures` equal to an empty list.
If a future library revision produces a different count, keep its exports in
a separate directory and record the build identity in the accompanying
notes. Do not overwrite this table without preserving the old hash.
