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
to equal 8,601. For the original ARM64 database, the current survey reports
11,271 total functions, 9,160 with names, and 2,111 without names. Those
figures describe the IDA database; the 8,601 count describes the reproducible
symbol import and rename pass. The one-entry difference from earlier notes is
the inferred `TClient_setSSLParameters_scriptCallback` label below. It is an
IDA semantic label and is not part of the 8,601 original ELF symbol records.

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

## Repeating the pass

Run the IDAPython script from IDA's Python console or with the IDA batch
runner. The input must be the same library revision used to build the IDB.
The script deliberately reports a byte or address mismatch instead of
silently applying names to a different build.

The generated summary should have `rename_failures` equal to an empty list.
If a future library revision produces a different count, keep its exports in
a separate directory and record the build identity in the accompanying
notes. Do not overwrite this table without preserving the old hash.
