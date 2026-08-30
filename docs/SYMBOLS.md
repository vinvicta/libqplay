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

## Persisted IDA result

The active ARM64 database was then processed by the reviewed callback,
script-table, application-role, CyaSSL, and bundled-library passes. The final
packed copy was saved as
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_from_active_v8.i64`.
An IDALIB reopen verified 11,297 functions, 11,297 named function heads, 421
remaining default `sub_` entries, and 1,249 reviewed names at their expected
addresses. The verification had zero failures.

The 1,249 reviewed names are made up of 277 native callback candidates, 906
exact script-table callbacks, 28 application or engine role aliases, 11
CyaSSL aliases, and 27 bundled-library aliases. The machine-readable record is
`artifacts/ida_translation_verification_20260830.json`.

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

## Repeating the pass

Run the IDAPython script from IDA's Python console or with the IDA batch
runner. The input must be the same library revision used to build the IDB.
The scripts deliberately report an address or boundary mismatch instead of
silently applying a reviewed alias to a different function.

The generated summary should have `rename_failures` equal to an empty list.
If a future library revision produces a different count, keep its exports in
a separate directory and record the build identity in the accompanying
notes. Do not overwrite this table without preserving the old hash.
