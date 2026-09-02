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
script-table, application-role, CyaSSL, bundled-library, and exact FreeType
source-match passes. The current packed copy was saved as
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_from_active_v11.i64`.
The active IDA verifier reports 11,297 functions, 11,297 named function heads,
274 remaining default `sub_` entries, and zero failures after the expanded
FreeType source-match pass. A separate close and reopen of that exact copy is
still pending.

The 1,396 reviewed names are made up of 277 native callback candidates, 906
exact script-table callbacks, 28 application or engine role aliases, 11
CyaSSL aliases, 30 bundled-library aliases, 3 GPC helper aliases, and 141
exact FreeType 2.3.6 source matches. The
machine-readable record is
`artifacts/ida_translation_verification_20260901.json`.

The remaining 274 default names are not an unfinished application boundary.
The active-IDB scope check found no default name in the Android bridge range,
no default name among the 1,779 unique script callback addresses, and no
direct call from a remaining default function to the selected socket, file,
process, or update imports. The 4 entries in the broader application-core
range are short static-state wrappers around existing library objects. Their
addresses remain available in
`artifacts/ida_active_translation_scope_check_20260901.json` without guessed
source names. The 141 exact FreeType and TrueType matches are listed in
`artifacts/ida_freetype_source_matches_20260901.json`, with the pinned source
tag, commit, source file, and line anchor for each routine.

The last four entries removed from the older residual queue are
`tt_get_cmap_info` at `0x254b98`, `default_bzfree` at `0x273350`,
`default_bzalloc` at `0x273360`, and `handle_compress` at `0x27336c`.
Their callback assignments and source control flow agree with the pinned
FreeType and bzip2 implementations, so they are recorded as source-role
aliases rather than address-only guesses.

The public `symbols/libqplay.function_inventory.json` and
`artifacts/script_table_inventory.json` are synchronized with this final
state. The function inventory has 11,297 rows, and the script-table inventory
has 1,779 unique callback targets. The older overlay and unresolved profile
remain as the pre-persistence inputs used by the residual calculation.

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

## Cross-version comparison

The public analysis currently contains the original 1.8 ARM64 library and the
local diagnostic builds derived from it. A 2.2 APK, `libqplay` library, or IDA
database is not present in the workspace, so this repository does not claim a
1.8-to-2.2 symbol translation or protocol match. The later 2.2 build is
reported to have stripped symbols, which makes a direct name transfer unsafe
even after the binary is supplied.

When a verified 2.2 input becomes available, the first comparison anchors
should be the JNI exports, connector and TLS strings, packet parser constants,
and recognizable bundled-library signatures. Any matches should be recorded
with the 2.2 file hash and an address relative to its load base. Names should
remain address-based until cross-references or a runtime trace establish that
the 1.8 and 2.2 routines have the same behavior.

## Repeating the pass

Run the IDAPython script from IDA's Python console or with the IDA batch
runner. The input must be the same library revision used to build the IDB.
The scripts deliberately report an address or boundary mismatch instead of
silently applying a reviewed alias to a different function.

The generated summary should have `rename_failures` equal to an empty list.
If a future library revision produces a different count, keep its exports in
a separate directory and record the build identity in the accompanying
notes. Do not overwrite this table without preserving the old hash.
