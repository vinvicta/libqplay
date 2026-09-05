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
script-table, application-role, CyaSSL, bundled-library, and exact embedded
source-role passes. The latest packed copy was saved as
`<workspace>/analysis/libqplay_translated_from_active_v16.i64` after the
connector comments were added.
The active IDA verifier reports 11,296 functions, 11,296 named function heads,
zero remaining default `sub_` entries, and zero failures after the expanded
source-role pass. The 124 residual functions carry stable descriptive labels;
the completed machine-readable verifier result describes the earlier v14 copy.
The v16 copy has not been independently closed and reopened because the IDA
bridge is not currently available. Its private hash and status are recorded in
`artifacts/ida_active_copy_status_20260904.json`.

The 1,551 reviewed aliases are made up of 277 native callback candidates, 906
exact script-table callbacks, 28 application or engine role aliases, 11
CyaSSL aliases, 30 bundled-library aliases, 3 GPC helper aliases, 141 exact
FreeType 2.3.6 source matches, 153 exact IJG libjpeg 6b matches, one exact
zlib 1.2.5 match, and one exact giflib role match. The
machine-readable record is
`artifacts/ida_translation_verification_20260902.json`.

The remaining 124 functions are not an unfinished application boundary. They
are IDA-created code without preserved source names, now labeled with their
evidence-backed role and address. The active-IDB scope check found no default
name or residual label in the Android bridge range, no residual label among
the 1,779 unique script callback addresses, and no direct call from a
residual function to the selected socket, file, process, or update imports.
The 23 entries in the broader application-core range are short static-state or
cleanup wrappers around existing library objects. Their labels are recorded in
`artifacts/ida_descriptive_residual_labels_20260902.json`, and the scope
check is in `artifacts/ida_active_translation_scope_check_20260902.json`. The
141 exact FreeType and TrueType matches are listed in
`artifacts/ida_freetype_source_matches_20260901.json`, with the pinned source
tag, commit, source file, and line anchor for each routine. The current IJG,
zlib, and giflib role records are in
`artifacts/ida_libjpeg_source_matches_20260902.json`,
`artifacts/ida_zlib_source_matches_20260902.json`, and
`artifacts/ida_giflib_source_matches_20260902.json`.

The last four entries removed from the older residual queue are
`tt_get_cmap_info` at `0x254b98`, `default_bzfree` at `0x273350`,
`default_bzalloc` at `0x273360`, and `handle_compress` at `0x27336c`.
Their callback assignments and source control flow agree with the pinned
FreeType and bzip2 implementations, so they are recorded as source-role
aliases rather than address-only guesses.

The public `symbols/libqplay.function_inventory.json` and
`artifacts/script_table_inventory.json` are synchronized with this final
state. The function inventory has 11,296 rows, and the script-table inventory
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

The earlier unverified package comparison was removed from the public
research record. The retained symbol and behavior claims in this document are
for the original 1.8 ARM64 library and its four packaged ABI variants. A
future cross-version pass needs a verified input, a new hash record, and a
separate review of names, callers, data references, and runtime behavior.

## Repeating the pass

Run the IDAPython script from IDA's Python console or with the IDA batch
runner. The input must be the same library revision used to build the IDB.
The scripts deliberately report an address or boundary mismatch instead of
silently applying a reviewed alias to a different function.

The generated summary should have `rename_failures` equal to an empty list.
If a future library revision produces a different count, keep its exports in
a separate directory and record the build identity in the accompanying
notes. Do not overwrite this table without preserving the old hash.

## ABI parity check

The four native variants in the original APK were compared by
`tools/generate_cross_abi_compatibility_review.py`. The report is
`artifacts/cross_abi_compatibility_review_20260902.json`. All four contain the
same connector and CyaSSL marker counts, the same 12,820-byte embedded trust
text hash, and the same five `DT_NEEDED` libraries, including
`libstdc++.so`. The ARM64 build has `0x10000` `LOAD` alignment; the armeabi,
x86, and x86_64 builds use `0x1000`.

The defined dynamic symbol sets are similar but not identical. The x86_64
variant shares 6,486 defined names with ARM64, while armeabi shares 6,349 and
x86 shares 6,346. ABI-specific mangling, compiler output, and data layout make
address transfer unsafe. The shared trust hash and marker set do, however,
make the stale connector chain a cross-build compatibility lead rather than an
ARM64-only hypothesis. No ABI was executed by this comparison.

The same report includes 34 exact shared address anchors for `QPlayMain`,
`QPlayLoop`, connector selection, HTTP completion, socket setup, NewGraal
framing, game connection, and selected CyaSSL calls. These addresses are
useful when comparing the four 1.8 builds, but they must not be copied into a
different release without a new match and a new file hash.
