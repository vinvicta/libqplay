# Residual IDA functions

The symbol pass covers every name that survived in the original ARM64
`libqplay.so`. IDA also creates functions for code that has no symbol record.
Those entries can be addressed by virtual address, but the APK does not retain
their original source names.

## Final count

The original active database started with 11,272 functions and 1,645 default
`sub_` names. The complete reviewed pass added 25 function boundaries and
1,551 names or aliases. One false boundary was then removed from a literal
pool between two JPEG DCT routines. The current packed copy at
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_from_active_v12.i64`
contains 11,296 functions and 124 default names. The active IDA verifier
returned zero failures after the expanded embedded-library source-role pass.
A separate reopen of this current copy is still pending.

The count is accounted for exactly:

```text
488 pre-persistence unresolved entries
- 28 applied application or engine role aliases
- 41 applied CyaSSL and bundled-library role aliases
-145 reclassified entries, including 141 FreeType matches, three GPC helpers,
   and one compiler branch veneer
-149 source matches intersecting the old residual profile
-  1 false function boundary removed from a literal pool
=124 residual default entries
```

The 28 application and engine role aliases are behavior-based names, not
recovered ELF source names. The CyaSSL pass adds seven high-confidence source
role matches and four descriptive aliases for routines whose behavior is
clear but whose exact source name is not preserved. The static-library pass
adds 30 high-confidence source-role aliases across seven bundled libraries.
The supporting records are
`artifacts/cyassl_static_role_audit_20260826.json`,
`artifacts/static_library_role_audit_20260826.json`, and
`artifacts/static_library_role_audit_20260901.json`.

The three former GPC residuals were reviewed separately because they were not
covered by the bundled-library alias artifact. `0xe01a0` is the tristrip
allocation-failure abort, `0x152200` is the scanbeam-tree cleanup helper, and
`0x152898` flattens the scanbeam tree into the sorted scanbeam array. Their
roles match the corresponding private helpers in the
[upstream GPC source](https://raw.githubusercontent.com/rickbrew/GeneralPolygonClipper/main/gpc.c).

The source comparison now matches 141 functions to the tagged FreeType 2.3.6
tree. The set covers the SFNT face and table loaders, the smooth rasterizer,
the TrueType interpreter and glyph loader, and the Latin, Latin2, CJK, and
dummy autofit classes. The exact address, size, xref count, source file, line
anchor, and evidence are in
`artifacts/ida_freetype_source_matches_20260901.json`.

The former coarse JPEG bucket is now resolved. One hundred fifty-three IJG
libjpeg 6b source matches were checked, with 147 intersecting the old
residual profile and six no-op callbacks already outside it. The corrected
marker-reader mappings include `examine_app14` at `0xe0454`,
`skip_variable` at `0x28d2ec`, and `next_marker` at `0x28db3c`. The zlib
`inflate_fast` role at `0x28a2f4` and the static giflib
`DGifDecompressLine` role at `0x2acb20` were separated from the old JPEG
address bucket. Their evidence is recorded in
`artifacts/ida_libjpeg_source_matches_20260902.json`,
`artifacts/ida_zlib_source_matches_20260902.json`, and
`artifacts/ida_giflib_source_matches_20260902.json`.

The checked-in function inventory and script-table inventory were regenerated
from the current saved IDA state. They now report 11,296 functions and 1,779
unique script callback addresses, with no default `sub_` name in the callback
set. The overlay and unresolved-function profile retain the earlier
pre-persistence snapshot because the residual calculation uses that snapshot
as its input. Their 11,272-function and 1,645-default-name counts are
historical inputs, not a description of the final database.

The APK has no full `.symtab` or DWARF record set. The 8,601 translated
aliases include dynamic names, PLT entries, jump thunks, and data aliases.
They are an analysis inventory rather than a claim that all original
debug symbols survived.

## Compact residual audit

The current residual set is recorded in
`artifacts/ida_final_residual_audit_20260902.json`. It contains one compact
record per remaining default `sub_` function, including its address, size,
segment, and incoming xref count. It also records the 11,296-row inventory
hash, the original ARM64 library hash, address buckets, and the most
referenced residual entries. The report contains 124 residual functions and
does not publish another full inventory. When the checked-in residual profile
matches the input addresses, the report also embeds its category counts and
profile hash.

The report was generated from the private translated IDA export with:

```text
python3 tools/generate_final_residual_audit.py \
  /home/v/Desktop/graal-decomp/analysis/libqplay.function_inventory.json
```

The input path is local to the analysis workstation. The report's SHA-256
fields make it possible to verify that a future export describes the same
library and inventory.

The final packed-database verification is recorded separately in
`artifacts/ida_translation_verification_20260902.json`. It includes the
source library hash, the saved IDA copy hash, all pass counts, and the exact
function and residual totals.

The 124 residual entries have also been classified by the persisted IDA
profile:

| Class | Count | Interpretation |
| --- | ---: | --- |
| TString cleanup wrappers | 97 | Compiler-generated destructors for fixed global strings |
| Init or fini array entries | 19 | Runtime registration or cleanup entry points referenced by ELF arrays |
| TStringList cleanup wrappers | 5 | Compiler-generated destructors for fixed global string lists |
| TGraalVar cleanup wrappers | 2 | Compiler-generated destructors for fixed global script values |
| AArch64 PLT resolver | 1 | The resolver slot at `0xd2170`, not an imported function |

This breakdown accounts for every residual entry. The former 150-entry JPEG
address bucket no longer appears because its 147 real residual functions have
source-role matches, two other entries were the zlib and GIF helpers, and one
entry was a false function boundary over literal data. The remaining queue is
therefore dominated by cleanup and runtime registration wrappers, where a
family label alone is not enough to prove an exact source function.

## How to work the remaining queue

Keep unresolved functions tied to their address and record the evidence used
to classify them. A library family, call pattern, string reference, or vtable
slot can justify a cautious descriptive label. It is not enough to turn a
nearby function into a guessed source symbol.

The public machine-readable inventory is
`symbols/libqplay.function_inventory.json`, and the symbol export is
`symbols/libqplay.symbols.json`. The compact summaries make it possible to
check counts without loading the full records. The IDA scripts in `tools/`
apply names only after checking the input library hash.

The current residual queue is therefore useful rather than a defect. It
separates confirmed names from hypotheses and leaves the original bytes
unchanged for future re-analysis.
