# Residual IDA functions

The symbol pass covers every name that survived in the original ARM64
`libqplay.so`. IDA also creates functions for code that has no symbol record.
Those entries can be addressed by virtual address, but the APK does not retain
their original source names.

## Final count

The original active database started with 11,272 functions and 1,645 default
`sub_` names. The complete reviewed pass added 25 function boundaries and
1,249 names or aliases. The final packed copy at
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_from_active_v8.i64`
contains 11,297 functions and 421 default names. An IDALIB reopen and the
read-only translation verifier both returned zero failures.

The count is accounted for exactly:

```text
488 pre-persistence unresolved entries
- 28 applied application or engine role aliases
- 11 applied CyaSSL static role aliases
- 27 applied static-library role aliases
-  1 compiler branch veneer reclassified as a named thunk
=421 residual default entries
```

The 28 application and engine role aliases are behavior-based names, not
recovered ELF source names. The CyaSSL pass adds seven high-confidence source
role matches and four descriptive aliases for routines whose behavior is
clear but whose exact source name is not preserved. The static-library pass
adds 27 high-confidence source-role aliases across seven bundled libraries.
The supporting records are
`artifacts/cyassl_static_role_audit_20260826.json` and
`artifacts/static_library_role_audit_20260826.json`.

The APK has no full `.symtab` or DWARF record set. The 8,601 translated
aliases include dynamic names, PLT entries, jump thunks, and data aliases.
They are an analysis inventory rather than a claim that all original
debug symbols survived.

## Compact residual audit

The final residual set is recorded in
`artifacts/ida_final_residual_audit_20260830.json`. It contains one compact
record per remaining default `sub_` function, including its address, size,
segment, and incoming xref count. It also records the 11,297-row inventory
hash, the original ARM64 library hash, address buckets, and the most
referenced residual entries. The report contains 421 residual functions and
does not publish another full inventory. When the checked-in residual profile
matches the input addresses, the report also embeds its category counts and
profile hash.

The report was generated from the private translated IDA export with:

```text
python3 tools/generate_final_residual_audit.py \
  /tmp/ida-v4-inventory/libqplay.function_inventory.json
```

The input path is local to the analysis workstation. The report's SHA-256
fields make it possible to verify that a future export describes the same
library and inventory.

The final packed-database verification is recorded separately in
`artifacts/ida_translation_verification_20260830.json`. It includes the
source library hash, the saved IDA copy hash, all pass counts, and the exact
function and residual totals.

The 421 residual entries have also been classified by the persisted IDA
profile:

| Class | Count | Interpretation |
| --- | ---: | --- |
| JPEG static internals | 150 | Unnamed routines inside the bundled JPEG implementation |
| FreeType static internals | 144 | Unnamed routines inside the bundled FreeType implementation |
| TString cleanup wrappers | 97 | Compiler-generated destructors for fixed global strings |
| Init or fini array entries | 19 | Runtime registration or cleanup entry points referenced by ELF arrays |
| TStringList cleanup wrappers | 5 | Compiler-generated destructors for fixed global string lists |
| GPC static internals | 3 | Unnamed routines inside the bundled polygon clipper |
| TGraalVar cleanup wrappers | 2 | Compiler-generated destructors for fixed global script values |
| AArch64 PLT resolver | 1 | The resolver slot at `0xd2170`, not an imported function |

This breakdown accounts for every residual entry. The large JPEG and FreeType
groups are not omitted from the analysis; they are left with address-based
names because their local source names were not retained and a family label
alone is not enough to prove an exact function match.

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
