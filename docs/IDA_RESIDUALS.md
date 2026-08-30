# Residual IDA functions

The symbol pass covers every name that survived in the original ARM64
`libqplay.so`. IDA also creates functions for code that has no symbol record.
Those entries can be addressed by virtual address, but the APK does not retain
their original source names.

## Final count

The public inventory is an earlier snapshot taken before the disposable IDA
copy was persisted. It contains 11,272 functions and 1,645 default `sub_`
names. After the callback, script-table, and role passes, the saved copy at
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v2.i64`
contained 11,297 functions and 459 default names. A follow-up CyaSSL alias
pass was saved as
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v3.i64`
with 448 default names. The static-library pass was saved as
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v4.i64`
and contains 11,297 functions and 421 default names.

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
