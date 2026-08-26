# Residual IDA functions

The exported-symbol translation is complete for the original ARM64
`libqplay.so`: all 8,601 surviving ELF symbol records were imported and
renamed with no failures. IDA also creates functions for code that has no
symbol record. Those entries are a different problem. They can be addressed
by their virtual address, but the APK does not preserve their original source
names.

## Final count

The public inventory is an earlier snapshot taken before the disposable IDA
copy was persisted. It contains 11,272 functions and 1,645 default `sub_`
names. After the callback, script-table, and role passes, the saved copy at
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v2.i64` contains
11,297 functions and 459 default names.

The count is accounted for exactly:

```text
488 pre-persistence unresolved entries
- 28 applied application or engine role aliases
-  1 compiler branch veneer reclassified as a named thunk
=459 residual default entries
```

The 28 role aliases are behavior-based names, not recovered ELF source names.
The branch veneer at `0x1f94fc` was reclassified as
`j_TCachedStream_get_minfilecachesize` when IDA rebuilt the saved copy. The
active desktop IDA database remained locked and was not changed.

## Categories

| Category | Count | Interpretation |
| --- | ---: | --- |
| libjpeg static internals | 150 | Unnamed functions inside the bundled JPEG implementation |
| FreeType static internals | 144 | Unnamed functions inside the bundled font implementation |
| CyaSSL static internals | 11 | Unnamed certificate, crypto, and TLS helpers |
| zlib static internals | 14 | Unnamed compression and checksum helpers |
| bzip2 static internals | 4 | Unnamed decompression helpers |
| General Polygon Clipper internals | 4 | Unnamed polygon clipping and allocation helpers |
| GIF support internals | 3 | Unnamed GIF decoder helpers |
| YAJL static internals | 2 | Unnamed JSON parser helpers |
| LibTomCrypt DES internal | 1 | Shared DES block transform |
| minizip static internals | 2 | Unnamed archive and central-directory helpers |
| init or fini array entries | 19 | Lifecycle functions referenced by ELF initialization arrays |
| `TString` cleanup wrappers | 97 | Compiler-generated fixed-global cleanup thunks |
| `TStringList` cleanup wrappers | 5 | Compiler-generated fixed-global destructor thunks |
| `TGraalVar` cleanup wrappers | 2 | Compiler-generated fixed-global destructor thunks |
| AArch64 PLT resolver | 1 | The resolver slot, not an imported application function |
| **Total** | **459** | **All remaining default functions in the saved copy** |

The largest groups are recognizable from their position between exported
third-party routines, their call graph, and their strings. That proves a
library family, not a particular upstream source name. Cleanup wrappers are
even more constrained: they compute a fixed global address and tail-call a
known destructor or `TString::clear`, so they have no independent source body
to name.

## Machine-readable record

`artifacts/ida_residual_profile.json` contains every one of the 459 residual
addresses, sizes, current IDA names, segments, and family classifications. It
also records the 28 removed role aliases, the reclassified branch veneer, the
persisted database hash, and the evidence used for each category.

The earlier `artifacts/unresolved_function_profile.json` remains in the
archive because it documents the pre-persistence 488-entry queue. The
earlier `symbols/libqplay.function_inventory.json` likewise preserves the
original 11,272-function inventory. Keeping both snapshots avoids silently
rewriting the provenance of the first analysis pass.

Rebuild the final report offline with:

```text
python3 tools/generate_ida_residual_profile.py
```

The generator reads only the public profile and role-candidate artifacts. It
does not load the native library, execute APK code, or contact a network.

## Cross-ABI check

The original APK also contains `armeabi`, `x86`, and `x86_64` copies of
`libqplay.so`. Their defined dynamic function exports were compared with the
ARM64 export set after grouping ABI-specific mangling differences by
demangled function stem. The other copies did not add an application or engine
source name that is absent from ARM64. The raw differences are 32-bit ABI and
compiler-runtime exports, plus signature spelling differences such as
`va_list` and pointer-width types. Functions such as `TList::qsort`, the
`TString` formatting helpers, the YAJL helpers, and JPEG allocation helpers
already have their ARM64 counterparts named in the main export inventory.

This check provides negative evidence only. The other ABI layouts are
different, so their addresses cannot be copied into the ARM64 IDA database.
It does, however, rule out the simplest path to recovering additional names
for the 459 residual entries.

## Practical conclusion

There are no remaining application or engine entries in the residual queue.
All of those 28 functions have evidence-backed role aliases in the persisted
copy. The 459 remaining defaults are compiler-generated lifecycle code,
library internals, cleanup thunks, or the PLT resolver. Assigning names such as
`jpeg_internal_17` would make the IDA view look fuller but would not be a
translation of a source symbol. They remain explicitly classified and
addressable instead.
