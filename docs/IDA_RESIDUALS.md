# Residual IDA functions

The exported-name translation is complete for the original ARM64
`libqplay.so`: all 8,601 rows in the applied alias inventory were renamed with
no failures. This is not an unstripped debug-symbol count. The APK is reported
as stripped, with no `.symtab` or DWARF sections, and its defined dynamic
symbol table contains 6,506 rows. The larger alias inventory keeps PLT,
jump-thunk, and data aliases explicit. The audit is recorded in
`artifacts/elf_symbol_table_audit_20260826.json`.

IDA also creates functions for code that has no symbol record. Those entries
are a different problem. They can be addressed by their virtual address, but
the APK does not preserve their original source names.

## Final count

The public inventory is an earlier snapshot taken before the disposable IDA
copy was persisted. It contains 11,272 functions and 1,645 default `sub_`
names. After the callback, script-table, and role passes, the base saved copy
at `/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v2.i64`
contained 11,297 functions and 459 default names. A follow-up CyaSSL alias
pass was saved as `/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v3.i64`;
that latest copy contains 11,297 functions and 448 default names.

The count is accounted for exactly:

```text
488 pre-persistence unresolved entries
- 28 applied application or engine role aliases
- 11 applied CyaSSL static role aliases
-  1 compiler branch veneer reclassified as a named thunk
=448 residual default entries
```

The 28 application and engine role aliases are behavior-based names, not
recovered ELF source names. The CyaSSL pass adds seven high-confidence source
role matches and four descriptive aliases for routines whose behavior is
clear but whose exact source name is not preserved. The aliases are recorded
in `artifacts/cyassl_static_role_audit_20260826.json`.
The branch veneer at `0x1f94fc` was reclassified as
`j_TCachedStream_get_minfilecachesize` when IDA rebuilt the saved copy. The
active desktop IDA database remained locked and was not changed.

## CyaSSL role pass

The CyaSSL gap was worth a separate pass because these routines sit directly
on the certificate and TLS paths that matter to the runtime diagnosis. The
IDA decompilation identified the algorithm transforms, certificate-chain
helpers, TLS PRF, record-MAC path, Finished-message calculation, and peer
certificate parser. Seven names match recognizable historical CyaSSL roles;
the other four are intentionally descriptive local aliases.

| Address | Latest IDA alias | Confidence | Role |
| --- | --- | --- | --- |
| `0x2b6384` | `CyaInt_ConfirmSignature` | High | RSA certificate-signature verification |
| `0x2bdc74` | `CyaInt_Md5Transform` | High | MD5 compression transform |
| `0x2c0408` | `CyaInt_ShaTransform` | High | SHA-1 compression transform |
| `0x2c2f1c` | `CyaInt_Sha256Transform` | High | SHA-256 compression transform |
| `0x2c47e0` | `CyaInt_ProcessBuffer` | High | PEM or DER certificate and key buffer loading |
| `0x2c50ac` | `CyaInt_ProcessVerifyPath` | Medium | Verification-store file and directory loading |
| `0x2c6514` | `CyaInt_PRF` | High | TLS pseudo-random function |
| `0x2c84bc` | `CyaInt_TLSRecordMac` | Medium | Legacy TLS record-MAC callback |
| `0x2c8710` | `CyaInt_VerifyRecordMac` | Medium | TLS CBC padding and MAC verification |
| `0x2c8a20` | `CyaInt_ComputeFinishedVerifyData` | Medium | TLS Finished verify-data calculation |
| `0x2ca940` | `CyaInt_ProcessPeerCerts` | High | TLS Certificate-handshake chain parser |

The names are analysis aliases, not a claim that those strings survived in
the APK. The complete evidence, call sites, function sizes, source-role
comparison links, and persisted database hash are in
`artifacts/cyassl_static_role_audit_20260826.json`. The reusable IDA scripts
are `tools/ida_apply_cyassl_static_aliases.py` and
`tools/ida_verify_cyassl_static_aliases.py`.

## Categories

| Category | Count | Interpretation |
| --- | ---: | --- |
| libjpeg static internals | 150 | Unnamed functions inside the bundled JPEG implementation |
| FreeType static internals | 144 | Unnamed functions inside the bundled font implementation |
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
| **Total** | **448** | **All remaining default functions in the latest saved copy** |

The largest groups are recognizable from their position between exported
third-party routines, their call graph, and their strings. That proves a
library family, not a particular upstream source name. Cleanup wrappers are
even more constrained: they compute a fixed global address and tail-call a
known destructor or `TString::clear`, so they have no independent source body
to name.

## Machine-readable record

`artifacts/ida_residual_profile.json` contains every one of the 448 residual
addresses, sizes, current IDA names, segments, and family classifications. It
also records the 28 application role aliases, the 11 CyaSSL aliases, the
reclassified branch veneer, the latest persisted database hash, and the
evidence used for each category. The eleven CyaSSL addresses are therefore
not counted as residual defaults anymore.

The earlier `artifacts/unresolved_function_profile.json` remains in the
archive because it documents the pre-persistence 488-entry queue. The
earlier `symbols/libqplay.function_inventory.json` likewise preserves the
original 11,272-function inventory. Keeping both snapshots avoids silently
rewriting the provenance of the first analysis pass.

Rebuild the final report offline with:

```text
python3 tools/generate_ida_residual_profile.py
```

The generator reads only the public profile, role-candidate artifact, and
CyaSSL role audit. It does not load the native library, execute APK code, or
contact a network.

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
for the 448 residual entries.

## Practical conclusion

There are no remaining application, engine, or CyaSSL certificate and TLS
roles in the residual queue. The 28 application roles and all eleven CyaSSL
roles have evidence-backed aliases in the latest persisted copy. The 448
remaining defaults are compiler-generated lifecycle code, other library
internals, cleanup thunks, or the PLT resolver. Assigning names such as
`jpeg_internal_17` would make the IDA view look fuller but would not be a
translation of a source symbol. They remain explicitly classified and
addressable instead.
