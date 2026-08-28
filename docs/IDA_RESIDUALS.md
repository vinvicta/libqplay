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
pass was saved as `/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v3.i64`
with 448 default names. The next static-library pass was saved as
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v4.i64` and
contains 11,297 functions and 421 default names.

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
clear but whose exact source name is not preserved. The next pass adds 27
high-confidence source-role aliases across seven bundled libraries. The two
audit records are `artifacts/cyassl_static_role_audit_20260826.json` and
`artifacts/static_library_role_audit_20260826.json`.
The branch veneer at `0x1f94fc` was reclassified as
`j_TCachedStream_get_minfilecachesize` when IDA rebuilt the saved copy. The
active desktop IDA database remained locked and was not changed.

## Spectron FreeType continuation

The source-side count above is preserved as its own historical inventory. It
is not the current count for the stripped Spectron 2.2 target. The v307
Spectron copy has 11,695 functions and 436 remaining default `sub_` names.
The v298 pass removed two names from the unresolved target queue by identifying
the FreeType base helpers at target `0x25e304` and `0x260300` as
`v18_destroy_size` and `v18_destroy_face`.

The first helper is the size-list destructor used by FreeType's
`FT_List_Finalize` path. The second releases a face and its associated glyph
slots, sizes, stream, driver callbacks, and internal storage. Both bodies
match the corresponding 1.8 functions in normalized ARM64 feature shape, and
the `destroy_face` difference is limited to register allocation detail. The
machine-readable record is
`artifacts/spectron_freetype_base_cleanup_manual_translation_anchors_20260828.json`.
The v298 checkpoint and database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v298.json`.

The v299 pass removed five more defaults from the FreeType queue. The target
service records identify `0x262008`, `0x264e24`, `0x263aac`, `0x2621f0`, and
`0x264ddc` as the `tt-cmaps`, `postscript-font-name`, and `sfnt-table`
callbacks. Their translated labels are `v18_tt_get_cmap_info`,
`v18_sfnt_get_ps_name`, `v18_tt_face_load_any`, `v18_get_sfnt_table`, and
`v18_sfnt_table_info`. The source and target functions have identical
normalized feature records. Four are complete metric matches, while
`get_sfnt_table` differs only in register allocation detail. The
machine-readable record is
`artifacts/spectron_freetype_sfnt_service_manual_translation_anchors_20260828.json`.
All five names reopened with zero failures, and the v299 checkpoint and
database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v299.json`.

The v300 pass removed 21 more defaults from the FreeType queue. Nineteen are
the non-null slots in the target's `sfnt_interface` record at `0x37fb70`,
paired with the original record at `0x36cda0`. They cover face setup and
teardown, SFNT directory and table loading, kerning, and horizontal metrics.
The other two are the `tt_name_entry_ascii_from_other` and
`tt_name_entry_ascii_from_utf16` helpers called by `sfnt_load_face`. Thirteen
pairs match the complete feature record and the remaining eight differ only
in register allocation detail. All 21 match the normalized ARM64 shape.
The machine-readable record is
`artifacts/spectron_freetype_sfnt_interface_manual_translation_anchors_20260828.json`.
All 21 names reopened with zero failures, and the v300 checkpoint and
database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v300.json`.

The v301 pass removes 12 more defaults from the FreeType queue. Eleven are
callback targets in the smooth renderer and gray raster records. The source
renderer records at `0x36d1c8`, `0x36d240`, and `0x36d2b8` line up with target
records at `0x37ff98`, `0x380010`, and `0x380088`, while the source and target
gray raster records are at `0x35e518` and `0x371298`. The twelfth label is
`tt_face_build_cmaps`, the cmap-construction helper called during SFNT face
loading. Ten pairs match complete feature metrics, and the other two differ
only in register allocation detail. All 12 match normalized ARM64 shape.
The machine-readable record is
`artifacts/spectron_freetype_smooth_manual_translation_anchors_20260828.json`.
All 12 names reopened with zero failures, and the v301 checkpoint and
database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v301.json`.

The v302 pass removes nine more defaults from the FreeType queue. The original
gray outline callback table at `0x35e4e8` identifies the move, line, conic,
and cubic callbacks. The worker call graph identifies the band conversion,
scanline, line, and span helpers used by `gray_raster_render`. Seven pairs
match complete feature metrics, while the span writer and inner conversion
helper differ only in register allocation detail. All nine match normalized
ARM64 shape. The machine-readable record is
`artifacts/spectron_freetype_gray_internal_manual_translation_anchors_20260828.json`.
All nine names reopened with zero failures, and the v302 checkpoint and
database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v302.json`.

The v303 pass removes 19 more defaults from the FreeType queue. Three are
TrueType driver and glyph-loader helpers: `tt_get_kerning`,
`tt_face_get_location`, and `tt_size_init`. The other 16 are fixed-point
interpreter helpers, movement and projection callbacks, and the NPUSHW,
PUSHW, GC, SCFS, GETINFO, MD, and IUP opcode handlers. The source and target
addresses form the same `0xd470`-displaced block used by the surrounding
FreeType translation passes. All 19 pairs match the complete ARM64 feature
record, and all 19 names reopened with zero failures. The machine-readable
record is
`artifacts/spectron_freetype_tt_interpreter_manual_translation_anchors_20260828.json`.
The v303 checkpoint and database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v303.json`; the persisted
database hash is
`36ebf8b934351b45aea6ba5664c93f0d7b66b8b7a3d7ed49980e030226d6c47c`.

The v304 pass removes six more defaults from the FreeType queue. Two are the
interpreter's current and original-coordinate movement helpers,
`Direct_Move` and `Direct_Move_Orig`. Three are the TrueType slot initializer
and face lifecycle callbacks, `tt_slot_init`, `tt_face_done`, and
`tt_face_init`. The sixth is the interpreter's `Current_Ratio` scaling helper.
All six pairs match normalized ARM64 shape. Five match the complete feature
record, while `tt_face_init` differs only in register-allocation detail. All
six names reopened with zero failures. The machine-readable record is
`artifacts/spectron_freetype_tt_runtime_manual_translation_anchors_20260828.json`.
The v304 checkpoint and database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v304.json`; the persisted
database hash is
`8c2e1b1591fbb80bb3d874c3dfa4708d6e7d4bfc503748a70c519f07202494c4`.

The v305 pass removes eight more defaults from the FreeType queue. Seven are
the remaining TrueType `Round_*` callbacks selected by `Compute_Round`, and
the eighth is `Compute_Funcs`, which selects the projection and movement
callbacks. All eight pairs match normalized ARM64 shape. Seven match the
complete feature record, while `Compute_Funcs` differs only in
register-allocation detail. All eight names reopened with zero failures. The
machine-readable record is
`artifacts/spectron_freetype_tt_rounding_manual_translation_anchors_20260828.json`.
The v305 checkpoint and database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v305.json`; the persisted
database hash is
`28920bb7cd08c4b94bc16b82bd3a4770e9873b55af3ff2269bec87755876c931`.

The v306 pass removes six more defaults from the FreeType queue. Four are the
TrueType `SZP0`, `SZP1`, `SZP2`, and `SZPS` zone-pointer handlers. The other
two are the `AlignRP` and `UTP` point-state handlers. Their source and target
pseudocode is joined by the `TT_RunIns` opcode dispatch and the same
`0xd470` block displacement. All six pairs match the complete recorded ARM64
feature set, and all six names reopened with zero failures. The machine-readable
record is
`artifacts/spectron_freetype_tt_opcode_state_manual_translation_anchors_20260828.json`.
The v306 checkpoint and database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v306.json`; the persisted
database hash is
`4a4eb58f2245daf73e262e87c447370e9e8da96329e5a0ab19ca8e2740ad91df`.

The v307 pass removes six more defaults from the FreeType queue. Two are the
TrueType `MDRP` and `MIRP` relative-point handlers. Two are the `Normalize`
unit-vector helper and the `TT_Done_Context` execution-context destructor.
The final two are the `MINDEX` stack operation and the `IP` point-interpolation
handler. Their source and target pseudocode, call topology, and complete ARM64
feature records support direct translation across the same `0xd470` block
displacement. All six names reopened with zero failures. The machine-readable
record is
`artifacts/spectron_freetype_tt_opcode_core_manual_translation_anchors_20260828.json`.
The v307 checkpoint and database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v307.json`; the persisted
database hash is
`2f9136831860bd73c73b966212134aea033a819d9f96520f6a0d887158f36b9c`.

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

## Static library role pass

The next pass covered the small residual gaps where the code matched a named
upstream routine closely enough to use a source-role alias. Every entry below
was applied to the v4 disposable database, saved, reopened, and verified. The
prefixes on the aliases identify the library family. They are analysis names,
not claims that those source names survived in the stripped ELF.

| Family | Address | Latest IDA alias | Source role |
| --- | --- | --- | --- |
| zlib | `0x27fd34` | `zlib_deflate_fast` | `deflate_fast` |
| zlib | `0x2806e8` | `zlib_deflate_stored` | `deflate_stored` |
| zlib | `0x280d70` | `zlib_deflate_slow` | `deflate_slow` |
| zlib | `0x286a30` | `zlib_inflate_table` | `inflate_table` |
| zlib | `0x2874a8` | `zlib_send_tree` | `send_tree` |
| zlib | `0x287a48` | `zlib_compress_block` | `compress_block` |
| zlib | `0x287eac` | `zlib_build_tree` | `build_tree` |
| zlib | `0x288908` | `zlib_tr_init` | `_tr_init` |
| zlib | `0x288998` | `zlib_tr_stored_block` | `_tr_stored_block` |
| zlib | `0x288b28` | `zlib_tr_align` | `_tr_align` |
| zlib | `0x288e5c` | `zlib_tr_flush_block` | `_tr_flush_block` |
| zlib | `0x2899ac` | `zlib_tr_tally` | `_tr_tally` |
| zlib | `0x289b80` | `zlib_zcalloc` | `zcalloc` |
| zlib | `0x289b88` | `zlib_zcfree` | `zcfree` |
| bzip2 | `0x0e02ac` | `bzip2_mainGtU` | `mainGtU` |
| bzip2 | `0x2751c0` | `bzip2_sendMTFValues` | `sendMTFValues` |
| bzip2 | `0x27d6f0` | `bzip2_fallbackSort` | `fallbackSort` |
| bzip2 | `0x27e0e4` | `bzip2_mainSort` | `mainSort` |
| minizip | `0x24840c` | `minizip_unz64local_GetCurrentFileInfoInternal` | `unz64local_GetCurrentFileInfoInternal` |
| minizip | `0x249580` | `minizip_unz64local_CheckCurrentFileCoherencyHeader` | `unz64local_CheckCurrentFileCoherencyHeader` |
| GPC | `0x152b0c` | `gpc_build_lmt` | `build_lmt` |
| CyaSSL | `0x2b3be8` | `CyaInt_GetLength` | `GetLength` |
| CyaSSL | `0x2b3c64` | `CyaInt_GetName` | `GetName` |
| LibTomCrypt | `0x246b50` | `LibTomCrypt_desfunc` | `desfunc` |
| YAJL | `0x2af788` | `yajl_internal_realloc` | `yajl_internal_realloc` |
| YAJL | `0x2af794` | `yajl_internal_free` | `yajl_internal_free` |
| YAJL | `0x2af79c` | `yajl_internal_malloc` | `yajl_internal_malloc` |

The zlib comparison was especially useful for avoiding a misleading name.
`0x288908` initializes the tree descriptors and the first block, so it is
`_tr_init`; it does not initialize the sliding-window match state of
`lm_init`. The bzip2 routines match the source call order from
`BZ2_blockSort` and `BZ2_compressBlock`, while the minizip routines match the
central-directory and local-header helpers. GPC `build_lmt` is identified by
its seven-argument shape and the literal allocation diagnostics for edge
table, scanbeam, and LMT insertion. The complete decompilation evidence,
callers, sizes, and source links are in
`artifacts/static_library_role_audit_20260826.json`.

Five address-only family classifications in the historical unresolved profile
were corrected during this pass. The three callbacks at `0x2af788`,
`0x2af794`, and `0x2af79c` are YAJL's default realloc, free, and malloc
callbacks. The two routines at `0x2b3be8` and `0x2b3c64` are CyaSSL's DER
length and certificate subject-name helpers. The old profile is preserved as
the pre-persistence snapshot, and the correction is recorded in the new role
artifact rather than silently rewriting history.

The application report renamed all 27 functions and added 27 evidence
comments with zero failures. A clean reopen found all 27 names at their
expected function starts, retained 11,297 total functions, and reduced the
default-name count from 448 to 421. The v4 database hash is
`089e588389206929cbcbd7d1d65dd477e0c69eed0841b430636bb7c947594ac3`, and the
exported inventory hash is
`5d25001293e816e7a2d91261ba9140b9f891df952b3427fd67343c643ed87496`.
The reusable scripts are `tools/generate_static_library_role_audit.py`,
`tools/ida_apply_static_library_aliases.py`, and
`tools/ida_verify_static_library_aliases.py`.

## Categories

| Category | Count | Interpretation |
| --- | ---: | --- |
| libjpeg static internals | 150 | Unnamed functions inside the bundled JPEG implementation |
| FreeType static internals | 144 | Unnamed functions inside the bundled font implementation |
| General Polygon Clipper internals | 3 | Unnamed polygon clipping and allocation helpers |
| init or fini array entries | 19 | Lifecycle functions referenced by ELF initialization arrays |
| `TString` cleanup wrappers | 97 | Compiler-generated fixed-global cleanup thunks |
| `TStringList` cleanup wrappers | 5 | Compiler-generated fixed-global destructor thunks |
| `TGraalVar` cleanup wrappers | 2 | Compiler-generated fixed-global destructor thunks |
| AArch64 PLT resolver | 1 | The resolver slot, not an imported application function |
| **Total** | **421** | **All remaining default functions in the latest saved copy** |

The largest groups are recognizable from their position between exported
third-party routines, their call graph, and their strings. That proves a
library family, not a particular upstream source name. Cleanup wrappers are
even more constrained: they compute a fixed global address and tail-call a
known destructor or `TString::clear`, so they have no independent source body
to name.

## Machine-readable record

`artifacts/ida_residual_profile.json` contains every one of the 421 residual
addresses, sizes, current IDA names, segments, and family classifications. It
also records the 28 application role aliases, the 11 CyaSSL aliases, the 27
static-library aliases, the reclassified branch veneer, the latest persisted
database hash, and the evidence used for each category. None of those 38
static-role addresses is counted as a residual default anymore.

The earlier `artifacts/unresolved_function_profile.json` remains in the
archive because it documents the pre-persistence 488-entry queue. The
earlier `symbols/libqplay.function_inventory.json` likewise preserves the
original 11,272-function inventory. Keeping both snapshots avoids silently
rewriting the provenance of the first analysis pass.

Rebuild the final report offline with:

```text
python3 tools/generate_ida_residual_profile.py
```

The generator reads only the public profile, role-candidate artifact, and the
two static-role audit files. It does not load the native library, execute APK
code, or contact a network.

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
for the 421 residual entries.

## Practical conclusion

There are no remaining application, engine, CyaSSL, zlib, bzip2, minizip,
YAJL, GPC edge-table, or LibTomCrypt DES roles in the residual queue. The 28
application roles, eleven earlier CyaSSL roles, and 27 new static-library
roles have evidence-backed aliases in the latest persisted copy. The profile's
421 residual entries are FreeType or JPEG internals, three still-uncertain GPC
helpers, compiler-generated lifecycle code, cleanup thunks, or the PLT
resolver. Assigning names such as `jpeg_internal_17` would make the IDA view
look fuller but would not be a translation of a source symbol. They remain
explicitly classified and addressable instead.
