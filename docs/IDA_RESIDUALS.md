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
is not the current count for the stripped Spectron 2.2 target. The v310
Spectron copy has 11,695 functions and 410 remaining default `sub_` names.
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

The v308 pass removes eleven more defaults from the FreeType queue. Eight are
TrueType opcode handlers: `ENDF`, `FDEF`, `IDEF`, `DELTAP`, `DELTAC`, `SHC`,
`SHP`, and `ISECT`. The other three are `tt_size_done`, `Dual_Project`, and
`TT_Load_Context`. Their source and target pseudocode, dispatcher or callback
topology, and the same `0xd470` block displacement support the role mapping.
All eleven match normalized ARM64 shape. Nine match the complete recorded
feature set, while `FDEF` and `IDEF` differ only in register allocation
detail. All eleven names reopened with zero failures. The machine-readable
record is
`artifacts/spectron_freetype_tt_runtime_tail_manual_translation_anchors_20260828.json`.

The same pass corrects the earlier target label at `0x26bab0`. The source
helper at `0x25e640` is installed by `Compute_Funcs` in the `func_project`
slot, so its semantic role is `Project`; the `TT_DotFix14` arithmetic is an
implementation detail inside that callback. The correction from
`v18_TT_DotFix14` to `v18_Project` is kept in the separate record
`artifacts/spectron_freetype_tt_projection_name_correction_20260828.json`.
The v308 checkpoint and database hash are recorded in
`artifacts/spectron_translation_checkpoint_20260828_v308.json`; the persisted
database hash is
`2ac5e911c27e2cc07642c7b8433d54b708a536062114b4b2bea3609524c3bab8`.

The v309 pass removes seven more defaults from the FreeType queue. Three are
the TrueType glyph-loader functions `load_truetype_glyph`, `TT_Load_Glyph`,
and `tt_glyph_load`. Four are interpreter helpers: `Ins_SxVTL`, `Ins_CALL`,
`Ins_LOOPCALL`, and `Ins_UNKNOWN`. The first three are tied to the driver
callback and glyph-loading call chain. The interpreter helpers are tied to
the `TT_RunIns` cases for SPVTL and SFVTL, LOOPCALL, and CALL, plus the
undefined-opcode path that dispatches active IDEF definitions. All seven
match normalized ARM64 shape. Six match the complete recorded feature set,
while `TT_Load_Glyph` differs only in register-allocation detail. All seven
names reopened with zero failures. The v309 database contains 11,695
functions and 418 remaining default `sub_` names. Its SHA-256 is
`73e94e4ea548857972a5a0222c24860c4ed6123e0fda9cba61bd3e090c4bd824`.

The machine-readable evidence is in
`artifacts/spectron_freetype_tt_glyph_loader_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_freetype_tt_glyph_loader_anchors.py`.
The v309 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v309.json`.

The v310 pass removes eight more defaults from the FreeType queue. Seven are
callback entries selected by the dummy, Latin, Latin2, and CJK autofit script
class records: `tt_driver_init`, `af_dummy_hints_init`,
`af_dummy_hints_apply`, `af_latin_hints_init`, `af_latin2_hints_init`,
`af_cjk_metrics_scale`, and `af_cjk_hints_init`. The eighth is
`af_latin2_hints_compute_segments`, identified from the Latin2 metrics-width
probe and hint-application call sites. All eight source and target functions
match the complete recorded ARM64 feature set, and all eight names reopened
with zero failures. The v310 database contains 11,695 functions and 410
remaining default `sub_` names. Its SHA-256 is
`b2b94918d6b9cd30c6fe90c34e8db95cf9fde200e6074b11f9db86476244c33b`.

The machine-readable evidence is
`artifacts/spectron_freetype_autofit_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_freetype_autofit_anchors.py`. The v310
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v310.json`.

The v311 follow-up removes seven more defaults from the same FreeType region.
The translated roles are `af_latin2_hints_link_segments`,
`af_latin2_hints_compute_edges`, `af_glyph_hints_done`, `af_loader_load_g`,
`af_glyph_hints_reload`, `af_latin2_metrics_scale`, and
`af_latin_metrics_scale`. The first two historical role labels were later
corrected to CJK roles after the source and target class records were checked.
All seven match normalized ARM64 shape. Six match
the complete recorded feature set, while `af_glyph_hints_done` differs only
in register-detail allocation. All seven names reopened with zero failures.
The v311 database contains 11,695 functions and 403 remaining default `sub_`
names. Its SHA-256 is
`ce20ddf7e3d8835cb79f6889c9291445a0472480169f07cfadc6c6d6e1e6a6df`.

The machine-readable evidence is
`artifacts/spectron_freetype_autofit_followup_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_freetype_autofit_followup_anchors.py`.
The v311 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v311.json`.

The v312 pass translates eleven new defaults from the next contiguous
FreeType autofit region and corrects the two v311 script-family labels. The
source class table at `0x35e630` and target class table at `0x3713b0` both
select the CJK hint callback at the corresponding `0x26d1f8` and `0x27a668`
addresses. That proves the two corrected helpers are
`af_cjk_hints_link_segments` and `af_cjk_hints_compute_edges`, rather than
Latin2 helpers. The new rows also cover shared Latin metrics probes, CJK and
Latin or Latin2 metrics initialization, CJK stem adjustment, Latin and
Latin2 edge construction, shared edge-point alignment, and the CJK apply
callback.

All thirteen v312 rows match normalized ARM64 shape. Eleven match the full
recorded feature set, and two differ only in register-detail allocation. The
fresh IDA copy was applied, closed, reopened, and checked with zero failures.
It contains 11,695 functions and 392 remaining default `sub_` names. Its
SHA-256 is
`a0ab5988b005eed29537dfb65f53e0b511fb6b7e6d9985bf5cb39e2414e06402`.

The machine-readable evidence is
`artifacts/spectron_freetype_autofit_metrics_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_freetype_autofit_metrics_anchors.py`.
The v312 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v312.json`. The anchor
record is offline-only and records `network_contacted: false`. The CJK role
references are Android FreeType's
[`afcjk.c`](https://android.googlesource.com/platform/external/freetype/+/a45c6a1cf3625709e149550b8fff1f09d01388d3/src/autofit/afcjk.c), with the
shared Latin and hint helpers documented in
[`aflatin.c`](https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c),
[`aflatin2.c`](https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c), and
[`afhints.c`](https://android.googlesource.com/platform/external/freetype/+/8483e21a1fdc252bd234eb55c6b63c17551933ee/src/autofit/afhints.c).

The v313 pass translates three residual helpers from the bundled bzip2
implementation. The source functions at `0x273350`, `0x273360`, and
`0x27336c` map to target functions at `0x2807c0`, `0x2807d0`, and `0x2807dc`
with a shared `0xb470` displacement. They are the default `bzfree` cleanup
callback, the default `bzalloc` callback, and the `handle_compress` streaming
state machine. All three match normalized ARM64 shape. Two match the full
recorded feature set, while the state machine differs only in register-detail
allocation. The fresh v313 IDA copy was applied, closed, reopened, and checked
with zero failures. It contains 11,695 functions and 389 remaining default
`sub_` names. Its SHA-256 is
`45f965884bffdc73e981d88d2965fac94f453640a29aa4d44acc7aca6b9e46e5`.

The machine-readable evidence is
`artifacts/spectron_bzip2_helpers_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_bzip2_helpers_anchors.py`. The v313
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v313.json`. The anchor
record is offline-only and records `network_contacted: false`. The role source
is the bundled bzip2 [`bzlib.c`](https://github.com/libarchive/bzip2/blob/master/bzlib.c).

The v314 pass translates the two remaining large callbacks in the contiguous
FreeType autofit run. The source `0x26df5c` and `0x26f820` functions map to
target `0x27b3cc` and `0x27cc90`, and the source and target script class
records select them in their respective Latin2 and Latin `hints_apply` slots.
Both pairs match the complete recorded ARM64 feature set. The fresh v314 IDA
copy was applied, closed, reopened, and checked with zero failures. It
contains 11,695 functions and 387 remaining default `sub_` names. Its SHA-256
is
`338d9a62d76c6c2178acbd2a8ea50d811ff2959f25745e1aa5bdebea369bf279`.

The machine-readable evidence is
`artifacts/spectron_freetype_apply_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_freetype_apply_anchors.py`. The v314
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v314.json`. The anchor
record is offline-only and records `network_contacted: false`. The role
sources are Android FreeType's
[`aflatin2.c`](https://android.googlesource.com/platform/external/freetype/+/6da2e02232e1bcf31cfb78894d46c7902b90ee9/src/autofit/aflatin2.c) and
[`aflatin.c`](https://android.googlesource.com/platform/external/freetype/+/2689da543c08133100124cab3ab19523b04f2f3d/src/autofit/aflatin.c).

The v315 pass translates nine residual routines in the bundled libjpeg marker
writer. Seven are selected directly by the source and target
`jinit_marker_writer` method tables, and the DQT and DHT emitters are selected
by their frame, table-only, and scan-header callers. The source `0x2986c0`
through `0x29aa48` functions map to target `0x2a5b30` through `0x2a7eb8` with
a shared `0xd470` displacement. All nine pairs match normalized ARM64 shape;
seven match every recorded metric and two differ only in register-detail
allocation. The fresh v315 IDA copy was applied, closed, reopened, and checked
with zero failures. It contains 11,695 functions and 378 remaining default
`sub_` names. Its SHA-256 is
`c0c270a006c67f5f7ee2bb5f097c6fa2639ebaaba859cfa6070b2ebfcb1dabe6`.

The machine-readable evidence is
`artifacts/spectron_jpeg_marker_writer_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_jcmarker_anchors.py`. The v315 checkpoint
is `artifacts/spectron_translation_checkpoint_20260828_v315.json`. The anchor
record is offline-only and records `network_contacted: false`. The role source
is libjpeg-turbo's
[`jcmarker.c`](https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jcmarker.c).

The v316 pass translates one more default in the same FreeType family. The
source function at `0x25eaf8` and target function at `0x26bf68` are selected by
the corresponding TrueType driver class `size_reset` slot at `0x36d3e0` and
`0x3801b0`. The class records begin at `0x36d3a0` and `0x380170`, so the slot
references preserve the same `0xd470` relocation as the surrounding TrueType
block. The helper requests face metrics, recomputes scaled horizontal and
vertical values with the FreeType fixed-point helpers, selects the active ppem
dimension, and marks the metrics valid. Every recorded ARM64 feature metric is
identical between the two functions.

The fresh v316 IDA copy was applied, closed, reopened, and checked with zero
failures. The broad translation reopen still verifies all 3,641 high-confidence
map entries. It contains 11,695 functions and 377 remaining default `sub_`
names. Its SHA-256 is
`ba52348b6c87fc441fe94c3c70fc96efd4a5e6be4a1c72ee1f3efc5269b42b5b`.

The machine-readable evidence is
`artifacts/spectron_freetype_tt_size_reset_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_freetype_tt_size_reset_anchor.py`. The
v316 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v316.json`. This pass is
offline-only and the anchor record reports `network_contacted: false`. The
role source is Android FreeType's
[`ttobjs.c`](https://android.googlesource.com/platform/external/freetype/%2B/6da2e02232e1bcf31cfb78894d46c7902b90ee9f/src/truetype/ttobjs.c).

The v317 pass translates four more residual target functions. The JPEG helper
at `0xdfae4` is the APP14 Adobe-marker examiner called from the marker-reader
`save_marker` and `get_interesting_appn` paths. The GPC helpers at `0x155028`
and `0x1556c0` are `free_sbtree` and `build_sbt`, identified by their
recursive tree behavior and their shared `0x2e28` displacement from source
addresses `0x152200` and `0x152898`. The small helper at `0xdf830` is the
compiler-extracted GPC `MALLOC` diagnostic for tristrip node creation. It is
named for that literal role rather than presented as an upstream function
that never had its own source declaration.

All four v317 pairs match normalized ARM64 shape. Three match the complete
recorded feature set, and the diagnostic helper differs only in
register-detail allocation. The fresh v317 IDA copy was applied, closed,
reopened, and checked with zero failures. The broad translation reopen still
verifies all 3,641 high-confidence map entries. It contains 11,695 functions
and 373 remaining default `sub_` names. Its SHA-256 is
`0d39dce494c293094f370237decece95f27b176d3e7f477be8f50b7ed402575c`.

The machine-readable evidence is
`artifacts/spectron_jpeg_gpc_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_jpeg_gpc_residual_anchors.py`. The v317
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v317.json`. This pass is
offline-only and the anchor record reports `network_contacted: false`. The
role references are libjpeg-turbo's
[`jdmarker.c`](https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdmarker.c)
and the General Polygon Clipper
[`gpc.c`](https://github.com/rickbrew/GeneralPolygonClipper/blob/main/gpc.c).

The v318 pass gives every remaining target `sub_` entry an explicit
target-only role label. This is a naming-coverage pass, not a claim that every
original source symbol was recoverable. The 373 entries break down into 117
default `.fini_array` entries, 113 default `.init_array` entries, 99
`C8THgaTQxF::clear` cleanup wrappers, 35 `CanTfaz6bZ::clear` cleanup wrappers,
six `vuuHgangcF` destructor thunks, two `G0gxgajWBw` destructor thunks, and
one AArch64 PLT resolver. The final init-array entry also initializes a global
`CanTfaz6bZ` object, but it remains labeled by its startup-table role because
the stripped target does not preserve the C++ global's source name.

The labels use the `spectron_` prefix and include the target address for
generated wrappers and startup entries. The reopen check verified all 373
labels with zero failures. The broad source-backed translation check still
verifies all 3,641 high-confidence aliases with zero failures. The v318 copy
contains 11,695 functions and no default `sub_` names. Its SHA-256 is
`006016f0d13a7a52e24fd18e3ec50443c69525cccfaad834b2b00d9b6d7fd58b`.

The machine-readable label record is
`artifacts/spectron_residual_target_only_labels_20260828.json`, generated by
`tools/generate_spectron_residual_target_only_labels.py`. The v318 checkpoint
is `artifacts/spectron_translation_checkpoint_20260828_v318.json`. This pass
is offline-only and the label record reports `network_contacted: false`. The
target-only labels are deliberately kept separate from the cross-build anchor
artifacts so a descriptive cleanup name cannot be mistaken for a recovered
1.8 source symbol.

## Spectron v319 and v320 coverage

The v319 name audit found nine remaining `nullsub_*` defaults in the 11,695
function copy. Each was a four-byte `RET` stub, so the fresh v319 copy labels
them as `spectron_nullsub_stub_0x...` and verifies the names after reopening.
This removes the last generic names in the checked `sub_`, `nullsub_`, `j_`,
`loc_`, and `unk_` families without pretending to know the original source
roles.

The v320 pass addresses a different residual: twelve positive-size,
section-defined dynamic `FUNC` symbols had no IDA function boundary. Their
valid AArch64 prologues and exact ELF sizes justify materializing the
boundaries, but not assigning new semantic source names. The v320 database
contains 11,707 functions, and all 5,782 section-defined dynamic `FUNC` rows
now have exact IDA starts. The 988 named dynamic rows that are not function
matches remain classified as non-function entries.

The name audits, dynamic boundary records, and v320 checkpoint are
`artifacts/spectron_name_coverage_audit_v318_20260828.json`,
`artifacts/spectron_name_coverage_audit_20260828.json`,
`artifacts/spectron_name_coverage_audit_v320_20260828.json`,
`artifacts/spectron_dynamic_symbol_boundaries_20260828.json`,
`artifacts/spectron_symbol_translation_inventory_20260828.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v320.json`.

### v321 GUI boundary translation

The v321 pass extends that boundary work to the original 1.8 database. Eleven
positive-size GUI `FUNC` symbols were present in the source ELF table but had
been classified as data by the source IDA analysis. The offline materializer
restored their exact source intervals and readable names before comparing them
to the eleven corresponding Spectron methods.

Ten pairs have high-confidence normalized ARM64 matches. One pair,
`GuiButtonCtrl::drawWithStyle`, is medium confidence because the target body is
eight bytes and two instructions shorter. Its class-local method order,
`Buttons` and `Taskbar.Button` strings, call and branch counts, and reviewed
pseudocode all agree. The shorter body is recorded as a rebuild-layout
difference rather than silently treated as an exact metric match.

The eleven applied target aliases are stored in
`artifacts/spectron_gui_missing_function_manual_translation_anchors_20260828.json`.
The application report shows eleven resolved rows, eleven renamed functions,
eleven comments, and zero failures. The close and reopen verification shows
eleven verified names in the 11,707-function target database. The final target
database hash is
`b7d17b9a5dbc34922cc40fe030cb539d69dcf89fe8a5f64bae83e962309263ab`, recorded
in `artifacts/spectron_translation_checkpoint_20260828_v321.json`.

The final v321 name audit has zero default names in the checked families. It
contains 6,228 translated `v18_` aliases, 417 target-only descriptive labels,
1,002 retained target names, seven JNI exports, and 4,053 other IDA or PLT
names. The separate dynamic-symbol audit still classifies all 6,770 named
rows, including 5,782 exact functions, 482 data items, 336 other non-code
items, and 170 undefined imports. This is a complete IDA boundary and item
accounting result, not a claim that stripped 2.2 source names were restored.

### v322 TGraalVar runtime-gap translation

The v322 pass moves from boundary accounting to semantic recovery in the
largest unresolved application block. The target class is the obfuscated
`G0gxgajWBw` implementation of `TGraalVar`. Automatic feature matching was
deliberately conservative here because the target rebuild replaces the source
`TString`, `TStringList`, hash-list, and array wrappers. The source and target
Hex-Rays decompilations still preserve enough data flow to review the method
identities directly.

| 1.8 source | Spectron target | Applied alias | Main evidence |
| ---: | ---: | --- | --- |
| `0x20d304` | `0x2136c4` | `v18_TGraalVar_receiveEvent_script_event` | event string and virtual +128 forward |
| `0x20e070` | `0x214520` | `v18_TGraalVar_getVarNames_bool_bool_bool` | three visibility flags, deduplication, sort |
| `0x20e5c4` | `0x214a78` | `v18_parseDynamicFunctionParameters_char_const_std_va_list` | all GS2 format cases and va_list walk |
| `0x20ec60` | `0x215148` | `v18_TGraalVar_executeStringFunctionF_TString_const_char_const` | parser, function call, result string, cleanup |
| `0x20f014` | `0x2154e0` | `v18_TGraalVar_saveString_TString_const_uint` | path, stream, file write, resource update |
| `0x20f17c` | `0x215660` | `v18_TGraalVar_saveLines_TString_const_uint` | line-list iteration and save |
| `0x20f2ac` | `0x2157a8` | `v18_TGraalVar_loadString_TString_const` | path, stream load, virtual +200 setter |
| `0x20f3bc` | `0x2158e4` | `v18_TGraalVar_setVarValueAsFloat_TString_const_double` | lookup, persistent fallback, numeric +192 setter |
| `0x20f474` | `0x2159f4` | `v18_TGraalVar_getVarValue_TString_const` | lookup, copied value, persistent fallback |
| `0x20fc18` | `0x216174` | `v18_TGraalVar_setArrayCellObject_int_TGraalVar` | index check, virtual +200 assignment, update flag |
| `0x20fe5c` | `0x216454` | `v18_TGraalVar_getVarValueAsFloat_TString_const` | lookup and numeric projection |
| `0x20ff2c` | `0x216558` | `v18_TGraalVar_updateArrayString_void` | comma-separated array cache rebuild |

All twelve rows are high-confidence layout-change anchors. The first row has
the same size, instruction count, block count, branch count, and mnemonic
shape in both builds. The other eleven retain the method-level control flow
and data flow but have changed metric records because of wrapper conversion
code. For example, the target dynamic-parameter parser keeps 48 basic blocks
and the same format-string cases, while its string and array construction
calls are renamed and expanded. The target object-array setter is especially
useful: automatic matching had assigned the nearby target string setter to
the source string setter, while the target `0x216174` body clearly performs
the object-cell assignment and update operation.

The review used compact IDA evidence exports with Hex-Rays pseudocode for all
24 functions. The anchor artifact stores a SHA-256 fingerprint for each
pseudocode result, the source and target feature records, direct-call names,
and the reasoning for each alias. No live endpoint, APK, or server was used
for this translation pass. The target aliases were applied to a fresh copy of
the verified v321 database. The application report records twelve resolved
rows, twelve renamed functions, twelve comments, and zero failures. Reopening
the saved copy verified all twelve names.

The v322 database contains 11,707 functions and zero audited default names in
the checked IDA families. Its name-origin counts are 6,240 translated
`v18_` aliases, 417 target-only descriptive labels, 990 retained target
names, seven JNI exports, and 4,053 other IDA or PLT names. The dynamic
boundary count remains 5,782 exact function starts. The full dynamic-symbol
audit still accounts for 6,770 named rows: 5,782 functions, 482 data items,
336 other non-code items, and 170 undefined imports. The twelve new aliases
move twelve rows from retained target names to the source-backed alias class,
so that class rises from 4,552 to 4,564.

The v322 database hash is
`af0f2361668f7cd375b33242a0b21591a53446c332c0e77c8a4e51e3c6bdf1ad`, recorded
in `artifacts/spectron_translation_checkpoint_20260829_v322.json`. The
machine-readable evidence is in
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_application_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v322_20260829.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v322_20260829.json`, and
`artifacts/spectron_dynamic_symbol_coverage_audit_v322_20260829.json`. The
reusable generators are
`tools/generate_spectron_tgraalvar_runtime_gap_anchors.py` and
`tools/generate_spectron_translation_checkpoint_v322.py`.

### v323 TGraalVar runtime continuation

The v323 pass reviews the next contiguous source and target method block. It
uses the same evidence standard as v322, but the larger group makes the class
relationships clearer. The source methods cover script lifecycle, function
lookup, sorting, persistent-variable serialization, value access, recursive
copying, array construction, static property registration, and string parsing.

| 1.8 source | Spectron target | Applied alias | Main evidence |
| ---: | ---: | --- | --- |
| `0x20d7dc` | `0x213c84` | `v18_TGraalVar_runScript_void` | attached script-space forwarder |
| `0x20e598` | `0x214a4c` | `v18_TGraalVar_leaveClass_TString_const` | lazy script-space creation and leave |
| `0x20eaf0` | `0x214fc4` | `v18_TGraalVar_cancelEvents_TString_const` | attached script-space forwarder |
| `0x20eb04` | `0x214fec` | `v18_TGraalVar_setScript_TString_const` | string script setter |
| `0x20eb2c` | `0x215014` | `v18_TGraalVar_setScript_TScript` | script-object setter overload |
| `0x20eb54` | `0x21503c` | `v18_TGraalVar_freeScript_void` | attached script-space release |
| `0x210a8c` | `0x217198` | `v18_TGraalVar_hasFunction_TString_const` | primary, global, and table lookup |
| `0x210b40` | `0x21727c` | `v18_TGraalVar_sortList_bool` | temporary records and value qsort |
| `0x210ce8` | `0x217444` | `v18_TGraalVar_sortListByValue_TString_const_TString_const_bool` | numeric or string qsort |
| `0x210f98` | `0x217754` | `v18_TGraalVar_listSubVars_TStringList_TString_const` | recursive persistent-variable listing |
| `0x211178` | `0x21797c` | `v18_TGraalVar_saveVarsToArray_void` | property filtering and export |
| `0x211850` | `0x21805c` | `v18_TGraalVar_writeFloatOrString_TString_const` | numeric test and setter choice |
| `0x21190c` | `0x218134` | `v18_TGraalVar_setSubVar_TString_const` | dotted path parsing and recursion |
| `0x211c00` | `0x218468` | `v18_TGraalVar_setVarValue_TString_const_TString_const` | direct lookup or equals fallback |
| `0x2124c0` | `0x218d70` | `v18_TGraalVar_getArrayMember_TString_const` | case-insensitive member scan |
| `0x21277c` | `0x219050` | `v18_TGraalVar_copyFrom_TGraalVar` | scalar, array, property, and child copy |
| `0x2135b0` | `0x219ed0` | `v18_TGraalVar_getFunctions_void` | function metadata array |
| `0x213b10` | `0x21a64c` | `v18_TGraalVar_writeStringList_TStringList` | array length synchronization |
| `0x213e48` | `0x21a970` | `v18_TGraalVar_insertArrayCellFloat_int_double` | numeric cell construction |
| `0x213f04` | `0x21aa0c` | `v18_TGraalVar_insertArrayCellString_int_TString_const` | string cell construction |
| `0x213fc0` | `0x21aab0` | `v18_TGraalVar_insertArrayCellObject_int_TGraalVar` | object cell construction |
| `0x21407c` | `0x21ab54` | `v18_TGraalVar_initStaticScriptVars_void` | static property registration |
| `0x2140c0` | `0x21ab98` | `v18_TGraalVar_writeString_TString_const` | comma and quoted-text parsing |

Six short wrappers have exact recorded metrics. The other seventeen are
layout-change matches caused by the target's rebuilt string, list, hash, and
iterator classes. The source and target pseudocode still agree on the key
virtual slots and decisions. In particular, the two sort methods preserve
their temporary records and qsort calls, `copyFrom` keeps its property-type
switch and recursive child copy, and the three cell constructors use the
float, string, and object setter slots in order.

The nearby target method at `0x214fd8` is not included. It is a short
target-only script-space helper with no independently established source
counterpart. Keeping it as a retained target symbol avoids assigning the
wrong adjacent source name. The continuation artifact records this exclusion
along with the 23 positive aliases.

The v323 application renamed all 23 target functions, added 23 evidence
comments, and reported zero failures. A fresh reopen verified all 23 names.
The final copy contains 11,707 functions and zero audited default names. Its
name origins are 6,263 translated `v18_` aliases, 417 target-only descriptive
labels, 967 retained target names, seven JNI exports, and 4,053 other IDA or
PLT names. The dynamic-symbol audit reports 4,587 source-backed aliases,
1,855 exact retained names, 151 other retained target names, seven
linker-boundary aliases, 169 exact PLT veneers, and one undefined `__sF`
import without an in-library veneer.

The v323 database hash is
`588e39f73c0946aea4ed45265820c9d95a73689339c365840b308170d36d0b4d`. The
machine-readable records are
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_application_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v323_20260829.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v323_20260829.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v323_20260829.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v323.json`. The reusable
generators are
`tools/generate_spectron_tgraalvar_runtime_continuation_anchors.py` and
`tools/generate_spectron_translation_checkpoint_v323.py`.

### v324 TScript runtime translation

The v324 pass moves the translation frontier into the next class-local block:
`TScriptFunction`, `TScript`, and `TScriptEnvironment`. The pairings below
were reviewed against compact Hex-Rays output from both IDA databases. The
target names are obfuscated exports, so the applied names retain the original
1.8 spelling behind a `v18_` prefix.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | ---: | --- | --- |
| `0x2148dc` | `0x21b490` | `v18_TScriptFunction_TScriptFunction_TScript_TString_const_int_int` | function construction and owner setup |
| `0x214a24` | `0x21b5f8` | `v18_TScriptFunction_addToFreeCallStackEntries_TCallStackEntry` | unique call-stack entry insertion |
| `0x214a70` | `0x21b644` | `v18_TScriptFunction_clearCallStackEntries_void` | call-stack destruction and clear |
| `0x214aec` | `0x21b6c0` | `v18_TScriptFunction_TScriptFunction` | destructor body |
| `0x214b34` | `0x21b708` | `v18_TScriptFunction_TScriptFunction__2` | deleting destructor wrapper |
| `0x214b54` | `0x21b728` | `v18_TScript_TScript_TString_const` | script construction |
| `0x21510c` | `0x21bd1c` | `v18_TScript_addCatchedEvent_TString_const_TString_const_int` | event-handler registration |
| `0x215488` | `0x21c0dc` | `v18_TScript_getFunction_TString_const` | direct and inherited function lookup |
| `0x2157f4` | `0x21c460` | `v18_TScript_getEventFunctions_TList_TString_const` | event-function collection |
| `0x215950` | `0x21c5dc` | `v18_TScript_installSelfEventCatchers_TGraalVar` | local event-catcher installation |
| `0x215a9c` | `0x21c758` | `v18_TScript_installEventCatchers_TGraalVar` | local and inherited catchers |
| `0x215cc4` | `0x21ca08` | `v18_TScript_addFunctionProfilerTime_TString_const_double_double` | profiler accumulation |
| `0x215eac` | `0x21cc10` | `v18_TScript_optimizeByteCode_void` | bytecode optimization |
| `0x216de8` | `0x21db68` | `v18_TScript_loadScriptEncrypted_int_TString_const_uint` | encrypted script loading |
| `0x216fa0` | `0x21dde0` | `v18_TScript_checkRequestScript_int_TString_const_uint` | script request and privilege check |
| `0x217108` | `0x21dff8` | `v18_TScript_initStaticVars_void` | static runtime property setup |
| `0x217138` | `0x21e028` | `v18_TScript_initStaticScriptVars_void` | static script property setup |
| `0x2176d8` | `0x21e618` | `v18_TScriptEnvironment_getPropertyList_TString_const` | normalized property enumeration |
| `0x217908` | `0x21e848` | `v18_TScriptEnvironment_makeTempVar_void` | temporary variable creation |
| `0x2179a4` | `0x21e8bc` | `v18_TScriptEnvironment_makeArrayVar_bool` | array variable creation |
| `0x217af0` | `0x21e9ec` | `v18_TScriptEnvironment_makeVarFromStringList_TStringList_const_bool` | string-list conversion |
| `0x217b80` | `0x21eaa0` | `v18_TScriptEnvironment_makeVarFromCommaText_TString_const_bool` | comma-text conversion |
| `0x217cd8` | `0x21ec14` | `v18_TScriptEnvironment_makeStringListFromVar_TGraalVar` | string-list export |
| `0x217db4` | `0x21ed10` | `v18_TScriptEnvironment_initStaticVars_void` | event-name and registry initialization |

Three rows have complete metric matches: the call-stack insertion, call-stack
clear, and first destructor body. The remaining 21 rows are layout-change
matches. The target adds wrapper calls around rebuilt `TString`, list, hash,
and iterator classes, but the decompiled decisions remain aligned. The
constructor and event methods preserve their object ownership and recursive
lookup structure. The optimizer retains the same 51-block, 32-branch, five-call
shape while the target instruction records grow from 32 to 40 bytes. The
environment helper family preserves active-universe linking, array setup, and
comma escaping. Its static initializer is deliberately treated as a layout
change because the target expands the source's compact registration into
individually constructed event-name and registry objects.

All 24 aliases were applied to a fresh copy and all 24 were verified after
reopening it. The final database has 11,707 functions and zero audited
default names. The v324 records are
`artifacts/spectron_tscript_runtime_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_runtime_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_runtime_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v324.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v324.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v324.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v324.json`. The reusable
generators are `tools/generate_spectron_tscript_runtime_anchors.py` and
`tools/generate_spectron_translation_checkpoint_v324.py`.

### v325 TScript destructor and profile cleanup aliases

The v325 pass closes eight raw target names in the same script-runtime
neighborhood. The source feature names for the property and profile entries
are historical IDA aliases, so the compact pseudocode comments are retained
in the anchor artifact to show their underlying D1, D2, and D0 destructor
forms.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | ---: | --- | --- |
| `0x214794` | `0x21b324` | `v18_TScript_getLogName_void` | `Class ` prefix and script-name assembly |
| `0x2150ec` | `0x21bcfc` | `v18_TScript_TScript__2` | deleting TScript destructor |
| `0x2175b8` | `0x21e4f8` | `v18_TScriptFunctionProperties_TScriptFunctionProperties` | property destructor body |
| `0x2175d4` | `0x21e514` | `v18_non_virtual_thunk_to_TScriptFunctionProperties_TScriptFunctionProperties` | property D1 thunk |
| `0x2175dc` | `0x21e51c` | `v18_TScriptFunctionProperties_TScriptFunctionProperties__2` | deleting property destructor |
| `0x217614` | `0x21e554` | `v18_non_virtual_thunk_to_TScriptFunctionProperties_TScriptFunctionProperties__2` | property D0 thunk |
| `0x21761c` | `0x21e55c` | `v18_TFunctionProfile_TFunctionProfile` | profile-name cleanup |
| `0x217630` | `0x21e570` | `v18_TFunctionProfile_TFunctionProfile__2` | deleting profile destructor |

Three rows have exact normalized metrics: the deleting TScript wrapper and
the two property destructor thunks. The other five differ only in the target
string wrapper or register-detail record. `getLogName` still emits `Class `,
copies the script name from object offset 8, and clears its temporary string.
The property destructor bodies reset the two vtable slots, invoke the base
destructor, and optionally call `operator delete`; their thunks subtract 16
from the receiver. The profile destructors reset their vtable, clear the name
at offset 8, and optionally release the object.

The v325 application renamed all eight target functions, added eight evidence
comments, and reported zero failures. A fresh reopen verified all eight names.
The database still has 11,707 functions and zero audited default names. The
v325 records are
`artifacts/spectron_tscript_destructor_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_destructor_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_destructor_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v325.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v325.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v325.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v325.json`. The reusable
generators are `tools/generate_spectron_tscript_destructor_anchors.py` and
`tools/generate_spectron_translation_checkpoint_v325.py`.

### v326 format-parameter and property runtime aliases

The v326 pass follows the destructor block into the next compact class-local
sequence. It closes the raw target names for the format-parameter wrapper,
`TCallStackEntryProperties`, `TProperties`, and two derived property writers.
The method order is useful here because the target's obfuscated `OV5NOaoBLl`
class contains the same next, indexed, numeric, and string accessors as the
source `TScriptMachine::FormatParameters` class.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | ---: | --- | --- |
| `0x224248` | `0x22c810` | `v18_TScriptMachine_FormatParameters_TScriptMachine_FormatParameters` | format-parameter D2 cleanup |
| `0x22424c` | `0x22c858` | `v18_TCallStackEntryProperties_TCallStackEntryProperties` | property D1/D2 cleanup |
| `0x224268` | `0x22c874` | `v18_non_virtual_thunk_to_TCallStackEntryProperties_TCallStackEntryProperties` | property D1 thunk |
| `0x224270` | `0x22c87c` | `v18_TCallStackEntryProperties_TCallStackEntryProperties__2` | property D0 cleanup |
| `0x2242a8` | `0x22c8b4` | `v18_non_virtual_thunk_to_TCallStackEntryProperties_TCallStackEntryProperties__2` | property D0 thunk |
| `0x2242b0` | `0x22c8bc` | `v18_TScriptMachine_FormatParameters_TScriptMachine_FormatParameters__2` | format-parameter D0 cleanup |
| `0x224400` | `0x22ca58` | `v18_TScriptMachine_FormatParameters_getNextU32_void` | next float to unsigned integer |
| `0x224448` | `0x22caa0` | `v18_TScriptMachine_FormatParameters_getNextS32_void` | next float to signed integer |
| `0x224490` | `0x22cae8` | `v18_TScriptMachine_FormatParameters_getNextF64_void` | next float passthrough |
| `0x224498` | `0x22caf0` | `v18_TScriptMachine_FormatParameters_getIndexedU32_int` | indexed float to unsigned integer |
| `0x2244e0` | `0x22cb38` | `v18_TScriptMachine_FormatParameters_getIndexedS32_int` | indexed float to signed integer |
| `0x224528` | `0x22cb80` | `v18_TScriptMachine_FormatParameters_getIndexedF64_int` | indexed float passthrough |
| `0x224530` | `0x22cb88` | `v18_TScriptMachine_FormatParameters_getNextString_void` | next string accessor |
| `0x224538` | `0x22cb94` | `v18_TScriptMachine_FormatParameters_getIndexedString_int` | indexed string accessor |
| `0x2245cc` | `0x22cc48` | `v18_TProperties_TProperties` | property-list and string cleanup |
| `0x224638` | `0x22ccbc` | `v18_non_virtual_thunk_to_TProperties_TProperties` | TProperties D1 thunk |
| `0x224640` | `0x22ccc4` | `v18_TProperties_TProperties__2` | TProperties D0 cleanup |
| `0x224660` | `0x22cce4` | `v18_non_virtual_thunk_to_TProperties_TProperties__2` | TProperties D0 thunk |
| `0x224668` | `0x22ce20` | `v18_TJoinedClassesProperty_writeObject_TGraalVar_TGraalVar` | object-to-string property write |
| `0x2246c8` | `0x22cea0` | `v18_TAniProperty_writeObject_TGraalVar_TGraalVar` | animation property write |

Eleven rows retain the complete normalized feature record. The nine layout
rows are still high-confidence: the format destructor clears a target string
array that is absent from the source body, the property destructors use the
rebuilt target containers, the two string wrappers add a small ABI detail,
and the object writers add explicit target string conversions and cleanup.
The exact thunk and deleting-destructor rows are particularly useful anchors
because receiver adjustment and `operator delete` placement are fixed by the
C++ ABI.

All 20 aliases were applied to a fresh v325-derived copy and all 20 were
verified after reopening. The final database has 11,707 functions and zero
audited default names. The v326 name-origin counts are 6,315 translated
`v18_` aliases, 417 target-only descriptive labels, 915 retained target
names, seven JNI exports, and 4,053 other IDA or PLT names. Dynamic coverage
reports 4,647 source-backed aliases, 1,803 exact retained names, and 143
other retained target names. The database hash is
`08ae63229dfbcabf94d314cda677a2c45b60e17b9c2fee8351a298b3cf6eb991`.

The v326 records are
`artifacts/spectron_format_parameters_property_manual_translation_anchors_20260829.json`,
`artifacts/spectron_format_parameters_property_manual_translation_application_20260829.json`,
`artifacts/spectron_format_parameters_property_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v326.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v326.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v326.json`,
`artifacts/spectron_semantic_translation_v326.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v326.json`. The reusable
generators are
`tools/generate_spectron_format_parameters_property_anchors.py` and
`tools/generate_spectron_translation_checkpoint_v326.py`.

### v341 GuiControl color-setter residual aliases

The v341 pass starts from the verified v340 database and translates four raw
entries in the obfuscated w9XxgaJdbx control implementation. Direct compact
Hex-Rays pseudocode was captured for every source and target row, and all four
rows are exact normalized ARM64 matches.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | --- | --- | --- |
| `0x1ba168` `GuiControl_setRed_float` | `0x1bea8c` `_ZN10w9XxgaJdbx10pONIFa0viIEf` | `v18_GuiControl_setRed_float` | red channel update |
| `0x1ba1ac` `GuiControl_setGreen_float` | `0x1bead0` `_ZN10w9XxgaJdbx10oDVIFaK5oIEf` | `v18_GuiControl_setGreen_float` | green channel update |
| `0x1ba1f0` `GuiControl_setBlue_float` | `0x1beb14` `_ZN10w9XxgaJdbx10EFcJFaGgEIEf` | `v18_GuiControl_setBlue_float` | blue channel update |
| `0x1ba234` `GuiControl_setAlpha_float` | `0x1beb58` `_ZN10w9XxgaJdbx10S0OSgapxJOEf` | `v18_GuiControl_setAlpha_float` | alpha channel update |

Every setter compares its consecutive channel field, updates only when the
value changes, invokes the shared color-state refresh helper, and invalidates
the control rectangle. The source and target preserve the same four-channel
method order and body shape. All four aliases were applied to a fresh
v340-derived database and verified after reopening.

The v341 database contains 11,707 functions, zero audited default names,
6,429 translated aliases, 419 target-only descriptive labels, 800 retained
target names, seven JNI exports, and 4,052 other IDA or PLT names. Dynamic
coverage reports 4,783 source-backed aliases and 1,688 exact retained dynamic
names. All 5,782 defined dynamic function symbols still resolve to exact IDA
function starts.

The saved database is
`analysis/spectron_libqplay_translated_v341_colorset_residual.i64` with
SHA-256
`f892d0eb81a79a242c41aeb19742dc33693863fd0373217727d2bba154d33d73`.
The machine-readable records are
`artifacts/spectron_colorset_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_colorset_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_colorset_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v341_colorset_residual.json`,
`artifacts/spectron_name_coverage_audit_v341.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v341.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v341.json`,
`artifacts/spectron_semantic_translation_v341.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v341.json`.
The reusable scripts are
`tools/generate_spectron_colorset_residual_anchors.py`,
`tools/carry_forward_spectron_semantic_translation_v341.py`, and
`tools/generate_spectron_translation_checkpoint_v341.py`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, alter TLS behavior, contact a game server, or test a
live endpoint.

### v340 tile and panel residual aliases

The v340 pass starts from the verified v339 database and translates four raw
entries in the TTilesBlock and TTilesPanel implementation. Direct compact
Hex-Rays pseudocode was captured for every source and target row, and all four
rows are exact normalized ARM64 matches.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | --- | --- | --- |
| `0x230a2c` `TTilesBlock_destroyImage_void` | `0x23a9a4` `_ZN10w7keKa2nGv10khjdKaaQOuEv` | `v18_TTilesBlock_destroyImage_void` | image destruction and pointer reset |
| `0x230b5c` `TTilesBlock_isTransparentWithout_int_int` | `0x23aad4` `_ZN10w7keKa2nGv10DnLcKawtluEii` | `v18_TTilesBlock_isTransparentWithout_int_int` | transparency bit-mask query |
| `0x230db4` `TTilesBlock_isBlackWithout_int_int` | `0x23ad2c` `_ZN10w7keKa2nGv10N2HYJa6FGhEii` | `v18_TTilesBlock_isBlackWithout_int_int` | black bit-mask query |
| `0x230ea0` `TTilesPanel_TTilesPanel_bool` | `0x23ae18` `_ZN10BEXWLaNNcXC1Eb` | `v18_TTilesPanel_TTilesPanel_bool` | constructor field initialization |

The image method invokes the image object's virtual destructor and clears its
pointer. The two tile queries preserve the x plus four-times-y bit index and
their separate transparency and black masks. The panel constructor copies its
boolean mode and clears the two integer fields and pointer. All four aliases
were applied to a fresh v339-derived database and verified after reopening.

The v340 database contains 11,707 functions, zero audited default names,
6,425 translated aliases, 419 target-only descriptive labels, 804 retained
target names, seven JNI exports, and 4,052 other IDA or PLT names. Dynamic
coverage reports 4,779 source-backed aliases and 1,692 exact retained dynamic
names. All 5,782 defined dynamic function symbols still resolve to exact IDA
function starts.

The saved database is
`analysis/spectron_libqplay_translated_v340_tiles_residual.i64` with SHA-256
`24a96367fa0730d1a125d146f4fd8e304ba96f6676c15deb2807d085671734d1`.
The machine-readable records are
`artifacts/spectron_tiles_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tiles_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tiles_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v340_tiles_residual.json`,
`artifacts/spectron_name_coverage_audit_v340.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v340.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v340.json`,
`artifacts/spectron_semantic_translation_v340.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v340.json`.
The reusable scripts are
`tools/generate_spectron_tiles_residual_anchors.py`,
`tools/carry_forward_spectron_semantic_translation_v340.py`, and
`tools/generate_spectron_translation_checkpoint_v340.py`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, alter TLS behavior, contact a game server, or test a
live endpoint.

### v339 geometry residual aliases

The v339 pass starts from the verified v338 database and translates four raw
entries in the rectangle and region geometry block. Direct compact Hex-Rays
pseudocode was captured for every source and target row, and all four rows
are exact normalized ARM64 matches.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | --- | --- | --- |
| `0x1e64f8` `TFloatRectangle_unionRects_TFloatRectangle_const` | `0x1ea7e4` `_ZN10vEhDgaHsFB10FwfGfa7F9NERKS_` | `v18_TFloatRectangle_unionRects_TFloatRectangle_const` | float rectangle union |
| `0x1e6574` `TDoubleRectangle_unionRects_TDoubleRectangle_const` | `0x1ea860` `_ZN10tIiGfa7lcO10FwfGfa7F9NERKS_` | `v18_TDoubleRectangle_unionRects_TDoubleRectangle_const` | double rectangle union |
| `0x1e65f0` `TRegion_TRegion_void` | `0x1ea8dc` `_ZN10e3mhxao0dCC1Ev` | `v18_TRegion_TRegion_void` | empty-region construction |
| `0x1e65f8` `TRegion_clear_void` | `0x1ea8e4` `_ZN10e3mhxao0dC5clearEv` | `v18_TRegion_clear_void` | region list cleanup |

The rectangle rows preserve the source minimum-origin and maximum-edge union
calculation for float and double values. The region constructor clears the
list head. The cleanup method walks the list, deletes entries, invokes list
destruction, and nulls the head. Three rows reinforce existing medium-
confidence semantic candidates, while the region constructor supplies new
context. All four aliases were applied to a fresh v338-derived database and
verified after reopening.

The v339 database contains 11,707 functions, zero audited default names,
6,421 translated aliases, 419 target-only descriptive labels, 808 retained
target names, seven JNI exports, and 4,052 other IDA or PLT names. Dynamic
coverage reports 4,774 source-backed aliases and 1,696 exact retained dynamic
names. All 5,782 defined dynamic function symbols still resolve to exact IDA
function starts.

The saved database is
`analysis/spectron_libqplay_translated_v339_geometry_residual.i64` with
SHA-256
`d50a0755bb461dada6b011b4df4ca01f9a0cbaf0112805b0ff1e5ab48764bebe`.
The machine-readable records are
`artifacts/spectron_geometry_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_geometry_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_geometry_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v339_geometry_residual.json`,
`artifacts/spectron_name_coverage_audit_v339.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v339.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v339.json`,
`artifacts/spectron_semantic_translation_v339.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v339.json`.
The reusable scripts are
`tools/generate_spectron_geometry_residual_anchors.py`,
`tools/carry_forward_spectron_semantic_translation_v339.py`, and
`tools/generate_spectron_translation_checkpoint_v339.py`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, alter TLS behavior, contact a game server, or test a
live endpoint.

### v338 THTMLPage lifecycle residual aliases

The v338 pass starts from the verified v337 database and translates seven raw
entries in the obfuscated `AS80gaE4zW` HTML-page class. Direct compact
Hex-Rays pseudocode was captured for every source and target row, and all
seven rows are exact normalized ARM64 matches.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | --- | --- | --- |
| `0x1d1318` `THTMLPage_initTabStops_void` | `0x1d5f6c` `_ZN10AS80gaE4zW10g3mRgak0vNEv` | `v18_THTMLPage_initTabStops_void` | tab-stop storage initialization |
| `0x1d1418` `THTMLPage_initLineTags_void` | `0x1d606c` `_ZN10AS80gaE4zW10EGlRgaCRuNEv` | `v18_THTMLPage_initLineTags_void` | line-tag storage initialization |
| `0x1d14b0` `THTMLPage_freeLineTags_void` | `0x1d6104` `_ZN10AS80gaE4zW10OZOQgaFv2MEv` | `v18_THTMLPage_freeLineTags_void` | linked line-tag cleanup |
| `0x1d14f8` `THTMLPage_initStyles_void` | `0x1d614c` `_ZN10AS80gaE4zW10XBgRgaCAqNEv` | `v18_THTMLPage_initStyles_void` | style storage initialization |
| `0x1d169c` `THTMLPage_initSubPages_void` | `0x1d62f0` `_ZN10AS80gaE4zW10uWkRgaPduNEv` | `v18_THTMLPage_initSubPages_void` | sub-page storage initialization |
| `0x1d276c` `THTMLPage_initLists_void` | `0x1d73c0` `_ZN10AS80gaE4zW10EmhRgaNdrNEv` | `v18_THTMLPage_initLists_void` | list-stack initialization |
| `0x1d2ad0` `THTMLPage_freeSubPages_void` | `0x1d7724` `_ZN10AS80gaE4zW10meOQgaMS1MEv` | `v18_THTMLPage_freeSubPages_void` | linked sub-page cleanup |

The five initializer rows clear the same `THTMLPage` member offsets and return
the receiver. The line-tag cleanup walks member index 43, clears and deletes
each node, and resets the head. The sub-page cleanup walks member index 44,
destroys and deletes each node, and resets that head. The target entries are
interleaved with already translated methods in exactly the source class order.

The v338 database contains 11,707 functions, zero audited default names,
6,417 translated aliases, 419 target-only descriptive labels, 4,769
source-backed dynamic rows, and 1,700 exact retained dynamic names. All 5,782
defined dynamic symbols still resolve to exact IDA function starts. The saved
database is
`analysis/spectron_libqplay_translated_v338_html_page_lifecycle.i64` with
SHA-256
`26584982aa976361088e7978b162d12e1be4bf2bf9991bf9484c56e92bba8c2d`.

The machine-readable records are
`artifacts/spectron_html_page_lifecycle_manual_translation_anchors_20260829.json`,
`artifacts/spectron_html_page_lifecycle_manual_translation_application_20260829.json`,
`artifacts/spectron_html_page_lifecycle_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v338_html_page_lifecycle.json`,
`artifacts/spectron_name_coverage_audit_v338.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v338.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v338.json`,
`artifacts/spectron_semantic_translation_v338.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v338.json`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, change TLS behavior, contact a game server, or test a
live endpoint.

### v337 libjpeg helper residual aliases

The v337 pass starts from the verified v336 database and translates twelve raw
libjpeg entries in two helper clusters. Direct compact Hex-Rays pseudocode was
captured for every source and target row, and all twelve rows are exact
normalized ARM64 matches.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | --- | --- | --- |
| `0x294ee8` `jpeg_get_small_jpeg_common_struct_ulong` | `0x2a2358` `_Z14jpeg_get_smallP18jpeg_common_structm` | `v18_jpeg_get_small_jpeg_common_struct_ulong` | small allocation |
| `0x294ef0` `jpeg_free_small_jpeg_common_struct_void_ulong` | `0x2a2360` `_Z15jpeg_free_smallP18jpeg_common_structPvm` | `v18_jpeg_free_small_jpeg_common_struct_void_ulong` | small release |
| `0x294ef8` `jpeg_get_large_jpeg_common_struct_ulong` | `0x2a2368` `_Z14jpeg_get_largeP18jpeg_common_structm` | `v18_jpeg_get_large_jpeg_common_struct_ulong` | large allocation |
| `0x294f00` `jpeg_free_large_jpeg_common_struct_void_ulong` | `0x2a2370` `_Z15jpeg_free_largeP18jpeg_common_structPvm` | `v18_jpeg_free_large_jpeg_common_struct_void_ulong` | large release |
| `0x294f08` `jpeg_mem_available_jpeg_common_struct_long_long_long` | `0x2a2378` `_Z18jpeg_mem_availableP18jpeg_common_structlll` | `v18_jpeg_mem_available_jpeg_common_struct_long_long_long` | memory amount passthrough |
| `0x294f10` `jpeg_open_backing_store_jpeg_common_struct_backing_store_struct_long` | `0x2a2380` `_Z23jpeg_open_backing_storeP18jpeg_common_structP20backing_store_structl` | `v18_jpeg_open_backing_store_jpeg_common_struct_backing_store_struct_long` | backing-store dispatch |
| `0x294f38` `jpeg_mem_init_jpeg_common_struct` | `0x2a23a8` `_Z13jpeg_mem_initP18jpeg_common_struct` | `v18_jpeg_mem_init_jpeg_common_struct` | initialization hook |
| `0x294f40` `jpeg_mem_term_jpeg_common_struct` | `0x2a23b0` `_Z13jpeg_mem_termP18jpeg_common_struct` | `v18_jpeg_mem_term_jpeg_common_struct` | termination hook |
| `0x297e40` `jdiv_round_up_long_long` | `0x2a52b0` `_Z13jdiv_round_upll` | `v18_jdiv_round_up_long_long` | upward integer division |
| `0x297e50` `jround_up_long_long` | `0x2a52c0` `_Z9jround_upll` | `v18_jround_up_long_long` | round to a multiple |
| `0x297ec8` `jcopy_block_row_short_64_short_64_uint` | `0x2a5338` `_Z15jcopy_block_rowPA64_sS0_j` | `v18_jcopy_block_row_short_64_short_64_uint` | 128-byte block copy |
| `0x297edc` `jzero_far_void_ulong` | `0x2a534c` `_Z9jzero_farPvm` | `v18_jzero_far_void_ulong` | far-buffer clear |

The first eight rows are the raw target memory-manager methods. The allocator
methods call malloc or free, the accounting hook returns its third argument,
and the backing-store method writes tag 49 before invoking the first callback.
The second cluster contains the rounding, coefficient-row copy, and buffer
clear helpers. Their pseudocode and normalized feature records agree exactly
between the two builds.

The v337 database contains 11,707 functions, zero audited default names,
6,410 translated aliases, 419 target-only descriptive labels, 4,762
source-backed dynamic rows, and 1,707 exact retained dynamic names. All 5,782
defined dynamic symbols still resolve to exact IDA function starts. The saved
database is
`analysis/spectron_libqplay_translated_v337_libjpeg_helper_residual.i64` with
SHA-256
`391d3bb01245f636760daeb8cef80012e602dfc04423d104a44ceb8e1e4d7113`.

The machine-readable records are
`artifacts/spectron_libjpeg_helper_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_libjpeg_helper_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_libjpeg_helper_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v337_libjpeg_helper_residual.json`,
`artifacts/spectron_name_coverage_audit_v337.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v337.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v337.json`,
`artifacts/spectron_semantic_translation_v337.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v337.json`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, change TLS behavior, contact a game server, or test a
live endpoint.

### v336 GSFunctionsInitstaticscriptvars and TFormat2 residual aliases

The v336 pass starts from the verified v335 database and translates nine raw
entries in the contiguous Format2 parameter block. Direct compact Hex-Rays
pseudocode was captured for every source and target row.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | --- | --- | --- |
| `0x20cd20` `gsfunctions_initStaticScriptVars_void` | `0x2130b0` `_Z10HWyrga7_Nrv` | `v18_gsfunctions_initStaticScriptVars_void` | count-37 function registration |
| `0x20ce88` `TFormat2_FormatParameters_getNextS32_void` | `0x213218` `_ZN10giqpgaXJ_p10mgCpgamO9pEv` | `v18_TFormat2_FormatParameters_getNextS32_void` | next signed number |
| `0x20cf10` `TFormat2_FormatParameters_getNextU32_void` | `0x2132a0` `_ZN10giqpgaXJ_p10tfvpgaJU3pEv` | `v18_TFormat2_FormatParameters_getNextU32_void` | next unsigned number |
| `0x20cfd0` `TFormat2_FormatParameters_getIndexedS32_int` | `0x213360` `_ZN10giqpgaXJ_p10a67ogaLqLpEi` | `v18_TFormat2_FormatParameters_getIndexedS32_int` | indexed signed number |
| `0x20d040` `TFormat2_FormatParameters_getIndexedU32_int` | `0x2133d0` `_ZN10giqpgaXJ_p10nn9ogamvMpEi` | `v18_TFormat2_FormatParameters_getIndexedU32_int` | indexed unsigned number |
| `0x20d0b0` `TFormat2_FormatParameters_TFormat2_FormatParameters` | `0x213440` `_ZN10giqpgaXJ_pD1Ev` | `v18_TFormat2_FormatParameters_TFormat2_FormatParameters` | D1/D2 destructor |
| `0x20d0c4` `TFormat2_FormatParameters_getIndexedString_int` | `0x213454` `_ZN10giqpgaXJ_p10Ym2oga0BGpEi` | `v18_TFormat2_FormatParameters_getIndexedString_int` | indexed string |
| `0x20d148` `TFormat2_FormatParameters_getNextString_void` | `0x2134f0` `_ZN10giqpgaXJ_p10B8wpgaSu5pEv` | `v18_TFormat2_FormatParameters_getNextString_void` | next string |
| `0x20d1d4` `TFormat2_FormatParameters_TFormat2_FormatParameters__2` | `0x213598` `_ZN10giqpgaXJ_pD0Ev` | `v18_TFormat2_FormatParameters_TFormat2_FormatParameters__2` | deleting D0 destructor |

Four rows match the complete normalized feature record. The initializer and
D1 rows differ only in register-detail allocation. The indexed and next
string methods record the target's expanded wrapper conversion and cleanup
layout. The D0 row was already an automatic semantic candidate and is
recorded here as an explicit manual promotion.

The v336 database contains 11,707 functions, zero audited default names,
6,398 translated aliases, 419 target-only descriptive labels, 4,750
source-backed dynamic rows, and 1,719 exact retained dynamic names. All 5,782
defined dynamic symbols still resolve to exact IDA function starts. The saved
database is
`analysis/spectron_libqplay_translated_v336_format2_residual.i64` with
SHA-256
`55662a1b9e5989c1e14350ab585015ccb6af0af123f12fab0dcab414f54ca199`.

The machine-readable records are
`artifacts/spectron_format2_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_format2_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_format2_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v336_format2_residual.json`,
`artifacts/spectron_name_coverage_audit_v336.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v336.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v336.json`,
`artifacts/spectron_semantic_translation_v336.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v336.json`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, change TLS behavior, contact a game server, or test a
live endpoint.

### v335 GSFunctionsClient and TAdventure residual aliases

The v335 pass starts from the verified v334 database and translates four raw
entries in the GSFunctionsClient and TAdventure blocks. The source and target
method order is preserved around each entry, and direct compact Hex-Rays
pseudocode was captured for every row.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | --- | --- | --- |
| `0x15ae0c` `gsfunctions_client_initStaticVars_void` | `0x15de64` `_Z10aitCvaXfZcv` | `v18_gsfunctions_client_initStaticVars_void` | static eight-byte shootparams storage |
| `0x15b4d0` `TAdventure_freeResources_void` | `0x15e528` `_ZN10oJlO1aTTY710wgSQgaCg5MEv` | `v18_TAdventure_freeResources_void` | graphics then sound cleanup |
| `0x15bf38` `TAdventure_handleMouseMove_void` | `0x15ef90` `_ZN10oJlO1aTTY710SenF1ahaq0Ev` | `v18_TAdventure_handleMouseMove_void` | empty mouse-move callback |
| `0x15c224` `TAdventure_initStaticScriptVars_void` | `0x15f27c` `_Z10H0oQ2aeFH_v` | `v18_TAdventure_initStaticScriptVars_void` | empty static-script callback |

Three rows match the complete normalized feature record. The static-variable
initializer is the one layout-change row, with only register-detail
allocation differing. The nearby empty target method at `0x15f724` is not
assigned because it has no established source counterpart beyond a data
reference.

The v335 database contains 11,707 functions, zero audited default names,
6,389 translated aliases, 419 target-only descriptive labels, 4,740
source-backed dynamic rows, and 1,728 exact retained dynamic names. All 5,782
defined dynamic symbols still resolve to exact IDA function starts. The saved
database is
`analysis/spectron_libqplay_translated_v335_adventure_static_residual.i64`
with SHA-256
`dae970eb4edf7237544073da7badb3cfe0bd9d3ccb03e8ec9bde5b5c7de73a16`.

The machine-readable records are
`artifacts/spectron_adventure_static_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_adventure_static_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_adventure_static_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v335_adventure_static_residual.json`,
`artifacts/spectron_name_coverage_audit_v335.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v335.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v335.json`,
`artifacts/spectron_semantic_translation_v335.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v335.json`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, change TLS behavior, contact a game server, or test a
live endpoint.

### v334 bitmap JPEG static initializer

The v334 pass starts from the verified v333 database and translates the
residual `TBitmap_jpeg_initStaticScriptVars_void` registration helper at
target `0x1541bc`. The source function at `0x151394` registers one JPEG
property definition. The target's obfuscated body makes the same one-entry
registration through its rebuilt `cWWYfaxbT2` property helper.

The source call is
`TScriptProperty_addProps_TProperties_TPropertyPropDef_int(0, &off_378268, 1)`.
The target call is `cWWYfaxbT2::hFWn2apYKC(0, &off_38B278, 1)`. Direct compact
Hex-Rays evidence and the adjacent translated TGA helper sequence make this
a high-confidence layout-change alias. The only normalized feature
difference is register-detail allocation.

The v334 database contains 11,707 functions, zero audited default names,
6,385 translated aliases, 419 target-only descriptive labels, 4,736
source-backed dynamic rows, and 1,732 exact retained dynamic names. All 5,782
defined dynamic symbols still resolve to exact IDA function starts. The saved
database is
`analysis/spectron_libqplay_translated_v334_bitmap_jpeg_static.i64` with
SHA-256
`c2002066a0412b180afd6abb36fe08f0873403d3068a2a0bdd88deb997101398`.

The machine-readable records are
`artifacts/spectron_bitmap_jpeg_static_manual_translation_anchors_20260829.json`,
`artifacts/spectron_bitmap_jpeg_static_manual_translation_application_20260829.json`,
`artifacts/spectron_bitmap_jpeg_static_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v334_bitmap_jpeg_static.json`,
`artifacts/spectron_name_coverage_audit_v334.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v334.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v334.json`,
`artifacts/spectron_semantic_translation_v334.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v334.json`.

This is a static IDA translation checkpoint. It did not patch the APK, rerun
the loopback client, change TLS behavior, contact a game server, or test a
live endpoint.

### v333 THashIntVar residual aliases

The v333 pass starts from the verified v332 database and translates the
obfuscated `SrwA5a7Ukj` destructor pair between the translated `THTMLColors`
and `TImageAnimation` blocks. The source alternative C++ name and target D1
or D0 symbols establish the destructor ABI relationship.

| Source role | Spectron address | Applied alias | Review result |
| --- | ---: | --- | --- |
| `THashIntVar_THashIntVar` | `0x11df60` | `v18_THashIntVar_THashIntVar` | complete D1/D2 cleanup; register-detail change |
| `THashIntVar_THashIntVar__2` | `0x11df74` | `v18_THashIntVar_THashIntVar__2` | deleting D0 cleanup; register-detail change |

Both bodies reset the vtable and clear the embedded string-like member at
offset 8. The deleting body then calls `operator delete`. The target uses its
rebuilt `CanTfaz6bZ` wrapper, so both rows differ only in register-detail
allocation while preserving normalized control-flow shape and cleanup order.
Direct compact Hex-Rays pseudocode is recorded for both source and target
rows. Both aliases were applied to a fresh v332-derived copy and verified
after reopening.

The v333 database contains 11,707 functions, zero audited default names,
6,384 translated aliases, 4,735 source-backed dynamic rows, and 1,733 exact
retained dynamic names. Its defined dynamic audit still resolves all 5,782
function symbols to exact IDA starts. The database is
`analysis/spectron_libqplay_translated_v333_hashintvar_residual.i64` with
SHA-256
`c6f31412206a9a893fedf594fac90dff2f13be69f2db28fcda80cc2c67ad7f4d`.
The records are
`artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_hashintvar_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_hashintvar_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v333_hashintvar_residual.json`,
`artifacts/spectron_name_coverage_audit_v333.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v333.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v333.json`,
`artifacts/spectron_semantic_translation_v333.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v333.json`.

### v332 TPanelOperation residual aliases

The v332 pass starts from the verified v331 database and translates the next
contiguous `TPanelOperation` and `TDrawingPanelProperties` sequence. The
target symbols are obfuscated, but the source and target retain the same
operation fields, bounds-result layout, C++ destructor forms, base cleanup,
and local method order.

| Source role | Spectron address | Applied alias | Review result |
| --- | ---: | --- | --- |
| `TPanelOperation_Clear_getBounds_void` | `0x11d318` | `v18_TPanelOperation_Clear_getBounds_void` | exact bounds copy |
| `TPanelOperation_DrawCurve_getBounds_void` | `0x11d344` | `v18_TPanelOperation_DrawCurve_getBounds_void` | exact endpoint bounds |
| `TPanelOperation_DrawStretched_getBounds_void` | `0x11d3d4` | `v18_TPanelOperation_DrawStretched_getBounds_void` | exact bounds copy |
| `TPanelOperation_DrawLine_getBounds_void` | `0x11d400` | `v18_TPanelOperation_DrawLine_getBounds_void` | exact endpoint bounds |
| `TPanelOperation_DrawText_getBounds_void` | `0x11d464` | `v18_TPanelOperation_DrawText_getBounds_void` | exact zeroed result |
| line, curve, and clear D1 boundaries | `0x11d47c`, `0x11d480`, `0x11d484` | three `v18_TPanelOperation_*` aliases | empty ABI boundaries |
| line, curve, and clear D0 boundaries | `0x11d530`, `0x11d534`, `0x11d538` | three `v18_TPanelOperation_*__2` aliases | `operator delete` forms |
| `TDrawingPanelProperties` destructor family | `0x11d4cc` to `0x11d528` | four `v18_TDrawingPanelProperties` aliases | vtable, base cleanup, and thunks |
| rectangle destructor family | `0x11d5ec`, `0x11d600` | two `v18_TPanelOperation_DrawRectangle` aliases | embedded resource cleanup |
| stretched-image destructor family | `0x11d630`, `0x11d644` | two `v18_TPanelOperation_DrawStretched` aliases | embedded resource cleanup |
| image deleting destructor | `0x11d688` | `v18_TPanelOperation_DrawImage_TPanelOperation_DrawImage__2` | embedded resource cleanup |

The five bounds rows are exact normalized ARM64 matches. The clear and
stretched methods copy the stored rectangle, the curve and line methods compute
endpoint minima and absolute extents, and the text method preserves the
zeroed four-field result. The target functions sit in the same order beside
the already translated rectangle and image operations.

The source IDA names for the six small operation entries look like
constructors because the historical database keeps alternative C++ names on
four-byte boundaries. Their source alternative names and the target `D1` and
`D0` symbols identify the actual destructor ABI roles. The D1 entries are
empty boundaries and the D0 entries release the object through
`operator delete`.

The `V8fxgahcBwProperties` target family resets both vtable pointers, calls
the base `TProperties` destructor, and uses 16-byte secondary-base thunks.
The `AK892aVY8g`, `zfJa3aJGDh`, and `EbOa3arQHh` destructor families clean up
their embedded `TResourceFileUser` members at the same class-local offsets as
the source operation objects. Seven rows differ only in register-detail
allocation; the other 13 match all normalized feature metrics.

All 20 aliases were applied to a fresh v331-derived copy and verified after
reopening. The v332 database contains 11,707 functions, zero audited default
names, 6,382 translated aliases, 4,732 source-backed dynamic rows, and 1,735
exact retained dynamic names. The defined dynamic audit still resolves all
5,782 function symbols to exact IDA starts.

The v332 database is
`analysis/spectron_libqplay_translated_v332_paneloperation_residual.i64` with
SHA-256
`f77edbe5076211bd3bd5a18c549f0c3cbaeeb88d2da7bc9c52a2733c1d87cdc2`.
Its records are
`artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_paneloperation_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_paneloperation_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v332_paneloperation_residual.json`,
`artifacts/spectron_name_coverage_audit_v332.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v332.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v332.json`,
`artifacts/spectron_semantic_translation_v332.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v332.json`.

### v331 static-variable runtime aliases

The v331 pass continues from the verified v330 database through the next
class-local residual block. It covers the universe static initializer, the
`TGraalPlayersArrayVar` destructor pair, the static and action variable
factories, and the complete property and object destructor families. The
target names are obfuscated, so each alias is backed by source and target
Hex-Rays pseudocode, ABI destructor form, function metrics, and local order.

| Source role | Spectron address | Applied alias | Review result |
| --- | ---: | --- | --- |
| `TScriptUniverse_initStaticScriptVars_void` | `0x236d04` | `v18_TScriptUniverse_initStaticScriptVars_void` | same property-registration initializer |
| `TScriptUniverseProperties_TScriptUniverseProperties` | `0x236d18` | `v18_TScriptUniverseProperties_TScriptUniverseProperties` | complete D1 destructor; register-detail change |
| `non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties` | `0x236d34` | `v18_non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties` | exact secondary-base thunk |
| `TScriptUniverseProperties_TScriptUniverseProperties__2` | `0x236d3c` | `v18_TScriptUniverseProperties_TScriptUniverseProperties__2` | deleting D0 destructor; register-detail change |
| `non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties__2` | `0x236d74` | `v18_non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties__2` | exact deleting thunk |
| `TGraalPlayersArrayVar_TGraalPlayersArrayVar` | `0x236d98` | `v18_TGraalPlayersArrayVar_TGraalPlayersArrayVar` | complete D1 destructor; register-detail change |
| `TGraalPlayersArrayVar_TGraalPlayersArrayVar__2` | `0x236dac` | `v18_TGraalPlayersArrayVar_TGraalPlayersArrayVar__2` | deleting D0 destructor; register-detail change |
| `jump_TScriptEnvironment_destroyScriptVariable_TGraalVar__2` | `0x236ddc` | `v18_jump_TScriptEnvironment_destroyScriptVariable_TGraalVar__2` | exact four-byte forwarder |
| `TStaticVar_create_TString_const` | `0x236f80` | `v18_TStaticVar_create_TString_const` | exact allocator and constructor sequence |
| `TStaticVar_TStaticVar` | `0x23702c` | `v18_TStaticVar_TStaticVar` | complete D2 destructor; register-detail change |
| `TStaticVar_TStaticVar__2` | `0x23705c` | `v18_TStaticVar_TStaticVar__2` | exact deleting D0 destructor |
| `TActionScriptVar_create_TString_const` | `0x2372c4` | `v18_TActionScriptVar_create_TString_const` | exact allocator and constructor sequence |
| `TStaticVarProperties_TStaticVarProperties` | `0x2373d4` | `v18_TStaticVarProperties_TStaticVarProperties` | complete D2 destructor; register-detail change |
| `non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties` | `0x2373f0` | `v18_non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties` | exact secondary-base thunk |
| `TActionScriptVarProperties_TActionScriptVarProperties` | `0x2373f8` | `v18_TActionScriptVarProperties_TActionScriptVarProperties` | complete D1 destructor; register-detail change |
| `non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties` | `0x237414` | `v18_non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties` | exact secondary-base thunk |
| `TStaticVarProperties_TStaticVarProperties__2` | `0x23741c` | `v18_TStaticVarProperties_TStaticVarProperties__2` | deleting D0 destructor; register-detail change |
| `non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties__2` | `0x237454` | `v18_non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties__2` | exact deleting thunk |
| `TActionScriptVarProperties_TActionScriptVarProperties__2` | `0x23745c` | `v18_TActionScriptVarProperties_TActionScriptVarProperties__2` | deleting D0 destructor; register-detail change |
| `non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties__2` | `0x237494` | `v18_non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties__2` | exact deleting thunk |
| `TActionScriptVar_TActionScriptVar` | `0x23749c` | `v18_TActionScriptVar_TActionScriptVar` | complete D1 destructor; register-detail change |
| `TActionScriptVar_TActionScriptVar__2` | `0x2374b0` | `v18_TActionScriptVar_TActionScriptVar__2` | deleting D0 destructor; register-detail change |

The target initializer at `0x236d04` makes the same one-call property-table
registration as the source. The `e4ZYfa8PV2Properties` functions reset two
vtable pointers, call the base property destructor, and release the receiver
for D0. The target thunks subtract 16 bytes from the secondary receiver, which
matches the source ABI boundary exactly.

The `JE42uaVwcK` pair follows the already translated array-cell method and
calls the obfuscated `G0gxgajWBw` base destructor. The four-byte jump wrapper
has the same one-instruction forwarding shape as the source environment
cleanup wrapper. The `NgNBgaN3oA` and `mH33wa4I1q` factories each allocate
`0x88` bytes, while their destructors preserve the static-variable garbage
collector cleanup, base destruction, and `operator delete` sequence.

Ten of the 22 rows have exact normalized metrics. The remaining twelve differ
only in the register-detail hash. That difference reflects compiler register
allocation in the obfuscated build and does not change the body shape or
operation. All 22 rows have pseudocode on both sides, are marked high
confidence, and were absent from the automatic semantic map before review.

The application renamed all 22 functions and added 22 evidence comments with
zero failures. Reopening the fresh copy verified all 22 names. The v331
database has 11,707 functions and zero audited default names, with 6,362
translated aliases, 4,706 source-backed dynamic rows, 1,755 exact retained
target names, and 5,782 exact dynamic function starts.

The private database is
`analysis/spectron_libqplay_translated_v331_tscript_var_residual.i64` with
SHA-256
`f6bb72c43b0022b372d6d98e4143aa920a7e3c43cd5a89ede10e7510cd00178c`.
The machine-readable records are
`artifacts/spectron_tscript_var_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v331_tscript_var_residual.json`,
`artifacts/spectron_name_coverage_audit_v331.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v331.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v331.json`,
`artifacts/spectron_semantic_translation_v331.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v331.json`.

This pass changed only the private IDA copy and the research archive. It did
not patch the APK, rerun the loopback client, alter TLS behavior, contact a
game server, or test a live endpoint.

### v330 TScriptUniverse residual aliases

The v330 pass follows the v329 TScriptSpace work into the next raw
`e4ZYfa8PV2` TScriptUniverse block. Six source-backed aliases were reviewed
against compact Hex-Rays pseudocode, target parameter classes, normalized
feature records, and class-local order.

| 1.8 source | Spectron target | Applied alias | Match class |
| ---: | ---: | --- | --- |
| `0x22b1f8` | `0x234bc0` | `v18_TScriptExecutionStats_TScriptExecutionStats__2` | exact D0 destructor |
| `0x22b3b4` | `0x234d98` | `v18_TScriptUniverse_setExecutingNPC_TServerNPC` | register-detail change |
| `0x22b3d0` | `0x234db4` | `v18_TScriptUniverse_setExecutingPlayer_TServerPlayer` | register-detail change |
| `0x22b614` | `0x235000` | `v18_TScriptUniverse_removeStaticObject_TGraalVar` | exact normalized metrics |
| `0x22c068` | `0x235a50` | `v18_TScriptUniverse_addToFreeMachines_TScriptMachine` | exact normalized metrics |
| `0x22c210` | `0x235bf8` | `v18_TScriptUniverse_TScriptUniverse__2` | exact D0 destructor |

The source `TScriptExecutionStats` deleting destructor maps to the target
`R94BFa3XE` D0 boundary. The target calls the complete destructor and then
`operator delete`, with the same normalized feature record. The two execution
state setters preserve the source stores for the current and action NPC or
player. Their target parameters are `LBgVgaqANQ` and `MpGzgariDy`, the
translated TServerNPC and TServerPlayer classes, and their only recorded
difference is register-detail allocation.

The static-object remover reads the universe's hash-list field, returns when
it is absent, and otherwise removes the supplied `G0gxgajWBw` variable. The
free-machine helper checks the `mTAogaaEip` machine against the free-machine
list before appending it. Both are exact normalized matches and sit beside
the already translated `clearVars`, `addStaticObject`, `getFreeMachine`, and
`clearGraalScriptMachines` methods. The final row is the target
`e4ZYfa8PV2` deleting destructor and is an exact D0 match.

The anchor generator records four exact metric rows, two register-detail
layout rows, six pseudocode-backed high-confidence anchors, and no new
automatic semantic-map matches. The application renamed all six functions
and added six evidence comments with zero failures. Reopening the fresh copy
verified all six names in the 11,707-function database.

The v330 database contains 6,340 translated `v18_` aliases and no audited
default names. Its dynamic audit reports 4,679 source-backed aliases, 1,776
exact retained target names, 136 other retained target names, 419 target-only
descriptive labels in the full name audit, and 5,782 exact dynamic function
starts. The complete records are
`artifacts/spectron_tscript_universe_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_universe_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_universe_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v330_tscript_universe_residual.json`,
`artifacts/spectron_name_coverage_audit_v330.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v330.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v330.json`,
`artifacts/spectron_semantic_translation_v330.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v330.json`.

The private packed IDA database is
`analysis/spectron_libqplay_translated_v330_tscript_universe_residual.i64`
with SHA-256
`be32d09e08a76b3641beff951644ec78167fcc2735d5fc5ea58f9ee12acf97a1`.
This pass changed only the private IDA copy and the archive. It did not patch
the APK, rerun the loopback client, alter TLS behavior, contact a game
server, or test a live endpoint.

### v329 TScriptSpace residual aliases and target-only labels

The v329 pass continues through the residual `N67CMatrxw` script-space block.
It adds two reviewed source-backed aliases and two descriptive labels for
target-only boundaries:

| 1.8 source | Spectron target | Applied name | Evidence role |
| ---: | ---: | --- | --- |
| `0x227454` | `0x230198` | `v18_TScriptSpace_freeSuspendedStates_void` | exact saved-state cleanup |
| `0x229f44` | `0x233114` | `v18_TScriptSpace_joinClass_TString_const_bool` | class join and permission path |
| none claimed | `0x23332c` | `spectron_TScriptSpace_receiveEvent_TString_const_CanTfaz6bZ_const_TGraalVar` | target-only event overload |
| none claimed | `0x2339b4` | `spectron_TScriptSpace_clearScheduledEventsAndCancelActions_void` | target-only queue cleanup |

The `freeSuspendedStates` row is an exact normalized feature match. Both
functions delete every saved machine state from field 16, clear the list, and
write a null pointer. The `joinClass(..., bool)` row is a layout-change match:
the source and target retain the same empty-script setup, class lookup,
permission check, join, catcher installation, and class-update action, while
the target's rebuilt wrappers add temporary construction and cleanup.

The `0x23332c` target function has a separate ABI boundary with a
`CanTfaz6bZ` event-name argument. Its pseudocode repeats the event limit,
duplicate detection, priority insertion, and activation policy of the
already translated `receiveEvent` method. The `0x2339b4` helper has no
argument, deletes every scheduled event, and marks every pending action as
canceled. Neither target-only boundary has a distinct 1.8 source function in
the recovered method set, so neither is counted as a source correspondence.

Both source aliases and both descriptive labels were applied to fresh
v328-derived IDA copies and verified after reopening. The v329 database has
11,707 functions, zero audited default names, 6,334 translated `v18_`
aliases, 419 target-only descriptive labels, and 5,782 exact dynamic
function starts. Dynamic coverage reports 4,673 source-backed aliases and
1,782 exact retained names.

The v329 records are
`artifacts/spectron_tscript_space_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_space_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_space_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_tscript_space_residual_labels_20260829.json`,
`artifacts/spectron_tscript_space_residual_label_application_20260829.json`,
`artifacts/spectron_tscript_space_residual_label_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v329.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v329.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v329.json`,
`artifacts/spectron_semantic_translation_v329.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v329.json`. The reusable
helpers are `tools/generate_spectron_tscript_space_residual_anchors.py`,
`tools/generate_spectron_tscript_space_residual_labels.py`, and
`tools/generate_spectron_translation_checkpoint_v329.py`.

### v328 TScriptMachine static-tail aliases

The v328 pass closes two raw functions immediately after the v327 property
runtime group:

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | ---: | --- | --- |
| `0x21f30c` | `0x227780` | `v18_TScriptMachine_initStaticScriptVars_void` | static property-object registration |
| `0x21f394` | `0x227808` | `v18_TCallStackEntry_TCallStackEntry__2` | deleting TCallStackEntry destructor |

The first row is a layout-change anchor. Both helpers allocate and register a
global `TCallStackEntryProperties` object, but the target allocates 0x68 bytes
for its rebuilt `l8eTfaIl5YProperties` class instead of the source 0x58 bytes.
The second row is an exact normalized feature match: the target D0 body calls
the D2 destructor and then `operator delete`.

Both aliases were applied to a fresh v327-derived copy and verified after
reopening. The v328 database has 11,707 functions, zero audited default names,
6,332 translated aliases, 4,671 source-backed dynamic rows, and 1,786 exact
retained dynamic names. The target overload at `0x221928` remains outside the
source-backed count because it is a `C8THgaTQxF` to `CanTfaz6bZ` string-wrapper
adapter around the already translated resolver.

The v328 records are
`artifacts/spectron_script_machine_static_tail_manual_translation_anchors_20260829.json`,
`artifacts/spectron_script_machine_static_tail_manual_translation_application_20260829.json`,
`artifacts/spectron_script_machine_static_tail_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v328.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v328.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v328.json`,
`artifacts/spectron_semantic_translation_v328.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v328.json`. The reusable
generators are
`tools/generate_spectron_script_machine_static_tail_anchors.py` and
`tools/generate_spectron_translation_checkpoint_v328.py`.

### v327 property construction and destructor-tail aliases

The v327 pass continues through the property runtime after v326. It closes
the target constructor, compiler, lookup, static-registration, and cleanup
entries that were still carrying obfuscated names. The nearby one-argument
`cWWYfaxbT2` constructor remains intentionally unaliased because it is an
additional target overload without an independently established 1.8 source
counterpart.

| 1.8 source | Spectron target | Applied alias | Evidence role |
| ---: | ---: | --- | --- |
| `0x225c14` | `0x22e49c` | `v18_TProperties_TProperties_TString_const_TString_const` | named property construction and global registration |
| `0x225cb8` | `0x22e568` | `v18_TProperties_compileProperties_void` | inherited and local property compilation |
| `0x225ea0` | `0x22e748` | `v18_getPropertyList_TString_const` | global property-list lookup |
| `0x225ee8` | `0x22e790` | `v18_TObjectCreator_TObjectCreator_TString_const_TGraalVar_TString_const` | object-creator callback registration |
| `0x22693c` | `0x22f540` | `v18_TScriptProperty_initStaticScriptVars_void` | static property definition registration |
| `0x226950` | `0x22f554` | `v18_TObjectCreator_TObjectCreator` | object-creator D1/D2 cleanup |
| `0x226964` | `0x22f568` | `v18_TObjectCreator_TObjectCreator__2` | object-creator D0 cleanup |
| `0x226994` | `0x22f598` | `v18_TScriptProperty_TScriptProperty` | TScriptProperty D1/D2 cleanup |
| `0x2269d4` | `0x22f5d8` | `v18_TScriptProperty_TScriptProperty__2` | TScriptProperty D0 cleanup |
| `0x226a1c` | `0x22f620` | `v18_TAniProperty_TAniProperty` | animation-property cleanup |
| `0x226a5c` | `0x22f660` | `v18_TAniProperty_TAniProperty__2` | animation-property D0 cleanup |
| `0x226aa4` | `0x22f6a8` | `v18_TJoinedClassesProperty_TJoinedClassesProperty` | joined-property cleanup |
| `0x226ae4` | `0x22f6e8` | `v18_TJoinedClassesProperty_TJoinedClassesProperty__2` | joined-property D0 cleanup |
| `0x226b2c` | `0x22f730` | `v18_TAcceptStringProperty_TAcceptStringProperty` | accept-property D1/D2 cleanup |
| `0x226b6c` | `0x22f770` | `v18_TAcceptStringProperty_TAcceptStringProperty__2` | accept-property D0 cleanup |

All 15 rows are high-confidence layout-change anchors. The source and target
constructors agree on global registry ownership and inherited compilation.
The cleanup pairs agree on the D1, D2, and D0 C++ ABI forms, vtable reset,
string cleanup, and object deletion. Register-detail differences remain in
the normalized records because the target uses its rebuilt string wrapper.

All 15 aliases were applied to a fresh v326-derived copy and all 15 were
verified after reopening. The final database has 11,707 functions and zero
audited default names. The v327 name-origin counts are 6,330 translated
`v18_` aliases, 417 target-only descriptive labels, 900 retained target
names, seven JNI exports, and 4,053 other IDA or PLT names. Dynamic coverage
reports 4,669 source-backed aliases, 1,788 exact retained names, and 136
other retained target names. The database hash is
`cc731360c7c08f825a7905c760897d3a7aede1dccdb4322d56d72f5c2e0c2f13`.

The v327 records are
`artifacts/spectron_property_constructor_destructor_manual_translation_anchors_20260829.json`,
`artifacts/spectron_property_constructor_destructor_manual_translation_application_20260829.json`,
`artifacts/spectron_property_constructor_destructor_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v327.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v327.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v327.json`,
`artifacts/spectron_semantic_translation_v327.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v327.json`. The reusable
generators are
`tools/generate_spectron_property_constructor_destructor_anchors.py` and
`tools/generate_spectron_translation_checkpoint_v327.py`.

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
