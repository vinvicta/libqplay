# libqplay research archive

This repository records a careful reverse-engineering pass over the ARM64
`libqplay.so` shipped with Graal Online Classic 1.8, together with a small
set of local-only protocol tools. The goal is to make the work reproducible
for people who have a lawful copy of the client and are trying to understand
why an old installation no longer starts.

The notes are written as a lab record. They separate facts observed in the
binary, facts reproduced in an emulator, and hypotheses that still need a
server-side test. That distinction matters here because a successful TCP
handshake is not the same thing as a successful game login.

## Current status

The current documented translation frontier is the v296 Spectron database. It
contains 11,696 functions and 531 remaining default `sub_` names. The v263
revision added three reviewed cross-build aliases for the
`GuiCanvas` dialog callback, `TGraalVar` trigger, and Facebook graph upload
callbacks. The v264 revision added 22 target-only names for the Android and
JNI bridge block. The v265 revision added four high-confidence legacy Android
anchors for the TapJoy credential setters, the TapJoy connector, and the
Android ID helper. The v266 revision added an initial five target-only Android
and anti-instrumentation labels. The v267 revision corrects a table-indexing
error in that set and adds the missed `getjavaclassexists` callback, leaving
six reviewed target-only labels. The v268 revision resolves the separate
`quattro::android::getsignature` package-signature helper. The v269 revision
adds five reviewed TGraalVar script callbacks, four exact metric matches and
one target-layout match, plus a target-only `loadvarsfromarray` callback whose
encoded table name decodes exactly. The v270 revision adds 17 script-table
callback anchors across the GUI, TGraalVar, and TTiles surfaces. It also
corrects the earlier dialog assignment: target `0x1b5cf8` is `pushdialog`,
while target `0x1b58c4` is `popdialog`. The v271 revision adds nine exact
runtime callback anchors for the TStream, zlib, and YAJL helper blocks, plus
two target-only TPlayer property labels for the Quattro zoom-culling getter
and setter. These names come from target tables, Java method strings,
retained callers, installation sites, and reviewed pseudocode. They are
labels for this stripped 2.2 library, not claims that original debug symbols
were recovered. The v272 revision adds one high-confidence zlib
`inflate_fast` role label at target `0x297764`. Both source and target
databases kept default names at that address, so the artifact records the
inferred library role separately from the current IDA names.
The v273 revision adds six high-confidence libjpeg source and destination
callback labels. They are tied to the target `jpeg_stdio_dest` and
`jpeg_stdio_src` installation sites, with exact or normalized source-target
feature matches.
The v274 revision adds four high-confidence libjpeg input-controller labels.
They are tied to the `consume_input`, `reset_input_controller`,
`start_input_pass`, and `finish_input_pass` slots installed by the target
`jinit_input_controller` routine, with exact or normalized source-target
feature matches.
The v275 revision adds nine high-confidence libjpeg marker-reader labels.
They are tied to the target marker-reader callback table and marker-loop call
sites, with eight complete metric matches and one register-allocation-only
difference.
The v276 revision adds seven high-confidence libjpeg output-pipeline labels.
They cover the two master-decompress output-pass callbacks and the five
merged-upsampler start, wrapper, and conversion routines. All seven have
complete source-target feature matches.
The v277 revision adds five high-confidence progressive-Huffman decoder
labels. They cover the start-pass dispatcher and the DC/AC first and
successive-approximation MCU decoders. All five preserve normalized source
target shape, with one complete metric match and four register-allocation-only
differences.
The v278 revision adds four high-confidence libjpeg postprocessing labels.
They cover the post-controller start-pass switch, one-pass quantization, and
the first and second passes of two-pass quantization. All four preserve
normalized source-target shape, with three complete metric matches.
The v279 revision adds nine high-confidence libjpeg upsampler labels. They
cover the start and row-processing callbacks, full-size and unused-component
paths, horizontal and vertical 2:1 expansion, fancy interpolation, generic
integral expansion, and the simple h2v2 path. All nine match the complete
recorded ARM64 feature set.
The v280 revision adds five high-confidence libjpeg error-handler labels.
They cover message emission, error-state reset, message formatting, stderr
output, and fatal exit handling. Four are complete metric matches, and one
differs only in register allocation detail.
The v281 revision adds eleven high-confidence libjpeg memory-manager labels.
They cover small and large allocation, sample and coefficient arrays, virtual
array realization and access, pool release, and manager teardown. Nine match
normalized features, six match the complete feature set, and two retain an
explicit call-layout difference caused by source PLT calls versus target
exports.
The v282 revision adds eight high-confidence libjpeg one-pass color-quantizer
labels. They cover the plain, ordered-dither, and Floyd-Steinberg row paths,
the start and finish callbacks, and the new-color-map error callback. All
eight match normalized features, and seven match the complete feature set.
The v283 revision adds nine high-confidence libjpeg two-pass color-quantizer
labels. They cover the histogram prescan, palette selection, inverse-map
filling, non-dithered mapping, Floyd-Steinberg mapping, pass callbacks, and
box updates. All nine match normalized features, and eight match the complete
feature set.
The v284 revision adds seven high-confidence libjpeg coefficient-controller
labels. They cover full-buffer and single-MCU input, normal and smoothed
output, pass setup, and one-pass decompression. All seven match normalized
features, and six match the complete feature set. The coefficient-controller
`start_input_pass` label is disambiguated because another file-local libjpeg
function with the same source name was already translated from `jdinput.c`.
The v285 revision adds six high-confidence libjpeg color-deconverter labels.
They cover YCbCr-to-RGB, direct component interleave, grayscale-to-RGB,
YCCK-to-CMYK, the empty pass callback, and grayscale copy. All six match the
complete recorded feature set.
The v286 revision adds one high-confidence libjpeg inverse-DCT manager label.
It identifies the start-pass callback that selects the per-component IDCT
method and rebuilds the matching multiplier tables. Its normalized metrics
match, with only register allocation detail differing.
The v287 revision adds two high-confidence libjpeg baseline-Huffman decoder
labels. They identify the entropy start-pass callback and the baseline MCU
decoder callback in the target `jinit_huff_decoder` initializer. The
start-pass row is an exact feature match. The MCU decoder has matching
instruction count, mnemonic sequence, control-flow counts, and reviewed
pseudocode; one relocated `PAGEOFF` operand lands in a different coarse
operand bucket, so that exception is recorded in the artifact.
The v288 revision adds four high-confidence libjpeg main-controller labels.
They identify the simple row path, context-row path, final two-pass crank
path, and pass dispatcher in the target `jinit_d_main_controller` initializer.
All four match normalized feature shape, and three match the complete feature
set.
The v289 revision adds six high-confidence libjpeg compressor color-converter
labels. They identify the RGB-to-YCbCr table initializer, RGB-to-YCbCr and
RGB-to-grayscale converters, CMYK-to-YCCK conversion, and the compressor-side
grayscale and direct-copy paths. All six match the complete recorded feature
set. The two duplicate file-local role names use a `c_` qualifier so they do
not collide with the decompressor-side `jdcolor.c` labels.
The v290 revision adds five high-confidence libjpeg compressor coefficient
controller labels. They identify the iMCU-row reset helper, pass-through,
full-buffer, and crank-destination data paths, plus the pass dispatcher. All
five match normalized feature shape, and four match the complete recorded
feature set.
The v291 revision adds three high-confidence libjpeg forward-DCT manager
labels. They identify the forward-DCT start-pass routine, the shared integer
quantization path, and the floating-point quantization path. All three match
normalized feature shape, and two match the complete recorded feature set.
The v292 revision adds five high-confidence libjpeg compressor Huffman
encoder labels. They identify the gather-statistics encoder, normal encoder,
both finish-pass callbacks, and the start-pass dispatcher. All five match
normalized feature shape, and two match the complete recorded feature set.
The v293 revision adds six high-confidence libjpeg compressor controller
labels. They identify the `jcmainct.c` row-processing and pass-start
callbacks, plus the `jcmaster.c` initial setup, pass startup, pass finish, and
per-pass preparation callbacks. All six match normalized feature shape, and
five match the complete recorded feature set. The two compressor callbacks
with the same upstream static names use a `c_` qualifier so they remain
distinct from the decompressor callbacks already translated in this archive.
The v294 revision adds eight high-confidence libjpeg progressive-Huffman
compressor labels. They identify the progressive start-pass dispatcher, the
DC and AC first/refinement encoders, the two finish callbacks, and the shared
end-of-band-run helper. All eight match normalized feature shape, and five
match the complete recorded feature set. The v294 pass also refreshed the
packed v293 database hash after IDA metadata was persisted during an evidence
read.
The v295 revision adds ten high-confidence libjpeg compressor preprocessing
and downsampling labels. They identify the two preprocessing paths, the
preprocessing start callback, the public component dispatcher, and the
integral, 2:1, smoothed, and full-size downsampling routines. All ten match
the complete recorded feature set.
The v296 revision adds one high-confidence internal GIF decoder label for
`DGifDecompressLine`. It also records a database-boundary finding: the
64-byte NEON constant pools at source `0x2ac400` and target `0x2b9870` are
not functions, even though IDA initially created `sub_` entries there. The
actual integer forward-DCT functions begin at `0x2ac440` and `0x2b98b0`.
The saved databases are
`analysis/spectron_libqplay_translated_v263_corrected.i64`,
`analysis/spectron_libqplay_translated_v264_corrected.i64`,
`analysis/spectron_libqplay_translated_v265.i64`,
`analysis/spectron_libqplay_translated_v266.i64`,
`analysis/spectron_libqplay_translated_v267.i64`,
`analysis/spectron_libqplay_translated_v268.i64`, and the v269 frontier in
`analysis/spectron_libqplay_translated_v269.i64`. The v270 database is kept
locally as `analysis/spectron_libqplay_translated_v270.i64`, and the v271
database is kept locally as
`analysis/spectron_libqplay_translated_v271.i64`. The current v272 database is
kept locally as `analysis/spectron_libqplay_translated_v272.i64`. The current
v273 database is kept locally as
`analysis/spectron_libqplay_translated_v273.i64`. Their hashes and reopen
reports are recorded in their checkpoints because packed IDA files are
intentionally excluded from the public repository.
The current v274 database is kept locally as
`analysis/spectron_libqplay_translated_v274.i64`.
The current v275 database is kept locally as
`analysis/spectron_libqplay_translated_v275.i64`.
The current v276 database is kept locally as
`analysis/spectron_libqplay_translated_v276.i64`.
The current v277 database is kept locally as
`analysis/spectron_libqplay_translated_v277.i64`.
The current v278 database is kept locally as
`analysis/spectron_libqplay_translated_v278.i64`.
The current v279 database is kept locally as
`analysis/spectron_libqplay_translated_v279.i64`.
The current v280 database is kept locally as
`analysis/spectron_libqplay_translated_v280.i64`.
The current v281 database is kept locally as
`analysis/spectron_libqplay_translated_v281.i64`.
The current v282 database is kept locally as
`analysis/spectron_libqplay_translated_v282.i64`.
The current v283 database is kept locally as
`analysis/spectron_libqplay_translated_v283.i64`.
The current v284 database is kept locally as
`analysis/spectron_libqplay_translated_v284.i64`.
The current v285 database is kept locally as
`analysis/spectron_libqplay_translated_v285.i64`.
The current v286 database is kept locally as
`analysis/spectron_libqplay_translated_v286.i64`.
The current v287 database is kept locally as
`analysis/spectron_libqplay_translated_v287.i64`.
The current v288 database is kept locally as
`analysis/spectron_libqplay_translated_v288.i64`.
The current v289 database is kept locally as
`analysis/spectron_libqplay_translated_v289.i64`.
The current v290 database is kept locally as
`analysis/spectron_libqplay_translated_v290.i64`.
The current v291 database is kept locally as
`analysis/spectron_libqplay_translated_v291.i64`.
The current v292 database is kept locally as
`analysis/spectron_libqplay_translated_v292.i64`.
The current v293 database is kept locally as
`analysis/spectron_libqplay_translated_v293.i64`.
The current v294 database is kept locally as
`analysis/spectron_libqplay_translated_v294.i64`.
The current v295 database is kept locally as
`analysis/spectron_libqplay_translated_v295.i64`.
The current v296 database is kept locally as
`analysis/spectron_libqplay_translated_v296.i64`.

The 22 bridge labels include deep-link and push-notification accessors,
Android version helpers, Google Play and Firebase calls, notification
operations, signing-key setters, generic Java static helpers, and the Android
system-property bridge. The v265 legacy anchors connect the target TapJoy
credential slots and `connectToTapJoyService([B[B)Z` path back to their 1.8
callbacks. The target Android ID helper is also now labeled from its matching
1.8 body. The v266 target-only set records `getandroidabi`, Java class and
method existence helpers, the Frida action setter, and a nanosleep loop called
by the retained Frida detection routines. The correction distinguishes
`getstaticjavafuncexists` at `0x2500EC` from `getjavaclassexists` at
`0x250090`, which the initial v266 artifact had reversed. The v268 pass also
labels the package-signature helper at `0x24A9EC` after decoding its
`getPackageInfo`, `signatures[0]`, and `toCharsString` path. The Frida labels
describe observed control flow and do not by themselves identify the reason
a client fails to start.

The nearby bridge registrations are now separated by their actual bodies. The
`getinstallerpackagename` callback calls
`PackageManager.getInstallerPackageName(packageName)`, while
`quattro::android::getsignature` calls `getPackageInfo`, reads
`signatures[0]`, and returns `toCharsString()`. The Android ID helper is a
separate target function at `0x2502F4`. This corrects an earlier swapped
description in the notes and keeps the three behaviors distinct.

The v269 script-runtime pass translates `clearvars`, `savejsontostring`,
`parsejson`, `loadini`, and `addnamedstring` in the target TGraalVar callback
tables. The first four target bodies are exact metric matches to their 1.8
wrappers. `addnamedstring` has the same callback role and result assignment but
constructs a target `CanTfaz6bZ` name temporary, so it is recorded as a
layout-change match. The adjacent target-only `loadvarsfromarray` callback at
`0x218870` has an exact decoded table name and converts an array of variables
through `readString` before calling `loadVarsFromArray`.

The v269 evidence is in
`artifacts/spectron_tgraalvar_script_runtime_manual_translation_anchors_20260828.json`
and
`artifacts/spectron_tgraalvar_target_only_labels_20260828.json`. The final
database and all six newly reviewed names were reopened with zero failures.
The v269 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v269.json`.

The v270 script-table evidence is in
`artifacts/spectron_script_table_surface_manual_translation_anchors_20260828.json`.
It covers `pushdialog`, `popdialog`, `iscursoron`, the first-responder and
repaint callbacks, the scroll-to-top and scroll-to-bottom callbacks, six
TGraalVar script functions, and four TTiles callbacks. Twelve rows match the
complete recorded feature set, three preserve the normalized body shape with
register-detail changes, and two are layout changes caused by rebuilt target
wrappers. The artifact also records the correction to the earlier
`0x1b5cf8` label. The v270 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v270.json`.

The v271 runtime callback evidence is in
`artifacts/spectron_runtime_callback_residual_manual_translation_anchors_20260828.json`.
It records nine exact source-to-target anchors: four TStream zlib file
callbacks, two zlib allocator callbacks, and three YAJL allocator callbacks.
The target-only TPlayer property evidence is in
`artifacts/spectron_tplayer_quattro_zoom_property_target_only_labels_20260828.json`.
It labels the getter at `0x170334` and setter at `0x170344` for the readable
target property
`Quattro::Rendering::Quattro2D::useQuattroZoomFactorCulling`. No 1.8 source
counterpart is claimed for that property. The v271 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v271.json`; it records
the reopened database with 11,696 functions and 670 remaining default names.

The v272 zlib evidence is in
`artifacts/spectron_zlib_inflate_fast_manual_translation_anchor_20260828.json`.
It records the source default helper at `0x28a2f4` and the target default
helper at `0x297764`, both called from their respective `inflate` routines.
The bodies share the zlib error strings, Huffman decode path, backreference
copy loop, and every recorded feature metric except register allocation
detail. The v272 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v272.json`; it records
the reopened database with 669 remaining default names.

The v273 libjpeg evidence is in
`artifacts/spectron_jpeg_io_manual_translation_anchors_20260828.json`.
It labels the three destination callbacks installed by
`v18_jpeg_stdio_dest` and the three source callbacks installed by
`v18_jpeg_stdio_src`. Their bodies implement the standard libjpeg buffer
initialization, refill, skip, flush, and final-write operations. The v273
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v273.json`; it records
the reopened database with 663 remaining default names.

The v274 libjpeg controller evidence is in
`artifacts/spectron_jpeg_input_controller_manual_translation_anchors_20260828.json`.
It labels the four callbacks installed by the stripped target's
`jinit_input_controller` routine. The source and target bodies match in
normalized feature shape, with two complete metric matches and two
register-allocation-only differences. The role names follow the standard
[libjpeg-turbo `jdinput.c` controller contract](https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/src/jdinput.c).
The v274 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v274.json`; it records
the reopened database with 659 remaining default names.

The v275 libjpeg marker-reader evidence is in
`artifacts/spectron_jpeg_marker_reader_manual_translation_anchors_20260828.json`.
It labels nine residual `jdmarker.c` roles, including SOF parsing, APP0
inspection, DHT parsing, marker saving and skipping, marker-reader reset,
the marker state machine, and restart-marker handling. Eight rows match the
complete recorded feature set and one differs only in register allocation.
The artifact also records that `get_soi`, `get_sos`, `get_dqt`, `get_dri`,
`next_marker`, and `first_marker` are represented inside larger target
functions instead of separate IDA function starts. The v275 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v275.json`; it records
the reopened database with 650 remaining default names.

The v276 libjpeg output-pipeline evidence is in
`artifacts/spectron_jpeg_master_merge_manual_translation_anchors_20260828.json`.
It labels the master-decompress `prepare_for_output_pass` and
`finish_output_pass` callbacks, then the merged-upsampler
`start_pass_merged_upsample`, `merged_1v_upsample`, `h2v1_merged_upsample`,
`h2v2_merged_upsample`, and `merged_2v_upsample` routines. The target
initializer at `0x29cd30` installs the master callbacks. The initializer at
`0x29d808` selects the one-row or two-row wrapper and its corresponding
conversion method. All seven rows match the complete recorded ARM64 feature
set. The v276 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v276.json`; it records
the reopened database with 643 remaining default names.

The v277 libjpeg progressive-Huffman evidence is in
`artifacts/spectron_jpeg_progressive_huffman_manual_translation_anchors_20260828.json`.
It labels `start_pass_phuff_decoder`, `decode_mcu_AC_refine`,
`decode_mcu_AC_first`, `decode_mcu_DC_refine`, and `decode_mcu_DC_first`.
The target `v18_jinit_phuff_decoder_jpeg_decompress_struct` initializer at
`0x29ea4c` installs the start-pass callback. Its dispatcher chooses the four
MCU decoders from the scan's DC or AC mode and its first or refinement state.
The v277 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v277.json`; it records
the reopened database with 638 remaining default names.

The v278 libjpeg postprocessing evidence is in
`artifacts/spectron_jpeg_postprocessing_manual_translation_anchors_20260828.json`.
It labels `start_pass_dpost`, `post_process_1pass`, `post_process_prepass`,
and `post_process_2pass`. The target initializer at `0x29ef00` installs the
start-pass routine, whose buffer-mode switch selects direct upsampling,
one-pass quantization, or the two two-pass handlers. The v278 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v278.json`; it records
the reopened database with 634 remaining default names.

The v279 libjpeg upsampler evidence is in
`artifacts/spectron_jpeg_upsampler_manual_translation_anchors_20260828.json`.
It labels the nine routines selected by the target
`v18_jinit_upsampler_jpeg_decompress_struct` initializer at `0x29fc9c`.
Those roles cover the public start and row callbacks, full-size and no-op
component handlers, simple and fancy h2v1 expansion, fancy h1v2 expansion,
generic integral expansion, and simple h2v2 expansion. Every row matches the
complete recorded ARM64 feature set. The v279 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v279.json`; it records
the reopened database with 625 remaining default names.

The v280 libjpeg error-handling evidence is in
`artifacts/spectron_jpeg_error_manual_translation_anchors_20260828.json`.
It labels the five callbacks installed by the target
`v18_jpeg_std_error` routine at `0x2a00fc`. The rows cover the standard
`emit_message`, `reset_error_mgr`, `format_message`, `output_message`, and
`error_exit` roles. The v280 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v280.json`; it records
the reopened database with 620 remaining default names.

The v281 libjpeg memory-manager evidence is in
`artifacts/spectron_jpeg_memory_manager_manual_translation_anchors_20260828.json`.
It labels the eleven methods assigned by the target
`v18_jinit_memory_mgr_jpeg_common_struct` initializer at `0x2a21b8`.
The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v281.json`; it records
the reopened database with 609 remaining default names.

The v282 libjpeg one-pass quantizer evidence is in
`artifacts/spectron_jpeg_one_pass_quantizer_manual_translation_anchors_20260828.json`.
It labels the eight callbacks and row quantizers assigned or selected by the
target `v18_jinit_1pass_quantizer_jpeg_decompress_struct` initializer at
`0x2a2f88`. All eight rows match normalized ARM64 features, and seven match
the complete feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v282.json`; it records
the reopened database with 602 remaining default names.

The v283 libjpeg two-pass quantizer evidence is in
`artifacts/spectron_jpeg_two_pass_quantizer_manual_translation_anchors_20260828.json`.
It labels the nine retained callback, palette, inverse-map, and row-processing
boundaries assigned or selected by the target
`v18_jinit_2pass_quantizer_jpeg_decompress_struct` initializer at `0x2a4f70`.
All nine rows match normalized ARM64 features, and eight match the complete
feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v283.json`; it records
the reopened database with 594 remaining default names.

The v284 libjpeg coefficient-controller evidence is in
`artifacts/spectron_jpeg_coefficient_controller_manual_translation_anchors_20260828.json`.
It labels the seven retained callbacks around
`v18_jinit_d_coef_controller_jpeg_decompress_struct_int` at `0x2aad18`.
All seven rows match normalized ARM64 features, and six match the complete
feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v284.json`; it records
the reopened database with 587 remaining default names.

The v285 libjpeg color-deconverter evidence is in
`artifacts/spectron_jpeg_color_deconverter_manual_translation_anchors_20260828.json`.
It labels the six conversion callbacks selected by
`v18_jinit_color_deconverter_jpeg_decompress_struct` at `0x2ab454`.
All six rows match normalized and complete ARM64 features. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v285.json`; it records
the reopened database with 582 remaining default names.

The v286 libjpeg inverse-DCT manager evidence is in
`artifacts/spectron_jpeg_inverse_dct_manager_manual_translation_anchors_20260828.json`.
It labels the start-pass callback selected by
`v18_jinit_inverse_dct_jpeg_decompress_struct` at `0x2abc20`. The normalized
feature set matches, with only register allocation detail differing. The
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v286.json`; it records
the reopened database with 581 remaining default names.

The v287 libjpeg baseline-Huffman evidence is in
`artifacts/spectron_jpeg_baseline_huffman_manual_translation_anchors_20260828.json`.
It labels the `start_pass_huff_decoder` and `decode_mcu` callbacks installed
by `v18_jinit_huff_decoder_jpeg_decompress_struct` at `0x2ad09c`. The
start-pass row matches the complete feature set. The MCU decoder preserves
the same instruction count, mnemonic sequence, control-flow counts, and
reviewed pseudocode, with one explicitly recorded relocated `PAGEOFF`
operand-bucket difference. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v287.json`; it records
the reopened database with 579 remaining default names.

The v288 libjpeg main-controller evidence is in
`artifacts/spectron_jpeg_main_controller_manual_translation_anchors_20260828.json`.
It labels `process_data_simple_main`, `process_data_context_main`,
`process_data_crank_post`, and `start_pass_main` around
`v18_jinit_d_main_controller_jpeg_decompress_struct_int` at `0x2ad964`. All
four match normalized ARM64 feature shape, and three match the complete
recorded feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v288.json`; it records
the reopened database with 575 remaining default names.

The v289 libjpeg compressor color-converter evidence is in
`artifacts/spectron_jpeg_compressor_color_converter_manual_translation_anchors_20260828.json`.
It labels six routines around
`v18_jinit_color_converter_jpeg_compress_struct` at `0x2b0354`: the
RGB-to-YCbCr table initializer, RGB-to-YCbCr and RGB-to-grayscale converters,
CMYK-to-YCCK conversion, and the compressor-side grayscale and direct-copy
paths. All six match the complete recorded feature set. The two duplicate
file-local roles use a `c_` qualifier to stay distinct from the decompressor
labels. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v289.json`; it records
the reopened database with 569 remaining default names.

The v290 libjpeg compressor coefficient-controller evidence is in
`artifacts/spectron_jpeg_compressor_coefficient_controller_manual_translation_anchors_20260828.json`.
It labels five routines around
`v18_jinit_c_coef_controller_jpeg_compress_struct_int` at `0x2afe2c`: the
iMCU-row reset helper, pass-through compressor, virtual-buffer output path,
full-buffer first pass, and start-pass dispatcher. All five match normalized
ARM64 feature shape, and four match the complete recorded feature set. The
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v290.json`; it records
the reopened database with 564 remaining default names.

The v291 libjpeg forward-DCT manager evidence is in
`artifacts/spectron_jpeg_forward_dct_manager_manual_translation_anchors_20260828.json`.
It labels three routines around
`v18_jinit_forward_dct_jpeg_compress_struct` at `0x2b1070`: the start-pass
table builder, the integer forward-DCT quantizer, and the floating-point
forward-DCT quantizer. All three match normalized ARM64 feature shape, and
two match the complete recorded feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v291.json`; it records
the reopened database with 561 remaining default names.

The v292 libjpeg compressor Huffman encoder evidence is in
`artifacts/spectron_jpeg_huffman_encoder_manual_translation_anchors_20260828.json`.
It labels five routines around
`v18_jinit_huff_encoder_jpeg_compress_struct` at `0x2b2a2c`: the
gather-statistics encoder, normal entropy encoder, two finish-pass callbacks,
and the start-pass dispatcher. All five match normalized ARM64 feature
shape, and two match the complete recorded feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v292.json`; it records
the reopened database with 556 remaining default names.

The v293 libjpeg compressor-controller evidence is in
`artifacts/spectron_jpeg_main_master_controller_manual_translation_anchors_20260828.json`.
It labels six routines around the target
`v18_jinit_c_main_controller_jpeg_compress_struct_int` at `0x2b2c2c` and
`v18_jinit_c_master_control_jpeg_compress_struct_int` at `0x2b44c8`. The
`jcmainct.c` rows are `process_data_simple_main` and `start_pass_main`. The
`jcmaster.c` rows are `initial_setup`, `pass_startup`, `finish_pass_master`,
and `prepare_for_pass`. All six match normalized feature shape, and five
match the complete recorded feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v293.json`; it records
the reopened database with 550 remaining default names.

The v294 libjpeg progressive-Huffman compressor evidence is in
`artifacts/spectron_jpeg_progressive_huffman_encoder_manual_translation_anchors_20260828.json`.
It labels eight routines around the target
`v18_jinit_phuff_encoder_jpeg_compress_struct` initializer at `0x2b78c4`:
the start-pass dispatcher, `emit_eobrun`, the DC and AC first/refinement MCU
encoders, and the normal and gather finish callbacks. All eight match
normalized ARM64 feature shape, and five match the complete recorded feature
set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v294.json`; it records
the reopened database with 542 remaining default names.

The v295 libjpeg preprocessing and downsampling evidence is in
`artifacts/spectron_jpeg_preprocessing_downsampling_manual_translation_anchors_20260828.json`.
It labels ten routines around the target
`v18_jinit_c_prep_controller_jpeg_compress_struct_int` at `0x2b7eb4` and
`v18_jinit_downsampler_jpeg_compress_struct` at `0x2b92c8`. The prep rows are
`start_pass_prep`, `pre_process_context`, and `pre_process_data`. The
downsampler rows are `sep_downsample`, `int_downsample`, `h2v1_downsample`,
`h2v2_downsample`, `h2v2_smooth_downsample`, `fullsize_smooth_downsample`,
and `fullsize_downsample`. All ten match normalized ARM64 feature shape and
the complete recorded feature set. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v295.json`; it records
the reopened database with 532 remaining default names.

The v296 GIF decoder evidence is in
`artifacts/spectron_gif_lzw_line_decoder_manual_translation_anchors_20260828.json`.
It labels the internal `DGifDecompressLine` helper at target `0x2b9f90`,
whose source counterpart is `0x2acb20`. The source and target normalized
feature records match, with only register allocation detail differing. The
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v296.json`; it records
the reopened database with 531 remaining default names.

The same v296 review found that source `0x2ac400` and target `0x2b9870` are
64-byte NEON constant pools embedded in executable `.text`, not callable
functions. IDA had created phantom `sub_` entries because the pools are
addressed by `ADR` instructions from the floating-point DCT routines. The
real `jpeg_fdct_ifast` functions begin at `0x2ac440` and `0x2b98b0`. A later
database-hygiene pass will remove those two phantom function boundaries and
represent the pools as data.

The latest checkpoints are
`artifacts/spectron_translation_checkpoint_20260828_v263_corrected.json` and
`artifacts/spectron_translation_checkpoint_20260828_v264_corrected.json`,
followed by
`artifacts/spectron_translation_checkpoint_20260828_v265.json` and
`artifacts/spectron_translation_checkpoint_20260828_v266.json`, followed by
the corrected
`artifacts/spectron_translation_checkpoint_20260828_v267.json`,
`artifacts/spectron_translation_checkpoint_20260828_v268.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v269.json`, followed by
`artifacts/spectron_translation_checkpoint_20260828_v270.json`,
`artifacts/spectron_translation_checkpoint_20260828_v271.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v272.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v273.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v274.json`,
`artifacts/spectron_translation_checkpoint_20260828_v275.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v276.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v277.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v278.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v279.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v280.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v281.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v282.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v283.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v284.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v285.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v286.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v287.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v288.json`,
`artifacts/spectron_translation_checkpoint_20260828_v289.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v290.json`, followed by
`artifacts/spectron_translation_checkpoint_20260828_v291.json`, followed by
`artifacts/spectron_translation_checkpoint_20260828_v292.json`, followed by
`artifacts/spectron_translation_checkpoint_20260828_v293.json`, followed by
`artifacts/spectron_translation_checkpoint_20260828_v294.json`, followed by
`artifacts/spectron_translation_checkpoint_20260828_v295.json`, followed by
`artifacts/spectron_translation_checkpoint_20260828_v296.json`. The reviewed
legacy, Android, script-table, runtime, property, zlib, and libjpeg labels
through v296 were reopened and verified with zero failures. That includes the
v296 GIF LZW line-decoder label added in the latest pass.
These passes were
static and offline. They did not modify the APK or contact a DNS, HTTP, or
TLS service.

The latest Spectron audit corrects a useful shorthand in the earlier notes.
The 2.2 `libqplay.so` is stripped of its static `.symtab` and DWARF data, but
it still retains a large dynamic export table. The target has 6,773 dynamic
entries, 6,770 named entries, 6,595 section-defined entries, and 5,782
section-defined functions. Its application C++ names are mostly obfuscated,
but the retained `CyaInt` or `CyaSSL` exports and the JNI entry points give us
real anchors for the connection audit. The app-level connection helper is
exported as `_ZN10XJLBgarMnA7connectERK10C8THgaTQxFi` at `0x20ad98`.
The complete rows, section presence checks, and exact 1.8 overlap are in
`artifacts/spectron_symbol_table_audit_20260827.json`, generated by
`tools/generate_spectron_symbol_table_audit.py`.

The next static pass found a more actionable Spectron difference in the
connector itself. The original 1.8 builder decodes `con.quattroplay.com` and
`con2.quattroplay.com`; Spectron decodes `cong.quattroplay.com` and
`cong2.quattroplay.com`. The path and transport modes remain the same, with
HTTPS for `/con.png` and `/con.gs`, and HTTP for `/conf.gs`. Spectron also
advertises version `6.171`, build `Oct 30 2022 12:58:55`, and `r=2.22` in the
connector query. This gives us a plausible routing failure to check before
changing TLS behavior. The raw fragments, sentinel repair, and exact hashes
are in `artifacts/spectron_connector_endpoint_audit_20260827.json`, generated
by `tools/audit_spectron_connector_endpoints.py`. The finding is static and
did not contact either hostname.

A target-specific local package path is reproducible as well. The Spectron
builder patches the target trust slot, resolver, HTTPS port defaults, and
outgoing-key diagnostic, then applies the previously isolated safe WebTop
branches. The target certificate still has to name `cong.quattroplay.com`,
because native hostname verification remains enabled. The exact byte guards
are in `artifacts/spectron_loopback_patch_audit_20260828.json`, generated by
`tools/generate_spectron_loopback_patch_audit.py`; the package builder is
`tools/build_spectron_loopback_apk.py`. The first build passed alignment and
APK signature checks with output hash
`45f469692cb6ee2e8d0f1529d8b0871dafdf718e2c8b6e345cb5082e40257751`.
That is an offline packaging result, not a live connection result.

The package was then run through a loopback-only TLS and game responder on the
available Android 36 x86_64 emulator. The ARM64 translation layer completed
the connector request, retained native RSA and TLS verification, opened two
encrypted game connections, loaded the map and level resources, and rendered
the green world with the HUD. The stock title/loading image remained when the
target premium-condition branch was untouched. The corrected target control
changes only the branch at `0x15fad8` so the existing clear block at `0x15fb1c`
runs. Its private APK hash is
`6988410c57bcc4874b9e6932e82d1eeba3e9a39e684a26112b54586a76022b02`, and its
rendered screenshot hash is
`08dc6793c3087caec00f1194e4966b1ab4753b53eacc0a1b2a86b92ad16c596e`.
The complete metadata is in
`artifacts/spectron_arm64_loopback_loading_replay_20260828.json`. The
responder, certificate key, APK, captures, and game assets remain private.

The v235 entry below is a historical checkpoint in the IDA translation
series. At that point, the current series reached
`analysis/spectron_libqplay_translated_v268.i64`. The v235 pass adds 12
high-confidence aliases from the GSFunctionsClient and GuiControl property
tables. They cover five carried-object getters, four screen-relative mouse
accessors, and three GuiControl callbacks. All 12 match the normalized
instruction shape, and the three GuiControl rows also match the complete
recorded metric set. The reopened v235 copy has 11,695 functions and 1,056
remaining default `sub_` names. Its SHA-256 is
`b58d447613b039f930e5ecd179a56a0e5ad19958715445f0663272dc830e0719`.
The evidence is in
`artifacts/spectron_gsfunctions_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gsfunctions_property_anchors.py`. The
generic manual-anchor applicator and verifier reopened all 12 names with zero
failures. The v235 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v235.json`.

The v236 pass adds 22 high-confidence aliases from the identification, time,
file-scripting, control-binding, and hardware-keyboard registration tables.
They include the two frame-tick callbacks, three identification wrappers, 11
file helpers, four control-binding properties, and the hardware-keyboard
getter/setter pair. Twenty-one rows match the normalized ARM64 instruction
shape, and 17 match every recorded metric. The target `setFileModTime` body is
40 bytes longer than the 1.8 body, but its registration and decompiled
file-resource update path preserve the same role, so that one difference is
called out explicitly. The reopened v236 copy has 11,695 functions and 1,034
remaining default `sub_` names. Its SHA-256 is
`04b1c4438c1d9473f949a1e27d8cf60b1d1199fddac80440a23429c8e5b1f44a`.
The evidence is in
`artifacts/spectron_time_files_input_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_time_files_input_anchors.py`. The v236
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v236.json`, and all 22
aliases reopened with zero failures.

The v237 pass adds seven `TLevelObject` property aliases and materializes the
missing target boundary for the `z` getter. The source and target coordinate,
layer, and vtable dispatch bodies match exactly in the recorded metrics, and
the recovered `z` range is `0x16d460-0x16d480`. The reopened v237 copy has
11,696 functions and 1,028 remaining default `sub_` names. Its SHA-256 is
`5229c4d4d67261076bd57c46c8331426ac775afdac6a578f409764b68e5ef872`.
The evidence is in
`artifacts/spectron_level_object_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_level_object_property_anchors.py`. The
v237 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v237.json`, and all seven
aliases reopened with zero failures.

The v238 pass adds eight high-confidence aliases from the residual
`TGaniObject` and `TGaniParam` property tables. They cover `aniparams`,
`anistep`, `attr`, the shared `body` and `bodyimg` getter, `colors`, `gmap`,
and the getter/setter pair for `enableganimoviereposition`. Five rows match
every recorded metric, one also matches normalized shape with a register
detail difference, and the two movie-reposition rows preserve the same
global-flag behavior with target instruction-form changes. The reopened v238
copy has 11,696 functions and 1,020 remaining default `sub_` names. Its
SHA-256 is
`b9e8068236409064bb27bde0f3f564398cc3ed7c664bc46af6eb5c5ce801f6a3`.
The evidence is in
`artifacts/spectron_gani_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gani_property_anchors.py`. The v238
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v238.json`, and all eight
aliases reopened with zero failures.

The v239 pass adds 30 high-confidence aliases from the residual `TOptions`
preference table. The batch contains 17 getters and 13 setters covering
plugin state, nickname limits, rendering effects, audio preferences, and the
screenshot format. Two existing video-style setters were already translated
and were intentionally left in place, so they are recorded as preexisting
aliases rather than renamed a second time. All 30 rows match the normalized
instruction shape. Their only recorded metric difference is target register
allocation, which is expected from the rebuilt 2.2 string and global-access
helpers. The reopened v239 copy has 11,696 functions and 990 remaining default
`sub_` names. Its SHA-256 is
`4b83ebdffa26611933a959770f39e1d43b1ff64d796d7d28c2c04c3aec4ff021`.
The complete source and target table rows are in
`artifacts/spectron_options_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_options_property_anchors.py`. The v239
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v239.json`, and all 30
aliases reopened with zero failures.

The v240 pass adds 42 high-confidence aliases from the residual
`TParticleEmitter` property table. It covers 26 getters and 16 setters for
particle placement, terrain behavior, emission timing, clipping, particle
counts, rendering flags, and modifier-related state. Nine other table entries
were already translated in earlier passes, including the two drop-emitter
getters and the bounded particle-count setters. Every one of the 42 new rows
matches the complete recorded feature set. The reopened v240 copy has 11,696
functions and 948 remaining default `sub_` names. Its SHA-256 is
`32225a918d1ac903ae68f624937fe4d4296afe75fec63448ff6aa60b96c6cd72`.
The complete table evidence is in
`artifacts/spectron_particle_emitter_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_particle_emitter_property_anchors.py`.
The v240 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v240.json`, and all 42
aliases reopened with zero failures.

The v241 pass adds three high-confidence `TParticleEmitter` GS2 callback
aliases from the residual function table: `addglobalmodifier`,
`addlocalmodifier`, and `addemitmodifier`. Each source and target body matches
the complete recorded feature set, including control-flow and register-detail
hashes. The reopened v241 copy has 11,696 functions and 945 remaining default
`sub_` names. Its SHA-256 is
`c154d03a1b28e31a06faa87876d1108c7acb971c884e4ae984cbe273573ba09e`.
The evidence is in
`artifacts/spectron_particle_emitter_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_particle_emitter_script_anchors.py`.
The v241 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v241.json`, and all three
aliases reopened with zero failures.

The v242 pass adds 22 high-confidence aliases from five residual world-object
property tables: `TBitmap`, `TServerWeapon`, `TProjectile`,
`TServerLevelLink`, and `TServerLevel`. The batch contains 19 getters and
three setters. All 22 rows match normalized ARM64 instruction shape, and eight
also match the complete recorded metric set. The other 14 differ only in
register-detail metadata. The reopened v242 copy has 11,696 functions and 923
remaining default `sub_` names. Its SHA-256 is
`6d8eb4e0dcacddce087564e3f14a7b355472cebac32f6854c007e98c740f5f44`.
The evidence is in
`artifacts/spectron_world_object_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_world_object_property_anchors.py`.
The v242 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v242.json`, and all 22
aliases reopened with zero failures.

The v243 pass adds nine high-confidence aliases from the residual `TPlayer`
auxiliary property table and the `TTranslations` property table. The batch
contains six getters and three setters for selected players, action-disable
flags, the configured language, and installed languages. All nine rows match
normalized ARM64 instruction shape. Their only recorded difference is target
register-detail allocation. The reopened v243 copy has 11,696 functions and
914 remaining default `sub_` names. Its SHA-256 is
`11d1275fbfca6b7500f430742de9e84f933d53462967e88fa61255ebad3e8e38`.
The evidence is in
`artifacts/spectron_player_translation_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_player_translation_property_anchors.py`.
The v243 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v243.json`, and all nine
aliases reopened with zero failures.

The v244 pass adds six high-confidence aliases from the residual `TServerNPC`
property table. They cover horse and NPC image getters, the `peltwithnpc`
flag, and the X/Y coordinate setters. All six rows match normalized ARM64
instruction shape, and two also match the complete recorded metric set. The
other four differ only in register-detail metadata. The reopened v244 copy has
11,696 functions and 908 remaining default `sub_` names. Its SHA-256 is
`10ea7f378ae0fafa155d45da163a116477240c01970e4e61b1e7dba1efd8b942`.
The evidence is in
`artifacts/spectron_server_npc_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_server_npc_property_anchors.py`.
The v244 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v244.json`, and all six
aliases reopened with zero failures.

The v245 pass adds seven high-confidence aliases from the residual
`TServerNPC` script-function table. They cover the can/cannot-be-carried,
can/cannot-be-pushed, can/cannot-be-pulled, and `timereverywhere` callbacks.
All seven rows match normalized ARM64 instruction shape. Their only recorded
difference is target register-detail allocation. The reopened v245 copy has
11,696 functions and 901 remaining default `sub_` names. Its SHA-256 is
`108d94cfb65b8e35d121e75d766b27c9490b82e501787eb0738a355c167f4a13`.
The evidence is in
`artifacts/spectron_server_npc_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_server_npc_script_anchors.py`.
The v245 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v245.json`, and all seven
aliases reopened with zero failures.

The v246 pass adds two high-confidence aliases for the residual `TServerNPC`
`showimg` and `showimg2` GS2 callbacks. The source and target registration
rows, argument shapes, image-list lookup, object creation, image-part reset,
coordinate updates, and refresh calls all line up. Spectron makes the image
string temporary explicit, so both target bodies are larger and have recorded
shape differences. The reopened v246 copy has 11,696 functions and 899
remaining default `sub_` names. Its SHA-256 is
`a8f616f41af51ec0076cbb37e3e9393910894674036e9e732a015ef59d64e515`.
The evidence is in
`artifacts/spectron_server_npc_showimg_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_server_npc_showimg_anchors.py`.
The v246 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v246.json`, and both
aliases reopened with zero failures.

The v247 pass adds 17 high-confidence aliases from the complete residual
`TTilesLayer` property table. They cover alpha, red, green, and blue channels,
the layer index, offset, and X/Y/Z coordinates. Every row matches the complete
recorded ARM64 metric set. The reopened v247 copy has 11,696 functions and 882
remaining default `sub_` names. Its SHA-256 is
`3e0c053b6dc847f21a437e4e77883481a37e5ecc128b3e47971ecd72ed050b4d`.
The evidence is in
`artifacts/spectron_tiles_layer_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tiles_layer_property_anchors.py`.
The v247 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v247.json`, and all 17
aliases reopened with zero failures.

The v248 pass translates the residual main `TPlayer` property table. It covers
30 registration rows and 27 distinct target callbacks, because `hearts` and
`hp`, `shield` and `shieldimg`, and `sword` and `swordimg` deliberately share
getter functions in the table. The pass includes 26 getter rows and four
setter rows. All 30 rows match the normalized ARM64 shape, seven rows match
the complete recorded metric set, and the other 23 retain only a register-
detail difference. The reopened v248 copy has 11,696 functions and 855
remaining default `sub_` names. Its SHA-256 is
`780a8ac4584699546ef14a692bd520f13389f5c3918f45b37e33256718028165`.
The evidence is in
`artifacts/spectron_player_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_player_property_anchors.py`.
The v248 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v248.json`, and all 30
registration rows reopened with zero failures.

The v249 pass translates the remaining `TGaniObject` and `TGaniParam`
property callbacks in the main animation property table. It covers 30
registration rows and 29 distinct target callbacks. The `head` and `headimg`
rows share one getter, so the artifact records 29 aliases plus the duplicate
registration. Twenty-six callback pairs match normalized ARM64 shape, eight
match the complete recorded metric set, and three retain larger target-shape
changes. The target's zoom getter and setter use an encoded backing value, and
the point setter is a shorter rebuilt wrapper, so those differences are
documented rather than treated as byte identity. The reopened v249 copy has
11,696 functions and 826 remaining default `sub_` names. Its SHA-256 is
`50377973defadbbf25181fdad93a1fcc4a06480f20bcdbd180dd9a63dc27defa`.
The evidence is in
`artifacts/spectron_gani_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gani_property_residual_anchors.py`.
The v249 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v249.json`, and all 29
aliases reopened with zero failures.

The v250 pass translates the unnamed `TDrawingPanel` property callbacks and
the `drawimagestretched` script wrapper. It covers 12 residual registration
rows and 10 distinct target callbacks. The `height` and `parth` rows share one
getter, as do `partw` and `width`. Eight callback anchors match the complete
recorded metric set, while the profile setter and available-filter getter
retain only register-detail differences. The reopened v250 copy has 11,696
functions and 816 remaining default `sub_` names. Its SHA-256 is
`d9fa44a190b1b5014dd9e56651fd416c0e1923cba4e2cd8e361314a9ba7a046f`.
The evidence is in
`artifacts/spectron_drawing_panel_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_drawing_panel_property_residual_anchors.py`.
The v250 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v250.json`, and all 10
aliases reopened with zero failures.

The v251 pass translates both `findweapon` callbacks. The property callback
maps from `0x16ca18` to `0x1705f0`, and the active-player static callback maps
from `0x16db28` to `0x171728`. Both target bodies iterate the weapon list and
compare weapon names, while preserving their distinct player-object and
active-player calling contexts. The target implementations are larger due to
rebuilt string-comparison and player-layout helpers, so both are documented as
high-confidence semantic matches with explicit metric differences. The
reopened v251 copy has 11,696 functions and 814 remaining default `sub_` names.
Its SHA-256 is
`7ab7b98f01f2a4e5241187e1f5864006a7b8b21f6fa163e61fc3c76081a65e9c`.
The evidence is in
`artifacts/spectron_tplayer_findweapon_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tplayer_findweapon_anchors.py`.
The v251 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v251.json`, and both
aliases reopened with zero failures.

The v252 pass translates 17 residual `TGUIAnimationProperties` callbacks: ten
getters and seven setters. The source table at `0x3823c0` and target table at
`0x395420` keep the same twelve property names and order. This pass covers the
remaining `currenttime`, `amplitude`, `bounds`, `delay`, `duration`, `interval`,
`sound`, `tabfirstonshow`, `timing`, and `transition` callbacks. The alpha and
rotation getters, the sound setter, and the ABI jump entries for the alpha,
rotation, timing, and transition setters were already translated and were not
renamed a second time. Every selected row matches the complete recorded ARM64
feature set, with no layout or register-detail difference. The reopened v252
copy has 11,696 functions and 797 remaining default `sub_` names. Its SHA-256
is
`90a0d433ed61969714d1c853823693ce4286e2d785e159535e7f68e06548af4b`.
The evidence is in
`artifacts/spectron_tgui_animation_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tgui_animation_property_residual_anchors.py`.
The v252 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v252.json`, and all 17
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v253 pass translates five residual `GuiBitmapCtrl` callbacks across six
property-table rows. The `tile` and `wrap` registrations intentionally share
one getter, leaving five distinct target functions: four getters and the
`fullbitmap` setter. The source table at `0x380250` and target table at
`0x3932b0` keep the same `bitmap`, `bitmaprectangle`, `fullbitmap`, `tile`, and
`wrap` order. Every selected callback matches the complete recorded ARM64
feature set. The bitmap and rectangle setters, plus the shared tile or wrap
setter, already had target names and were not duplicated. The reopened v253
copy has 11,696 functions and 792 remaining default `sub_` names. Its SHA-256
is
`924bca24389cf9c6f8d07ade1f6a7b31726c8bc7991f7fdbacf6e94967a5028c`.
The evidence is in
`artifacts/spectron_gui_bitmap_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_bitmap_property_anchors.py`. The
v253 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v253.json`, and all five
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v254 pass translates 11 residual GUI button callbacks from two adjacent
property blocks. Six are the `GuiBitmapButtonCtrl` image getters and setters,
and five are `GuiButtonBaseCtrl` callbacks for button type, group number, and
text. The source tables at `0x380190` through `0x3801f0` and `0x3803a0` line up
with the Spectron blocks at `0x3931f0` through `0x393250` and `0x393400`.
Nine rows match the complete recorded ARM64 feature set. The two button-type
rows retain only a register-detail difference, with no layout or normalized
shape change. The checked callbacks and the text setter already had target ABI
names and were not duplicated. The reopened v254 copy has 11,696 functions and
781 remaining default `sub_` names. Its SHA-256 is
`078918adcdeadc3fa6a894d07e0f9b1929dacaeb2043de3f9952ed8e2f9289e8`.
The evidence is in
`artifacts/spectron_gui_bitmap_button_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_bitmap_button_property_anchors.py`.
The v254 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v254.json`, and all 11
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v255 pass translates four residual `GuiControl` property callbacks: the
`cursor` getter plus the `flickering`, ordinary-animation, and in-or-out
animation setters. The source table at `0x3806a0` and target table at
`0x393700` use the same 0x30-byte property records. All four selected bodies
match the complete recorded ARM64 feature set, with no layout or register
detail differences. The reopened v255 copy has 11,696 functions and 777
remaining default `sub_` names. Its SHA-256 is
`41201714ed45c2e165f0199268d1863fb6d7895f8067678c6614fc786c5254b6`.
The evidence is in
`artifacts/spectron_guicontrol_property_tail_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guicontrol_property_tail_anchors.py`.
The v255 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v255.json`, and all four
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v256 pass translates the two remaining `GuiGraalCtrl` callbacks for the
`isrendering` property. The source row is at `0x3816d0` and the target row is
at `0x394730`; the getter reads object offset +456 and the setter writes the
same byte. Both target bodies match the complete recorded ARM64 feature set.
The reopened v256 copy has 11,696 functions and 775 remaining default `sub_`
names. Its SHA-256 is
`51cc802c6c5ae38aa70bf09119f3caef12fe4e6907403d9a54211e79e110731c`.
The evidence is in
`artifacts/spectron_guigraalctrl_isrendering_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guigraalctrl_isrendering_anchors.py`.
The v256 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v256.json`, and both
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v257 pass translates 11 residual `GuiScrollCtrl` property callbacks. The
batch covers child margin, constant thumb height, horizontal and vertical
scrollbar names, scroll position, tile, wheel-scroll lines, and first-responder
state. The source table at `0x381df0` and target table at `0x394e50` keep the
same eight property rows. All 11 rows match normalized ARM64 shape, and nine
also match the complete metric set. The two scrollbar getters differ only in
register-detail hashes. The reopened v257 copy has 11,696 functions and 764
remaining default `sub_` names. Its SHA-256 is
`91201c29da6a4798a7f1918c2f11fa848cb66848615079beaaf29d04b022d82e`.
The evidence is in
`artifacts/spectron_guiscrollctrl_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guiscrollctrl_property_anchors.py`.
The v257 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v257.json`, and all 11
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v258 pass translates seven residual callbacks from the `GuiStretchCtrl`
property block and its inherited `GuiTextCtrl` rows. The batch covers client
extent, client height, client width, maximum character count, and text. All
seven rows match the complete recorded ARM64 feature set. The reopened v258
copy has 11,696 functions and 757 remaining default `sub_` names. Its SHA-256
is `7e7aa1628bd8f9123540346c06455d7b2e1aca803092f4ba3466cd4974f2bbd8`.
The evidence is in
`artifacts/spectron_guistretchctrl_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guistretchctrl_property_anchors.py`.
The v258 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v258.json`, and all seven
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v259 pass translates nine residual `GuiTextEditCtrl` property callbacks.
The batch covers denied sound, history size, input type, cursor visibility, tab
completion, and the text getter. The password pair and the already named
history-size, input-type, and text setters were left untouched. All nine
selected rows match the complete recorded ARM64 feature set. The reopened
v259 copy has 11,696 functions and 748 remaining default `sub_` names. Its
SHA-256 is
`9b5a46e16dbf912a7e67583b8f626f52878bcbb30225e3674793d3b8ef5114d9`.
The evidence is in
`artifacts/spectron_guitexteditctrl_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guitexteditctrl_property_anchors.py`.
The v259 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v259.json`, and all nine
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v260 pass translates four residual `TGraalVar` property callbacks: the
name setter, the paused-state getter and setter, and the joined-classes getter.
The source table at `0x387340` and target table at `0x39a460` resolve two
callbacks that were ambiguous in broad feature matching and two that were
unmatched. The pause pair is an exact metric match. The name setter and
joined-classes getter retain rebuilt-wrapper shape differences. The reopened
v260 copy has 11,696 functions and 744 remaining default `sub_` names. Its
SHA-256 is
`a8d0c87f225ba9cd5490e7616ea05d983d48c80b8ef07ec7a8da2b91e675e944`.
The evidence is in
`artifacts/spectron_tgraalvar_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tgraalvar_property_residual_anchors.py`.
The v260 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v260.json`, and all four
aliases reopened with zero failures. This was an offline IDA pass with no APK
or native-library changes.

The v261 pass translates the last unnamed callback in the server and player
property block, `TBodyPanel_get_bodycacheperplayer`. The source registration
row is at `0x38af98` and the target row is at `0x39e0e8`; both bodies return the
same panels-per-player static integer. The normalized ARM64 shape matches,
with only a register-detail difference. The reopened v261 copy has 11,696
functions and 743 remaining default `sub_` names. Its SHA-256 is
`d2f88d291451b82578968bff85c7018fdba2d2c0a18ec256ac7b3368d73e77de`.
The evidence is in
`artifacts/spectron_tbodypanel_bodycacheperplayer_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_tbodypanel_bodycacheperplayer_anchor.py`.
The v261 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v261.json`, and the alias
reopened with zero failures. This was an offline IDA pass with no APK or
native-library changes.

The v262 pass translates six callbacks from three short residual property
runs: `GuiButtonCtrl.stylesection`,
`TScriptProperty.scriptlogwritetoreadonly`, and `TTiles.waterheight`. All six
rows match normalized ARM64 shape. The style-section pair is an exact metric
match, while the other four rows differ only in register-detail hashes. The
reopened v262 copy has 11,696 functions and 737 remaining default `sub_`
names. Its SHA-256 is
`6ec4091d8781101661216a2b99f6414cc3f5a07c556185eb40de2e203351d67e`.
The evidence is in
`artifacts/spectron_residual_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_residual_property_anchors.py`. The v262
checkpoint is `artifacts/spectron_translation_checkpoint_20260828_v262.json`,
and all six aliases reopened with zero failures. This was an offline IDA pass
with no APK or native-library changes.

The preceding v234 pass recovered the missing target function boundary for
the `tclient_setplayerhurt` property callback and applied the reviewed alias
`v18_TClient_script_tclient_setplayerhurt`. The reopened v234 copy has 11,695
functions and 1,068 remaining default `sub_` names. Its SHA-256 is
`c7dda722fbab84a403ed8ba21351af98dc01e181c640c5048c126b2ff4f669b2`.
The evidence is in
`artifacts/spectron_tclient_playerhurt_property_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_tclient_playerhurt_anchor.py`; the
existing manual-anchor applicator and verifier materialized and reopened the
function range. The v234 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v234.json`.

The preceding v233 pass gave three
target-only property callbacks explicit `spectron_` labels. Two callbacks
copy bounded integer arrays into separate debug-handler globals, and the third
is a small `tclient_setotherplayerprops` ABI adapter around the already named
`v18_TClient_updateGlobalPlayer` body. These are descriptive target labels,
not claimed 1.8 counterparts. The reopened v233 copy has 11,694 functions and
1,068 remaining default `sub_` names. Its SHA-256 is
`21fa935e68dd605c0549656df3a3b832d0c91e080b7d703b2042132ba078ddd6`.
The evidence is in
`artifacts/spectron_target_only_callback_labels_20260828.json`, generated by
`tools/generate_spectron_target_only_labels.py`; the IDA applicator and
reopen verifier are `tools/ida_apply_spectron_target_only_labels.py` and
`tools/ida_verify_spectron_target_only_labels.py`. The v233 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v233.json`.

The v232 pass corrects a
feature-shape collision in the TClient inbound handler table and adds two
high-confidence handler aliases. The old alias at `0xecba0` was restored to
the retained `_ZN10yL3_IaDMFt10XEm8Ta8FEQEP10vuuHgangcFRK10C8THgaTQxF` symbol,
because its body is a hash-container iterator rather than a client packet
handler. `TClient_processServerModifies` now belongs at target `0x1eefa0`,
the pointer stored in handler-table slot 48, and
`TClient_handleServerLoginPacket` belongs at `0x1f37e0`, slot 10. The
reopened v232 copy has 11,694 functions and 1,071 remaining default `sub_`
names. Its SHA-256 is
`51b76f3945f282bc62c1fb72a5749115315db1e6d5fac5e04ef4208c816a3bf6`.
The correction and evidence are in
`artifacts/spectron_tclient_handler_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tclient_handler_anchors.py`; the
correction applicator is
`tools/ida_apply_spectron_name_corrections.py`. The v232 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v232.json`.

The v231 pass adds six
high-confidence aliases across the password, cache, and file-download script
property tables. The source and target registration records are retained
alongside the decompiled behavior. The reopened v231 copy has 11,694
functions and 1,073 remaining default `sub_` names. Its SHA-256 is
`329596637abe0446019eb80c952e4536157bed027dce3c5f40fc6b8a68cf2fa2`.
The evidence is in
`artifacts/spectron_file_cache_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_file_cache_property_anchors.py`, and the
v231 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v231.json`.

The v230 pass adds five high-confidence aliases in the TClient script-property
table. They cover download-size state, server-list connection completion,
flag-data wrappers, and active-player weapon updates. The reopened v230 copy
has 11,694 functions and 1,079 remaining default `sub_` names. Its SHA-256 is
`220e9fe71bb8e93472ed7892b4b16363559e1d24a3733bb876fd6abb393023ba`.
The evidence is in
`artifacts/spectron_tclient_script_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tclient_script_property_anchors.py`,
and the v230 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v230.json`.

The v219 revision is `analysis/spectron_libqplay_translated_v219.i64`.
It adds 30 high-confidence aliases for the residual `GuiTextListEntry` and
`GuiTextListCtrl` property accessors. Each target body reads or writes the
same receiver offset as the 1.8 body, appears in the corresponding target
property table, and matches all recorded normalized feature fields. The
aliases reduce the target's default `sub_` count from 1,165 to 1,135. The
database hash is
`bf219383ca3b9d99ca0fc8133b61c8204263458dc916f3f0cf846e41f9383097`.
The machine-readable evidence is in
`artifacts/spectron_gui_text_list_entry_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_text_list_entry_property_anchors.py`.
All 30 names reopened successfully. This is a semantic IDA label pass only,
and it does not modify the APK or native library. The superseding checkpoint
is `artifacts/spectron_translation_checkpoint_20260828.json`, generated by
`tools/extend_spectron_translation_checkpoint.py`.

The following v220 revision adds 10 more high-confidence aliases beside that
property block. They cover sort-order getters and setters, hint and geometry
accessors, and the script-facing profile setter. All target bodies preserve
the source operation and normalized ARM64 shape. Four rows match every
recorded metric; six differ only in register-detail or rebuilt-wrapper call
names. The v220 database has 11,694 functions and 1,125 default `sub_` names.
Its hash is
`8ed23c3f19d77413dd044e64b810352c66dc76660e34b7c205d9648a82edd09f`.
The evidence is in
`artifacts/spectron_gui_text_list_residual_manual_translation_anchors_20260828.json`,
and the latest checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v220.json`.

The readable-name translation pass is complete. The ARM64 IDA database
contains 8,601 applied aliases with zero rename failures:

| Kind | Count |
| --- | ---: |
| Functions | 4,714 |
| PLT thunks | 3,183 |
| Jump thunks | 199 |
| Data symbols | 505 |
| Total translated symbols | 8,601 |

The 8,601 total is an IDA alias inventory, not an unstripped debug-symbol
count. The original shared object is reported as stripped, with no `.symtab`
or DWARF sections. Its defined dynamic symbol table contains 6,506 rows. The
larger alias inventory keeps PLT and jump-thunk names separate and includes
data aliases. The exact audit is in
`artifacts/elf_symbol_table_audit_20260826.json`.

The old connector has a concrete compatibility problem. Its embedded
GraalWeb certificate expired on 2023-07-29, so the original HTTPS path cannot
be trusted by a current clock. The saved connector fixture is structurally
valid and passes the native wolfSSL raw-digest RSA check against this APK's
embedded public key. An earlier parser reported the opposite because it used
the standard ASN.1 `DigestInfo` form. The certificate problem remains real,
and both it and any response signed by a different key must stay separate from
the game-server protocol.

The native parser audit now explains the date part of that failure. It checks
the X.509 `notBefore` and `notAfter` fields against the current UTC clock
inside CyaSSL, before the connector sends HTTP. The static function map and
paired local control are documented in `docs/CONNECTOR_TLS.md`.

The decoded connector script also carries a separate stale trust literal for
legacy branches. It installs the same expired Eurocenter Games certificate
with native DES key `NakFpz15`, `RC4-SHA`, and `SSLv23`. The recovered Classic
branch sets `usessl` to false before `sendLoginNewProtocol`, and the script
also clears it unconditionally, so this game-server TLS literal is not active
in the main Classic path. The current Classic SSL concern is the connector's
native HTTPS trust bundle. See `artifacts/game_server_tls.json` for the
offline source and certificate evidence.

The saved connector fixture has now also been replayed with the native RSA
result branch unchanged. A private ARM64-only candidate made the connector
request, opened both game connections, loaded the map and resources, and
rendered the same local world through Android's ARM64 translation layer. The
RSA bypass is therefore not needed for this saved fixture. The remaining
diagnostic controls are the stale trust skip, loopback routing, deterministic
test key, and loading-state candidate.

The certificate payload contains six historical certificate blocks in a PEM
bundle. One AlphaSSL block uses malformed `BEGINCERTIFICATE` and
`ENDCERTIFICATE` markers, so the decoder records both raw and normalized
hashes. The native path uses the ordinary base64 alphabet, DES-ECB with
bit-reversed key bytes, and a seven-byte short-block tail. The first entry is
the expired Eurocenter Games certificate; the bundle also carries the expired
AddTrust root and an AlphaSSL intermediate that expired in 2024. The exact
hashes and an offline decoder are kept in
`artifacts/graalweb_trust_bundle.json` and
`tools/decode_graalweb_cert_bundle.py`.

The symbolized handler-table investigation also produced an important
correction. The original `setInDataHandlers` instructions are correct for this
client revision. The earlier x86_64 `xchg` patch and the matching ARM64
operand swap were a false lead caused by reading the intermediate bytecode
array in the wrong order. The decoded runtime pairs are packet type first,
handler index second, and the unmodified table accepts the normal local
sequence.

The corrected two-connection replay renders the level tile field, player HUD,
and status icons with an x86_64 diagnostic build. That is a downstream
protocol and renderer result, not a claim about stock x86 loading-state
ownership: several historical x86 test APKs used a loading-getter override.
The client accepts a server-warp, a player-properties packet, the
connecting-window completion packet, the map transition, three encrypted
level containers, and `pics1.png`. The file response is packet 102, not packet
59. A direct packet-59 parser jump was retained only as a negative control
because it breaks the normal request sequence.

The same replay was run with an ARM64-only diagnostic APK. The available
Android emulator is x86_64, so Android loaded the ARM64 library through its
native translation layer. The ordinary ARM64 build completed the connector
request, server warp, encrypted login exchange, map request, three level-file
requests, `pics1.png` request, and continuing heartbeats, but stayed on the
title or loading image. A second diagnostic build cleared the loading byte
only after timer and packet processing, at the JNI render boundary. That build
displayed the tiled world, player HUD, and status icons. A stronger
one-instruction candidate instead forces the existing non-premium
initialization path at `0x15ca7c`; with the corrected map fixture, it displays
the same world through the normal render branch. The candidate still needs
real ARM64-device and authorized live-service validation.

A follow-up isolation run served the original 15,581-byte connector script
without the direct script-level loading assignment. The same native candidate
still rendered the world and HUD after the map, three level containers, image,
and heartbeat path completed. This makes the native startup branch the leading
local explanation for the visual transition. The direct script insertion is
compatible with the VM and useful as a control, but it is not required for
the observed local render. See
`artifacts/arm64_native_only_original_script_replay_20260826.json`.

The matched stock-branch control used the same original script, responder,
resource fixtures, and translated ARM64 package with `0x15ca7c` restored to
`B.LE`. It completed the same resource and heartbeat path but kept showing the
title/loading artwork. That control is recorded in
`artifacts/arm64_native_stock_original_script_control_20260826.json`.

The complete private diagnostic package can now be rebuilt from the original
APK with `tools/build_arm64_loopback_apk.py`. Two independent builds produced
the same APK hash and the fresh package reproduced the rendered-world replay.
The builder keeps the original connector script and emits only the ARM64
library, so it cannot silently select a different ABI in the emulator.

The connector certificate hypothesis now has a paired local control. A
package that trusts a SAN-matching certificate valid from 2025 to 2035 sent
the expected `/con.png` request through native TLS. An otherwise equivalent
package that trusts a SAN-matching certificate expired in 2021 reached the
loopback TCP listener but closed during the TLS handshake and sent no HTTP.
This is strong evidence that certificate validity is checked before connector
HTTP in the translated ARM64 path. It is still a local control, not a live
service test. See `artifacts/connector_tls_expiry_control_20260826.json` and
the certificate validity section in `docs/TESTING.md`.

The valid trust bundle was then used in a working local control that kept the
native RSA check and native certificate verification enabled. With the
loopback transport edits, the fixed responder key, and the tested native
loading-state branch, the ARM64 package made one connector request, opened
two game connections, loaded the map and resources, continued heartbeats,
and displayed the tiled world with its HUD. The matching package with the
stock loading branch made the same connector and resource requests but stayed
on the title artwork. This separates the stale trust failure from the later
loading-state gate. The builder and hashes are in
`artifacts/arm64_native_verification_working_control_20260826.json`.

The ARM64 IDA audit now identifies the local screen split more precisely. The
native loading byte at `0x37a549` starts at `1`; the successful `classic`
premium-option path skips the native clear at `0x15cac8`; and the packet-190
completion wrapper does not write the byte. The JNI loop reads it at
`0x244228` before choosing the loading or game draw path. This points to a
startup loading-state gate, rather than a missing map or failed resource
download, while leaving the production meaning of the entitlement branch
unverified.

The expanded callback naming pass has also been exercised in IDA 9.3's
IDALIB mode on a disposable copy of the database. It resolved and checked all
277 curated native callback names, 886 bounded script-table names, 20
`.eh_frame`-backed script callbacks, and 28 behavior-based application or
engine role aliases with zero mismatches. These role aliases describe proven
function behavior; they are not recovered original ELF source names. The pass
added 25 function starts, including two splits where IDA had merged a callback
into a larger neighboring function.
This validates the addresses and names, but the desktop IDA session's active
unpacked database was still locked, so its live database was not overwritten.
The exact result is in `artifacts/ida_translation_validation.json`.

The validated names and boundaries were also persisted into a separate local
IDA 9.3 database copy at
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v2.i64`. A
close-and-reopen check found all 1,211 expected names, 11,297 functions, and
459 remaining default `sub_` entries. The 56 MB database is intentionally not
committed to the public repository; its hash and verification status are in
the same IDA artifact. Exporting that saved copy produced a private inventory
with 8,096 ELF-backed functions, 2,742 named non-ELF functions, and 459
remaining defaults.

A follow-up static CyaSSL pass applied eleven additional behavior aliases to a
new packed copy at
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v3.i64`. A
clean reopen verified all eleven names, 11,297 functions, and 448 remaining
default `sub_` entries. Seven aliases match recognizable historical CyaSSL
roles, while four are deliberately descriptive local names. The copy remains
outside the public repository; the evidence and hash are in
`artifacts/cyassl_static_role_audit_20260826.json`.

The next static-library pass applied 27 high-confidence role aliases to a new
copy at `/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v4.i64`.
It covers the remaining small zlib, bzip2, minizip, GPC, CyaSSL, LibTomCrypt,
and YAJL gaps. A clean reopen verified all 27 names, retained 11,297
functions, and reduced the default `sub_` count from 448 to 421. This pass
also corrected five address-only family classifications in the historical
profile. The complete record is in
`artifacts/static_library_role_audit_20260826.json` and the combined residual
accounting is in `artifacts/ida_residual_profile.json`.

The supplied Spectron 2.2 package can be compared at the function level even
though its application C++ symbols are obfuscated. A normalized IDA feature
export and matcher map 3,700 named 1.8 functions to unique Spectron ARM64
targets, with 3,641 high-confidence labels applied and 59 medium-confidence
rows left for review. A validation set of 396 one-to-one shared-name matches
produced no wrong unique matches. The saved local copies are
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v1.i64`
and `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v2.i64`;
the latter adds four reviewed
context anchors for the premium marker, loading getter, connecting window,
and JNI loop. These are `v18_` semantic labels, not claims that original
debug symbols survived in the 2.2 build. The map and evidence are in
`artifacts/spectron_semantic_function_translation_20260826.json`,
`artifacts/spectron_manual_translation_anchors_20260826.json`, and
`artifacts/spectron_translation_checkpoint_20260826.json`.

An exact-name companion inventory records 1,008 one-to-one names shared by
the two function exports. It keeps the 612 rows outside the strict semantic
matcher separate from inferred labels, and records both build-specific
addresses without transferring them. Six reviewed network context anchors
cover the connector-mode, HTTP, TLS, and socket paths. Their artifacts are
`artifacts/spectron_exact_shared_name_anchors_20260826.json` and
`artifacts/spectron_network_manual_translation_anchors_20260826.json`. The
anchors are applied in the local disposable copy
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v3.i64`,
which reopened with all six names intact.

A fourth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v4.i64`,
adds 16 reviewed core anchors for resource loading, rendering, GUI setup,
file scripting, input focus, HTTP script execution, and client support. All
16 reopened with their `v18_` names intact. The copy hash and evidence are
recorded in `artifacts/spectron_core_manual_translation_anchors_20260826.json`
and `artifacts/spectron_translation_checkpoint_20260826.json`.

A fifth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v5.i64`,
adds 13 reviewed runtime-path anchors for map entry, file chunks, encrypted
scripts, text controls, disconnects, server warps, and the main server-list
loop. All 13 reopened successfully. The evidence is in
`artifacts/spectron_runtime_path_manual_translation_anchors_20260826.json`,
and the v5 database SHA-256 is recorded in the checkpoint.

A sixth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v6.i64`,
adds five reviewed update and protocol anchors for download queues, server
modifications, CRC requests, and modification-time requests. All five
reopened successfully. The evidence is in
`artifacts/spectron_update_protocol_manual_translation_anchors_20260826.json`,
and the v6 database SHA-256 is recorded in the checkpoint.

A seventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v7.i64`,
adds 11 reviewed client-action packet anchors. They cover level-warp timing,
board edits, bombs, triggers, projectiles, shots, damage, explosions, and text
serialization. All 11 reopened successfully. The evidence is in
`artifacts/spectron_client_action_manual_translation_anchors_20260826.json`,
and the v7 database SHA-256 is recorded in the checkpoint.

An eighth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v8.i64`,
adds 29 reviewed outbound client serializers covering level entry, file and
image requests, uploads, scripts, chat, flags, extras, and deletion or warp
commands. Twenty-eight are new context labels and one corroborates a target
already present in the strict semantic map. All 29 reopened successfully. The
evidence is in
`artifacts/spectron_client_outbound_manual_translation_anchors_20260826.json`,
and the v8 database SHA-256 is recorded in the checkpoint.

A ninth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v9.i64`,
adds six reviewed resource resolver anchors for wildcard matching, file-list
construction, stream loading, game-file lookup, and encoded resource-key
validation. All six reopened successfully. The evidence is in
`artifacts/spectron_resource_manual_translation_anchors_20260826.json`, and
the v9 database SHA-256 is recorded in the checkpoint.

A tenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v10.i64`,
adds 13 reviewed client script bridge anchors for file upload, terrain and
board refresh, trigger actions, appearance colors, weapon calls, request text,
level lookup, server-list events, and text commands. All 13 reopened
successfully. The evidence is in
`artifacts/spectron_script_bridge_manual_translation_anchors_20260826.json`,
and the v10 database SHA-256 is recorded in the checkpoint.

An eleventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v11.i64`,
adds 11 reviewed client request and window-state anchors. They cover weapon
image changes, RC chat, request text, file deletion and rename operations,
file moves, update-package requests, window presence, ping answers, and the
window list. All 11 reopened successfully. The evidence is in
`artifacts/spectron_client_request_manual_translation_anchors_20260826.json`,
and the v11 database SHA-256 is recorded in the checkpoint.

A twelfth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v12.i64`,
adds eight reviewed client inbound and state-transition anchors. They cover
script data events, queued upload completion, server modification cleanup,
server map tile entry, update-package completion, global-player login and
logout handling, and both GANI update layers. All eight reopened successfully.
The evidence is in
`artifacts/spectron_client_inbound_manual_translation_anchors_20260826.json`,
and the v12 database SHA-256 is recorded in the checkpoint.

A thirteenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v13.i64`,
adds eight reviewed login, event, and small client-state anchors. They cover
the folder-log and RC-chat event helpers, server-login signature handling,
four login-state string setters, and the player login or logout packet decoder.
All eight reopened successfully. The evidence is in
`artifacts/spectron_login_helper_manual_translation_anchors_20260826.json`,
and the v13 database SHA-256 is recorded in the checkpoint.

A fourteenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v14.i64`,
adds one reviewed client encryption-in tail-thunk anchor. The source and
target both load the global client object, check it, and forward the string to
the connection encryption-in parser. The target already had a mangled
function boundary, and the raw bytes are recorded as an additional integrity
check. It reopened successfully. The evidence is in
`artifacts/spectron_parse_wrapper_manual_translation_anchor_20260826.json`,
and the v14 database SHA-256 is recorded in the checkpoint.

A fifteenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v15.i64`,
adds three reviewed lookup anchors. They cover active-player lookup by ID,
deleted-player lookup by ID, and case-insensitive download-file lookup. Each
pair preserves the same list scan and six-block loop shape. All three reopened
successfully. The evidence is in
`artifacts/spectron_lookup_helper_manual_translation_anchors_20260826.json`,
and the v15 database SHA-256 is recorded in the checkpoint.

A sixteenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v16.i64`,
adds 18 reviewed connection and SSL helper anchors. They cover encryption-key
cleanup, outgoing-list cleanup, the parser-key setter, socket-error state,
SSL enable and configuration propagation, the SSL error getter, and seven
low-level connection field accessors. All 18 reopened successfully. The
evidence is in
`artifacts/spectron_connection_helper_manual_translation_anchors_20260826.json`,
and the v16 database SHA-256 is recorded in the checkpoint.

A seventeenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v17.i64`,
adds seven reviewed compact client-state anchors. They cover the vtable-320
forwarder, server-options and time-variable setters, the Graal 2002 mode flag,
and three active-player or ghost-mode state setters. All seven reopened
successfully. The evidence is in
`artifacts/spectron_client_state_helper_manual_translation_anchors_20260826.json`,
and the v17 database SHA-256 is recorded in the checkpoint.

An eighteenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v18.i64`,
adds five reviewed client connection-state anchors. They cover three
connection-string accessors, the encrypted-file-key continuation wrapper, and
the encrypted server-level save wrapper. All five reopened successfully. The
evidence is in
`artifacts/spectron_connection_state_manual_translation_anchors_20260826.json`,
and the v18 database SHA-256 is recorded in the checkpoint.

A nineteenth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v19.i64`,
adds 12 reviewed HTTP request helpers. They cover ten request-object string
field accessors, the deleting destructor, and the outbound-buffer sender. All
12 reopened successfully. The evidence is in
`artifacts/spectron_http_request_manual_translation_anchors_20260826.json`,
and the v19 database SHA-256 is recorded in the checkpoint.

A twentieth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v20.i64`,
adds five reviewed socket-state anchors. They cover the socket error predicate,
the subprocess-close hook, nonblocking setup, numeric peer IP access, and
formatted peer IP access. All five reopened successfully. The evidence is in
`artifacts/spectron_socket_state_manual_translation_anchors_20260826.json`,
and the v20 database SHA-256 is recorded in the checkpoint.

A twenty-first disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v21.i64`,
adds four reviewed HTTP request-state anchors. They cover request counters,
request and download timestamps, and the file-download predicate. All four
reopened successfully. The evidence is in
`artifacts/spectron_http_request_state_manual_translation_anchors_20260826.json`,
and the v21 database SHA-256 is recorded in the checkpoint.

A twenty-second disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v22.i64`,
adds 15 reviewed `TServerNPC` helper anchors. They cover blocking modes,
draw-layer modes, level visibility, bow assignment, and five pelt predicates.
All 15 reopened successfully. The evidence is in
`artifacts/spectron_npc_helper_manual_translation_anchors_20260826.json`,
and the v22 database SHA-256 is recorded in the checkpoint.

A twenty-third disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v23.i64`,
adds five reviewed `THTMLAtom` anchors. They cover construction, buffer start
and length storage, and buffer-length or buffer-end accessors. All five
reopened successfully. The evidence is in
`artifacts/spectron_html_atom_manual_translation_anchors_20260826.json`,
and the v23 database SHA-256 is recorded in the checkpoint.

A twenty-fourth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v24.i64`,
adds five reviewed `TPlayer` helper anchors. They cover attachment state,
property-change notification, the freeze counter, and two sprite-draw
wrappers. All five reopened successfully. The evidence is in
`artifacts/spectron_player_helper_manual_translation_anchors_20260826.json`,
and the v24 database SHA-256 is recorded in the checkpoint.

A twenty-fifth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v25.i64`,
adds eight reviewed input and window bridge anchors. They cover key-state
access, cursor positioning, screen dimensions, canvas lookup, initialization,
and preferred position. All eight reopened successfully. The evidence is in
`artifacts/spectron_input_window_manual_translation_anchors_20260826.json`,
and the v25 database SHA-256 is recorded in the checkpoint.

A twenty-sixth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v26.i64`,
adds 11 reviewed visual helper anchors. They cover animation visibility and
depth, GUI alpha and rotation, particle dimensions and player look, show-image
mode and type, and particle count. All 11 reopened successfully. The evidence
is in `artifacts/spectron_visual_helper_manual_translation_anchors_20260826.json`,
and the v26 database SHA-256 is recorded in the checkpoint.

A twenty-seventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v27.i64`,
adds 12 reviewed GS2-facing script-runtime anchors. They cover array size,
pause and timeout state, timer and scheduled-event wrappers, script logging,
array-update propagation, access rights, event masks, and universe variable
cleanup. All 12 reopened successfully. The evidence is in
`artifacts/spectron_script_runtime_manual_translation_anchors_20260826.json`,
and the v27 database SHA-256 is recorded in the checkpoint.

A twenty-eighth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v28.i64`,
adds 30 reviewed core-helper anchors. They cover level-object coordinates and
rectangles, numeric arrays, NPC lists and predicates, safe-connector fallback,
socket policy, update lookup, script command records, script-stack behavior,
player arrays, static-variable cleanup, tile state, particle modifiers,
explosion and bomb fields, and texture reload state. All 30 reopened
successfully. The evidence is in
`artifacts/spectron_core_helper_manual_translation_anchors_20260826.json`,
and the v28 database SHA-256 is recorded in the checkpoint.

A twenty-ninth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v29.i64`,
adds 20 reviewed render and GUI anchors. They cover texture timestamp state,
OpenGL reset and blend color, drawing-panel cache and clear behavior, text
measurement, panel operations, client bounds, cursor control, click priority,
scroll dimensions and deltas, and markup selection state. All 20 reopened
successfully. The evidence is in
`artifacts/spectron_render_gui_manual_translation_anchors_20260826.json`,
and the v29 database SHA-256 is recorded in the checkpoint.

A thirtieth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v30.i64`,
adds eight reviewed image-callback, folder-loader, and YAJL JSON anchors. The
GIF and JPEG callbacks are exact normalized matches. The recursive folder
loader and four JSON callbacks changed size, but their callers and callback
table slots preserve the same roles. All eight reopened successfully. The
evidence is in
`artifacts/spectron_json_folder_manual_translation_anchors_20260826.json`,
and the v30 database SHA-256 is recorded in the checkpoint.

A thirty-first disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v33.i64`,
adds 11 reviewed resource-object anchors. They cover the resource insertion
path, filename comparator, file and object link classes, encoded-file keys,
resource-object construction, size and loadability checks, alternative
selection, and stream materialization. These functions changed size in
Spectron, but their class-local behavior and callers preserve the 1.8 roles.
All 11 reopened successfully. The evidence is in
`artifacts/spectron_resource_object_manual_translation_anchors_20260826.json`,
and the v33 database SHA-256 is recorded in the checkpoint.

A thirty-second disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v34.i64`,
adds seven reviewed GS2 script-machine anchors. They cover construction and
destruction, executing-object setup, object-member resolution, assignment,
and numeric comparison. The source and target pseudocode preserve the same
machine state transitions, alias resolution, type dispatch, and comparison
semantics. All seven reopened successfully. The evidence is in
`artifacts/spectron_script_machine_manual_translation_anchors_20260826.json`,
and the v34 database SHA-256 is recorded in the checkpoint.

A thirty-third disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v35.i64`,
adds eight reviewed `TScriptSpace` anchors. They cover event-catcher
registration, class leave transitions, pending leave processing, event-state
lookup, and timeout scheduling. The changed-size target bodies preserve the
same event lists, class-depth checks, timeout normalization, and state
cleanup. All eight reopened successfully. The evidence is in
`artifacts/spectron_script_space_manual_translation_anchors_20260826.json`,
and the v35 database SHA-256 is recorded in the checkpoint.

A thirty-fourth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v36.i64`,
adds six reviewed GS2 execution anchors. They cover function invocation,
self-caught and named-object action dispatch, caught actions, suspended caller
wake-up, and action-list cleanup. The target pseudocode preserves the same
machine lifecycle, event lookup, typed argument construction, and cleanup
paths. All six reopened successfully. The evidence is in
`artifacts/spectron_script_execution_manual_translation_anchors_20260826.json`,
and the v36 database SHA-256 is recorded in the checkpoint.

A thirty-fifth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v37.i64`,
adds three reviewed top-level GS2 dispatch anchors. They cover script-state
execution, action dispatch, and incoming event queueing. The target bodies
preserve machine-state handling, action routing, queue limits, duplicate
suppression, and priority insertion. All three reopened successfully. The
evidence is in
`artifacts/spectron_script_dispatch_manual_translation_anchors_20260826.json`,
and the v37 database SHA-256 is recorded in the checkpoint.

A thirty-sixth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v38.i64`,
adds six reviewed scheduler and cleanup anchors. They cover scheduled-event
cancellation and polling, the main script action loop, event-object unlinking,
ignored events, and class-list replacement. All six reopened successfully.
The evidence is in
`artifacts/spectron_script_scheduler_manual_translation_anchors_20260826.json`,
and the v38 database SHA-256 is recorded in the checkpoint.

A thirty-seventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v39.i64`,
adds six reviewed event-object and catcher-list anchors. They cover the two
constructors, the two deleting destructors, catcher registration, and catcher
list event delivery. All six reopened successfully. The evidence is in
`artifacts/spectron_event_object_manual_translation_anchors_20260826.json`,
and the v39 database SHA-256 is recorded in the checkpoint.

A thirty-eighth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v40.i64`,
adds two reviewed `TScriptAction` anchors for construction and destruction.
Both reopened successfully. The evidence is in
`artifacts/spectron_script_action_manual_translation_anchors_20260826.json`,
and the v40 database SHA-256 is recorded in the checkpoint.

A thirty-ninth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v41.i64`,
adds three reviewed `TScriptStackEntry` conversion anchors for float, string,
and object values. All three reopened successfully. The evidence is in
`artifacts/spectron_stack_entry_manual_translation_anchors_20260826.json`,
and the v41 database SHA-256 is recorded in the checkpoint.

A fortieth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v42.i64`,
adds four reviewed machine-helper anchors for execution restoration, character
extraction, and action-context lookup. All four reopened successfully. The
evidence is in
`artifacts/spectron_machine_helper_manual_translation_anchors_20260826.json`,
and the v42 database SHA-256 is recorded in the checkpoint.

A forty-first disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v43.i64`,
adds three reviewed array-mutation anchors for single-cell, two-dimensional,
and replacement writes. All three reopened successfully. The evidence is in
`artifacts/spectron_array_mutation_manual_translation_anchors_20260826.json`,
and the v43 database SHA-256 is recorded in the checkpoint.

A forty-second disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v44.i64`,
adds two reviewed string-search anchors for all matching indices and
substring positions. Both reopened successfully. The evidence is in
`artifacts/spectron_string_search_manual_translation_anchors_20260826.json`,
and the v44 database SHA-256 is recorded in the checkpoint.

A forty-third disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v45.i64`,
adds three reviewed string-stack anchors for next-string retrieval, indexed
string retrieval, and string formatting. All three reopened successfully. The
evidence is in
`artifacts/spectron_string_helper_manual_translation_anchors_20260826.json`,
and the v45 database SHA-256 is recorded in the checkpoint.

A forty-fourth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v46.i64`,
adds two reviewed variable-construction anchors for script variable creation
and legacy dotted-path resolution. Both reopened successfully. The evidence is
in
`artifacts/spectron_variable_construction_manual_translation_anchors_20260826.json`,
and the v46 database SHA-256 is recorded in the checkpoint.

A forty-fifth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v47.i64`,
adds two reviewed script-object anchors for diagnostic line messages and object
creation. Both reopened successfully. The evidence is in
`artifacts/spectron_script_object_manual_translation_anchors_20260826.json`,
and the v47 database SHA-256 is recorded in the checkpoint.

A forty-sixth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v48.i64`,
adds two reviewed script-state anchors for profiling and player-flag updates.
Both reopened successfully. The evidence is in
`artifacts/spectron_script_state_manual_translation_anchors_20260826.json`,
and the v48 database SHA-256 is recorded in the checkpoint.

A forty-seventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v49.i64`,
adds two reviewed execution-dispatch anchors for script calls and native
function dispatch. Both reopened successfully. The evidence is in
`artifacts/spectron_execution_dispatch_manual_translation_anchors_20260826.json`,
and the v49 database SHA-256 is recorded in the checkpoint.

A forty-eighth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v50.i64`,
adds one reviewed tokenizer anchor for tokenized string array construction. It
reopened successfully. The evidence is in
`artifacts/spectron_tokenizer_manual_translation_anchors_20260826.json`,
and the v50 database SHA-256 is recorded in the checkpoint.

A forty-ninth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v51.i64`,
adds one reviewed script-executor anchor for the bytecode execution loop. It
reopened successfully. The evidence is in
`artifacts/spectron_script_executor_manual_translation_anchors_20260826.json`,
and the v51 database SHA-256 is recorded in the checkpoint.

A fiftieth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v52.i64`,
adds nine reviewed GS2 script-property anchors covering typed reads, typed
writes, property construction, cloning, and property or function registration.
All nine reopened successfully. The evidence is in
`artifacts/spectron_script_property_manual_translation_anchors_20260826.json`,
and the v52 database SHA-256 is recorded in the checkpoint.

A fifty-first disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v53.i64`,
adds eight reviewed GS2 script-universe anchors covering global variables,
static objects, class loading, and zipped script packages. All eight reopened
successfully. The zip compiler is an IDA split function, so its artifact keeps
the short entry range and records the large associated instruction set. The
evidence is in
`artifacts/spectron_script_universe_manual_translation_anchors_20260826.json`,
and the v53 database SHA-256 is recorded in the checkpoint.

A fifty-second disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v54.i64`,
adds three reviewed anchors for static script-variable construction, recursive
JSON serialization, and tile-definition persistence. All three reopened
successfully. The evidence is in
`artifacts/spectron_static_json_tiles_manual_translation_anchors_20260826.json`,
and the v54 database SHA-256 is recorded in the checkpoint.

A fifty-third disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v55.i64`,
adds eight reviewed anchors across tile selection, definition updates,
temporary-tile reconciliation, and screen rendering. All eight reopened
successfully. The tile-block predicates were already covered by the earlier
core-helper checkpoint and are not duplicated. The evidence is in
`artifacts/spectron_tiles_update_manual_translation_anchors_20260826.json`,
and the v55 database SHA-256 is recorded in the checkpoint.

A fifty-fourth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v56.i64`,
adds five reviewed anchors for particle animation names, player-look
appearance restoration, template copying, and coded polygon setup. All five
reopened successfully. The evidence is in
`artifacts/spectron_particle_manual_translation_anchors_20260826.json`,
and the v56 database SHA-256 is recorded in the checkpoint.

A fifty-fifth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v57.i64`,
adds three reviewed `TShowImg` anchors for wire-string encoding, wire-string
dispatch, and network-property encoding. All three reopened successfully. The
evidence is in
`artifacts/spectron_showimg_manual_translation_anchors_20260826.json`,
and the v57 database SHA-256 is recorded in the checkpoint.

A fifty-sixth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v58.i64`,
adds two reviewed particle-emitter anchors for static variable-list setup and
the main emission path. Both reopened successfully. The evidence is in
`artifacts/spectron_particle_emitter_manual_translation_anchors_20260826.json`,
and the v58 database SHA-256 is recorded in the checkpoint.

A fifty-seventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v59.i64`,
adds three reviewed server-animation anchors for explosions, carried objects,
and flying projectiles. All three reopened successfully. The evidence is in
`artifacts/spectron_server_animation_manual_translation_anchors_20260826.json`,
and the v59 database SHA-256 is recorded in the checkpoint.

A fifty-eighth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v60.i64`,
adds two reviewed player lifecycle anchors for initial level loading and the
periodic player timer. Both reopened successfully. The evidence is in
`artifacts/spectron_player_lifecycle_manual_translation_anchors_20260826.json`,
and the v60 database SHA-256 is recorded in the checkpoint.

A fifty-ninth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v61.i64`,
adds two reviewed player emoticon-coordinate anchors for the X and Y getters.
Both reopened successfully. The evidence is in
`artifacts/spectron_player_emoticon_manual_translation_anchors_20260826.json`,
and the v61 database SHA-256 is recorded in the checkpoint.

A sixtieth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v62.i64`,
adds two reviewed player level-entry anchors for main-level and server-level
transitions. Both reopened successfully. The evidence is in
`artifacts/spectron_player_level_entry_manual_translation_anchors_20260826.json`,
and the v62 database SHA-256 is recorded in the checkpoint.

A sixty-first disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v63.i64`,
adds four reviewed player side-level anchors for grid setup, level loading,
coordinate lookup, and directional occupancy. All four reopened successfully.
The evidence is in
`artifacts/spectron_player_side_level_manual_translation_anchors_20260826.json`,
and the v63 database SHA-256 is recorded in the checkpoint.

A sixty-second disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v64.i64`,
adds two reviewed player map-position anchors for active-map refresh and
map-link checks. Both reopened successfully. The evidence is in
`artifacts/spectron_player_map_position_manual_translation_anchors_20260826.json`,
and the v64 database SHA-256 is recorded in the checkpoint.

A sixty-third disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v65.i64`,
adds three reviewed player link-traversal anchors for level animation, nearby
map links, and general object-link traversal. All three reopened successfully.
The evidence is in
`artifacts/spectron_player_link_traversal_manual_translation_anchors_20260826.json`,
and the v65 database SHA-256 is recorded in the checkpoint.

A sixty-fourth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v66.i64`,
adds four reviewed player weapon-state anchors for attribute reset, selected
weapon removal and selection, and weapon lookup. All four reopened
successfully. The evidence is in
`artifacts/spectron_player_weapon_state_manual_translation_anchors_20260826.json`,
and the v66 database SHA-256 is recorded in the checkpoint.

A sixty-fifth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v67.i64`,
adds five reviewed player draw-state and visual setter anchors for the draw
rectangle, head, body, sword, and shield paths. All five reopened successfully.
The evidence is in
`artifacts/spectron_player_visual_setter_manual_translation_anchors_20260826.json`,
and the v67 database SHA-256 is recorded in the checkpoint.

A sixty-sixth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v68.i64`,
adds eight reviewed player movement and interaction anchors for stone actions,
jump checks, movement dispatch, item availability and loss, jump animation,
and hurt handling. All eight reopened successfully. The evidence is in
`artifacts/spectron_player_movement_manual_translation_anchors_20260826.json`,
and the v68 database SHA-256 is recorded in the checkpoint.

A sixty-seventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v69.i64`,
adds six reviewed server-player state anchors for default initialization, head
updates, level membership, nickname propagation, encoded properties, and
weapon-image parsing. All six reopened successfully. The evidence is in
`artifacts/spectron_server_player_state_manual_translation_anchors_20260826.json`,
and the v69 database SHA-256 is recorded in the checkpoint.

A sixty-eighth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v70.i64`,
adds seven reviewed server-NPC anchors for construction, shape callbacks, log
naming, default images, movement updates, and encoded properties. All seven
reopened successfully. The evidence is in
`artifacts/spectron_server_npc_state_manual_translation_anchors_20260826.json`,
and the v70 database SHA-256 is recorded in the checkpoint.

A sixty-ninth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v71.i64`,
adds 17 reviewed compact server-NPC accessor anchors for hurt displacement,
blocking, layer, save state, power, coordinates, and visibility. All 17
reopened successfully. The evidence is in
`artifacts/spectron_npc_accessor_manual_translation_anchors_20260826.json`,
and the v71 database SHA-256 is recorded in the checkpoint.

A seventieth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v72.i64`,
adds two reviewed server-NPC destructor anchors for complete destruction and
the deleting-destructor wrapper. Both reopened successfully. The evidence is
in `artifacts/spectron_npc_destructor_manual_translation_anchors_20260826.json`,
and the v72 database SHA-256 is recorded in the checkpoint.

A seventy-first disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v73.i64`,
adds eight reviewed server-level and level-link property anchors for preload,
dimensions, zone flags, tile-layer count, and destination level access. All
eight reopened successfully. The evidence is in
`artifacts/spectron_server_level_property_manual_translation_anchors_20260826.json`,
and the v73 database SHA-256 is recorded in the checkpoint.

A seventy-second disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v74.i64`,
adds five reviewed server-level interaction anchors for level-link coordinates
and indexed explosion, bomb, and arrow removal. All five reopened successfully.
The evidence is in
`artifacts/spectron_server_level_interaction_manual_translation_anchors_20260826.json`,
and the v74 database SHA-256 is recorded in the checkpoint.

A seventy-third disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v75.i64`,
adds seven reviewed server-level lifecycle, script-test, and animation helper
anchors. All seven reopened successfully. The evidence is in
`artifacts/spectron_server_level_lifecycle_manual_translation_anchors_20260826.json`,
and the v75 database SHA-256 is recorded in the checkpoint.

A seventy-fourth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v76.i64`,
adds four reviewed server-level side-level and flower-hook anchors. The two
side-level methods preserve the source position and directional lookup roles
while using Spectron's expanded seven-by-seven grid. The two adjacent flower
hooks are exact empty-body matches. All four reopened successfully. The
evidence is in
`artifacts/spectron_server_level_side_helpers_manual_translation_anchors_20260826.json`,
and the v76 database SHA-256 is recorded in the checkpoint.

A seventy-fifth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v77.i64`,
adds four reviewed server-level construction, encrypted storage, and
player-enter dispatch anchors. The constructor, save, load, and callback
methods preserve the source control-flow shapes and serialized-format or
event-dispatch behavior. All four reopened successfully. The evidence is in
`artifacts/spectron_server_level_storage_manual_translation_anchors_20260826.json`,
and the v77 database SHA-256 is recorded in the checkpoint.

A seventy-sixth disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v78.i64`,
materializes the previously unnamed 124-byte Spectron `testnpc` callback body
at `0x1a9bb0` and applies the translated label. Its body metrics and normalized
hashes match the 1.8 callback exactly. The boundary addition and verification
are recorded in
`artifacts/spectron_hidden_testnpc_manual_translation_anchor_20260826.json`.

A seventy-seventh disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v79.i64`,
adds six reviewed level and map helper labels. The set covers normalized level
lookup, level-list indexing, link serialization, current-map selection, GMAP
loading, and optional map placeholder construction. All six reopened
successfully. The evidence is in
`artifacts/spectron_level_map_lookup_manual_translation_anchors_20260826.json`,
and the v79 database SHA-256 is recorded in the checkpoint.

An additional v80 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v80.i64`,
adds the reviewed `TGaniObject` constructor anchor. The target preserves the
same animation-parameter and color-variable initialization, including the
`attr` and `black` literals. Its larger body also records the extra Spectron
random-seed and encoded-buffer state. The label reopened successfully, with
the evidence in
`artifacts/spectron_gani_constructor_manual_translation_anchor_20260826.json`.

A v81 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v81.i64`,
adds two smaller Gani helpers. The first translates the color-variable string
setter, including its named-color lookup, integer fallback, and virtual color
assignment. The second translates sprite image-name selection, including the
child-Gani walk, indexed image lookup, body fields, global sprites and tiles
filenames, and the type switch. Both labels reopened successfully. The
evidence is in
`artifacts/spectron_gani_helper_manual_translation_anchors_20260826.json`.

A v82 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v82.i64`,
adds four Gani runtime anchors. They cover 2D draw-matrix setup, parameter
and attribute writes, parameter and attribute reads, and the main animation
start routine. The labels reopened successfully in a serial IDA check. The
evidence is in
`artifacts/spectron_gani_runtime_manual_translation_anchors_20260826.json`.

A v83 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v83.i64`,
adds three Gani rendering anchors. They cover parameter string decoding and
child-animation creation, animation reload and child-script refresh, and the
player draw dispatcher. All three labels reopened successfully. The evidence
is in
`artifacts/spectron_gani_render_manual_translation_anchors_20260826.json`.

A v84 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v84.i64`,
adds two larger Gani runtime anchors. The frame setter preserves the complete
actor-property pipeline, including movement modifiers, equipment, sprite
selectors, text fields, colors, zoom, and text-style flags. The playback
method preserves child-object updates, frame looping, active-player action
handling, sound-resource lookup, and the audio bridge. Both labels reopened
successfully. The evidence is in
`artifacts/spectron_gani_frame_playback_manual_translation_anchors_20260826.json`,
and the v84 database SHA-256 is recorded in the checkpoint.

A v85 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v85.i64`,
adds 50 high-confidence Gani lifecycle anchors. The set covers Gani object
teardown, inherited coordinate and attachment accessors, virtual hooks,
property destructor pairs, event forwarding, color-variable cleanup, animation
flags, the `setbackto` string, owner-list operations, encrypted script loading
and saving, type classification, constructor state, cache cleanup, resource
loading, and static property setup. The target keeps the same field offsets,
virtual slots, class-local ordering, or exact wrapper shape for each reviewed
role. All 50 labels reopened successfully. The evidence is in
`artifacts/spectron_gani_lifecycle_manual_translation_anchors_20260826.json`,
and the v85 database SHA-256 is recorded in the checkpoint.

A v86 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v86.i64`,
adds two high-confidence TPlayer anchors. The network-property serializer
keeps the same property switch, packet encoding, player field offsets, and
`head` and whitespace literals. The integer constructor keeps the complete
player initialization order and all seven constructor literals, including
`client`, `clientr`, `selectedlistplayers`, `weapons`, `letters.png`, `idle`,
and `android`. Both labels reopened successfully, and the v86 database
SHA-256 is recorded in the checkpoint. The evidence is in
`artifacts/spectron_tplayer_core_manual_translation_anchors_20260826.json`.

A v87 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v87.i64`,
adds three high-confidence parser and resource anchors. They cover the
generated Gani lexer, cached-resource download path selection, and the
update-package directive parser. The target preserves the parser state
machine, all 53 resource path literals, and all 19 package directive
literals. All three labels reopened successfully, and the v87 database
SHA-256 is recorded in the checkpoint. The evidence is in
`artifacts/spectron_resource_parser_manual_translation_anchors_20260826.json`.

A v88 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v88.i64`,
adds five high-confidence static utility anchors. They cover engine
statistics, profiler output, GUI button-style extraction, ZIP resource
scanning, and translation plural-rule handling. The target preserves the
distinctive report, style, resource, and plural-form literals, with one
explicit target-only `GRAALRELOADED-version` report line recorded as a
version difference. All five labels reopened successfully, and the v88
database SHA-256 is recorded in the checkpoint. The evidence is in
`artifacts/spectron_static_utility_manual_translation_anchors_20260826.json`.

A v89 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v89.i64`,
adds four high-confidence font and bitmap anchors. They cover glyph data setup,
font atlas generation, font resource loading, and bitmap resource loading with
retry behavior. The target preserves the distinctive font, texture, profiler,
and graphics messages. All four labels reopened successfully, and the v89
database SHA-256 is recorded in the checkpoint. The evidence is in
`artifacts/spectron_font_bitmap_manual_translation_anchors_20260826.json`.

A v90 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v90.i64`,
adds one high-confidence image-animation anchor. The 1.8 MNG animation-step
decoder maps to a same-size target routine with the same instruction count and
four-call pixel-pass structure. Its one extra target basic block is recorded
as a rebuild difference. The label reopened successfully, and the v90 database
SHA-256 is recorded in the checkpoint. The evidence is in
`artifacts/spectron_mng_animation_manual_translation_anchor_20260826.json`.

A v91 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v91.i64`,
adds two high-confidence script-machine anchors. They cover function-parameter
conversion and native callback dispatch. The target keeps the same stack type
conversions, callback packing, and result-slot updates, while adding newer
string handling and an `e` parameter type. Both labels reopened successfully,
and the v91 database SHA-256 is recorded in the checkpoint. The evidence is in
`artifacts/spectron_script_machine_tail_manual_translation_anchors_20260826.json`.

A v92 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v92.i64`,
adds two high-confidence script-stream and profiling anchors. They cover the
GS2 bytecode stream parser and the function/class profile report. The target
preserves the same script record walk, `public.` handling, function
registration, elapsed-time calculation, sorting, and `Class ` output. Its
rebuilt string and list wrappers, long-double profile temporaries, and missing
standalone percent literal reference are recorded as target-version or
decompiler differences. Both labels reopened successfully, and the v92
database SHA-256 is recorded in the checkpoint. The evidence is in
`artifacts/spectron_script_stream_profile_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_stream_profile_anchors.py`.

A v93 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v93.i64`,
adds one high-confidence generated-animation-lexer anchor. The target helper
is called by the already translated Spectron lexer and has the same compact
fatal-path shape as 1.8. Spectron calls `exit(0)` where 1.8 calls `exit(2)`,
so the status change is recorded rather than hidden. The label reopened
successfully, and the v93 database SHA-256 is recorded in the checkpoint. The
evidence is in
`artifacts/spectron_ani_lexer_fatal_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_ani_lexer_fatal_anchor.py`.

A v94 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v94.i64`,
adds eight high-confidence numeric-array string anchors. The set covers the
double and short template versions of indexed string setters, indexed string
reads, comma-separated array reads, and string-list writes. The target keeps
the same array access and virtual setter logic, while its rebuilt string and
list wrappers make several temporaries explicit and increase the call counts.
All eight labels reopened successfully, and the v94 database SHA-256 is
recorded in the checkpoint. The evidence is in
`artifacts/spectron_number_array_string_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_number_array_string_anchors.py`.

A v95 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v95.i64`,
adds two high-confidence client-environment clock anchors. They cover the
build-time helper and the time-expiry check. The comparison also records an
important version difference: 1.8 builds a fixed 2019-02-13 timestamp and
uses a fixed 15-day threshold, while Spectron reads the date and day count from
globals. Both labels reopened successfully, and the v95 database SHA-256 is
recorded in the checkpoint. The evidence is in
`artifacts/spectron_client_environment_clock_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_environment_clock_anchors.py`.

A v96 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v96.i64`,
adds three high-confidence `TGraalClientVar` anchors. They cover the flag
send and unset dispatcher, the string write path, and indexed string updates.
The target preserves child-name construction, change suppression, virtual
value reads, base-class writes, and send-on-change behavior. Its rebuilt
string wrappers add a few calls and bytes. All three labels reopened
successfully, and the v96 database SHA-256 is recorded in the checkpoint. The
evidence is in
`artifacts/spectron_client_var_core_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_var_core_anchors.py`.

A v97 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v97.i64`,
adds four high-confidence `TStringList` comma-text anchors. They cover the
quoted-field parser, string constructor, single-quote serializer, and
double-quote serializer. The target keeps the same comma splitting, quote
escaping, empty-field behavior, length guards, and list iteration. Spectron
adds explicit `C8THgaTQxF` temporary-string operations and a constructor byte
flag, so the target bodies are not byte-identical even though their control
flow and helper roles line up. All four labels reopened successfully, and the
full translation check still reports zero failures. The v97 database SHA-256
is recorded in the checkpoint. The evidence is in
`artifacts/spectron_tstringlist_comma_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tstringlist_comma_anchors.py`.

A v98 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v98.i64`,
adds seven high-confidence `TStringList` anchors for assignment, range append,
key/value access, newline serialization, file output, and tokenization. The
target keeps the same list-copy, key lookup, empty-replacement deletion,
newline, file-mode, delimiter, quote, trim, and trailing-empty-field logic.
Its rebuilt `C8THgaTQxF` and `CanTfaz6bZ` wrappers change several body sizes
and call counts, and some literals are represented as data rather than IDA
string references. All seven labels reopened successfully, and the full
translation check still reports zero failures. The v98 database SHA-256 is
recorded in the checkpoint. The evidence is in
`artifacts/spectron_tstringlist_extended_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tstringlist_extended_anchors.py`.

A v99 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v99.i64`,
adds nine high-confidence `THashList` and `THashStrings` anchors. They cover
case-sensitive, case-insensitive, and encoded bucket lookup, hash-list copy
and sorting, hash-string lookup and updates, and name/value serialization. The
target retains the same bucket traversal, iterator, insertion, replacement,
deletion, and quote-escaping decisions. Spectron has a narrower hash-list
assignment signature and uses rebuilt string wrappers, so those differences
are recorded in the evidence. All nine labels reopened successfully, and the
full translation check still reports zero failures. The v99 database SHA-256
is recorded in the checkpoint. The evidence is in
`artifacts/spectron_hash_family_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_hash_family_anchors.py`.

A v100 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v100.i64`,
adds seven high-confidence `TOptions` anchors. They cover external and default
GUI-style change events, decoded nickname, account, and password getters,
account list and registry persistence, and the options refresh timer. The
target keeps the same guards, credential slots, guest and cookie filtering,
five-entry list cap, and event behavior. Its explicit string wrappers and
`accountname_new` literal are recorded as target-version differences. All
seven labels reopened successfully, and the full translation check still
reports zero failures. The v100 database SHA-256 is
`3b438b39ec6f02fe7a8059c1abe8172338b0d1cee936522ce9e23611f4f94b5d`. The
evidence is in
`artifacts/spectron_options_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_options_anchors.py`.

A v101 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v101.i64`,
adds ten high-confidence `TTexture` anchors. They cover bitmap width and
height accessors, GPU texture allocation and dimensions, the deleting
destructor, the window-backed constructor, Graal bitmap lookup, global
registry cleanup, and static registry initialization. The target retains the
same lazy-load guards, bitmap and GPU dimension fields, virtual load path,
registry behavior, and constructor initialization order. Its explicit
`C8THgaTQxF` and `CanTfaz6bZ` wrappers, constructor ABI spelling, and extra
Graal lookup overloads are recorded as target-version differences. All ten
labels reopened successfully, and the full translation check still reports
zero failures. The v101 database SHA-256 is
`8944246d7b9b491cecbeec2298383defe1d624a6643d654fdc28894885c15913`. The
evidence is in
`artifacts/spectron_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_texture_anchors.py`.

A v102 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v102.i64`,
adds five high-confidence `TDrawingPanelTexture` anchors. They cover the
complete and deleting destructors, the window-backed constructor, and the
GPU texture width and height accessors. The target preserves panel-port base
destruction and construction, the null texture initialization, the virtual
texture update call, and the same dimension fields. The target's C1 and D0
ABI spellings and obfuscated base class are recorded as implementation
differences. All five labels reopened successfully, and the full translation
check still reports zero failures. The v102 database SHA-256 is
`387015ee8aa3b32836bec8914d471f111ea310780a9da2dd2d5349fcde98f650`. The
evidence is in
`artifacts/spectron_drawing_panel_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_drawing_panel_texture_anchors.py`.

A v103 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v103.i64`,
adds four high-confidence `TDrawTexture` anchors. They cover the static
texture-list initializer, global texture cleanup, full texture reload, and
the OpenGL bind helper. The target preserves list allocation and publication,
indexed traversal, per-entry delete and load calls, and the OpenGL texture
target and object field. The static initializer was still a default `sub_`
name and is now recorded with a readable `v18_` label. All four labels
reopened successfully, and the full translation check still reports zero
failures. The v103 database SHA-256 is
`bb0cb110ad0926c183bccc00d71d084ba5f5220945f56d70950d0f7bb300808e`. The
evidence is in
`artifacts/spectron_draw_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_draw_texture_anchors.py`.

A v104 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v104.i64`,
adds five high-confidence `TBitmapArrayHolder` anchors. They cover the
string constructor, deleting destructor, bitmap rectangle discovery loop,
lazy rectangle registry lookup, and static registry initialization. The
target preserves color-run scanning, rectangle edge detection, list
insertion, normalized filename lookup, and registry creation. Its typed
string and list wrappers are recorded as target-version differences. All five
labels reopened successfully, and the full translation check still reports
zero failures. The v104 database SHA-256 is
`a2f163408c9fb6e29863efd888d98597ae87cdb514335fdc27647e4b9f5f0fe1`. The
evidence is in
`artifacts/spectron_bitmap_array_holder_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_bitmap_array_holder_anchors.py`.

A v105 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v105.i64`,
adds five high-confidence `TColorManager` anchors. They cover activation,
top-entry lookup, full transform-stack cleanup, top-entry removal, and static
matrix-list initialization. The target preserves the global list guards,
last-entry selection, ownership cleanup, and 0x18-byte list allocation while
using the obfuscated `X7ZxganTcx` class and its `UuAMgaMjuJ` global. All five
labels reopened successfully, and the full translation check still reports
zero failures. The v105 database SHA-256 is
`705878c4d7ceaf711e1a93e80bc6bed3449d0af9d28ac3c38c7f5f4ca69dc36c`. The
evidence is in
`artifacts/spectron_color_manager_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_color_manager_anchors.py`.

A v106 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v106.i64`,
adds six high-confidence font and resource anchors. They cover TFont
construction and texture creation, TFontManager file lookup and static
registries, UTF-8 font-range registration, and TFontData construction. The
target preserves the font search fallbacks, glyph texture setup, range list
ownership, and 0x18-byte font-data list. Its smaller font-manager initializer
does not seed the `/system/fonts/` string in this function, so that target
version difference remains visible in the evidence. All six labels reopened
successfully, and the full translation check still reports zero failures. The
v106 database SHA-256 is
`f4089384f3663f387e9838fa1b4f6ad4932b003b163940ddd1a78e0047729c52`. The
evidence is in
`artifacts/spectron_font_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_font_runtime_anchors.py`.

A v107 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v107.i64`,
adds two high-confidence `TWindow` input anchors. They cover mouse-event
normalization and key-event dispatch, including canvas routing, cursor and
special-key handling, input fallback, control bindings, and control-key
events. The target adds explicit logging and rebuilt input wrappers, but the
event state transitions remain aligned. Both labels reopened successfully,
and the full translation check still reports zero failures. The v107 database
SHA-256 is
`53c6c656d4f44bf6b74977e9a6441658bf0bd502f1013d387b078098caac3dee`. The
evidence is in
`artifacts/spectron_window_input_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_window_input_anchors.py`.

A v108 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v108.i64`,
adds six high-confidence `TDrawingPanel` anchors. They cover both panel
constructors, image and image-rectangle implementation wrappers, named image
filter selection, and named draw-palette selection. The target preserves the
tiles special case, texture-size lookup, rectangle forwarding, all six image
filters, and palette list behavior while exposing updated wrappers. All six
labels reopened successfully, and the full translation check still reports
zero failures. The v108 database SHA-256 is
`8350a43be6b31306954e34a17f77d742c8d1702015d671019d2bf2dd6c1bb1e1`. The
evidence is in
`artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_drawing_panel_residual_anchors.py`.

A v109 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v109.i64`,
adds four high-confidence anchors for HTML color-list initialization and the
`TImageAnimation` lifecycle. They cover the color registry initializer, the
image-animation constructor, and both complete and deleting destructors. The
target keeps the same two-container color registry, palette construction,
optional bitmap-buffer release, and palette cleanup. Its obfuscated
`nDIHgaJ9nF`, `n_rGfa49jO`, and `NLT0HaSwmE` classes replace the source names,
and the target string and list wrappers make a few temporary conversions
explicit. All four labels reopened successfully, and the full translation
check still reports zero failures. The v109 database SHA-256 is
`50b930130628290213ede4905c578676ca3996280c40ac8d9bb8527e44d5695d`. The
evidence is in
`artifacts/spectron_image_html_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_image_html_anchors.py`.

A v110 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v110.i64`,
adds four high-confidence panel and bitmap-loader anchors. They cover
window-backed `TPanelInterface` construction, bitmap extension dispatch,
forced resource redownload, and level-image lookup with extension fallback.
The target preserves the source PNG, MNG, BMP, DIB, GIF, JPEG, and TGA
decoder choices, resource lookup guards, and download state transitions. It
also contains a logged GIF retry path, which is documented as a 2.2 behavior
difference. All four labels reopened successfully, and the full translation
check still reports zero failures. The v110 database SHA-256 is
`1a10cd6b7c5a586ecdd8c6f475c753dbbdc9ac5d21b74e3590758212fe8a2129`. The
evidence is in
`artifacts/spectron_panel_bitmap_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_panel_bitmap_anchors.py`.

A v146 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v146.i64`,
adds six exact-shape GSFunctions callback anchors for `degtorad`, `radtodeg`,
temporary-string cleanup, case-insensitive comparison, `uppercase`, and
`lowercase`. It also materializes the previously unbounded 24-byte `radtodeg`
callback from the Spectron script table. The v146 database has 11,680
functions and 1,469 remaining default `sub_` names. Its SHA-256 is
`a868b16b549a8e70c40d5ded8f487228674d3295f9d41fe35c3bc03449b05556`. The
evidence is in
`artifacts/spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_math_string_residual_anchors.py`.

A v147 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v147.i64`,
restores the missing IDA boundary for the target `getstringkeys` callback at
`0x2111d8` and reviews 13 callbacks from the shared GSFunctions script-table
block. The v147 database has 11,681 functions and 1,470 remaining default
`sub_` names before the aliases from this batch are applied. The persisted
v148 copy contains all 13 new `v18_` labels and has 1,457 remaining defaults.
Its SHA-256 is
`ea1cd81d0d6639959b0ddbf70d2f66ec20883fdd49e879ec077e61d8199a2b8d`. Eight
pairs are exact normalized-shape matches. Five larger pairs are high-confidence
script-table matches with layout or helper-call changes in the stripped build.
The `getstringkeys` range is materialized as `0x2111d8..0x211424`, ending
before the next table callback. The evidence is in
`artifacts/spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_callback_residual_anchors.py`.

A v154 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v154.i64`,
closes the `GSFunctionsClient` table audit with 11 exact-shape callbacks from
the Adventure, fullscreen, application-state, and URL groups. Their table
fields use the same verified `+0x13010` relocation, and all 11 normalized
function fingerprints match. The v154 database has 11,693 functions and
1,396 remaining default `sub_` names. Its SHA-256 is
`5464d8379812980ccd785837e6000adf82d9a965ccac563faed78ca43ac90c06`. The
evidence is in
`artifacts/spectron_gsfunctions_client_exact_residual_v4_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v4_anchors.py`.

A v155 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v155.i64`,
adds 30 exact-shape aliases for the residual `CyaInt` TLS and cryptography
methods. The batch covers verification-path and certificate-buffer loading,
session and cipher accessors, protocol selectors, and the master-secret
derivation path. Every target keeps a readable CyaInt C++ method name in its
obfuscated mangling, every normalized fingerprint matches, and every target
address is the source address plus `0xd590`. The v155 database has 11,693
functions and 1,396 remaining default `sub_` names. Its SHA-256 is
`c622c67da076477d4c82917cc18ccc92260679e1e0034a5bf029ea517456de09`. The
evidence is in
`artifacts/spectron_cyaint_tls_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_cyaint_tls_residual_anchors.py`.

A v156 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v156.i64`,
adds the remaining 53 exact-shape `CyaInt` aliases. This completes the
combined audit of all 266 named `CyaInt` methods in the original feature
export. The second batch covers RSA verification and decryption, TLS I/O
callbacks, verification-mode setters, DTLS and timeout helpers, TLS 1.0
through 1.2 client methods, OCSP and X.509 accessors, and the TLS mutex
wrappers. Every row keeps the same `+0xd590` relocation and exact normalized
fingerprint. The v156 database still has 11,693 functions and 1,396 default
`sub_` names. Its SHA-256 is
`addc91603c90f9dff6653fcf9d18dd636731237585549f4461efe7a6f7a6bd91`. The
evidence is in
`artifacts/spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_cyaint_tls_residual_v2_anchors.py`.

A v157 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v157.i64`,
adds 37 exact-shape aliases for the contiguous scalar `TServerPlayer`
accessor block. The source getters and setters at `0x18a1a4..0x18a2c4`
correspond to the obfuscated `MpGzgariDy` block at
`0x18e98c..0x18eaac`. Every pair has the same complete normalized fingerprint,
and the target fields are consistently the source fields plus 24 bytes. All
37 labels reopened successfully. The v157 database still has 11,693 functions
and 1,396 default `sub_` names. Its SHA-256 is
`6daaa47e8ee98b08a5e447e86790b3e05f5828fa0cfb0d9e97f99e7b857ca3fc`. The
evidence is in
`artifacts/spectron_tserverplayer_accessor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tserverplayer_accessor_anchors.py`.

A v158 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v158.i64`,
adds ten exact-shape aliases for the contiguous `TPlayer` scalar setter
block. The source setters at `0x16cec4..0x16d5cc` correspond to the
obfuscated `W6NzgawMJy` block at `0x170ac4..0x1711cc`. The first pair is a
168-byte, 41-instruction body and the other nine pairs are 204-byte,
51-instruction bodies. Every pair has the same complete normalized
fingerprint, and the target address is source plus `0x3c00` throughout.
The target object-layout constants move between individual setters, so the
artifact records the mapping as a class-local block rather than claiming one
uniform field-offset delta. All ten labels reopened successfully. The v158
database has 11,693 functions and 1,396 default `sub_` names. Its SHA-256 is
`d779d88b82129c4502d0f6682449c519a698f7317b9e4b5be5af1de18d5a2444`. The
evidence is in
`artifacts/spectron_tplayer_scalar_setter_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tplayer_scalar_setter_anchors.py`.

A v159 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v159.i64`,
adds 21 exact-shape aliases for the contiguous `TPlayer` scalar getter block.
The source getters at `0x17afd8..0x17b510` correspond to the obfuscated
`W6NzgawMJy` block at `0x17f37c..0x17f8b4`. The block covers local
coordinates, health, inventory, combat power, movement flags, and visibility
state. Every pair has the same complete normalized fingerprint, the target
address is source plus `0x43a4`, and the encoded storage and mask offsets are
source plus 24 bytes. All 21 labels reopened successfully. The v159 database
still has 11,693 functions and 1,396 default `sub_` names. Its SHA-256 is
`75cd77b15f4c27b4f73f7a39797f76459c42cb8d6abf3b75c3ba99fbddea914d`. The
evidence is in
`artifacts/spectron_tplayer_scalar_getter_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tplayer_scalar_getter_anchors.py`.

A v160 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v160.i64`,
adds seven exact-shape aliases for the remaining `TPlayer` flag and feature
setters. Six boolean setters form a contiguous source block at
`0x17b59c..0x17b7b8`, and `setEnabledFeatures` follows the already translated
`setPaused` interstitial at `0x17b8a0`. The matching obfuscated
`W6NzgawMJy` targets are at `0x17f940..0x17fb5c` and `0x17fc44`. Every pair
has the same complete normalized fingerprint and the code relocation is
`+0x43a4`. All seven labels reopened successfully. The v160 database still
has 11,693 functions and 1,396 default `sub_` names. Its SHA-256 is
`bc4bfdf5b0b3f82dfc9e61802c6cafdaad535b8c876a77f1e6612def5d8fa9f8`. The
evidence is in
`artifacts/spectron_tplayer_flag_setter_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tplayer_flag_setter_anchors.py`.

A v161 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v161.i64`,
adds 39 exact-shape aliases for the main `TServerPlayer` property block. The
source range is `0x18a55c..0x18aa5c` and the corresponding obfuscated
`MpGzgariDy` range is `0x18edbc..0x18f2bc`. It covers the paused and combat
properties, relationship and account flags, MP and rating values, and the X
and Y coordinate accessors and setters. Four rows already had `v18_` labels
and were retained as sequence checkpoints. The 39 newly labeled pairs have identical
complete normalized fingerprints, and the target address is source plus
`0x4860` throughout. Thirty-eight target functions had default `sub_` names
before this pass. All 39 labels reopened successfully. The v161 database has
11,693 functions and 1,358 default `sub_` names. Its SHA-256 is
`000eb36e5ceb7dfc75c9b8565b92c16649cb0d835232972c4ccad81ebab044d0`. The
evidence is in
`artifacts/spectron_tserverplayer_property_block_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tserverplayer_property_block_anchors.py`.

A v163 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v163.i64`,
adds 25 aliases for the remaining `TServerPlayer` registration callbacks. The
pass reads the 52-entry `TServerPlayerProperties` table in both builds and the
six-entry script-function table. The source property table starts at
`0x37ce00`, the Spectron table at `0x38fe60`, and each record is `0x30` bytes.
The callback fields are read directly from record offsets `+0x10` and `+0x18`.

This table evidence matters because Spectron reorders the image and text
accessors. Twenty-three pairs have identical complete normalized fingerprints,
including the three newly bounded script callbacks at `0x18f2c8`, `0x18f2e8`,
and `0x18f2f0`. The headset getter and show-profile callback are two
high-confidence layout changes with the same registration slots and roles, but
larger target bodies. All 25 targets had default names before this pass.
The player-index and log-name implementations already had shared aliases, so
they are documented as preserved context rather than renamed twice.

All 25 new labels reopened successfully. The full semantic reopen check still
passed with 3,641 high-confidence labels and zero failures across 11,694
functions. The v163 database has 1,334 default `sub_` names. Its SHA-256 is
`a71091ea191f50791b1f5c74d11beb104b96fc828b80fee65ec4609ff9f2d6cb`. The
evidence is in
`artifacts/spectron_tserverplayer_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tserverplayer_residual_anchors.py`.

A v164 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v164.i64`,
adds the final seven named `TServerPlayer` rows from the current residual
list. The batch covers the `attachedtoobject` setter, nickname cleanup, the
D0 deleting destructor, both static initializers, and the local X and Y
setters. The attachment setter is confirmed by property-table index 3. The
other rows are supported by exact normalized fingerprints and their
class-local lifecycle or initialization sequences.

All seven pairs match the complete normalized feature set. Only the target
attachment setter had a default `sub_` name before this pass. The source alias
`TServerPlayer_TServerPlayer__2` is constructor-like because of the local alias
convention, but its original ELF symbol is `_ZN13TServerPlayerD0Ev`, so the
correct role is the D0 deleting destructor. The target `_ZN10MpGzgariDyD0Ev`
confirms that interpretation.

The seven labels reopened successfully, and the full semantic check still
passed with 3,641 high-confidence labels and zero failures across 11,694
functions. The v164 database has 1,333 default `sub_` names. Its SHA-256 is
`321b0d07651f463e128399cc3e0e0f56669394cd6ba97ed1c13224b6a5462cc5`. The
evidence is in
`artifacts/spectron_tserverplayer_tail_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tserverplayer_tail_anchors.py`.

A v166 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v166.i64`,
adds 24 aliases for the remaining named `TShowImg` class methods and the
`TShowImgProperties` destructor family. The rows cover the double z helper,
image and layer wrappers, text, polygon, animation, font, resource-update,
attach-owner, singleton initialization, the `TShowImg` D0 destructor, and
both properties-class destructor thunks.

Twenty-two pairs match the complete normalized feature set. The two
properties-class destructor rows keep the same lifecycle role and common
metrics, but their vtable literals change the opcode and overall-shape
hashes, so they are documented as layout-aware anchors. The target names all
retained obfuscated C++ symbols before this pass, so this batch does not
reduce the default `sub_` count. The residual code deltas group as `+0x9d58`
for one row, `+0x9df0` for one, `+0x9e88` for seven, and `+0x9ea0` for 15.

All 24 labels reopened successfully. The full semantic check still reports
zero failures across 11,694 functions, 3,641 high-confidence labels, and
1,264 default `sub_` names. The v166 database SHA-256 is
`31b96a52e45a605de9aa2c881ea9061c33afda1b2dfac5773c1a420ea7caec77`.
The evidence is in
`artifacts/spectron_showimg_residual_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_showimg_residual_anchors.py`.

A v167 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v167.i64`,
adds 12 exact-shape aliases in the server-object cluster. The batch resolves
the `TServerBomb` time, order-point, and image methods, the `TServerChest`
open setter, the six short `TServerFlying` scalar accessors plus its
order-point helper, and the `TExplosion` constructor.

All 12 rows match the complete normalized feature set. Eight target bodies
had default `sub_` names before the pass; the other four retained obfuscated
C++ names. Class-local ordering and IDA pseudocode distinguish repeated
getter and setter shapes, including the observed `TServerFlying` dy setter
store, which is recorded exactly as present in both builds. All 12 labels
reopened successfully. The full semantic check remains at zero failures
across 11,694 functions, with 3,641 high-confidence labels and 1,256 default
`sub_` names. The v167 database SHA-256 is
`99e9466a62544d22433484e73013683ff716f2308956066c83650abc6f449387`.
The evidence is in
`artifacts/spectron_server_object_scalar_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_server_object_scalar_anchors.py`.

A v168 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v168.i64`,
adds five exact-shape aliases for the `TCompression` family. The rows cover
the string and raw-buffer `CompressBuf` overloads, the string decompression
wrapper, and both `CompressBuf2` overloads. IDA pseudocode confirms the
TString extraction, empty-value fallback, raw implementation dispatch, and
output-buffer append behavior in both builds.

All five pairs match the complete normalized feature set and share the
`+0xbe8` address delta. The target methods retain the obfuscated
`MHEiIauRiT` class names, so the `v18_` labels are a readable analysis
overlay, not recovered 2.2 symbols. All five labels reopened successfully.
The full semantic check remains at zero failures across 11,694 functions, with
3,641 high-confidence labels and 1,256 default `sub_` names. The v168
database SHA-256 is
`f128cbd323aa0e5f1a021c447f404b0f9b3778d83ab1dfffc7095b004191b4fd`. The
evidence is in
`artifacts/spectron_compression_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_compression_anchors.py`.

A v169 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v169.i64`,
adds six exact-shape aliases for the `TFiles` family. The batch covers file
size, UTC modification time, filename extraction, lower-case filename
handling, URL-aware filename stripping, and URL-aware extension stripping.
The target `wiULgacZUI` pseudocode preserves the same stat guards, separator
handling, temporary-string cleanup, and URL exceptions seen in the 1.8 build.

All six pairs match the complete normalized feature set and share the
`+0xbe8` address delta. The target functions retain obfuscated C++ names, so
the `v18_` labels are a readable analysis overlay rather than recovered 2.2
symbols. All six labels reopened successfully. The full semantic check still
reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,256 default `sub_` names. The v169 database SHA-256 is
`0904e8d1b0f8f97a2536cd34a44f12974365f427f4c590c89e83efc1ca570d53`. The
evidence is in
`artifacts/spectron_files_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_files_anchors.py`.

A v170 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v170.i64`,
adds nine exact-shape aliases for the `TEncryption` family. The batch covers
the DES string wrappers, the script-facing MD5 wrapper, RSA signing, RC4
cleanup and processing, and AES cleanup, encryption, and decryption. IDA
pseudocode confirms the algorithm-specific native calls and their guard,
temporary-buffer, key-lifecycle, and output-copy behavior.

All nine pairs match the complete normalized feature set. Three rows share
the `+0xbe8` delta and six rows share `+0x2294`, reflecting two target class
subclusters rather than a global relocation. One target body had a default
`sub_` name before the pass. All nine labels reopened successfully. The full
semantic check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,255 default `sub_` names. The v170 database
SHA-256 is
`3464dc1d4195ae163bf8648b0de26d4e3d51c6722a27e4bd0600fd912d44d4e8`. The
evidence is in
`artifacts/spectron_encryption_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_encryption_anchors.py`.

A v171 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v171.i64`,
adds six exact-shape aliases for the `TList` family. The rows cover indexed
replacement, repeated-value removal, full-list append, signed and unsigned
indexed access, and the qsort thunk. IDA pseudocode confirms the list bounds,
delete loop, bulk-range forwarding, and direct qsort dispatch.

All six pairs match the complete normalized feature set and share the
`+0xfd0` address delta. The signed and unsigned accessors have identical
bodies, so their adjacent overload order is recorded as part of the evidence.
All six labels reopened successfully. The full semantic check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,255
default `sub_` names. The v171 database SHA-256 is
`48c9462053b822cd6e511abfc317dd1fa8c5082c8152425d4130e710c4c97714`. The
evidence is in
`artifacts/spectron_tlist_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tlist_anchors.py`.

A v172 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v172.i64`,
adds eight exact-shape aliases for the `TSounds` family. The batch covers
offscreen-distance state, disabled-effects comma text, the script stop-sounds
wrapper, sound-resource cleanup, MIDI shutdown, and absolute playback. IDA
pseudocode confirms the global state accesses, list cleanup, virtual player
call, and playback forwarding path.

All eight pairs match the complete normalized feature set. The address deltas
split into `+0xbb0`, `+0xbd4`, and `+0xbe8` class-local groups. Five target
bodies had default `sub_` names before the pass, reducing the measured count
to 1,250. All eight labels reopened successfully. The full semantic check
reports zero failures across 11,694 functions, with 3,641 high-confidence
labels. The v172 database SHA-256 is
`fb51afe8228075594ac0c80e0582ea2733cb38a73b8526542ebfcf1500dc23cd`. The
evidence is in
`artifacts/spectron_sounds_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sounds_anchors.py`.

A v173 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v173.i64`,
adds five exact-shape aliases across the remaining `THashList` and
`THashStrings` helpers. The rows cover deleting destructors, iterator
registration, the maximum-count setter, and a string-membership predicate.
The source constructor-like aliases are documented as deleting destructors
where the bodies and target D0 names establish that lifecycle role.

All five pairs match the complete normalized feature set. Their local address
deltas are `+0xbec`, `+0xc4c`, and `+0xc74`, reflecting separate target class
clusters. All five labels reopened successfully, and the full semantic check
remains at zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,250 default `sub_` names. The v173 database SHA-256 is
`9640159d6f6080f9b0ec9c86c9fe244a68be1a43e768138f25e2b2ce49b958e5`. The
evidence is in
`artifacts/spectron_hash_container_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_hash_container_anchors.py`.

A v174 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v174.i64`,
adds six exact-shape aliases for the `TString` helper family. The rows cover
signed, unsigned, and 64-bit integer stream insertion, prefix testing, and
the `strcasecmp` and `strncasecmp` wrappers. IDA pseudocode confirms the
three internal integer-formatting calls, the null and length guards in the
prefix predicate, and the direct libc comparison thunks.

All six pairs match the complete normalized feature set. The three insertion
rows share the `+0x14d8` delta, while the prefix and comparison rows share
`+0x1720`. None of the six target bodies had a default `sub_` name before the
pass. All six labels reopened successfully, and the full semantic check still
reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,250 default `sub_` names. The v174 database SHA-256 is
`782b29da324e6eac107788b32c1a03105adedd976d561f0802a10913692af4ed`. The
evidence is in
`artifacts/spectron_tstring_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tstring_anchors.py`.

A v175 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v175.i64`,
adds the core `TString_clear_void` alias. The source and target bodies both
release the reference-counted string storage when needed, decrement a shared
reference count otherwise, and then null the object pointer. The broad matcher
left this row ambiguous because the separate `CanTfaz6bZ::clear` method has
the same normalized shape, so the class-qualified `C8THgaTQxF::clear` name and
the surrounding TString cluster are recorded as the deciding evidence.

The pair matches the complete normalized feature set and uses the local
`+0x14d8` delta. The target body already had an obfuscated C++ name, so the
default `sub_` count remains 1,250. The alias reopened successfully, and the
full semantic check still reports zero failures across 11,694 functions, with
3,641 high-confidence labels. The v175 database SHA-256 is
`b414cf0d0d025c85c0cb4ddab2ea9987ecfbd6484da7ca4846b0ed3588d35c49`. The
evidence is in
`artifacts/spectron_tstring_clear_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tstring_clear_anchors.py`.

A v176 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v176.i64`,
adds two static cleanup aliases: `TClient_clearStaticStrings` and
`TSocket_clearStaticStrings`. The source functions are registered in adjacent
static callback-table slots at `0x35d2e8` and `0x35d2f0`. The corresponding
Spectron callbacks are `sub_E0128` in the obfuscated `w6qzgacqqy` client class
and `sub_E0258` in the `XJLBgarMnA` socket class. Those class assignments are
independently supported by the translated constructor, reset, connect, accept,
and related method families.

The target cleanup bodies preserve the two-block static-string cleanup role,
but each adds one target-only `CanTfaz6bZ::clear` call for a field that is not
present in the 1.8 layout. Each target is therefore recorded as a high-
confidence layout-change anchor rather than an exact-shape match. The aliases
reopened successfully, and the full semantic check remains at zero failures
across 11,694 functions, with 3,641 high-confidence labels and 1,248 default
`sub_` names. The v176 database SHA-256 is
`0c5b0f55006fd4a22c6044a6addfcaa07346e1b1cec1f092676a06701ba12e7c`. The
evidence is in
`artifacts/spectron_static_clear_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_static_clear_anchors.py`.

This pass deliberately does not assign `TServerFlying_clearStaticStrings`.
The nearby target static callbacks at `0xe0220` and `0xe0438` clear different
global groups associated with request and video state. The flying-object
callback remains a separate investigation item until its target globals are
isolated.

A follow-up data-reference audit corrected the source role behind that open
item. The 1.8 function at `0xe06a8` clears the old Android TapJoy secret,
TapJoy application-ID, and video-player state strings. `TServerFlying::animate`
does not reference any of those three globals, while its known property global
is separate at `0x3911f8`. The descriptive source-only replacement is
`Android_TapJoy_video_clearStaticStrings`. No Spectron target was assigned:
`0xe0220` clears request state and `0xe0438` clears a different video and
Android runtime group. The historical candidate and overlay remain unchanged
for reproducibility, and the correction is recorded in
`artifacts/spectron_static_callback_role_correction_20260827.json`, generated
by `tools/generate_spectron_static_callback_role_correction.py`.

A v177 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v177.i64`,
adds two response-side HTTP aliases: `THTTPRequest_read_void` at target
`0x206414` and `THTTPRequest_parseData_void` at target `0x207bec`. The
obfuscated target names are `_ZN10ZAuvgaUl6u4readEv` and
`_ZN10ZAuvgaUl6u10ZdIGHasPxmEv`. The first keeps the socket read, response
stream append, byte counters, and download timestamp update. The second keeps
the `data` variable lookup, line-array construction, and script callback loop.

Both rows are high-confidence semantic matches, but neither is an exact
normalized-body match. The 2.2 read implementation is shorter and no longer
contains the older periodic file-progress log. The parser uses rebuilt string
and array container classes. That implementation drift is recorded explicitly
in the artifact instead of being hidden behind a shape-match claim.

Both labels reopened successfully. The full semantic check remains at zero
failures across 11,694 functions, with 3,641 automatic high-confidence labels
and 1,248 default `sub_` names. The v177 database SHA-256 is
`d4d343a931a408cf34d6e32ca11a335711df184d7124b7d4d23a831445aa3cc2`.
The evidence is in
`artifacts/spectron_http_request_receive_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_http_request_receive_anchors.py`.

A v178 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v178.i64`,
adds five server-list anchors. Four are exact-shape getters for the server
start parameters, server-start connection text, and the two server-name
callback forms. The target getters are at `0x208318`, `0x208350`, `0x208388`,
and `0x2083c0`, and their matching target globals are tied to the neighboring
setter methods at `0x2082f0` and `0x208304` plus the connection handoff at
`0x20a1f4`.

The fifth row translates `TServerList_setConnectionAttributes_TString_const_TString_const_int`
to the obfuscated target method at `0x20a1f4`. Both builds normalize the
server name, store the address and port, preserve restart state, load tile
definitions, initialize local players, load their starting levels, and update
the main-window identifier. Spectron has a larger body and different helper
classes, so this row is documented as a high-confidence layout-change anchor.
The target also retains the `GPFDGfY4` string used in the connection handoff.

All five aliases reopened successfully. The full semantic check remains at
zero failures across 11,694 functions, with 3,641 automatic high-confidence
labels and 1,244 default `sub_` names. The v178 database SHA-256 is
`4bc213e88a767e49efdef3c7d0ce160d946446846cfff53b6461bcc7654391c1`.
The evidence is in
`artifacts/spectron_server_list_connection_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_server_list_connection_anchors.py`.

A v179 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v179.i64`,
adds four exact-shape server-list state aliases. They cover the
remove-vars-on-logout setter, the allow-login-reconnect getter, and the
server-start parameter and connection setters at targets `0x2082b0`,
`0x2082c0`, `0x2082f0`, and `0x208304`.

IDA pseudocode ties the rows to the target globals
`xiYWfajld1::x7tqLaYXTv`, `xiYWfajld1::mLqqLax7Qv`,
`xiYWfajld1::OcLpLarkhv`, and `xiYWfajld1::Jq54MaebUU`. The last two are
also read by the v178 getter aliases, and the reconnect global is written by
the already translated `setAllowLoginReconnect` method. All four pairs match
the complete normalized feature record.

All four aliases reopened successfully. The full semantic check remains at
zero failures across 11,694 functions, with 3,641 automatic high-confidence
labels and 1,240 default `sub_` names. The v179 database SHA-256 is
`c4f8361f9fa8d138358215b3d63ef4ada9755aa8cd0e60302d077002f400b37b`.
The evidence is in
`artifacts/spectron_server_list_state_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_server_list_state_anchors.py`.

A v180 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v180.i64`,
adds five HTTP cleanup and request-properties lifecycle aliases. The request
cleanup at target `0x204d5c` preserves the keep-alive check, socket release,
`data` variable removal, response-stream reset, counters, flags, and request
field clearing from the 1.8 `THTTPRequest_clearRequest_void` method.

The other four rows are the complete and deleting request-properties
destructors plus their adjusted-this thunks. The source database names these
entries with constructor-like labels, but their bodies are the D2 and D0
destructor roles. Spectron keeps the explicit `ZAuvgaUl6uProperties` D2, D0,
D1 thunk, and D0 thunk names, and all four pairs match the complete normalized
feature record. The request cleanup is a small layout change, with the same
field offsets and reset responsibilities but a shorter target body.

All five aliases reopened successfully. The full semantic check remains at
zero failures across 11,694 functions, with 3,641 automatic high-confidence
labels and 1,240 default `sub_` names. The v180 database SHA-256 is
`a01af52c52de0c5d203d15ee0eb839b6a30ff13094a08474668c71773a0f17a2`.
The evidence is in
`artifacts/spectron_http_request_cleanup_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_http_request_cleanup_anchors.py`.

A v181 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v181.i64`,
adds four residual socket aliases. The target `0x20ab0c` method preserves the
`"clients"` hash-list lookup, client-variable removal, cleanup callback, and
client-pointer reset from `TSocket_removeFromClientList_void`, with a small
2.2 layout change.

The other three rows cover the socket deleting destructor and the two
property adapters for socket error and IP values. The destructor matches the
complete D0 shape at target `0x20ac44`. The error and IP adapters are exact
one-block matches at default target names `0x20ad1c` and `0x20ad78`, and call
the already translated target methods for the underlying error and IP state.

All four aliases reopened successfully. The full semantic check remains at
zero failures across 11,694 functions, with 3,641 automatic high-confidence
labels and 1,238 default `sub_` names. The v181 database SHA-256 is
`b8a14b0070e9dc9b23e9d7456088ef62f061247cfa3d8048f6c5e0e4b9e2857f`.
The evidence is in
`artifacts/spectron_tsocket_residual_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tsocket_residual_anchors.py`.

A v192 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v192.i64`,
adds the reviewed `GuiGraalCtrl` alignment-table initializer. Source
`sub_E0930` at `0xe0930` maps to target `sub_E0DAC` at `0xe0dac` through the
static-initializer table, the matching five-entry horizontal and vertical
tables, and the adjacent `GuiGraalCtrl` property metadata. The target adds
one neighboring `CanTfaz6bZ` string with a cleanup callback, so the pair is a
high-confidence layout-change anchor.

The alias reopened successfully. The full semantic check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,227
default `sub_` names. The v192 database SHA-256 is
`fa7c62af8d8aa0608d58792573ade2a0de41c373b844b7adf76d9f8e296b9c48`. The
evidence is in
`artifacts/spectron_gui_alignment_tables_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_gui_alignment_tables_anchors.py`.

A v193 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v193.i64`,
adds the reviewed `GuiStretchCtrl` mode-table initializer. Source
`sub_E0960` at `0xe0960` maps to target `sub_E0E54` at `0xe0e54` through the
static-initializer table, the matching `alwaysOn`, `alwaysOff`, and `dynamic`
entries, and the adjacent three-record `GuiStretchCtrl` property table. The
target adds one neighboring `CanTfaz6bZ` string with a cleanup callback, so the
pair is a high-confidence layout-change anchor.

The alias reopened successfully. The full semantic check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,226
default `sub_` names. The v193 database SHA-256 is
`fef77c04831227ee44dfe1edf8499744b627851daa651b5b1d77f8d92ea920c7`. The
evidence is in
`artifacts/spectron_gui_stretch_modes_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_gui_stretch_modes_anchors.py`.

A v194 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v194.i64`,
adds the reviewed `TGUIRender` border-color initializer. Source `sub_E0984`
at `0xe0984` maps to target `sub_E0F0C` at `0xe0f0c` through the static
initializer table, the identical five RGBA defaults, and the matching
`TGUIRender::renderBorder` consumer. The target adds one neighboring
`CanTfaz6bZ` string with a cleanup callback, so the pair is a high-confidence
layout-change anchor.

The alias reopened successfully. The full semantic check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,225
default `sub_` names. The v194 database SHA-256 is
`62b68defbcd16bc235d1c9da05c623f610e1ebea8bda0c473f6260a600f40c27`. The
evidence is in
`artifacts/spectron_tgui_render_colors_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tgui_render_colors_anchors.py`.

A v195 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v195.i64`,
adds the reviewed `THTMLDefinitions` default initializer. Source `sub_E09F4`
at `0xe09f4` maps to target `sub_E0FC4` at `0xe0fc4` through the static
initializer table, the horizontal-line color and bitmap-indent stores, and
the matching translated HTML consumers. The target class is obfuscated as
`D2x4gaXfrZ`, while its field and method context identifies the same
`THTMLDefinitions` role.

The normalized function shape is exact at 56 bytes and 14 instructions. The
only differing recorded fingerprint is IDA's register-detail hash, which is
kept explicitly in the evidence. The target callback writes the same color
bytes `[64, 64, 64, 255]`, indent value `5`, and adjacent cleared state as
the source. The full semantic reopen check reports zero failures across
11,694 functions, with 3,641 high-confidence labels and 1,224 default `sub_`
names. The v195 database SHA-256 is
`be423f317890860401a1d7570cfeeb5783f45f0e967448656808a51cf76d30c7`. The
evidence is in
`artifacts/spectron_thtml_definitions_defaults_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_thtml_definitions_defaults_anchors.py`.

A v196 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v196.i64`,
adds the reviewed `TClient` static-string initializer. Source `sub_E0A2C`
at `0xe0a2c` maps to target `sub_E1118` at `0xe1118` through the static
initializer table and the same eleven client string fields in the same order.
The target class is obfuscated as `w6qzgacqqy`, and its existing translated
client and cleanup methods establish the `TClient` class context.

Spectron adds one target-only `CanTfaz6bZ` string around those shared fields,
so this is a high-confidence layout-change anchor. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,223 default `sub_` names. The v196 database
SHA-256 is
`7f640cdd78f40b66d562676e6f5525dbab9586981b1a08dccf97fe0db28e8bad`. The
evidence is in
`artifacts/spectron_tclient_static_strings_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tclient_static_strings_anchors.py`.

A v197 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v197.i64`,
adds the reviewed `TSocket` static-string initializer. Source `sub_E0AB4` at
`0xe0ab4` maps to target `sub_E12DC` at `0xe12dc` through the adjacent static
callback tables, the two allowed-connection and allowed-port fields, and the
independently translated cleanup pair. The target class is obfuscated as
`XJLBgarMnA`, which is already established as the Spectron `TSocket` family.

The source clears `allowedsocketsconnect` and `allowedportsbind`. Spectron
keeps those fields as `DcjBgagM_z` and `gwjBgaP1_z` and adds one target-only
`CanTfaz6bZ` string at `qword_3A4D90`. That string is initialized by the
callback and cleared by `v18_TSocket_clearStaticStrings`, so the larger target
body is a documented layout change rather than a weak shape-only guess. The
alias reopened successfully. The full semantic check reports zero failures
across 11,694 functions, with 3,641 high-confidence labels and 1,222 default
`sub_` names. The v197 database SHA-256 is
`8be87e35fedd96c6961e725a5b8f12de9e381a1e25abb35fd6193e64c404002d`. The
evidence is in
`artifacts/spectron_tsocket_static_state_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tsocket_static_state_anchors.py`.

A v198 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v198.i64`,
resolves the corrected Android, TapJoy, and video static-state group. Source
`sub_E0AD0` at `0xe0ad0` maps to target `sub_E1640` at `0xe1640`, and the
source cleanup callback at `0xe06a8` maps to target `sub_E0438` at `0xe0438`.
The callbacks are tied together by their static tables, TapJoy setters, video
callbacks, cached rectangle fields, and matching cleanup order.

This also closes the earlier role correction. The old `TServerFlying` label
was wrong because `TServerFlying::animate` never references the cleared
globals. The source fields are Android and TapJoy strings, video state, and
four rectangle coordinates. Spectron preserves those fields under a moved
global block and adds `qword_3A59C8`, a target-only `CanTfaz6bZ` string that is
initialized by `sub_E1640` and cleared by `sub_E0438`. Both aliases reopened
successfully. The full semantic check reports zero failures across 11,694
functions, with 3,641 high-confidence labels and 1,220 default `sub_` names.
The v198 database SHA-256 is
`8f0f2b7d7ef3593c95316c88c8ca5c9b7b9e1a1481cdf9da8bc9e02adcfb1ee3`. The
evidence is in
`artifacts/spectron_android_tapjoy_video_state_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_android_tapjoy_video_state_anchors.py`.

A v199 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v199.i64`,
adds the three core `TSounds` music-state wrappers that the automatic matcher
had left ambiguous. Source `TSounds_isMusicPlaying` at `0xe0af8` maps to
target `0xe16a8`; source `TSounds_getMusicPos_void` at `0xe0b3c` maps to
target `0xe16ec`; and source `TSounds_getMusicLen_void` at `0xe0b7c` maps to
target `0xe172c`.

All three bodies use the same sound-player global, null fallback, and
class-local ordering as Spectron's `IUKzgam4Gy` cluster. The virtual-table
slots are `+56` for `isMusicPlaying`, `+80` for music position, and `+88` for
music length. The normalized shape fingerprints agree; only the register
detail fingerprint differs in this compiler pair. The aliases reopened
successfully. The full semantic check reports zero failures across 11,694
functions, with 3,641 high-confidence labels and 1,219 default `sub_` names.
The v199 database SHA-256 is
`023b4f6f9254d607adb9aafe0936eb3da608dad6049688446d5496a76a6a9148`. The
evidence is in
`artifacts/spectron_sounds_music_state_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sounds_music_state_anchors.py`.

A v200 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v200.i64`,
adds the `TSoundEffect` constructor and the sound-effect cache lookup. Source
`TSoundEffect_TSoundEffect_TString_const` at `0xe0dc0` maps to Spectron's
`fEVMgax6LJ` constructor at `0xe1970`. Source
`TSounds_getSoundEffect_TString_const` at `0xe0e48` maps to the
`IUKzgam4Gy` lookup at `0xe1a1c`.

The constructor preserves filename normalization, hash-list base
construction, the copied filename, and playback-field defaults. Spectron
also constructs and clears a target-only `CanTfaz6bZ` helper, which is why it
is recorded as a layout change. The lookup preserves lowercasing, hash
calculation, case-insensitive retrieval, and temporary string cleanup. Both
aliases reopened successfully. The full semantic check reports zero failures
across 11,694 functions, with 3,641 high-confidence labels and 1,219 default
`sub_` names. The v200 database SHA-256 is
`604ebbe701eca3e90de161f10ac01d8bcbbd201f6ae5761bd0eefcc0c0294df3`. The
evidence is in
`artifacts/spectron_sounds_effect_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sounds_effect_anchors.py`.

A v202 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v202.i64`,
adds the complete seven-method `TSoundEffect` virtual interface. Source
methods from `hasChannel` at `0xe2b24` through `getLength` at `0xe2b4c` map in
order to Spectron's `fEVMgax6LJ` methods at `0xe3714` through `0xe373c`.

The source and target method-table records advance in the same order, and
every recorded feature matches, including register detail. The already
identified `TSoundEffect` constructor and Java sound-effect path independently
confirm the class family. All seven aliases reopened successfully. The full
semantic check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,218 default `sub_` names. The v202 database
SHA-256 is
`87fb8ed432789f0f729d645c34fb11b6d3bfe55ebdcc96705d7beaa865c9b77d`. The
evidence is in
`artifacts/spectron_tsound_effect_methods_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tsound_effect_methods_anchors.py`.

A v203 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v203.i64`,
adds seven small Java sound bridge methods. The two
`TSoundPlayerJava` methods map into Spectron's `ohGYZakbFK` class, while the
five `TSoundEffectJava` methods map into `QPh5pbnC3y`. The source and target
method-table records, class-local order, receiver behavior, and complete
ARM64 feature fingerprints agree for every row.

The reviewed aliases are `v18_TSoundPlayerJava_stopMidi_void`,
`v18_TSoundPlayerJava_setMusicVolumeAndPan_int_int`,
`v18_TSoundEffectJava_freeResource_void`,
`v18_TSoundEffectJava_load_void`, `v18_TSoundEffectJava_setVolume_int`,
`v18_TSoundEffectJava_setPan_int`, and `v18_TSoundEffectJava_stop_void`.
All seven reopened successfully. The full semantic check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and
1,218 default `sub_` names. The v203 database SHA-256 is
`c9ef630efa45cf233022f46b3f051702acf07f72d4d49c32b9621f0f7ee289b5`. The
evidence is in
`artifacts/spectron_sound_java_small_methods_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sound_java_small_methods_anchors.py`.

A v204 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v204.i64`,
adds the two Java sound deleting-destructor wrappers. Source
`TSoundEffectJava_TSoundEffectJava__2` at `0xe2c14` maps to target
`QPh5pbnC3yD0Ev` at `0xe3804`. Source
`TSoundPlayerJava_TSoundPlayerJava__2` at `0xe360c` maps to target
`ohGYZakbFKD0Ev` at `0xe4190`. The source constructor-shaped `__2` labels
are deleting destructors: both bodies call the complete destructor and then
`operator delete`.

Both rows preserve the complete normalized shape. The sound-effect wrapper
matches every metric, and the sound-player wrapper differs only in register
detail. The second row upgrades an existing medium-confidence semantic
candidate with explicit D0 and method-table evidence. Both aliases reopened
successfully. The v204 database SHA-256 is
`34e94dad94d50d81664f109b3831cc29528d1a64c0ac0a8f1dd18a90c6d69765`. The
evidence is in
`artifacts/spectron_sound_java_destructor_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sound_java_destructor_anchors.py`.

A v205 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v205.i64`,
adds 18 Java sound interface methods. Fourteen `TSoundPlayer` base stubs map
in order to Spectron's `gqiNgaG64J` table, two `TSoundEffectJava` capability
methods map to `QPh5pbnC3y`, and two `TSoundPlayerJava` capability methods map
to `ohGYZakbFK`.

The rows preserve the exact return, no-op, factory, and capability behavior
seen in the decompiler. All 18 source and target feature records match,
including register detail, and every target table slot was checked against
the corresponding source slot. All aliases reopened successfully. The full
semantic check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,218 default `sub_` names. The v205 database
SHA-256 is
`cc2ce413b073ec7735a890074a7fc6870bf4baba838a7594d49e12c91a01e143`. The
evidence is in
`artifacts/spectron_sound_base_interface_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sound_base_interface_anchors.py`.

A v206 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v206.i64`,
adds three remaining `TSounds` tail methods. The stop-SFX wrapper at
`0xe0ea4` maps to target `0xe1a78`, and the script pitch bridge at `0xe2a7c`
maps to target `0xe366c`. The adjacent static initializer at `0xe2a88` maps
to target `0xe3678`.

The stop-SFX and script-pitch rows are exact complete feature matches. The
static initializer keeps the same one-block allocation order, call count,
return convention, and class-local position, but Spectron uses a larger
second helper object. Source `THashList` and `TStringList` construction
become target `KKhLga4xoI` and `vuuHgangcF` construction, with the second
allocation changing from `0x18` to `0x20` bytes. The target globals are
`IUKzgam4Gy::fqEVZaFC6H` and `IUKzgam4Gy::mDUVZaIfkI`, which are also used by
the surrounding sound methods.

The stop-SFX row upgrades the existing medium-confidence candidate using its
`+112` virtual stop call, the matching sound-effect lookup, and callback-table
references `0x376120` and `0x389120`. The pitch bridge uses callback-table
references `0x376450` and `0x389450`. The initializer is supported by the
source static-registration references `0x2f8c0` and `0x374108`, target
references `0x1daa8` and `0x383a50`, and the matching method order beside the
pitch bridge and `TSounds_initStaticScriptVars_void`.

All three aliases reopened successfully. The full semantic reopen check still
reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,217 default `sub_` names. The v206 database SHA-256 is
`f909721bba6d7d22b56727328f18382f71d57ce3d539686d450e6d910fa5aabd`. The
evidence is in
`artifacts/spectron_sounds_tail_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sounds_tail_anchors.py`.

A v207 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v207.i64`,
adds the complete D1 destructor for `TSoundPlayerJava`. The source
constructor-shaped entry at `0xe35c8` maps to Spectron's
`ohGYZakbFKD1Ev` at `0xe417c`, immediately before the already translated D0
destructor at `0xe4190`.

Both bodies install their class vtable and clear the embedded string without
deleting the object. Their normalized shape matches, with only the register
detail fingerprint differing. The source and target method-table references
are `0x35ed80` and `0x371b00`. The alias reopened successfully, and the full
semantic reopen check reports zero failures across 11,694 functions, with
3,641 high-confidence labels and 1,217 default `sub_` names. The v207
database SHA-256 is
`dff2f079771c58100c2dd745f48dbecdde881f461598021b890b67e2fa0665f9`. The
evidence is in
`artifacts/spectron_sound_java_d1_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sound_java_d1_anchor.py`.

A v208 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v208.i64`,
adds eight small `THTMLPage` methods to the Spectron analysis. The source
methods cover font-pointer cleanup, dirty-state and word-wrap setters,
parse-tag and selection state, URL and line initialization, and tab-stop
replacement. Their target names all belong to the obfuscated `AS80gaE4zW`
class family.

All eight pairs are exact matches across the complete exported feature record,
including size, instruction count, block and branch counts, call and return
counts, normalized opcode and register shapes, register detail, and string
references. The target pseudocode also preserves the same receiver offsets.
Because these methods are below the normal 32-byte matcher threshold, they are
kept in a separate reviewed anchor artifact. All eight aliases reopened
successfully. The general semantic reopen check reports zero failures across
11,694 functions, with 3,641 high-confidence labels and 1,217 default `sub_`
names. The v208 database SHA-256 is
`8fdd5acca704b5ca0e4bdd54747a60ce132ddb671fa493f4b4ffe8e2e88906a8`. The
evidence is in
`artifacts/spectron_html_page_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_html_page_anchors.py`.

A v209 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v209.i64`,
adds eight small `GuiTextListCtrl` methods. The set covers the cell-size
getter, sort-column property, clear-rows and remove-row wrappers, default and
numerical sort wrappers, and column-offset insertion. The target pseudocode
places all eight methods in the obfuscated `u0eyga1eqx` list-control class.

Every pair matches the complete feature record, including the normalized
opcode and register shapes and register detail. The target rows also preserve
the source receiver offsets and the corresponding script-table or call-site
context. Four target names were ordinary IDA `sub_` names and are now labeled
with `v18_` aliases. All eight aliases reopened successfully. The general
semantic reopen check reports zero failures across 11,694 functions, with
3,641 high-confidence labels and 1,213 default `sub_` names. The v209
database SHA-256 is
`9689b137d9e9688ad7669f531ecde91308d812390dc493a2434ba5b22c6a4f4a`. The
evidence is in
`artifacts/spectron_gui_text_list_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_gui_text_list_anchors.py`.

A v210 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v210.i64`,
adds six small hash-container lifecycle helpers. The set covers the
`THashListObject` and `THashListLink` constructors, the `THashString` value
setter, both `THashListIterator` lifecycle helpers, and the
`THashStringsIterator` container-use helper. The target pseudocode places
these methods in the obfuscated `J7zOgaf09K`, `U1slUah2F0`, `NYF9TaOVKR`,
`R_MvgaEQlv`, and `Zb7cUaSFEU` classes used by the `KKhLga4xoI` and
`yL3_IaDMFt` hash-container clusters.

All six pairs preserve the normalized control-flow shape. Five match every
recorded feature, and the `THashListObject` constructor differs only in
`register_detail_hash`, which is recorded as a target register-allocation
change. The source iterator constructor-shaped label is documented as a
complete destructor because its alternative ABI name is D2 and its body
unregisters the iterator. All six aliases reopened successfully. The general
semantic reopen check reports zero failures across 11,694 functions, with
3,641 high-confidence labels and 1,213 default `sub_` names. The v210
database SHA-256 is
`b4bb37f4af6e3ce32f71329de3d3292f4620b84f380d5f2726a1626161bd739a`. The
evidence is in
`artifacts/spectron_hash_lifecycle_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_hash_lifecycle_anchors.py`.

A v211 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v211.i64`,
adds three short `GuiTextListEntry` property helpers. The set covers the
flickertime getter and setter and the profile fallback getter. The target
functions were ordinary `sub_` names, but their pseudocode is identical to
the 1.8 bodies and their callback references occupy the matching property
table slots.

All three pairs match the complete exported feature record, including the
normalized opcode and register shapes, register detail, and string-reference
hash. The getter and setter use the float at receiver offset `+144`; the
profile getter prefers the override at `+208` and falls back to the base
profile at `+200`. All three aliases reopened successfully. The general
semantic reopen check reports zero failures across 11,694 functions, with
3,641 high-confidence labels and 1,210 default `sub_` names. The v211
database SHA-256 is
`5fe1b5504cbca2cd774a0e7a2e6ef20c6f073bcf880c22b929688ec05f9489d2`. The
evidence is in
`artifacts/spectron_gui_text_list_entry_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_gui_text_list_entry_anchors.py`.

A v212 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v212.i64`,
adds three compact helpers from the encryption and script-variable runtime.
The set covers the `TEncryption` 15-entry script-property initializer and the
`TGraalVar` paused-state getter and protected-object setter. The target
pseudocode maps the initializer to the obfuscated property bridge and places
the two state helpers in the named `G0gxgajWBw` class.

All three pairs match the complete exported feature record, including
instruction shape, register detail, and string-reference hash. The initializer
preserves the table-registration count of 15, while the two state helpers
preserve byte offsets `+17` and `+18`. All three aliases reopened
successfully. The general semantic reopen check reports zero failures across
11,694 functions, with 3,641 high-confidence labels and 1,210 default `sub_`
names. The v212 database SHA-256 is
`1eeda98f88a0816f00340f010c724695f36f66c08c6622241610ac680e30270d`. The
evidence is in
`artifacts/spectron_encryption_graalvar_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_encryption_graalvar_anchors.py`.

A v213 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v213.i64`,
adds 13 compact residual helpers that the broad semantic matcher skips because
they are below its size cutoff. The set covers child and player properties,
drawing-panel cache state, TClient inbound wrappers, cache-size setters,
TFileDownload script callbacks, a call-stack property, and the script-universe
garbage-collector wrapper. Property-table and inbound-handler-table positions
identify the target roles where short feature matches have multiple candidates.

All 13 rows match the normalized feature shape. Two match every recorded
feature, and 11 differ only in `register_detail_hash`. The child getter records
one real layout change: the source field is at `+748` and the target field is
at `+772`. Twelve target `sub_` names were replaced, while the clear-files
target already carried an ABI name. The aliases reopened successfully, and the
general semantic check reports zero failures across 11,694 functions, with
3,641 high-confidence labels and 1,198 default `sub_` names. The v213 database
SHA-256 is
`e6973d7c25827bc7cebf9f7f905376fd3eb6162e514f053c85b81baaa20381c5`. The
evidence is in
`artifacts/spectron_compact_residual_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_compact_residual_anchors.py`.

The source `TFileDownload_canDownload_void` body has the same client-present
predicate as the translated `TPlayer_get_online` target, but the target has no
separate FileDownload table entry for it. That possible compiler or linker
fold is recorded as an unresolved note rather than assigning two source names
to one target function. No APK or native library was modified.

A v214 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v214.i64`,
adds four methods from the compact `T2DMatrixManager` block. The target ABI
names place them in the named `AUzMgaePtJ` class, and the decompiled bodies
preserve the matrix-list activation test, top-entry lookup, full clear loop,
and pop operation. All four normalized feature records match, with only
`register_detail_hash` changing. The aliases reopened successfully, leaving
11,694 functions, 3,641 high-confidence labels, and 1,198 default `sub_`
names. The v214 database SHA-256 is
`a0b839b194114b7e7af26f14205e66a68017f38ac828af1d52f10f43f8100694`. The
evidence is in
`artifacts/spectron_t2d_matrix_manager_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_t2d_matrix_manager_anchors.py`.

The matching `T2DMatrixManager_initStaticVars_void` source row remains
deferred. Its compact allocation shape collides with several unrelated target
static initializers, and the target `AUzMgaePtJ` global initializer needs a
separate global-reference proof before it is safe to rename.

A v215 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v215.i64`,
adds 29 methods from the compact random-generator family. The source
`MRandomGenerator`, `MRandomLCG`, and `MRandomR250` blocks map into the named
Spectron classes `o3AZxayNqc`, `Vx2_xajLEd`, and `ZwL1xarB5e`. The set includes
the shared-base constructors, both generator factories and seed initializers,
the property destructors and thunks, the LCG and R250 object destructors, and
the process-wide generator initializer. All 29 normalized feature records
match. Eight match every recorded metric and 21 differ only in
`register_detail_hash`. The aliases reopened successfully, leaving 11,694
functions, 3,641 high-confidence labels, and 1,198 default `sub_` names. The
v215 database SHA-256 is
`76c43334d5e5afae29a5dc51067056ebe0118bbae6366fd64908c62d317b9186`. The
evidence is in
`artifacts/spectron_mrandom_family_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_mrandom_anchors.py`.

The static initializer was previously only a medium-confidence shape match.
Its target body allocates the 0x90-byte LCG, stores it in
`Lry_xa0Aed`, and calls the target garbage-collector removal helper. That
global and the contiguous class block resolve the earlier collision with
unrelated static initializers. No APK or native library was modified.

A v216 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v216.i64`,
adds the four remaining reviewed `TStringList` methods: the deleting
destructor wrapper, repeated-value removal, case-insensitive lookup, and
indexed string access. The target method block belongs to the obfuscated
`vuuHgangcF` class and uses the rebuilt `CanTfaz6bZ` and `C8THgaTQxF` string
wrappers. Three rows match every recorded feature metric, and the fourth is a
reviewed layout-change row because Spectron makes its temporary string
conversion and cleanup explicit. All four aliases reopened successfully. The
v216 database SHA-256 is
`ab792c07ded18a61682da7a191aefd1fc9d7714f480e70685ca2386ff42089f1`. The
evidence is in
`artifacts/spectron_tstringlist_residual_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tstringlist_residual_anchors.py`.

The target `W2tZ2afUk7` method scans the same list as the source
`indexOfIgnoreCase` routine, converts each element into `C8THgaTQxF`, calls
the case-insensitive comparator, and clears the temporary wrapper. The
additional wrapper work explains the target's 176-byte body versus the
source's 140-byte body. No APK or native library was modified.

A v218 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v218.i64`,
adds 39 residual `GuiMLTextCtrl` accessors, script wrappers, input handlers,
reflow helpers, and property destructors. The target methods occupy the
obfuscated `GbMhIaz9yS` class block, with property destructors at the matching
`GbMhIaz9ySProperties` ABI entries. Twenty-seven rows match every recorded
feature metric and 30 preserve normalized shape. Nine are explicitly marked
as layout changes because Spectron adds rebuilt string-wrapper or base-control
work to the larger handlers and line-list paths. All 39 aliases reopened with
zero failures, leaving 11,694 functions, 3,641 high-confidence labels, and
1,165 default `sub_` names. The v218 database SHA-256 is
`d82c297a781db70c75d56b9dad679db224127653c55a5c312542ab698e5b53b5`. The
evidence is in
`artifacts/spectron_gui_ml_text_residual_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_gui_ml_text_residual_anchors.py`. No APK or native
library was modified.

A v219 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v219.i64`,
adds 30 residual GUI text-list property aliases. The source and target
property tables preserve the accessor order, and IDA pseudocode confirms the
same byte or integer field operation for every row. All 30 rows match the
recorded normalized and full feature metrics, and all 30 target functions
started with default `sub_` names. The aliases reopened with zero failures,
leaving 11,694 functions and 1,135 default `sub_` names. The v219 database
SHA-256 is
`bf219383ca3b9d99ca0fc8133b61c8204263458dc916f3f0cf846e41f9383097`. The
evidence is in
`artifacts/spectron_gui_text_list_entry_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_text_list_entry_property_anchors.py`. No APK or
native library was modified.

A v220 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v220.i64`,
adds ten adjacent GUI text-list methods. The rows cover sort-order getters
and setters, hint and geometry accessors, and the script-facing profile
setter. All ten match normalized shape, four match the complete metric set,
and all ten target functions initially had default `sub_` names. The aliases
reopened with zero failures, leaving 11,694 functions and 1,125 default
`sub_` names. The v220 database SHA-256 is
`8ed23c3f19d77413dd044e64b810352c66dc76660e34b7c205d9648a82edd09f`. The
evidence is in
`artifacts/spectron_gui_text_list_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_text_list_residual_anchors.py`.
The v220 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v220.json`. No APK or
native library was modified.

The v221 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v221.i64`,
adds 16 high-confidence GUI property aliases. Six cover the
`GuiDrawingPanel` rectangle, cache, and filter properties. Ten cover
`GuiShowImgCtrl` offsets, layer, direction, animation, and refresh helpers.
All 16 rows match normalized ARM64 shape, 15 match the complete recorded
metric set, and every target started with a default `sub_` name. The reopened
copy has 11,694 functions and 1,109 remaining default `sub_` names. Its
database SHA-256 is
`8fccf4d07bcb149f4a682144c450b8ae36fe854a15dcc6e5491ea19c85c4e1f6`.
The evidence is in
`artifacts/spectron_gui_drawing_showimg_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_residual_property_anchors.py`. The v221
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v221.json`. Two nearby
target-only cleanup helpers are recorded in the artifact and remain
unaliased because the 1.8 binary has no corresponding source method. No APK
or native library was modified.

The v222 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v222.i64`,
adds three high-confidence `GuiBrowserCtrl` property aliases: the allow-zoom
flag and the URL and text getters. All three match normalized shape and the
complete recorded metric set. The reopened copy has 11,694 functions and
1,106 remaining default `sub_` names. Its database SHA-256 is
`858a8ded6274a0bc186fdbade4beab3951e6e5d6b6814b467afa4b4626431b6f`.
The evidence is in
`artifacts/spectron_gui_browser_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_browser_property_anchors.py`. The v222
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v222.json`. No APK or
native library was modified.

The v223 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v223.i64`,
adds five high-confidence `GuiContextMenuCtrl` callbacks: maximum popup
height getter and setter, the script close dispatcher, the open-state getter,
and the width getter. All five match normalized shape and the complete
recorded metric set. The reopened copy has 11,694 functions and 1,101
remaining default `sub_` names. Its database SHA-256 is
`c0d1c3257745f841a4b24393828905c83a0ba8778f312d1471fae8f48969fe05`.
The evidence is in
`artifacts/spectron_gui_context_menu_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_context_menu_property_anchors.py`. The v223
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v223.json`. No APK or
native library was modified.

The v224 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v224.i64`,
adds six high-confidence array and popup GUI callbacks. They cover the
`GuiArrayCtrl` multiple-selection getter, the context-menu rows lookup, popup
force-action and force-close dispatchers, and popup row-count and selected-ID
helpers. Five rows match normalized shape and the complete recorded metric
set. The rows lookup is a documented wrapper-change correspondence because
the target rebuilt its string and hash-list helpers. The reopened copy has
11,694 functions and 1,095 remaining default `sub_` names. Its database
SHA-256 is
`aed4f3fe539b4616519dfefdda98c5eed7a7357efd740ed9bc44cfcaa24d0547`.
The evidence is in
`artifacts/spectron_gui_array_popup_residual_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_array_popup_residual_anchors.py`. The v224
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v224.json`. One nearby
target-only static cleanup helper is recorded and remains unaliased. No APK
or native library was modified.

The v225 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v225.i64`,
adds the remaining popup `GuiPopUpMenuCtrl_get_rows` alias reviewed in this
block. The source function at `0x1d9404` and target function at `0x1de3c4`
both build the literal `rows` key, compute its hash, and query the owned
profile hash list. The target property table points at `0x1de3c4`, and its
class-local placement follows the popup callback block. The target's rebuilt
`C8THgaTQxF` and `KKhLga4xoI` helpers change the normalized shape, so the one
row is explicitly marked as a wrapper-change correspondence. The reopened
copy has 11,694 functions and 1,094 remaining default `sub_` names. Its
SHA-256 is
`a6626fec1ef58be22f30e2f23c83ce2573602b556c1f140c9da1530f19aa9f1b`.
The evidence is in
`artifacts/spectron_gui_popup_rows_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_gui_popup_rows_anchor.py`. The v225
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v225.json`. No APK or
native library was modified.

The v226 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v226.i64`,
adds the residual `GuiProgressCtrl_get_progress` alias. The source getter at
`0x1dbfa0` and target getter at `0x1dfd3c` both return the float at receiver
offset `+456`. Their progress property records are at `0x383078` and
`0x3960d8`, respectively, with the getter pointers at `0x383088` and
`0x3960e8`. All recorded normalized and complete feature metrics match. The
reopened copy has 11,694 functions and 1,093 remaining default `sub_` names.
Its SHA-256 is
`ae8ab50751ac9f82e108fff9de5ae0274b857c44db27522821ac7c5cdefad45a`.
The evidence is in
`artifacts/spectron_gui_progress_getter_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_gui_progress_getter_anchor.py`. The v226
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v226.json`. No APK or
native library was modified.

The v227 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v227.i64`,
adds two high-confidence text-list selection script aliases. The source
`setselectedrows` function at `0x1df918` maps to target `0x1e3794`, and the
source `setselectedbyids` function at `0x1dfa48` maps to target `0x1e38c8`.
The decoded target script table registers these entries as `setselectedrows`
and `setselectedbyids` at records `0x396cb0` and `0x396c20`. The decompiled
targets preserve the empty-list reset, single-selection path, multi-selection
deselection, and invalid-ID behavior. Spectron's rebuilt wrappers add one
instruction to each body, so both rows are documented as layout changes. The
reopened copy has 11,694 functions and 1,091 remaining default `sub_` names.
Its SHA-256 is
`150ad989b94e83ebcd6287aeb935961c0b4081c99856a59ce4d789ce1d275276`.
The evidence is in
`artifacts/spectron_gui_text_list_selection_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_text_list_selection_script_anchors.py`.
The v227 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v227.json`. No APK or
native library was modified.

The v228 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v228.i64`,
adds four exact MRandomGenerator aliases. The source seed getter and setter at
`0x1e3220` and `0x1e3228` map to target `0x1e70f0` and `0x1e70f8`. The source
`randint` and `randfloat` callbacks at `0x1e3248` and `0x1e3268` map to target
`0x1e7118` and `0x1e7138`. The source property-table records are at
`0x384228`, `0x384288`, and `0x384258`; the target records are at
`0x397288`, `0x3972e8`, and `0x3972b8`. All four rows match the complete
recorded feature set. The reopened copy has 11,694 functions and 1,087
remaining default `sub_` names. Its SHA-256 is
`eeea668d6fa3eb549c41b9dbec001b5c6a7c7e0a44c17a14faea45664004b06b`.
The evidence is in
`artifacts/spectron_mrandom_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_mrandom_property_residual_anchors.py`.
The v228 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v228.json`. No APK or
native library was modified.

The v229 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v229.i64`,
adds three exact `GuiDrawingPanel` script aliases. The source callbacks at
`0x1e00e4`, `0x1e00ec`, and `0x1e00f4` map to target `0x1e3fd8`, `0x1e3fe0`,
and `0x1e3fe8`. The target table records are `0x3970d0` for `setdrawpalette`,
`0x3970a0` for `maskimage`, and `0x397070` for `filterrectangle`; the source
records are `0x384070`, `0x384040`, and `0x384010`. Each target forwards to
the corresponding `TDrawingPanel` operation and matches the complete recorded
feature set. The reopened copy has 11,694 functions and 1,084 remaining
default `sub_` names. Its SHA-256 is
`a2f715b293c1bd6bd0a29d8299ad6d492af6e23a8459b549486de756dcab79c8`.
The evidence is in
`artifacts/spectron_gui_drawing_panel_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_drawing_panel_script_anchors.py`.
The v229 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v229.json`. No APK or
native library was modified.

## Spectron TParticleEmitter GS2 modifier callbacks

The v241 pass resolves the three remaining default callbacks in the
`TParticleEmitter` script-function table. The source function table begins at
`0x38ae10`; the canonical Spectron table begins at `0x39df60`. The callback
pointer is stored at record offset `+0x18`, and the decoded names identify the
three modifier operations directly.

| 1.8 role | Source | Spectron target | Source record | Target record | Script function |
| --- | ---: | ---: | ---: | ---: | --- |
| `TParticleEmitter_script_addglobalmodifier` | `0x239414` | `0x2432b4` | `0x38ae10` | `0x39df60` | `addglobalmodifier` |
| `TParticleEmitter_script_addlocalmodifier` | `0x239500` | `0x2433a0` | `0x38ae40` | `0x39df90` | `addlocalmodifier` |
| `TParticleEmitter_script_addemitmodifier` | `0x2395ec` | `0x24348c` | `0x38ae70` | `0x39dfc0` | `addemitmodifier` |

The three wrappers parse the script arguments and forward them into the
emitter and modifier objects. The target uses obfuscated helper names, but the
function-table rows, argument shape, and decompiled dispatch are unchanged.
All three source and target functions match the complete recorded feature
metrics, including size, instruction count, branches, calls, normalized
hashes, and register detail. Each target callback began as a default `sub_`
name.

The aliases were applied to a copy of v240 and verified after reopening. The
v241 database contains 11,696 functions and 945 remaining default `sub_` names,
with SHA-256
`c154d03a1b28e31a06faa87876d1108c7acb971c884e4ae984cbe273573ba09e`. The
machine-readable record is
`artifacts/spectron_particle_emitter_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_particle_emitter_script_anchors.py`. The
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v241.json`. The clean
reopen verified all three names. This pass performed no DNS, HTTP, or TLS
operation.

## Spectron TParticleEmitter property aliases

The v240 pass translates the residual default callbacks in the
`TParticleEmitterProperties` table. The source table starts at `0x38a8d0`; the
canonical Spectron table starts at `0x39da20`. Both use 0x30-byte records with
the decoded property name and direct getter or setter pointers. The target
class is obfuscated, but this table preserves the source property order and
the callback behavior.

| 1.8 role | Source | Spectron target | Source record | Target record | Script property | Role |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `TParticleEmitter_get_attachposition` | `0x238188` | `0x242028` | `0x38a8d0` | `0x39da20` | `attachposition` | getter |
| `TParticleEmitter_set_attachposition` | `0x238190` | `0x242030` | `0x38a8d0` | `0x39da20` | `attachposition` | setter |
| `TParticleEmitter_get_autorotation` | `0x238198` | `0x242038` | `0x38a900` | `0x39da50` | `autorotation` | getter |
| `TParticleEmitter_set_autorotation` | `0x2381a0` | `0x242040` | `0x38a900` | `0x39da50` | `autorotation` | setter |
| `TParticleEmitter_get_checkbelowterrain` | `0x2381a8` | `0x242048` | `0x38a930` | `0x39da80` | `checkbelowterrain` | getter |
| `TParticleEmitter_set_checkbelowterrain` | `0x2381b0` | `0x242050` | `0x38a930` | `0x39da80` | `checkbelowterrain` | setter |
| `TParticleEmitter_get_clippingbox` | `0x2385b8` | `0x242458` | `0x38a960` | `0x39dab0` | `clippingbox` | getter |
| `TParticleEmitter_get_cliptoscreen` | `0x2381b8` | `0x242058` | `0x38a990` | `0x39dae0` | `cliptoscreen` | getter |
| `TParticleEmitter_set_cliptoscreen` | `0x2381c0` | `0x242060` | `0x38a990` | `0x39dae0` | `cliptoscreen` | setter |
| `TParticleEmitter_get_continueafterdestroy` | `0x2381c8` | `0x242068` | `0x38a9c0` | `0x39db10` | `continueafterdestroy` | getter |
| `TParticleEmitter_set_continueafterdestroy` | `0x2381d0` | `0x242070` | `0x38a9c0` | `0x39db10` | `continueafterdestroy` | setter |
| `TParticleEmitter_get_currentparticlecount` | `0x2381d8` | `0x242078` | `0x38a9f0` | `0x39db40` | `currentparticlecount` | getter |
| `TParticleEmitter_get_delaymax` | `0x2381e0` | `0x242080` | `0x38aa20` | `0x39db70` | `delaymax` | getter |
| `TParticleEmitter_get_delaymin` | `0x238210` | `0x2420b0` | `0x38aa50` | `0x39dba0` | `delaymin` | getter |
| `TParticleEmitter_get_emissionoffset` | `0x238548` | `0x2423e8` | `0x38aae0` | `0x39dc30` | `emissionoffset` | getter |
| `TParticleEmitter_set_emissionoffset` | `0x238514` | `0x2423b4` | `0x38aae0` | `0x39dc30` | `emissionoffset` | setter |
| `TParticleEmitter_get_emitatterrainheight` | `0x238240` | `0x2420e0` | `0x38ab10` | `0x39dc60` | `emitatterrainheight` | getter |
| `TParticleEmitter_set_emitatterrainheight` | `0x238248` | `0x2420e8` | `0x38ab10` | `0x39dc60` | `emitatterrainheight` | setter |
| `TParticleEmitter_get_emitautomatically` | `0x238250` | `0x2420f0` | `0x38ab40` | `0x39dc90` | `emitautomatically` | getter |
| `TParticleEmitter_set_emitautomatically` | `0x238258` | `0x2420f8` | `0x38ab40` | `0x39dc90` | `emitautomatically` | setter |
| `TParticleEmitter_get_emittedparticles` | `0x238260` | `0x242100` | `0x38ab70` | `0x39dcc0` | `emittedparticles` | getter |
| `TParticleEmitter_get_firstinfront` | `0x238268` | `0x242108` | `0x38aba0` | `0x39dcf0` | `firstinfront` | getter |
| `TParticleEmitter_set_firstinfront` | `0x238270` | `0x242110` | `0x38aba0` | `0x39dcf0` | `firstinfront` | setter |
| `TParticleEmitter_get_forceaboveterrain` | `0x238278` | `0x242118` | `0x38abd0` | `0x39dd20` | `forceaboveterrain` | getter |
| `TParticleEmitter_set_forceaboveterrain` | `0x238280` | `0x242120` | `0x38abd0` | `0x39dd20` | `forceaboveterrain` | setter |
| `TParticleEmitter_get_isfrozen` | `0x238288` | `0x242128` | `0x38ac00` | `0x39dd50` | `isfrozen` | getter |
| `TParticleEmitter_get_maxparticles` | `0x238290` | `0x242130` | `0x38ac30` | `0x39dd80` | `maxparticles` | getter |
| `TParticleEmitter_get_movementfactor` | `0x238298` | `0x242138` | `0x38ac60` | `0x39ddb0` | `movementfactor` | getter |
| `TParticleEmitter_set_movementfactor` | `0x2382a0` | `0x242140` | `0x38ac60` | `0x39ddb0` | `movementfactor` | setter |
| `TParticleEmitter_get_noclipping` | `0x2382a8` | `0x242148` | `0x38ac90` | `0x39dde0` | `noclipping` | getter |
| `TParticleEmitter_set_noclipping` | `0x2382b0` | `0x242150` | `0x38ac90` | `0x39dde0` | `noclipping` | setter |
| `TParticleEmitter_get_nrofparticles` | `0x2382b8` | `0x242158` | `0x38acc0` | `0x39de10` | `nrofparticles` | getter |
| `TParticleEmitter_get_particle` | `0x23841c` | `0x2422bc` | `0x38acf0` | `0x39de40` | `particle` | getter |
| `TParticleEmitter_get_particletypes` | `0x2382c0` | `0x242160` | `0x38ad20` | `0x39de70` | `particletypes` | getter |
| `TParticleEmitter_get_showonground` | `0x2382cc` | `0x24216c` | `0x38ad50` | `0x39dea0` | `showonground` | getter |
| `TParticleEmitter_set_showonground` | `0x2382d4` | `0x242174` | `0x38ad50` | `0x39dea0` | `showonground` | setter |
| `TParticleEmitter_get_showontop` | `0x2382dc` | `0x24217c` | `0x38ad80` | `0x39ded0` | `showontop` | getter |
| `TParticleEmitter_set_showontop` | `0x2382e4` | `0x242184` | `0x38ad80` | `0x39ded0` | `showontop` | setter |
| `TParticleEmitter_get_switchyandzaxis` | `0x2382ec` | `0x24218c` | `0x38adb0` | `0x39df00` | `switchyandzaxis` | getter |
| `TParticleEmitter_set_switchyandzaxis` | `0x2382f4` | `0x242194` | `0x38adb0` | `0x39df00` | `switchyandzaxis` | setter |
| `TParticleEmitter_get_wraptoclippingbox` | `0x2382fc` | `0x24219c` | `0x38ade0` | `0x39df30` | `wraptoclippingbox` | getter |
| `TParticleEmitter_set_wraptoclippingbox` | `0x238304` | `0x2421a4` | `0x38ade0` | `0x39df30` | `wraptoclippingbox` | setter |

The simple boolean and integer callbacks read or store their corresponding
emitter fields. `delaymax` and `delaymin` use the source's small bounded setter
wrappers, while `emissionoffset` and `clippingbox` preserve the point or box
object accessors. The `particle` getter is a slightly larger indexed lookup,
and the count properties expose the emitter's current, configured, emitted,
and type counts. All of those roles are visible in the source and target
pseudocode, not inferred from names alone.

The target already had reviewed aliases for the `clippingbox`, `delaymax`, and
`delaymin` setters, the two drop-emitter getters, and the bounded setters for
`isfrozen`, `maxparticles`, `nrofparticles`, and `particletypes`. Those nine
entries remain in place. This pass renamed only the 42 target callbacks that
were still default `sub_` functions.

All 42 selected rows match the complete feature metrics, including size,
instruction count, branch shape, call count, normalized hashes, and register
detail. The aliases were applied to a copy of v239 and verified after
reopening. The v240 database contains 11,696 functions and 948 remaining
default `sub_` names, with SHA-256
`32225a918d1ac903ae68f624937fe4d4296afe75fec63448ff6aa60b96c6cd72`. The
machine-readable record is
`artifacts/spectron_particle_emitter_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_particle_emitter_property_anchors.py`.
The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v240.json`. The clean
reopen verified all 42 names. This pass performed no DNS, HTTP, or TLS
operation.

## Spectron TOptions preference property aliases

The v239 pass translates the remaining default callbacks in the `TOptions`
static property table. The source table begins at `0x37b148`; the canonical
Spectron table begins at `0x38e168`. Registration names provide the first
mapping, and the decompiled bodies confirm that each target callback performs
the same direct global getter or setter as its 1.8 counterpart.

| 1.8 role | Source | Spectron target | Source record | Target record | Script property | Role |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `TOptions_get_graalplugincookie` | `0x16a4b8` | `0x16df10` | `0x37b148` | `0x38e168` | `graalplugincookie` | getter |
| `TOptions_get_isgraalplugin` | `0x16a26c` | `0x16dcc4` | `0x37b178` | `0x38e198` | `isgraalplugin` | getter |
| `TOptions_get_pref__graal__dontsavepasswords` | `0x16a27c` | `0x16dcd4` | `0x37b1a8` | `0x38e1c8` | `$pref::graal::dontsavepasswords` | getter |
| `TOptions_set_pref__graal__dontsavepasswords` | `0x16a28c` | `0x16dce4` | `0x37b1a8` | `0x38e1c8` | `$pref::graal::dontsavepasswords` | setter |
| `TOptions_get_pref__graal__limitnicknames` | `0x16a29c` | `0x16dcf4` | `0x37b1d8` | `0x38e1f8` | `$pref::graal::limitnicknames` | getter |
| `TOptions_set_pref__graal__limitnicknames` | `0x16a2ac` | `0x16dd04` | `0x37b1d8` | `0x38e1f8` | `$pref::graal::limitnicknames` | setter |
| `TOptions_get_pref__graal__nicknamelimit` | `0x16a2bc` | `0x16dd14` | `0x37b208` | `0x38e228` | `$pref::graal::nicknamelimit` | getter |
| `TOptions_set_pref__graal__nicknamelimit` | `0x16a2cc` | `0x16dd24` | `0x37b208` | `0x38e228` | `$pref::graal::nicknamelimit` | setter |
| `TOptions_get_drawallinsidenpcs` | `0x16a2dc` | `0x16dd34` | `0x37b238` | `0x38e258` | `drawallinsidenpcs` | getter |
| `TOptions_set_drawallinsidenpcs` | `0x16a2ec` | `0x16dd44` | `0x37b238` | `0x38e258` | `drawallinsidenpcs` | setter |
| `TOptions_get_lighteffectsenabled` | `0x16a2fc` | `0x16dd54` | `0x37b268` | `0x38e288` | `lighteffectsenabled` | getter |
| `TOptions_set_lighteffectsenabled` | `0x16a30c` | `0x16dd64` | `0x37b268` | `0x38e288` | `lighteffectsenabled` | setter |
| `TOptions_get_weathereffectsenabled` | `0x16a31c` | `0x16dd74` | `0x37b298` | `0x38e2b8` | `weathereffectsenabled` | getter |
| `TOptions_set_weathereffectsenabled` | `0x16a32c` | `0x16dd84` | `0x37b298` | `0x38e2b8` | `weathereffectsenabled` | setter |
| `TOptions_get_particleeffectsenabled` | `0x16a33c` | `0x16dd94` | `0x37b2c8` | `0x38e2e8` | `particleeffectsenabled` | getter |
| `TOptions_set_particleeffectsenabled` | `0x16a34c` | `0x16dda4` | `0x37b2c8` | `0x38e2e8` | `particleeffectsenabled` | setter |
| `TOptions_get_pref__audio__reversestereo` | `0x16a35c` | `0x16ddb4` | `0x37b2f8` | `0x38e318` | `$pref::audio::reversestereo` | getter |
| `TOptions_set_pref__audio__reversestereo` | `0x16a36c` | `0x16ddc4` | `0x37b2f8` | `0x38e318` | `$pref::audio::reversestereo` | setter |
| `TOptions_get_pref__audio__midivolume` | `0x16a37c` | `0x16ddd4` | `0x37b328` | `0x38e348` | `$pref::audio::midivolume` | getter |
| `TOptions_set_pref__audio__midivolume` | `0x16a38c` | `0x16dde4` | `0x37b328` | `0x38e348` | `$pref::audio::midivolume` | setter |
| `TOptions_get_pref__audio__mp3volume` | `0x16a39c` | `0x16ddf4` | `0x37b358` | `0x38e378` | `$pref::audio::mp3volume` | getter |
| `TOptions_set_pref__audio__mp3volume` | `0x16a3ac` | `0x16de04` | `0x37b358` | `0x38e378` | `$pref::audio::mp3volume` | setter |
| `TOptions_get_pref__audio__radiovolume` | `0x16a3bc` | `0x16de14` | `0x37b388` | `0x38e3a8` | `$pref::audio::radiovolume` | getter |
| `TOptions_set_pref__audio__radiovolume` | `0x16a3cc` | `0x16de24` | `0x37b388` | `0x38e3a8` | `$pref::audio::radiovolume` | setter |
| `TOptions_get_pref__audio__sfxvolume` | `0x16a3dc` | `0x16de34` | `0x37b3b8` | `0x38e3d8` | `$pref::audio::sfxvolume` | getter |
| `TOptions_set_pref__audio__sfxvolume` | `0x16a3ec` | `0x16de44` | `0x37b3b8` | `0x38e3d8` | `$pref::audio::sfxvolume` | setter |
| `TOptions_get_pref__video__defaultguistyle` | `0x16a480` | `0x16ded8` | `0x37b3e8` | `0x38e408` | `$pref::video::defaultguistyle` | getter |
| `TOptions_get_pref__video__externalguistyle` | `0x16a448` | `0x16dea0` | `0x37b418` | `0x38e438` | `$pref::video::externalguistyle` | getter |
| `TOptions_get_pref__video__screenshotformat` | `0x16a410` | `0x16de68` | `0x37b448` | `0x38e468` | `$pref::video::screenshotformat` | getter |
| `TOptions_set_pref__video__screenshotformat` | `0x16a3fc` | `0x16de54` | `0x37b448` | `0x38e468` | `$pref::video::screenshotformat` | setter |

The plugin-cookie, GUI-style, and screenshot-format getters copy global
strings into the script result. The screenshot-format setter stores the
incoming string. The plugin and rendering rows read or write global boolean
or integer values, while the audio rows do the same for the reverse-stereo
flag and the four volume settings. This is a direct accessor family, not a
new connection path, so the pass does not change the APK or network behavior.

The two target video-style setters at `0x16df48` and `0x16e03c` already had
reviewed `v18_TOptions_` names from the earlier options pass. Their getters
were still default names and are included above. All selected target callbacks
began as default `sub_` functions. The normalized shape matched for all 30,
while the full metric set did not because every pair uses a different target
register-detail hash. This distinction is preserved in the JSON record.

The aliases were applied to a copy of v238 and verified after reopening. The
v239 database has 11,696 functions and 990 remaining default `sub_` names,
with SHA-256
`4b83ebdffa26611933a959770f39e1d43b1ff64d796d7d28c2c04c3aec4ff021`. The
machine-readable record is
`artifacts/spectron_options_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_options_property_anchors.py`. The
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v239.json`. The clean
reopen verified all 30 names. This pass performed no DNS, HTTP, or TLS
operation.

## Spectron TGaniObject and TGaniParam property aliases

The v238 pass translates eight remaining default callbacks from the target
animation property tables. The main source table is at `0x37a5b0`; the target
table has one extra property at its front, so the matching `ani` row begins at
`0x38d5d0`. The separate movie-reposition property is at `0x37ab50` in the
source and `0x38db70` in the target.

| 1.8 role | Source | Spectron target | Source record | Target record | Property |
| --- | ---: | ---: | ---: | ---: | --- |
| `TGaniParam_getStringField304` | `0x15da98` | `0x160cf0` | `0x37a5e0` | `0x38d600` | `aniparams` |
| `TGaniObject_getField292` | `0x15d4d8` | `0x160568` | `0x37a610` | `0x38d630` | `anistep` |
| `TGaniObject_getField320` | `0x15d51c` | `0x1605ac` | `0x37a6d0` | `0x38d6f0` | `attr` |
| `TGaniParam_getStringField376` | `0x15da68` | `0x160cc0` | `0x37a700` | `0x38d720` | `body` |
| `TGaniObject_getField448` | `0x15d524` | `0x1605b4` | `0x37a760` | `0x38d780` | `colors` |
| `TGaniObject_getField576` | `0x15d590` | `0x160620` | `0x37a7c0` | `0x38d7e0` | `gmap` |
| `TGaniObject_getEnableMovieReposition` | `0x15d4b0` | `0x160540` | `0x37ab50` | `0x38db70` | `enableganimoviereposition` |
| `TGaniObject_setEnableMovieReposition` | `0x15d4c0` | `0x160550` | `0x37ab50` | `0x38db70` | `enableganimoviereposition` |

The `body` getter is also registered as `bodyimg` in both builds. It is one
callback at `0x160cc0`, not two different functions. The corresponding body
setter was already translated in an earlier pass. The other rows read the
same string, integer, or pointer fields identified in the 1.8 IDB, while the
movie-reposition pair accesses one global flag.

Five rows match the complete recorded feature metrics. The `gmap` getter keeps
the same normalized shape with a register-detail difference. The two
movie-reposition wrappers use a different target instruction form for global
access, so their metric differences remain visible in the evidence rather
than being treated as a missing semantic match.

All eight target callbacks began as default `sub_` functions and reopened with
zero failures. The v238 database contains 11,696 functions and 1,020 remaining
default `sub_` names. Its SHA-256 is
`b9e8068236409064bb27bde0f3f564398cc3ed7c664bc46af6eb5c5ce801f6a3`.
The machine-readable record is
`artifacts/spectron_gani_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gani_property_anchors.py`. The checkpoint
is `artifacts/spectron_translation_checkpoint_20260828_v238.json`.

This pass changed only the disposable IDA database and performed no DNS,
HTTP, or TLS operation.

## Spectron TLevelObject property aliases

The v237 pass translates the remaining default callbacks in the target's
level-object property table and recovers one function boundary that IDA had
not created. The source table is at `0x37b048`; the corresponding target table
is the `.data` copy beginning at `0x38e068`.

| 1.8 role | Source | Spectron target | Source record | Target record |
| --- | ---: | ---: | ---: | ---: |
| `TLevelObject_getLevel` | `0x1698b0` | `0x16d308` | `0x37b048` | `0x38e068` |
| `TLevelObject_getX` | `0x1698b8` | `0x16d310` | `0x37b078` | `0x38e098` |
| `TLevelObject_setX` | `0x1698ec` | `0x16d344` | `0x37b078` | `0x38e098` |
| `TLevelObject_getY` | `0x169960` | `0x16d3b8` | `0x37b0a8` | `0x38e0c8` |
| `TLevelObject_setY` | `0x169994` | `0x16d3ec` | `0x37b0a8` | `0x38e0c8` |
| `TLevelObject_getZ` | `0x169a08-0x169a28` | `0x16d460-0x16d480` | `0x37b0d8` | `0x38e0f8` |
| `TLevelObject_getLayer` | `0x169a28` | `0x16d480` | `0x37b108` | `0x38e128` |

The `level` getter returns the owning level pointer. The `x` and `y` getters
add the object's tile offsets to the virtual base coordinates at 64 pixels per
tile. Their setters keep the source clamp for ordinary objects and forward the
resulting delta through the target vtable. The `layer` getter maps the internal
layer values into the script-visible numbering. The existing v237 database
also retains the previously translated `TLevelObject_setZ` callback at the
target address immediately after the recovered getter.

The `z` getter was the only row without a target function feature record in
v236. Its table pointer enters `0x16d460`, the raw instructions form a complete
eight-instruction vtable dispatch, and the next known target function begins
at `0x16d480`. After IDA materialized that range, the target feature export
matched all source metrics, including the 32-byte size, one basic block, one
indirect call, and the vtable displacement of 360 bytes.

All seven target entries started as default names or an unbounded code label.
The aliases reopened with zero failures. The v237 database contains 11,696
functions and 1,028 remaining default `sub_` names. Its SHA-256 is
`5229c4d4d67261076bd57c46c8331426ac775afdac6a578f409764b68e5ef872`.
The machine-readable record is
`artifacts/spectron_level_object_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_level_object_property_anchors.py`. The
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v237.json`.

This pass changed only the disposable IDA database and performed no DNS,
HTTP, or TLS operation.

## Spectron identification, time, file, and input callbacks

The v236 pass translates a compact but useful part of the target's script
surface. These rows are especially good anchors because the encoded script
names, table order, callback pointers, and decompiled behavior all agree. The
target table addresses below deliberately use its `.data` copy. Spectron also
contains a duplicate read-only table in `.data.rel.ro`, but the `.data` copy is
the one used consistently by the translation record.

| 1.8 role | Source | Spectron target | Source record | Target record |
| --- | ---: | ---: | ---: | ---: |
| `TIdentification_script_getOSID` | `0xec6d8` | `0xed694` | `0x3768d0` | `0x3898d8` |
| `TIdentification_script_getNetworkID` | `0xec270` | `0xed0b8` | `0x376900` | `0x389908` |
| `TIdentification_script_getSystemID` | `0xec7ac` | `0xed77c` | `0x376930` | `0x389938` |
| `TTime_script_adventure_getframetick` | `0xf6e58` | `0xf87d0` | `0x3769f0` | `0x3899f8` |
| `TTime_script_adventure_setframetick` | `0xf6e68` | `0xf87e0` | `0x376a20` | `0x389a28` |
| `TFileScripting_script_getScriptAccessFile` | `0xfc880` | `0xfee28` | `0x376bd0` | `0x389be0` |
| `TFileScripting_script_escapeFilename` | `0xfbba4` | `0xfe124` | `0x376c30` | `0x389c40` |
| `TFileScripting_script_removeEscapesFromFilename` | `0xfbeec` | `0xfe46c` | `0x376c60` | `0x389c70` |
| `TFileScripting_script_freeAllResources` | `0xfbe68` | `0xfe3e8` | `0x376cf0` | `0x389d00` |
| `TFileScripting_script_findFiles` | `0xfbe20` | `0xfe3a0` | `0x376d20` | `0x389d30` |
| `TFileScripting_script_extractFileExt` | `0xfbb84` | `0xfe104` | `0x376d50` | `0x389d60` |
| `TFileScripting_script_getExtension` | `0xfbb64` | `0xfe0e4` | `0x376d80` | `0x389d90` |
| `TFileScripting_script_setFileModTime` | `0xfc540` | `0xfeac0` | `0x376e10` | `0x389e20` |
| `TFileScripting_script_extractFileBase` | `0xfbc5c` | `0xfe1dc` | `0x376ff0` | `0x38a000` |
| `TFileScripting_script_extractFilename` | `0xfbb44` | `0xfe0c4` | `0x377020` | `0x38a030` |
| `TFileScripting_script_extractFilepath` | `0xfbb24` | `0xfe0a4` | `0x377050` | `0x38a060` |
| `TControlBinding_getAction` | `0x168b10` | `0x16c4e8` | `0x37ae98` | `0x38deb8` |
| `TControlBinding_getKeycode` | `0x168b18` | `0x16c4f0` | `0x37aec8` | `0x38dee8` |
| `TControlBinding_getKeytext` | `0x168e40` | `0x16c840` | `0x37aef8` | `0x38df18` |
| `TControlBinding_getSlot` | `0x168b20` | `0x16c4f8` | `0x37af28` | `0x38df48` |
| `TInput_getHardwareKeyboardEnabled` | `0x168af0` | `0x16c4c8` | `0x37af58` | `0x38df78` |
| `TInput_setHardwareKeyboardEnabled` | `0x168b00` | `0x16c4d8` | `0x37af58` | `0x38df78` |

The three identification entries are thin wrappers around the OS, network,
and system identifier methods. The frame-tick pair reads and writes one global
value. The getter is registered twice in both builds: the source also exposes
it as `getFrameTick`, while the target row is `getframetick`. That is one
callback with two script names, not two independent functions.

The file rows retain the old split between filename utilities, resource
cleanup, file enumeration, extension and path helpers, and timestamp updates.
`findfiles` builds a script value from a temporary file list and releases the
list afterward. `setFileModTime` is the only non-shape-exact row in this group.
The target body is 364 bytes compared with 324 bytes in 1.8 and contains a few
additional target-side wrapper calls, but both versions choose between an
explicit file path and a packaged level resource before updating UTC metadata.

The four control-binding properties read the action, keycode, key text, and
slot fields. The key-text getter resolves the stored keycode through the input
helper. The final pair accesses the global hardware-keyboard flag. Seventeen
rows match every recorded feature field, five differ only in register detail,
and the expanded timestamp wrapper differs in its full control-flow metrics.

All 22 target functions started as default `sub_` names. The aliases were
applied to a copy of v235 and reopened with zero failures. The v236 database
contains 11,695 functions and 1,034 remaining default `sub_` names. Its
SHA-256 is
`04b1c4438c1d9473f949a1e27d8cf60b1d1199fddac80440a23429c8e5b1f44a`.
The machine-readable record is
`artifacts/spectron_time_files_input_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_time_files_input_anchors.py`. The
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v236.json`.

This pass changed only the disposable IDA database and performed no DNS,
HTTP, or TLS operation.

## Spectron GSFunctionsClient and GuiControl property aliases

The v235 disposable copy adds 12 aliases whose roles are fixed by matching
property names, source and target registration records, direct callback
pointers, decompiled behavior, and ARM64 feature shape.

| 1.8 role | Source | Spectron target | Source table record | Target table record |
| --- | ---: | ---: | ---: | ---: |
| `GSFunctionsClient_get_carriesbush` | `0x1565ec` | `0x159414` | `0x378388` | `0x38b398` |
| `GSFunctionsClient_get_carriessign` | `0x156640` | `0x159468` | `0x3783b8` | `0x38b3c8` |
| `GSFunctionsClient_get_carriesvase` | `0x156694` | `0x1594bc` | `0x3783e8` | `0x38b3f8` |
| `GSFunctionsClient_get_carriesstone` | `0x1566e8` | `0x159510` | `0x378418` | `0x38b428` |
| `GSFunctionsClient_get_carriesblackstone` | `0x15673c` | `0x159564` | `0x378448` | `0x38b458` |
| `GSFunctionsClient_get_mousescreeny` | `0x1571d8` | `0x15a000` | `0x378958` | `0x38b968` |
| `GSFunctionsClient_get_mousescreenx` | `0x157234` | `0x15a05c` | `0x378928` | `0x38b938` |
| `GSFunctionsClient_set_mousescreeny` | `0x157290` | `0x15a0b8` | `0x378958` | `0x38b968` |
| `GSFunctionsClient_set_mousescreenx` | `0x157304` | `0x15a12c` | `0x378928` | `0x38b938` |
| `GuiControl_setClientHeight` | `0x1b27cc` | `0x1b6ccc` | `0x3808c8` | `0x393910` |
| `GuiControl_setClientWidth` | `0x1b2818` | `0x1b6d18` | `0x3808f8` | `0x393940` |
| `GuiControl_getIsInAnimation` | `0x1b2944` | `0x1b6e44` | `0x380c80` | `0x393cd0` |

The carried-object getters ask whether the action player is carrying the
named bush, sign, vase, stone, or blackstone sprite. The target uses the
rebuilt action-player class and different virtual-table offsets, but it keeps
the same one-call boolean test. The mouse accessors read or update the canvas
cursor relative to the active player's origin. The target moves the player
fields and cursor helper, while the getter and setter pairs retain the same
screen-relative operation.

The two geometry setters compute a point from the control bounds and call the
same virtual layout callback used by the source. The animation getter checks
whether the control's animation object has a positive frame count. The nine
GSFunctionsClient rows differ only in the recorded register-detail hash. All
12 have matching normalized shape, and the three GuiControl rows match every
recorded metric field.

The materialized target names are `v18_GSFunctionsClient_get_carriesbush`,
`v18_GSFunctionsClient_get_carriessign`,
`v18_GSFunctionsClient_get_carriesvase`,
`v18_GSFunctionsClient_get_carriesstone`,
`v18_GSFunctionsClient_get_carriesblackstone`,
`v18_GSFunctionsClient_get_mousescreeny`,
`v18_GSFunctionsClient_get_mousescreenx`,
`v18_GSFunctionsClient_set_mousescreeny`,
`v18_GSFunctionsClient_set_mousescreenx`,
`v18_GuiControl_setClientHeight`, `v18_GuiControl_setClientWidth`, and
`v18_GuiControl_getIsInAnimation`.

The v235 aliases reopened successfully with zero failures. The database has
11,695 functions and 1,056 remaining default `sub_` names. Its SHA-256 is
`b58d447613b039f930e5ecd179a56a0e5ad19958715445f0663272dc830e0719`.
The machine-readable artifact is
`artifacts/spectron_gsfunctions_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gsfunctions_property_anchors.py`. The
generic apply and reopen helpers are
`tools/ida_apply_spectron_manual_anchors.py` and
`tools/ida_verify_spectron_manual_anchors.py`. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v235.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron tclient_setplayerhurt boundary recovery

The v234 disposable copy recovers a target function boundary that IDA had not
created for the `tclient_setplayerhurt` property callback.

| 1.8 role | Source | Spectron target | Target table evidence |
| --- | ---: | ---: | --- |
| `TClient_script_tclient_setplayerhurt` | `0x1ed158-0x1ed1e4` | `0x1f1b08-0x1f1b94` | `tclient_setplayerhurt` record at `0x398010`, callback pointer at `0x398028` |

The target raw instructions perform the same active-player and no-hurt checks
as the source callback. They preserve the script arguments, call the target
no-hurt helper, and tail-branch to the already translated
`v18_TClient_hurtPlayer` routine at `0x1f1b90`. The next known target function
starts at `0x1f1b94`, which supplies the recovered end boundary. The target
uses moved singleton and state offsets, so this is a semantic anchor rather
than an instruction-for-instruction match.

The target range was materialized and renamed to
`v18_TClient_script_tclient_setplayerhurt`. A clean IDA reopen verified the
boundary and name. The v234 copy has 11,695 functions and 1,068 remaining
default `sub_` names. Its SHA-256 is
`c7dda722fbab84a403ed8ba21351af98dc01e181c640c5048c126b2ff4f669b2`.
The evidence is in
`artifacts/spectron_tclient_playerhurt_property_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_tclient_playerhurt_anchor.py`; the
generic apply and reopen helpers are
`tools/ida_apply_spectron_manual_anchors.py` and
`tools/ida_verify_spectron_manual_anchors.py`. The v234 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v234.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron target-only property callback labels

The v233 disposable copy gives three target callbacks explicit descriptive
names after the v231 property-table review found them without demonstrated
1.8 source pairs.

| Target address | Property name | Target label | Role |
| ---: | --- | --- | --- |
| `0x1f00f8` | `setdebugdatahandlers` | `spectron_setdebugdatahandlers` | copy up to 256 integers into the debug-handler table |
| `0x1f0010` | `adventure_setdebugdatahandlersauthorization` | `spectron_adventure_setdebugdatahandlersauthorization` | copy up to 256 integers into the authorization table |
| `0x1f2160` | `tclient_setotherplayerprops` | `spectron_tclient_setotherplayerprops_adapter` | positive-result guard around `v18_TClient_updateGlobalPlayer` |

The first two callbacks clear a 1024-byte target global and copy the bounded
array supplied through the script ABI. The third callback is only an adapter,
so it does not create a second label for `updateGlobalPlayer`. The
`spectron_` prefix is intentional. It separates target-specific descriptions
from `v18_` names that represent reviewed 1.8-to-Spectron correspondences.
None of these three rows is counted as a source mapping.

The labels reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v233.i64`.
The copy has 11,694 functions and 1,068 remaining default `sub_` names. Its
SHA-256 is
`21fa935e68dd605c0549656df3a3b832d0c91e080b7d703b2042132ba078ddd6`.
The machine-readable evidence is in
`artifacts/spectron_target_only_callback_labels_20260828.json`, generated by
`tools/generate_spectron_target_only_labels.py`. The apply and reopen helpers
are `tools/ida_apply_spectron_target_only_labels.py` and
`tools/ida_verify_spectron_target_only_labels.py`. The v233 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v233.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

The v232 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v232.i64`,
corrects a false feature-only match and adds two high-confidence aliases in
the TClient inbound handler table. Handler slot 10 maps
`TClient_handleServerLoginPacket` at `0x1edf04` to target `0x1f37e0`, where
the target decodes the server signature and invokes `onServerLogin`. Handler
slot 48 maps `TClient_processServerModifies` at `0x1eab78` to target
`0x1eefa0`, where the target preserves the server-level transition decision.
The earlier row that assigned `TClient_processServerModifies` to `0xecba0`
was wrong: that address is an exported `yL3_IaDMFt` hash-container method.
The v232 copy restores its retained symbol
`_ZN10yL3_IaDMFt10XEm8Ta8FEQEP10vuuHgangcFRK10C8THgaTQxF` and places the
readable alias at the actual handler target. The copy has 11,694 functions
and 1,071 remaining default `sub_` names. Its SHA-256 is
`51b76f3945f282bc62c1fb72a5749115315db1e6d5fac5e04ef4208c816a3bf6`.
The evidence and correction record are in
`artifacts/spectron_tclient_handler_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tclient_handler_anchors.py`; the name
repair helper is `tools/ida_apply_spectron_name_corrections.py`. The v232
checkpoint is `artifacts/spectron_translation_checkpoint_20260828_v232.json`.
No APK or native library was modified.

The v231 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v231.i64`,
adds six high-confidence aliases from the password, cache, and file-download
property tables. The source callbacks
`TClient_getGraalPassword`, `TCachedStream_get_minfilecachesize`,
`TCachedStream_get_maxramcachesize`,
`TFileDownload_script_getlastfilerequesttime`,
`TFileDownload_script_getlastfiledownloadtime`, and
`TFileDownload_get_lastdownloadfile` map to target `0x1f01e4`, `0x1ffcac`,
`0x1ffcd4`, `0x201400`, `0x201410`, and `0x201420`. The target registration
records are `0x397530`, `0x3986d8`, `0x398708`, `0x398858`, `0x398888`, and
`0x398768`; the source records are `0x3844d0`, `0x385618`, `0x385648`,
`0x385798`, `0x3857c8`, and `0x3856a8`. All six rows match normalized
feature shape, and one also matches the complete recorded feature set. The
other five differ only in register-detail allocation. Three target-only rows
for debug-handler callbacks and an ABI wrapper are retained separately in the
artifact. All six aliases reopened successfully. The v231 copy contains
11,694 functions and 1,073 remaining default `sub_` names. Its SHA-256 is
`329596637abe0446019eb80c952e4536157bed027dce3c5f40fc6b8a68cf2fa2`.
The evidence is in
`artifacts/spectron_file_cache_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_file_cache_property_anchors.py`. The
v231 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v231.json`. No APK or
native library was modified.

The v230 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v230.i64`,
adds five high-confidence aliases from the TClient script-property table. The
source callbacks `TClient_setBigFileSizeAndContinue`,
`TGUIScriptLoader_finishServerListConnect`,
`TClient_setPlayerFlagValueNullName`,
`TClient_setPlayerFlagValueEmptyName`, and
`TClient_addWeaponForActivePlayer` map to target `0x1ef660`, `0x1efb64`,
`0x1eff68`, `0x1eff70`, and `0x1eff94`. The decoded target records are
`0x397b90`, `0x397830`, `0x3979e0`, `0x3979b0`, and `0x3978f0`; the source
records are `0x384b30`, `0x3847d0`, `0x384980`, `0x384950`, and `0x384890`.
Two rows match the complete feature set, two preserve the operation with an
explicit wrapper-layout difference, and the weapon wrapper differs only in
register detail. The reopened copy has 11,694 functions and 1,079 remaining
default `sub_` names. Its SHA-256 is
`220e9fe71bb8e93472ed7892b4b16363559e1d24a3733bb876fd6abb393023ba`.
The evidence is in
`artifacts/spectron_tclient_script_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tclient_script_property_anchors.py`.
The v230 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v230.json`. No APK or
native library was modified.

The 2.2 dynamic-export audit adds a complete offline inventory for the
otherwise stripped Spectron library. It confirms that `.symtab`, `.strtab`,
the DWARF sections, and `.gnu_debuglink` are absent, while `.dynsym` and
`.dynstr` remain. The table contains 5,782 section-defined functions, 28
named JNI entry points, and 256 functions in the retained CyaInt or CyaSSL
family. The target's obfuscated C++ exports are preserved byte-for-byte in
the artifact, so future IDA work can distinguish a real target export from a
reviewed `v18_` semantic alias. The exact-name overlap with the original is
1,036 names. This audit is static and contacted no endpoint.

A v217 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v217.i64`,
adds 49 residual methods from the contiguous Explosion, Bomb, Chest, Extra,
Flying, Leap, and Sign server-object blocks. The rows cover compact getters,
level-bound constructors, native and script-property initializers, property
destructors, object destructors, and deleting-destructor wrappers. The source
and target class order is preserved across all seven blocks. All 49 normalized
feature records match. Nine match every recorded metric and 40 differ only in
`register_detail_hash`; seven target getters initially had default `sub_`
names. The aliases reopened successfully, leaving 11,694 functions, 3,641
high-confidence labels, and 1,191 default `sub_` names. The v217 database
SHA-256 is
`f6a40e8f1849fa008b64af1cdf31a47375ae521a6edcb8afc333af9fa00a9840`. The
evidence is in
`artifacts/spectron_server_object_lifecycle_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_server_object_lifecycle_anchors.py`.

The target class names are `Dq2rua2Ece`, `irqhGaERgb`, `dJ10YaC3tX`,
`k1h4JaIMdn`, `gId5RaV8_6`, `X0HXmbuEQV`, and `C2t_vaQTax`. The target ABI
destructor roles and the class-local placement make the short lifecycle rows
reviewable even where their direct calls use rebuilt wrapper names. No APK or
native library was modified.

A v201 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v201.i64`,
adds two remaining `TSounds` control wrappers. The script-facing
`TSounds_setMusicVolume` callback at `0xe1350` maps exactly to target
`sub_E1F28` at `0xe1f28`. The native `TSounds_updateMusic_void` method at
`0xe1888` maps to target `IUKzgam4Gy::EEuMgaWopJ` at `0xe2470`.

The first row is a complete feature match and preserves the callback-table
record that forwards the two script doubles. The second shares its compact
shape with the separate stop-MIDI method, but its sound-player virtual slot
is `+48`, while stop-MIDI uses `+72`. Callback-table references and the
matching `IUKzgam4Gy::soundplayer` global confirm the role. Both aliases
reopened successfully. The full semantic check reports zero failures across
11,694 functions, with 3,641 high-confidence labels and 1,218 default `sub_`
names. The v201 database SHA-256 is
`17db3651520fac5f9ef448f8b70be215cc6c1c36255ffa0aa21f65436a032c03`. The
evidence is in
`artifacts/spectron_sounds_control_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sounds_control_anchors.py`.

A v165 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v165.i64`,
translates the `TShowImg` property callback registry. The source
`TShowImgProperties` table at `0x389fa0` and the obfuscated Spectron table at
`0x39d0f0` both contain the same 48 decoded property names in the same order.
Each record is `0x30` bytes, with the getter at record offset `+0x10` and the
setter at `+0x18`. Reading those pointers directly resolves the callback even
when Spectron moved the implementation away from the source address order.

The two tables expose 93 non-null callback slots. The review records 85
high-confidence correspondences, including 84 complete normalized
fingerprint matches and one documented layout change for the `code` getter.
The three null setters are `actor`, `imageindex`, and `emitter`. Eight rows
were already covered by earlier semantic or manual work, and the Spectron
`code` setter reuses the existing `v18_TGaniParam_writeFloat_double` body, so
that target implementation was kept as shared context instead of being given
a second name. The other callbacks now have readable `v18_TShowImg_` aliases.

The `code` getter explains why a simple address delta is not sufficient here.
The 1.8 body is a 40-byte wrapper around virtual slot `+184`, while the
Spectron body is a 76-byte wrapper that also converts and cleans up the
returned string. The remaining rows match their complete normalized metrics,
but their address deltas fall into six groups because the target linker
reordered the property methods. All 85 rows reopened successfully, and the
full semantic check still reports zero failures across 11,694 functions,
3,641 high-confidence labels, and 1,264 remaining default `sub_` names. The
v165 IDA database SHA-256 is
`284432daf4efd99359cd41c2dc436f554c65b43f4e1d579bab4b3030fb72c153`.
The complete table evidence is in
`artifacts/spectron_showimg_property_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_showimg_property_anchors.py`. The read-only table
decoders are `tools/ida_dump_property_table.py` and
`tools/ida_dump_qwords.py`. The latter prints a small read-only qword window
for comparing IDA table records and obfuscated callback pointers.

A v153 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v153.i64`,
materializes and labels the 12 remaining `GSFunctionsClient` callbacks whose
Spectron table pointers landed in unbounded code. The ranges were recovered
from raw ARM64 control flow, including every conditional return and tail-call
path, and cross-checked against the adjacent relocated table pointer. The
v153 database has 11,693 functions and 1,407 remaining default `sub_` names.
Its SHA-256 is
`3c52ae8040e920dcf81c6a8ed5a5a9610d715bfbb56938bd2a40cb67ea8d35b9`. The
evidence is in
`artifacts/spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_boundary_residual_anchors.py`.

A v152 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v152.i64`,
adds the final nine already-bounded exact-shape callbacks from the current
`GSFunctionsClient` audit. They cover the Adventure nickname helper, level
origin, screen dimensions, mouse-button state, log output, and RPG messages.
The same `+0x13010` callback-table relocation was verified for every row, and
all nine normalized code-shape comparisons are exact. The v152 database has
11,681 functions and 1,407 remaining default `sub_` names. Its SHA-256 is
`275a6c98896248bfd99b1cdae7e7344bee3ef67d468c75749ed13293ea9e102f`. The
evidence is in
`artifacts/spectron_gsfunctions_client_exact_residual_v3_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v3_anchors.py`.

A v151 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v151.i64`,
adds a second batch of 20 exact-shape `GSFunctionsClient` aliases. The rows
cover shooting parameters, image and weapon state, mouse globals, URL and key
helpers, file cleanup, and Adventure file operations. As in v150, every
source callback pointer field maps to the Spectron field at `+0x13010`, and
the target field contains the reviewed target address. All 20 pairs match on
the nine normalized code-shape metrics. The v151 database has 11,681
functions and 1,416 remaining default `sub_` names. Its SHA-256 is
`853866783a4c652caf5dd594a47c70c398a9bbace25574eb95842bd108068229`. The
evidence is in
`artifacts/spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v2_anchors.py`.

A v150 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v150.i64`,
adds 20 exact-shape `GSFunctionsClient` callback aliases. This batch covers
the all-features, render-object, statistics, carry-state, version, OpenGL,
gravity, map, mouse, scripted-control, weapon, and image callbacks. The
corresponding Spectron table pointer field is `0x13010` bytes after the 1.8
field for every row, and the target table stores the reviewed target address.
All 20 pairs also match on size, instruction count, basic blocks, branches,
calls, mnemonic shape, opcode shape, register shape, and overall shape. The
v150 database has 11,681 functions and 1,436 remaining default `sub_` names.
Its SHA-256 is
`da6942a1bd21c3d56b602f33106803736391e6e6e4224de9108f96e674cb0cf6`. The
evidence is in
`artifacts/spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_anchors.py`.

A v149 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v149.i64`,
adds the remaining `GSFunctionsInitstaticscriptvars_script_randomstring`
anchor. The source table slot at `0x3872c0` and target slot at `0x39a3e0`
place it directly after the already translated `strequals` callback. The
target retains trailing-comma handling, random list selection, and temporary
list cleanup. It grows from 260 to 264 bytes because the 2.2 string-list
wrappers are explicit. The v149 database has 11,681 functions and 1,456
remaining default `sub_` names. Its SHA-256 is
`12de3cc80150cba753609346f881cec872df68966f47634befff579dcf9590b1`. The
evidence is in
`artifacts/spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_randomstring_residual_anchors.py`.

A v145 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v145.i64`,
adds five exact-shape `TUpdatePackageProperties` lifecycle anchors. They cover
the uninstall jump thunk, complete and deleting destructors, and both
non-virtual thunks. The v145 database has 1,473 remaining default `sub_`
names. Its SHA-256 is
`3b26ba1e6a150a8aebef18c46372843615523a76a813af5eba231c924a459f59`. The
evidence is in
`artifacts/spectron_update_package_properties_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_properties_residual_anchors.py`.

A v144 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v144.i64`,
adds six high-confidence update-package event and lookup anchors. They cover
failure notification, downloading and privileged package containment, force
and no-force update wrappers, and the download-complete event. The v144
database has 1,473 remaining default `sub_` names. Its SHA-256 is
`fecbafa39ffeca37580a23828e71b4a0d3be317029bd896548d02d7ae61799f6`. The
evidence is in
`artifacts/spectron_update_package_wrapper_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_wrapper_residual_anchors.py`.

A v143 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v143.i64`,
adds one exact-shape `TUpdatePackage` deleting-destructor anchor. It closes
the lifecycle row between the already translated constructor and client
helpers. The v143 database has 1,475 remaining default `sub_` names. Its
SHA-256 is
`0ff80f9687ea4115fd861d8319f1c1ee6fb9b3292d830659af242a6c01ce0e15`. The
evidence is in
`artifacts/spectron_update_package_destructor_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_destructor_residual_anchors.py`.

A v142 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v142.i64`,
adds 20 exact-shape `TClient` and `TUpdatePackage` accessor anchors. They
cover the base-package pointer, download-list count, package progress fields,
directive flags, numeric fields, and six string getters. The target entries
were default `sub_` names, so the v142 database has 1,475 remaining default
`sub_` names. Its SHA-256 is
`b8596d19b6c12d71c5ed331474d78bc9e274192a88566bcbe5f46dcbee4b9a66`. The
evidence is in
`artifacts/spectron_update_package_accessor_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_accessor_residual_anchors.py`.

A v141 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v141.i64`,
adds seven exact-shape client-thread anchors for socket locking, incoming and
outgoing package cleanup, the running-state guard, and outgoing sends. The
v141 database has 1,495 remaining default `sub_` names. Its SHA-256 is
`88c9abdbc6997eac4ee321d695df1170f17cc394b2ee0906370e2f5e726cb6b7`. The
evidence is in
`artifacts/spectron_client_thread_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_client_thread_residual_anchors.py`.

A v140 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v140.i64`,
adds three high-confidence `TPlayerList` anchors for the staff-guild setter,
static initialization, and empty static-script initializer. The target keeps
the same local sequence, although its static initializer allocates a 0x20-byte
obfuscated list object where 1.8 allocates a 0x18-byte `TStringList`. The v140
database has 1,495 remaining default `sub_` names. Its SHA-256 is
`45a774f4240b145c575dd7ff2e92d8b15d1bec215e64c98386d81519b039729b`. The
evidence is in
`artifacts/spectron_player_list_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_player_list_residual_anchors.py`.

A v139 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v139.i64`,
adds five high-confidence URL-cache anchors for insertion, loading, static
setup, and cache-entry destruction. The v139 database has 1,495 remaining
default `sub_` names. Its SHA-256 is
`ffa33dac8790bd45cfabeaae38201f09954a9cb298ceb747ed3f82b76155c08a`. The
evidence is in
`artifacts/spectron_url_cache_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_url_cache_residual_anchors.py`.

A v138 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v138.i64`,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v138.i64`,
adds five high-confidence socket-cache support anchors for static setup,
host and port matching, and cached-host destruction. The v138 database has
1,495 remaining default `sub_` names. Its SHA-256 is
`73a990ab8d29c9dd83e5542eb0130bfdb7ff80bc9e7b5f0eb3f9495354c7cfc8`. The
evidence is in
`artifacts/spectron_socket_cache_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_socket_cache_residual_anchors.py`.

A v137 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v137.i64`,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v137.i64`,
adds four exact `TSocketProperties` destructor-family anchors, including the
complete and deleting destructors and both 16-byte non-virtual thunks. The
v137 database has 1,495 remaining default `sub_` names. Its SHA-256 is
`594158817ff9bcecdd2e16896ad7216f6f470bc711809709f225178e604a1dc7`. The
evidence is in
`artifacts/spectron_tsocket_properties_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_properties_residual_anchors.py`.

A v136 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v136.i64`,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v136.i64`,
adds three high-confidence `TSocket` host and logging anchors. They cover
cached IPv4 storage, the SSL logging callback thunk, and host resolution.
The nearby plain send and receive helpers were already translated. The v136
database has 1,495 remaining default `sub_` names. Its SHA-256 is
`fbd9c0aaacb910343fda7807264cb8c66c25a9f8b9f8f394950e620479678723`. The
evidence is in
`artifacts/spectron_tsocket_host_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_host_residual_anchors.py`.

A v135 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v135.i64`,
adds four high-confidence `TSocket` lifecycle anchors for cleanup,
allowed-port checks, bind and script-state processing. The nearby
`checkScriptActive` method was already in the canonical semantic map and is
kept as a documented boundary. The v135 database has 1,497 remaining default
`sub_` names. Its SHA-256 is
`66f9607ed18bcd93ebbee727c3f42299fd05c7c17fa5659746afd52bd9e3598f`. The
evidence is in
`artifacts/spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_lifecycle_residual_anchors.py`.

A v134 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v134.i64`,
adds two high-confidence `TSocket` receive-path anchors for package
splitting and native reads. The target bodies preserve the on-connect,
ordinary-data, UDP-data, and data-package event paths with explicit wrapper
growth. The v134 database has 1,497 remaining default `sub_` names. Its
SHA-256 is
`0fa7676435cea1bdbdb334e9926d99dbb4437ccc4ff4c04d81c4531399b62971`. The
evidence is in
`artifacts/spectron_tsocket_receive_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tsocket_receive_residual_anchors.py`.

A v133 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v133.i64`,
adds four exact `TSocket` SSL and outgoing-buffer anchors. They cover SSL
enable state, cipher-list and protocol propagation, and the small send wrapper.
The v133 database has 1,497 remaining default `sub_` names. Its SHA-256 is
`d3d0be59f3cee7f3b10ab9f3da04910a4f6e4a7cdacdefa4996e4cb1a594afcd`. The
evidence is in
`artifacts/spectron_tsocket_ssl_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tsocket_ssl_residual_anchors.py`.

A v132 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v132.i64`,
adds 19 high-confidence `TSocket` accessor, output, and factory anchors.
They align at `+0x5ed8`, with 18 exact normalized-shape matches and one
allowed-port setter layout change caused by the target string wrapper. The
v132 database has 1,497 remaining default `sub_` names. Its SHA-256 is
`56d799699ce321c4e212fb2e9c9ca0e7d8fed8a349da89dc733972d8f4e8bef9`. The
evidence is in
`artifacts/spectron_tsocket_accessor_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tsocket_accessor_residual_anchors.py`.

A v131 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v131.i64`,
resolves the remaining `GuiControl_create_TString_const` factory ambiguity.
The source and target wrappers both allocate `0x1c8` bytes and call the
parameterized constructor, with identical normalized metrics. The v131
database has 1,514 remaining default `sub_` names. Its SHA-256 is
`0a9e38bcc80186b86ed83b5f6c92cad4101f8a2d7746e7379b2a192a02e8b603`. The
evidence is in
`artifacts/spectron_guicontrol_create_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_guicontrol_create_residual_anchors.py`.

A v130 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v130.i64`,
adds two high-confidence `GuiControl` initialization anchors. They cover the
full field and child-list initializer and the parameterized C2 constructor in
the obfuscated `w9XxgaJdbx` class. Both target bodies expose additional
temporary wrapper work, and both names reopened successfully. The v130
database has 1,514 remaining default `sub_` names. Its SHA-256 is
`1113a2703e11e58c61ff69510de89d938801ca3c405ca03c7a0fab3faa5b574d`. The
evidence is in
`artifacts/spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_guicontrol_initialization_residual_anchors.py`.

A v129 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v129.i64`,
adds eight high-confidence `GuiControl` event-dispatch anchors in the
obfuscated `w9XxgaJdbx` class. They cover first-responder, dialog push and
pop, add, visibility notification, action, and both mouse-wheel hooks. Six
target bodies grow because encoded event strings and temporary wrappers are
explicit, while the two mouse-wheel pairs retain exact normalized shapes.
All eight names reopened successfully. The v129 database has 1,514 remaining
default `sub_` names. Its SHA-256 is
`f2f0e0e125d868a43ed9aba2caf46025bd65df9254669fc6aa3caeef0771c0bf`. The
evidence is in
`artifacts/spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_guicontrol_event_dispatch_residual_anchors.py`.

A v128 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v128.i64`,
adds 12 high-confidence `GuiControl` style, geometry, profile, and color
anchors. The first three use a `+0x4500` delta. Spectron's `getStyle` body
adds 0x34 bytes of explicit wrapper work, so the remaining rows use
`+0x4534`. Eleven pairs have exact normalized shapes, while `getStyle` is
recorded as a layout-change match. All 12 names reopened successfully. The
v128 database has 1,514 remaining default `sub_` names. Its SHA-256 is
`d48e2c7f17fb26f72f4619589b6612cffdd862570476f3e3efa77b3b5c67d6b4`. The
evidence is in
`artifacts/spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_style_bounds_residual_anchors.py`.

A v127 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v127.i64`,
adds eight high-confidence `GuiControl` event and sizing anchors. They cover
child-resize, input, mouse-move, key-repeat, scroll-line, and vertical and
horizontal sizing methods. The source and target blocks align at a fixed
`+0x4500` delta, with exact normalized shapes. Six rows inside the enclosing
sequence were already mapped, and the unnamed source `sub_1B2FDC` row remains
an explicit gap. All eight names reopened successfully, with seven new names
written because one target alias was already present in the v126 lineage. The
v127 database has 1,526 remaining default `sub_` names. Its SHA-256 is
`a8b9293373fc4424b5a6de148a3822fd2819e21888703d1062aea3117bb1d1c5`. The
evidence is in
`artifacts/spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_event_sizing_residual_anchors.py`.

A v126 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v126.i64`,
adds 13 high-confidence `GuiControl` base and virtual-hook anchors. They
cover cache-size reporting, minimum extent, cursor type, root and external
window lookup, client-bound refresh, right-mouse hooks, script-access state,
forced clipping, and context-menu visibility. The source and target blocks
align at a fixed `+0x41c0` delta, and every pair has an exact normalized shape
match. The target already had obfuscated non-default names, so the default
`sub_` count remains 1,529. All 13 names reopened successfully. The v126
database SHA-256 is
`aed7e8fe3fd07cfe33c1ea0cc13df6742dec3e9a120e06873729203d9c4404a4`. The
evidence is in
`artifacts/spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_virtual_residual_anchors.py`.

A v125 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v125.i64`,
adds 61 high-confidence `GuiControl` property and script-wrapper anchors.
They cover the residual drop, activity, color, clipping, focus, flicker,
hint, sizing, scroll-line, visibility, profile-ownership, position, parent,
and topmost-property rows. The source and target blocks align at a fixed
`+0x4500` delta, and every pair has an exact normalized shape match. Seven
rows inside the enclosing block were already in the semantic map, and the
target-only helper at `0x1b7078` remains explicitly outside the translated
interval. All 61 names reopened successfully, with 60 new names written
because one target name was already present in the v124 lineage. The v125
database has 1,529 remaining default `sub_` names. Its SHA-256 is
`0b55e73e765827d37e37e7403c2f0779229a178f3deb78314e86da17d770a75b`. The
evidence is in
`artifacts/spectron_guicontrol_property_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_property_residual_anchors.py`.

A v124 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v124.i64`,
adds six high-confidence `GuiControlProfileProperties` and
`GuiControlProfile` destructor-family anchors. Four are exact shape matches;
the two main profile destructors document the target's eight-byte object
growth and one additional cleanup call. All six labels reopened successfully,
and the full translation check still reports zero failures. The v124 database
has 1,589 remaining default `sub_` names. Its SHA-256 is
`0db16cc6d06a77627a4b57048764aabb24f3a7b0c50cd9013b8b0a45c5bf0608`. The
evidence is in
`artifacts/spectron_gui_control_profile_destructor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gui_control_profile_destructor_anchors.py`.

A v123 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v123.i64`,
adds 89 high-confidence `GuiControlProfile` accessor anchors. They cover
scalar fields, alignment and point wrappers, font-style strings, color
setters and getters, background inset, the resource-file notification hook,
and the profile font-color helper. The target-only method and two source
coverage gaps remain explicitly unlabeled. All 89 labels reopened
successfully, and the full translation check still reports zero failures. The
v123 database has 1,589 remaining default `sub_` names. Its SHA-256 is
`50300d39030edb45142902407ff7651d7a436bb237fe54fe9d1aa59c8f3d7b8f`. The
evidence is in
`artifacts/spectron_gui_control_profile_accessor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gui_control_profile_accessor_anchors.py`.

A v122 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v122.i64`,
adds 16 high-confidence residual anchors for the screen-panel lifecycle,
font-option properties, font-data lookup, and window-properties destructor
families. They include six target functions that were still generic `sub_`
names. All 16 labels reopened successfully, and the full translation check
still reports zero failures. The v122 database has 1,677 remaining default
`sub_` names. Its SHA-256 is
`6163a6d7dcb2b510ec8664f72e40965ee31b56bc8d177a2c2ed1f969664a5c85`. The
evidence is in
`artifacts/spectron_font_options_font_data_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_font_options_font_data_residual_anchors.py`.

A v121 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v121.i64`,
adds nine high-confidence font and font-manager residual anchors. They cover
the remaining font and font-character-info deleting destructors, texture
binding and text metrics, font-cache cleanup, and the manager's height,
ascent, and descent helpers. All nine labels reopened successfully, and the
full translation check still reports zero failures. The v121 database SHA-256
is
`b331d230f59f5229f98c69747b501e7015a4a979fb50bf2e7d3f40ab48021fae`. The
evidence is in
`artifacts/spectron_font_manager_font_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_font_manager_font_residual_anchors.py`.

A v120 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v120.i64`,
adds seven high-confidence renderer and GLES-window residual anchors. They
cover the remaining screen-panel polygon-font stub, the empty offscreen and
resize hooks, the complete and deleting `TWindowGLES` destructors, its
window-backed pixel-buffer factory, and its native-mode predicate. All seven
labels reopened successfully, and the full translation check still reports
zero failures. The v120 database SHA-256 is
`c110ed3f38aad8b12296aa81cc6d780c2911d608fba5b895e0eaee7a2f48d955`. The
evidence is in
`artifacts/spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_screen_panel_window_gles_residual_anchors.py`.

A v119 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v119.i64`,
adds ten high-confidence renderer residual anchors. They cover the
`TPixelBufferOpenGL` texture predicate and the concrete `TScreenPanelOpenGL`
matrix, triangle-strip, shader, and alpha-reference methods. Spectron keeps
the same roles in its `uzN1fatj75` and `SU3JfaCUmR` classes, with predictable
object-layout shifts in the matrix fields. All ten labels reopened
successfully, and the full translation check still reports zero failures. The
v119 database SHA-256 is
`d57ae1011d866d392898e057f6a1cc309955755a8c5175a5ca07c66644fdaa27`. The
evidence is in
`artifacts/spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_screen_panel_renderer_residual_anchors.py`.

A v118 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v118.i64`,
adds 14 high-confidence residual panel anchors. They cover three remaining
`TPanelInterface` hooks and the full `TDummyPanel` virtual and destructor
block in the target `oMhmIajzmW` and `HtZ2_aJk7E` classes. The target keeps the
source method order and exact function shapes, including the zeroed
transformed-clipping rectangle and the complete and deleting destructor pair.
All 14 labels reopened successfully, and the full translation check still
reports zero failures. The v118 database SHA-256 is
`de9c45f75c839c7cbbe802544129f2021e29f1aec02f0543d374df89a777fbbf`. The
evidence is in
`artifacts/spectron_dummy_panel_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_dummy_panel_residual_anchors.py`.

A v117 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v117.i64`,
adds 23 high-confidence panel and renderer residual anchors. They cover the
18 `TPanelInterface` base hooks, the inherited panel-port texture flush hook,
the panel screen-capture and pixel hooks, and the `TGraphicOperation` texture
flush loop. The target preserves the complete base-method order except for a
clearly identified 2.2-only four-byte hook inserted after `setArrays`. The
renderer loop still walks the drawing-panel list and dispatches the same
texture flush operation, with a target vtable slot shift from 320 to 328
bytes. All 23 labels reopened successfully, and the full translation check
still reports zero failures. The v117 database SHA-256 is
`82f78696b705112585e04e2b3c522b88bed026d9d281bc4fdc9a7fff085ad5c4`. The
evidence is in
`artifacts/spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_panel_virtual_renderer_residual_anchors.py`.

A v116 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v116.i64`,
adds four high-confidence image-animation and palette lifecycle anchors. They
cover the two abstract `TImageAnimation` hooks and the deleting-destructor
wrappers for `TMNGAnimation` and `TPalette`. All four labels reopened
successfully, and the full translation check still reports zero failures. The
v116 database SHA-256 is
`e0befd5c98459fd191889bfe921fb9c2e1caa7d372a8e0feceed8ce2ffe69e77`. The
evidence is in
`artifacts/spectron_animation_palette_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_animation_palette_residual_anchors.py`.

A v115 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v115.i64`,
adds four high-confidence destructor anchors and corrects one medium-confidence
class collision in the automatic comparison. The source `TPixelBuffer` and
`TBitmap` destructor pairs are assigned to the separate target
`uSjUgask_P` and `Fcx_gaoydV` classes. All four labels reopened successfully,
and the full translation check still reports zero failures. The correction is
recorded in
`artifacts/spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826.json`,
generated by `tools/generate_spectron_pixelbuffer_bitmap_lifecycle_anchors.py`.
The v115 database SHA-256 is
`a0272f3a6d1a8acd0e700e6924b99a2faa93f87151f47581385cbe6bdadb932e`.

A v113 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v113.i64`,
adds three high-confidence sound-runtime anchors. They cover the main sound
dispatcher, note-based pitch calculation, and Java sound-effect playback. The
target dispatcher preserves extension classification, volume selection,
download and cache handling, music restart, effect creation, and playback
state. The note helper keeps the twelve-note table and the same `powf` ratio.
The Java method keeps the `startSound([BII)V` lookup, path trimming, byte-array
release, rate limiting, and pan or volume calculation. All three labels
reopened successfully, and the full translation check still reports zero
failures. The v113 database SHA-256 is
`b8d25d41ea73f217003a7e39799ce9f124f2452c12f4df694b22c3caf4c70b37`. The
evidence is in
`artifacts/spectron_sound_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_sound_runtime_anchors.py`. The source
sound-effect constructor was reviewed but left unnamed because its stripped
target constructor was not isolated with the same confidence.

A v114 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v114.i64`,
adds ten high-confidence `TPixelBuffer` residual anchors. They cover pixel
and palette field updates, pointer clearing, format storage, lazy pixel
allocation, the base texture predicate, and the base texture create, update,
rectangle-update, and bind hooks. The target `uSjUgask_P` class preserves the
same roles and local method order around the previously translated allocation
and compatible-bitmap methods. All ten labels reopened successfully, and the
full translation check still reports zero failures. The v114 database SHA-256
is
`62362bfe045dfa107edc90dc3ca501baec50eaf6477b949f9e74be888c6fd725`. The
evidence is in
`artifacts/spectron_pixelbuffer_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_pixelbuffer_residual_anchors.py`.

A v112 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v112.i64`,
adds two high-confidence `TWindow` residual anchors. They cover the main
window close-query path and the window-backed pixel-buffer factory. The target
preserves the main-window identity guard, shutdown preparation, heap buffer
allocation, and pixel-buffer constructor call. Spectron also writes a second
shutdown-state value, which is documented as a target-version difference. All
two labels reopened successfully, and the full translation check still
reports zero failures. The v112 database SHA-256 is
`d8c782e2040a57c3bae8e406c90e0d94d7bc32fef82b203a33621fcd0a6c9209`. The
evidence is in
`artifacts/spectron_window_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_window_residual_anchors.py`.

A v111 disposable copy,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v111.i64`,
adds one high-confidence `TBitmap` GIF decoder anchor. The target preserves
GIF record parsing, Graphic Control Extension transparency and delay
handling, palette conversion, animation-step allocation, row copying, and
first-frame bitmap setup. Spectron adds explicit `GifErrorString` diagnostics,
a retry-mode flag, and success logging. The label reopened successfully, and
the full translation check still reports zero failures. The v111 database
SHA-256 is
`aa225a0d07cbd7f7ab3e015762c3d9ab14e4c6c46b6154b0bf11ef6852d3d64c`. The
evidence is in
`artifacts/spectron_gif_decoder_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_gif_decoder_anchor.py`.

A focused static comparison also reviewed the three changed-size socket
functions that were not safe exact-match rename candidates. It records the
shared TLS verification sequence, nonblocking connect state machine, and
receive error policy, along with the small 2.2 logging differences, in
`artifacts/spectron_socket_behavior_comparison_20260826.json`.

The first direct emulator launch of the supplied Spectron package also found
a separate modding-layer problem. After Start was tapped, `libxposed.so`
crashed at its statically confirmed WebTop `crash` command branch. The same
run logged qplay scoped-storage write failures, but the crash was not shown to
come from qplay. This was not a no-network or playable-world test, and the
observation is recorded in
`artifacts/spectron_runtime_crash_control_20260826.json`.

A private signed Spectron control then disabled only the ARM64 WebTop
`crash`, `freeze`, and `abort` branches. The process stayed alive through
qplay activation, OpenGL setup, login-server connection, two server-warps,
and Connected. After the welcome and tutorial dialogs were advanced, it
rendered a stable local in-game scene with the player, map furniture, HUD
controls, and status icons. This isolates the intentional bridge crash and
demonstrates local game entry for the supplied 2.2 package. It does not claim
live-service compatibility. The control APK and runtime record are
documented in `artifacts/spectron_webtop_safe_runtime_20260826.json`.

I also made a second local handoff copy directly from the active desktop IDA
snapshot. The source snapshot hash is
`56da88101fe904ca298dcadf31e90433a69c43818c681ccb72364c66ac99eaa4`, and the
translated copy is
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_from_active.i64`.
It was saved and reopened in a clean IDA 9.3 environment with all 1,211 names
verified. The active desktop database was not changed. Both generated IDA
databases are local handoff files and are intentionally outside this public
repository.

A clean 2026-08-25 revalidation of the same signed ARM64-only diagnostic APK
was also completed from fresh app data. After the Android compatibility
warning was dismissed, the local responders saw one connector request and two
game connections. The client accepted the map, three encrypted level
containers, and the tile sheet, kept its heartbeat alive, and displayed the
green tiled world with its HUD and status icons. The minimal responder needed
one temporary GUI placeholder for `guigames_graymessage2.png`; it was copied
from a local APK and remains outside this repository. This confirms that the
documented diagnostic chain is repeatable, but it does not add live-service or
physical-device coverage. See
`artifacts/arm64_diagnostic_apk_revalidation_20260825.json`.

The game has not yet been verified against a live game server. The local test
demonstrates that the x86_64 native client and the patched ARM64 library can
reach a rendered world through a bounded loopback responder. Live endpoint
availability, current package signing, account authentication, and physical
ARM64-device behavior remain open.

The recovered connector script now has a documented compiler path as well.
HexaParser's raw output reverses the same-line brace literals used for handler
tables and server lists, and the narrow adapter restores that order for static
comparison. A clean runtime control still found a larger instruction and
record-layout difference, and the adapted output did not reach the expected
game port. The proven compatibility path keeps the original VM stream and
uses `tools/patch_connector_bytecode_loading_clear.py` to insert the existing
loading-state assignment into `onServerLogin`. That candidate reaches the
local game/resource protocol path, but its bounded screenshot remains on the
title/loading artwork.

The separate game-server certificate path now has a source-level repair tool
as well. It is not active in the recovered Classic branch, but
`tools/replace_game_server_tls_source.py` finds both recovered
`setSSLParameters` certificate literals, verifies the existing native DES
format, and writes a new GS2 file without changing the input. The original
certificate produces an identity source and bytecode result, while a longer
offline test certificate compiled successfully at 1,072 Base64 characters.
The tool leaves verification enabled and does not contact a network.

The native connector trust replacement has also been exercised locally. A
SAN-matching test certificate was installed into a private ARM64 copy, the
HTTPS port was moved only for ADB reverse, and the original RSA branch stayed
unchanged. The package completed the connector and game replay and rendered
the same world through the x86_64 emulator's ARM64 translation layer. This
proves the local native TLS path, not a current live certificate or service.

## Repository layout

* `docs/RESEARCH_NOTES.md` is the chronological investigation record.
* `docs/PROTOCOL.md` describes the connector and NewGraal wire formats.
* `docs/LEVEL_CONTAINER.md` describes the encrypted `.code` level container.
* `docs/SYMBOLS.md` explains the symbol export and naming policy.
* `docs/IDA_RESIDUALS.md` accounts for every default function left in the
  persisted IDA copy.
* `docs/RUNTIME_STATUS.md` lists verified milestones and open blockers.
* `docs/ARM64_RENDER_REPAIR.md` records the ARM64 loading-state experiments
  and the successful render-boundary diagnostic.
* `docs/REPAIR_MATRIX.md` separates the connector, loading-state, and rejected
  handler-table diagnostics from release-ready repairs.
* `docs/HELPER_TOOLCHAIN.md` records the pinned GS2 and connector-helper
  checks, including their reproducible hashes and current limitations.
* `docs/CONNECTOR_TLS.md` records the native trust path, certificate date
  checks, and the paired validity control.
* `docs/SPECTRON_COMPARISON.md` records the supplied modded APK comparison.
* `artifacts/spectron_native_compare.json` records the offline ELF, symbol,
  section, and embedded-string comparison for the two ARM64 native builds.
* `artifacts/spectron_hook_analysis.json` records the Spectron WebTop URL,
  its nine obfuscated qplay lookups, three explicit hook installations, and
  the six native dispatcher commands. The URL was recovered offline and was
  not contacted.
* `artifacts/spectron_function_signature_match.json` records the exact
  function-byte comparison against Spectron. It found one obfuscated match
  and no usable source-name transfer.
* `artifacts/spectron_semantic_function_translation_20260826.json` records
  the normalized-function translation map, its confidence counts, and the
  shared-name validation set.
* `artifacts/spectron_manual_translation_anchors_20260826.json` records the
  four reviewed Spectron context anchors.
* `artifacts/spectron_exact_shared_name_anchors_20260826.json` records the
  1,008 exact one-to-one names shared by both builds.
* `artifacts/spectron_network_manual_translation_anchors_20260826.json`
  records the six reviewed connector and socket anchors.
* `artifacts/spectron_client_outbound_manual_translation_anchors_20260826.json`
  records the 29 reviewed remaining outbound client serializers, including
  their target signature cues and source-to-target evidence.
* `artifacts/spectron_resource_manual_translation_anchors_20260826.json`
  records the six reviewed resource resolver anchors and their pseudocode
  evidence.
* `artifacts/spectron_script_bridge_manual_translation_anchors_20260826.json`
  records the 13 reviewed client script bridge anchors and their target shape
  checks.
* `artifacts/spectron_client_request_manual_translation_anchors_20260826.json`
  records the 11 reviewed client request and window-state serializer anchors.
* `artifacts/spectron_client_inbound_manual_translation_anchors_20260826.json`
  records the eight reviewed client inbound and state-transition anchors.
* `artifacts/spectron_login_helper_manual_translation_anchors_20260826.json`
  records the eight reviewed login, event, and small client-state anchors.
* `artifacts/spectron_parse_wrapper_manual_translation_anchor_20260826.json`
  records the reviewed client encryption-in tail-thunk anchor and its raw
  bytes.
* `artifacts/spectron_lookup_helper_manual_translation_anchors_20260826.json`
  records the three reviewed player and download lookup anchors.
* `artifacts/spectron_connection_helper_manual_translation_anchors_20260826.json`
  records the 18 reviewed connection, SSL, and low-level field anchors.
* `artifacts/spectron_client_state_helper_manual_translation_anchors_20260826.json`
  records the seven reviewed compact client-state and forwarding anchors.
* `artifacts/spectron_connection_state_manual_translation_anchors_20260826.json`
  records the five reviewed connection-string and encrypted-file helpers.
* `artifacts/spectron_http_request_manual_translation_anchors_20260826.json`
  records the 12 reviewed HTTP request field, lifecycle, and send helpers.
* `artifacts/spectron_socket_state_manual_translation_anchors_20260826.json`
  records the five reviewed socket status, nonblocking, and IP helpers.
* `artifacts/spectron_http_request_state_manual_translation_anchors_20260826.json`
  records the four reviewed request counter, timestamp, and download-state
  helpers.
* `artifacts/spectron_http_request_receive_manual_translation_anchors_20260827.json`
  records the two reviewed HTTP response read and data-parser roles, including
  their implementation changes and target class context.
* `artifacts/spectron_server_list_connection_manual_translation_anchors_20260827.json`
  records the five reviewed server-list getter and connection-handoff roles,
  including target setter/global relationships and the handoff layout change.
* `artifacts/spectron_server_list_state_manual_translation_anchors_20260827.json`
  records the four exact-shape server-list boolean and start-state methods,
  including their target global relationships and existing context methods.
* `artifacts/spectron_http_request_cleanup_manual_translation_anchors_20260827.json`
  records the request reset layout anchor and the four exact-shape
  request-properties destructor and thunk roles.
* `artifacts/spectron_tsocket_residual_manual_translation_anchors_20260827.json`
  records the four reviewed residual socket client-list, destructor, error,
  and IP adapter roles.
* `artifacts/spectron_game_environment_manual_translation_anchors_20260827.json`
  records the four reviewed `TGameEnvironment` startup and property callback
  roles, including the target registration-table evidence.
* `artifacts/spectron_client_environment_graphics_manual_translation_anchors_20260827.json`
  records the exact-shape `TClientEnvironment_initGraphics_void` wrapper
  and its class-local neighbor evidence.
* `artifacts/spectron_client_environment_static_clear_manual_translation_anchors_20260827.json`
  records the two exact-shape profiler-string cleanup callbacks registered by
  the translated `runTimers` and `drawGame` methods.
* `artifacts/spectron_client_environment_restart_state_manual_translation_anchors_20260827.json`
  records the high-confidence layout-change match for the saved-restart state
  cleanup callback and its target field and initializer evidence.
* `artifacts/spectron_particle_emitter_script_vars_manual_translation_anchors_20260827.json`
  records the exact-shape particle-emitter script-property initializer and
  its independently translated target property-class evidence.
* `artifacts/spectron_resource_link_lists_manual_translation_anchors_20260827.json`
  records the exact-shape resource file-link and object-link list initializer,
  including the resolved collision with the particle-emitter candidate.
* `artifacts/spectron_clear_cur_anis_manual_translation_anchors_20260827.json`
  records the high-confidence 248-byte current-animation-state cleanup match,
  including the target string-lifetime change and animation consumer evidence.
* `artifacts/spectron_options_window_position_manual_translation_anchors_20260827.json`
  records the high-confidence `TOptions` window-position initializer match,
  including the target option fields and adjacent string initialization.
* `artifacts/spectron_displayed_gif_manual_translation_anchors_20260827.json`
  records the high-confidence displayed-GIF state initializer match, including
  the shared draw-consumer family and target cleanup callback.
* `artifacts/spectron_gui_button_types_manual_translation_anchors_20260827.json`
  records the high-confidence GUI button-type table initializer, including the
  preserved PushButton, ToggleButton, and RadioButton entries.
* `artifacts/spectron_gui_alignment_tables_manual_translation_anchors_20260827.json`
  records the high-confidence `GuiGraalCtrl` horizontal and vertical
  alignment-table initializer, its property metadata, and target cleanup
  evidence.
* `artifacts/spectron_gui_stretch_modes_manual_translation_anchors_20260827.json`
  records the high-confidence `GuiStretchCtrl` mode-table initializer, its
  decoded property table, and target cleanup evidence.
* `artifacts/spectron_tgui_render_colors_manual_translation_anchors_20260827.json`
  records the high-confidence `TGUIRender` border-color initializer, its
  five RGBA defaults, render consumer, and target cleanup evidence.
* `artifacts/spectron_thtml_definitions_defaults_manual_translation_anchors_20260827.json`
  records the exact normalized-shape `THTMLDefinitions` default initializer,
  its HTML consumers, obfuscated target class, and register-detail hash
  difference.
* `artifacts/spectron_tclient_static_strings_manual_translation_anchors_20260827.json`
  records the high-confidence `TClient` static-string initializer, all eleven
  preserved field mappings, the obfuscated target class, and cleanup evidence.
* `artifacts/spectron_tsocket_static_state_manual_translation_anchors_20260827.json`
  records the high-confidence `TSocket` static-string initializer, both
  preserved field mappings, the target-only string lifetime, and cleanup
  evidence.
* `artifacts/spectron_android_tapjoy_video_state_manual_translation_anchors_20260827.json`
  records the corrected Android, TapJoy, and video reset or cleanup pair,
  including seven shared state fields and the target-only string lifetime.
* `artifacts/spectron_sounds_music_state_manual_translation_anchors_20260827.json`
  records the three exact normalized-shape `TSounds` music-state wrappers,
  their virtual slots, callback-table references, and ambiguity resolution.
* `artifacts/spectron_sounds_effect_manual_translation_anchors_20260827.json`
  records the `TSoundEffect` constructor layout change and the exact-shape
  `TSounds` cache lookup, including their obfuscated target call roles.
* `artifacts/spectron_sounds_control_manual_translation_anchors_20260827.json`
  records the `TSounds` set-music-volume and update-music control wrappers,
  including the stop-MIDI virtual-slot disambiguation.
* `artifacts/spectron_sounds_tail_manual_translation_anchors_20260827.json`
  records the stop-SFX wrapper, script pitch bridge, and layout-change sound
  cache initializer, including their callback and static-registration evidence.
* `artifacts/spectron_sound_java_d1_manual_translation_anchors_20260827.json`
  records the complete `TSoundPlayerJava` D1 destructor beside the translated
  D0 destructor, including method-table and lifecycle evidence.
* `artifacts/spectron_html_page_manual_translation_anchors_20260827.json`
  records eight exact small `THTMLPage` methods mapped into Spectron's
  obfuscated `AS80gaE4zW` class family.
* `artifacts/spectron_gui_text_list_manual_translation_anchors_20260827.json`
  records eight exact small `GuiTextListCtrl` methods mapped into Spectron's
  obfuscated `u0eyga1eqx` class family.
* `artifacts/spectron_gui_text_list_entry_manual_translation_anchors_20260827.json`
  records the three exact small `GuiTextListEntry` property helpers from the
  v211 pass.
* `artifacts/spectron_gui_text_list_entry_property_manual_translation_anchors_20260828.json`
  records 30 residual `GuiTextListEntry` and `GuiTextListCtrl` property
  accessors matched by property-table order, field offsets, and IDA
  pseudocode.
* `artifacts/spectron_gui_text_list_residual_manual_translation_anchors_20260828.json`
  records ten adjacent sort, hint, geometry, and profile methods matched by
  table references and decompiled behavior.
* `artifacts/spectron_encryption_graalvar_manual_translation_anchors_20260827.json`
  records the three exact compact TEncryption and TGraalVar helpers from the
  v212 pass.
* `artifacts/spectron_compact_residual_manual_translation_anchors_20260827.json`
  records 13 compact property, wrapper, handler, cache, and script helpers
  from the v213 pass, including table context and the folded canDownload note.
* `artifacts/spectron_t2d_matrix_manager_manual_translation_anchors_20260827.json`
  records four `T2DMatrixManager` methods mapped into the named `AUzMgaePtJ`
  class, plus the deferred static-initializer review note.
* `artifacts/spectron_mrandom_family_manual_translation_anchors_20260827.json`
  records the 29-method MRandomGenerator, MRandomLCG, and MRandomR250 class
  block, including the resolved static-generator global.
* `artifacts/spectron_mrandom_property_residual_manual_translation_anchors_20260828.json`
  records four exact MRandomGenerator seed and random-number property or
  script callbacks, with source and target registration-table records.
* `artifacts/spectron_gui_drawing_panel_script_manual_translation_anchors_20260828.json`
  records three exact drawing-panel script callbacks and their decoded target
  registration-table records.
* `artifacts/spectron_tclient_script_property_manual_translation_anchors_20260828.json`
  records five TClient script-property callbacks, including the two explicit
  wrapper-layout differences and the register-detail difference.
* `artifacts/spectron_file_cache_property_manual_translation_anchors_20260828.json`
  records six password, cache, and file-download property callbacks, plus
  the three target-only rows kept separate from source mappings.
* `artifacts/spectron_tstringlist_residual_manual_translation_anchors_20260827.json`
  records the four remaining TStringList methods in the `vuuHgangcF` class,
  including the reviewed case-insensitive lookup layout change.
* `artifacts/spectron_server_object_lifecycle_manual_translation_anchors_20260827.json`
  records 49 residual server-object accessors, constructors, static-property
  initializers, and lifecycle methods across seven named class blocks.
* `artifacts/spectron_gui_ml_text_residual_manual_translation_anchors_20260827.json`
  records 39 residual `GuiMLTextCtrl` accessors, script wrappers, input
  handlers, reflow helpers, and property destructors.
* `artifacts/spectron_tsound_effect_methods_manual_translation_anchors_20260827.json`
  records the seven exact `TSoundEffect` virtual methods and their matching
  source and target method-table order.
* `artifacts/spectron_npc_helper_manual_translation_anchors_20260826.json`
  records the 15 reviewed `TServerNPC` blocking, draw-mode, visibility, bow,
  and pelt helpers.
* `artifacts/spectron_html_atom_manual_translation_anchors_20260826.json`
  records the five reviewed `THTMLAtom` constructor and buffer helpers.
* `artifacts/spectron_player_helper_manual_translation_anchors_20260826.json`
  records the five reviewed `TPlayer` attachment, update, freeze, and sprite
  helpers.
* `artifacts/spectron_input_window_manual_translation_anchors_20260826.json`
  records the eight reviewed input and window bridge helpers.
* `artifacts/spectron_visual_helper_manual_translation_anchors_20260826.json`
  records the 11 reviewed animation, particle, and show-image helpers.
* `artifacts/spectron_script_runtime_manual_translation_anchors_20260826.json`
  records the 12 reviewed GS2-facing `TGraalVar`, `TScript`, `TScriptSpace`,
  and `TScriptUniverse` helpers.
* `artifacts/spectron_core_helper_manual_translation_anchors_20260826.json`
  records the 30 reviewed level, script, network-policy, tile, particle, and
  native callback helpers.
* `artifacts/spectron_render_gui_manual_translation_anchors_20260826.json`
  records the 20 reviewed texture, OpenGL, drawing-panel, GUI-control,
  markup, and scrolling helpers.
* `artifacts/spectron_gani_frame_playback_manual_translation_anchors_20260826.json`
  records the two reviewed Gani frame-property and animation-playback anchors.
* `artifacts/spectron_gani_lifecycle_manual_translation_anchors_20260826.json`
  records the 50 reviewed Gani object, animation state, ownership, loading,
  and property lifecycle anchors.
* `artifacts/spectron_tplayer_core_manual_translation_anchors_20260826.json`
  records the two reviewed TPlayer network-property and constructor anchors.
* `artifacts/spectron_tplayer_scalar_setter_manual_translation_anchors_20260826.json`
  records the ten reviewed TPlayer scalar setter anchors from the v158 pass.
* `artifacts/spectron_tplayer_scalar_getter_manual_translation_anchors_20260826.json`
  records the 21 reviewed TPlayer scalar getter anchors from the v159 pass.
* `artifacts/spectron_tplayer_flag_setter_manual_translation_anchors_20260826.json`
  records the seven reviewed TPlayer flag and feature setter anchors from the
  v160 pass.
* `artifacts/spectron_tserverplayer_property_block_manual_translation_anchors_20260826.json`
  records the 39 reviewed TServerPlayer property-block anchors from the v161
  pass.
* `artifacts/spectron_tserverplayer_residual_manual_translation_anchors_20260826.json`
  records the 25 reviewed TServerPlayer property and script-table callbacks
  from the v163 pass, including the two layout-change rows and two preserved
  shared implementations.
* `artifacts/spectron_tserverplayer_tail_manual_translation_anchors_20260826.json`
  records the seven reviewed TServerPlayer lifecycle, static-initializer,
  attachment, and coordinate-tail callbacks from the v164 pass.
* `artifacts/spectron_showimg_property_manual_translation_anchors_20260827.json`
  records the 48 decoded TShowImg properties and 85 reviewed getter and
  setter callback correspondences from the v165 pass, including the one
  layout-change row, eight existing-context rows, and three null setters.
* `artifacts/spectron_showimg_residual_manual_translation_anchors_20260827.json`
  records the 24 reviewed residual TShowImg methods and properties-class
  destructor anchors from the v166 pass, including 22 exact rows and two
  layout-aware lifecycle rows.
* `artifacts/spectron_server_object_scalar_manual_translation_anchors_20260827.json`
  records the 12 exact-shape TServerBomb, TServerChest, TServerFlying, and
  TExplosion rows from the v167 pass.
* `artifacts/spectron_compression_manual_translation_anchors_20260827.json`
  records the five exact-shape TCompression wrapper rows from the v168 pass.
* `artifacts/spectron_files_manual_translation_anchors_20260827.json`
  records the six exact-shape TFiles metadata, filename, and URL-aware path
  helper rows from the v169 pass.
* `artifacts/spectron_encryption_manual_translation_anchors_20260827.json`
  records the nine exact-shape TEncryption DES, MD5, RSA, RC4, and AES rows
  from the v170 pass.
* `artifacts/spectron_tlist_manual_translation_anchors_20260827.json`
  records the six exact-shape TList mutation, accessor, append, and sorting
  rows from the v171 pass.
* `artifacts/spectron_sounds_manual_translation_anchors_20260827.json`
  records the eight exact-shape TSounds state, script, cleanup, MIDI, and
  playback rows from the v172 pass.
* `artifacts/spectron_hash_container_manual_translation_anchors_20260827.json`
  records the five exact-shape THashList and THashStrings lifecycle, iterator,
  count, and membership rows from the v173 pass.
* `artifacts/spectron_hash_lifecycle_manual_translation_anchors_20260827.json`
  records the six reviewed hash-container constructor, destructor, iterator,
  and value-setter rows from the v210 pass.
* `artifacts/spectron_tstring_manual_translation_anchors_20260827.json`
  records the six exact-shape TString integer insertion, prefix, and
  case-insensitive comparison rows from the v174 pass.
* `artifacts/spectron_tstring_clear_manual_translation_anchors_20260827.json`
  records the exact-shape TString reference-counted clear row from the v175
  pass.
* `artifacts/spectron_static_clear_manual_translation_anchors_20260827.json`
  records the two reviewed TClient and TSocket static cleanup layout anchors
  from the v176 pass.
* `artifacts/spectron_static_callback_role_correction_20260827.json` records
  the corrected source role for the old third static callback and the two
  rejected Spectron target candidates. It does not assign a target alias.
* `artifacts/spectron_resource_parser_manual_translation_anchors_20260826.json`
  records the three reviewed Gani lexer, cached-resource path, and
  update-package parser anchors.
* `artifacts/spectron_static_utility_manual_translation_anchors_20260826.json`
  records the five reviewed statistics, profiler, GUI-style, ZIP-resource,
  and translation utility anchors.
* `artifacts/spectron_font_bitmap_manual_translation_anchors_20260826.json`
  records the four reviewed glyph, font-atlas, font-resource, and bitmap-loader
  anchors.
* `artifacts/spectron_mng_animation_manual_translation_anchor_20260826.json`
  records the reviewed MNG animation-step decoder anchor.
* `artifacts/spectron_script_machine_tail_manual_translation_anchors_20260826.json`
  records the two reviewed script-machine parameter and native callback anchors.
* `artifacts/spectron_json_folder_manual_translation_anchors_20260826.json`
  records the eight reviewed GIF/JPEG callbacks, recursive folder-loader
  helper, and YAJL JSON callbacks.
* `artifacts/spectron_socket_behavior_comparison_20260826.json` records the
  static comparison of the changed SSL setup, connect, and read bodies.
* `artifacts/spectron_translation_checkpoint_20260826.json` records the
  close-and-reopen check for the persisted Spectron IDA copy.
* `artifacts/spectron_runtime_crash_control_20260826.json` records the local
  WebTop crash-branch observation and its IDA correlation.
* `artifacts/spectron_webtop_safe_runtime_20260826.json` records the bounded
  runtime control after disabling the three destructive WebTop branches.
* `docs/TESTING.md` describes local-only reproduction without contacting a
  live game service.
* `artifacts/helper_toolchain_replay.json` records the verified HexaParser and
  conpack hashes, including the legacy ZIP-header and corrected clean-control
  status for the literal-order experiment.
* `artifacts/bytecode_loading_clear_replay.json` records the direct
  original-stream script patch, package signature check, and local protocol
  replay hashes.
* `artifacts/arm64_loopback_handshake_replay.json` records a fresh
  handshake-only replay of the ARM64 loading candidate, including the
  connector request, both game captures, and the remaining disconnect state.
* `artifacts/arm64_local_fixture_render_replay.json` records the held-
  connection replay that loaded matching encrypted level containers and
  captured the rendered ARM64 world through emulator translation.
* `artifacts/arm64_diagnostic_apk_revalidation_20260825.json` records the
  fresh packaged-APK revalidation, including signature metadata, responder
  captures, fixture hashes, and the clean rendered-world result.
* `artifacts/arm64_native_only_original_script_replay_20260826.json` records
  the native-only loading-state isolation run with the original connector
  script and its capture hashes.
* `artifacts/arm64_native_stock_original_script_control_20260826.json` records
  the matched stock-branch negative control for that isolation run.
* `artifacts/arm64_reproducible_builder_validation_20260826.json` records the
  deterministic builder output and fresh package replay.
* `artifacts/connector_tls_expiry_control_20260826.json` records the paired
  valid and expired certificate control, including the no-HTTP handshake
  failure and the matching successful request.
* `artifacts/arm64_native_verification_working_control_20260826.json` records
  the valid-trust, native-verification working control and its stock-loading
  comparison.
* `artifacts/connector_tls_parser_analysis_20260826.json` records the native
  CyaSSL validity call chain and the recovered `notBefore` and `notAfter`
  error mapping.
* `artifacts/elf_symbol_table_audit_20260826.json` records the distinction
  between the surviving dynamic rows and the larger applied alias inventory.
* `symbols/libqplay.symbols.csv` is the searchable symbol table.
* `symbols/libqplay.symbols.json` is the machine-readable equivalent.
* `symbols/libqplay.symbols.summary.json` records the translation counts.
* `symbols/libqplay.function_inventory.csv` and
  `symbols/libqplay.function_inventory.json` preserve the pre-persistence
  inventory of all 11,272 IDA function starts, including the 1,645
  analysis-created `sub_` entries that had no translated alias at that point.
* `symbols/libqplay.function_inventory.summary.json` records the input hash
  and the boundary between translated symbols and IDA-created functions in
  that original inventory.
* `artifacts/unresolved_function_profile.json` profiles the 488 default
  `sub_` entries in the pre-persistence snapshot that lacked source names. It
  separates likely static library internals, compiler-generated cleanup
  wrappers, init/fini array entries, a compiler branch veneer, the PLT resolver
  slot, and the 28 application or engine entries that were later given role
  aliases.
* `artifacts/ida_residual_profile.json` accounts for the 421-entry latest
  residual queue after the CyaSSL and static-library passes and records the
  earlier 459-entry base and 448-entry intermediate counts through its
  applied-alias accounting. It records every latest residual address and
  explains why no source name is claimed for it.
* `artifacts/cyassl_static_role_audit_20260826.json` records eleven static
  CyaSSL and bundled-crypto role aliases, their IDA evidence, source-role
  comparison links, and the verified latest database hash.
* `artifacts/static_library_role_audit_20260826.json` records 27 additional
  zlib, bzip2, minizip, GPC, CyaSSL, LibTomCrypt, and YAJL role aliases. It
  includes the five corrected library-boundary classifications and the v4
  database and inventory hashes.
* `artifacts/ida_semantic_labels.json` records 467 evidence-backed names
  applied to formerly unnamed login, file-download, handler-table, UI, TLS,
  HTTP, socket, animation, sound, network-thread, update-package, and JNI
  bridge helpers.
* `artifacts/ida_translation_validation.json` records the disposable-copy
  IDALIB audit of the expanded callback naming pass. It includes the five
  native FDE ranges, the twenty script-table FDE ranges, the two split
  functions, zero apply failures, and the hash of the persisted translated
  database copy. It also records the exact hash of the active desktop IDB
  snapshot and the separate translated handoff copy made from it. The live
  desktop IDA database was not changed.
* `artifacts/native_callback_candidates.json` records the next table-backed
  callback, static-state, sound-wrapper, and server-object names recovered from
  the native library. The current review set contains 277 entries. They remain
  clearly marked as candidates in the artifact, while all 277 were applied and
  verified in the persisted disposable IDA copy. The locked desktop database
  was not modified.
* `artifacts/script_table_inventory.json` records all 132 static registration
  calls, 1,455 declared property and function records, and 1,779 unique
  callback targets. It separates 886 exact bounded rename candidates from
  20 exact callback pointers that lack saved IDA boundaries. All 906 new
  targets have recovered script names, and the 20 missing boundaries have
  matching ELF `.eh_frame` ranges.
* `tools/generate_script_table_inventory.py` rebuilds that inventory offline;
  `tools/ida_apply_script_table_inventory.py` creates a review-only IDA rename
  plan for the exact bounded subset, while
  `tools/ida_apply_script_table_boundaries.py` handles the 20
  `.eh_frame`-backed boundaries separately. The boundary pass also handles the
  two saved IDA ranges that contain an independently proven callback start.
  The decoder regression check is in `tools/test_script_table_inventory.py`.
* `artifacts/symbol_translation_overlay.json` joins the pre-persistence set of
  1,645 default `sub_` functions with 886 exact script-table names and 271
  curated callback candidates. It leaves the remaining 488 default functions
  explicit instead of assigning speculative names.
* `tools/generate_symbol_translation_overlay.py` rebuilds that overlay from
  the saved function, script-table, and candidate inventories.
* `tools/generate_unresolved_function_profile.py` rebuilds the unresolved
  function profile from the saved inventories and ELF section metadata.
* `artifacts/unresolved_function_candidates.json` records 28 behavior-based
  role aliases for profiler, image-I/O, animation-lexer, spatial-query, UI,
  script-object, folder-loader, and JSON-parser helpers. All 28 are
  high-confidence role assignments, including the nearest-player comparator
  cross-referenced from both nearest-player script wrappers. The candidate
  artifact remains a review input for the locked desktop database, while all
  28 aliases were applied and verified in the persisted disposable copy. The
  generator also checks that the 28 roles cover the complete application or
  engine queue in the unresolved profile.
* `tools/generate_unresolved_function_candidates.py` rebuilds that candidate
  artifact, while `tools/ida_apply_unresolved_function_candidates.py` provides
  a review-only IDA applier.
* `tools/generate_ida_residual_profile.py` derives the exact 421-entry latest
  residual report from the base 459-entry report, the intermediate CyaSSL
  role audit, and the static-library role audit.
* `tools/generate_cyassl_static_role_audit.py` rebuilds the offline CyaSSL role
  map, while `tools/ida_apply_cyassl_static_aliases.py` and
  `tools/ida_verify_cyassl_static_aliases.py` apply and verify the separate
  disposable-copy pass.
* `tools/generate_static_library_role_audit.py` rebuilds the next offline
  static-library role map, while
  `tools/ida_apply_static_library_aliases.py` and
  `tools/ida_verify_static_library_aliases.py` apply and verify its disposable
  IDA pass.
* `tools/validate_research_archive.py` checks the published count partitions,
  input hashes, candidate coverage, and offline-only markers without needing
  IDA or a network connection.
* `artifacts/inbound_handler_table.json` records the native handler-index table,
  its current function targets, and the observed packet-to-index pairs.
* `artifacts/premium_option.json` records the complete marker bytes and the
  native decoded value.
* `artifacts/loading_state_ownership.json` records the ARM64 flag readers,
  writers, render branch, and packet-190 call-site audit.
* `artifacts/graalweb_trust_bundle.json` records the recovered certificate
  bundle hashes, dates, and native decoder details. The PEM material itself is
  not committed.
* `artifacts/elf_symbol_table_audit_20260826.json` records the distinction
  between the surviving dynamic rows and the larger applied alias inventory.
* `artifacts/connector_tls_parser_analysis_20260826.json` records the native
  CyaSSL date-check call chain and error mapping recovered from IDA.
* `artifacts/spectron_connector_endpoint_audit_20260827.json` records the
  decoded 1.8 and Spectron connector host fragments, paths, transport modes,
  build literals, and raw input hashes. The offline generator is
  `tools/audit_spectron_connector_endpoints.py`.
* `artifacts/spectron_loopback_patch_audit_20260828.json` records the
  target-specific resolver, HTTPS-port, trust-bundle, outgoing-key, and safe
  WebTop byte guards. `tools/generate_spectron_loopback_patch_audit.py`
  regenerates it from the supplied APK.
* `docs/CONNECTOR_TLS.md` explains the native connector path, date logic, and
  local validity control in one place.
* `artifacts/diagnostic_patch_matrix.json` records exact patch sites, private
  replay hashes, and the result of each compatibility experiment.
* `tools/export_inbound_handler_table.py` reproduces the handler-table export
  from the active IDA database.
* `tools/ida_apply_native_callback_candidates.py` reviews and optionally applies
  the prepared callback, static-state, and sound-wrapper names from the IDA
  bridge or IDALIB.
* `tools/ida_apply_all_translations.py` runs the native, exact script-table,
  FDE-boundary, and unresolved-role passes in one IDA session. It is
  review-only by default; enable both switches only after checking the
  individual plans.
* `tools/ida_apply_all_translations_persist.py` runs that same pass under
  IDALIB and returns control to the database closer so a disposable copy can
  be saved. `tools/ida_verify_all_translations.py` reopens the copy and checks
  every prepared name and boundary without changing it.
* `tools/ida_apply_all_translations_save.py` applies the complete pass and
  explicitly writes a new packed `.i64` output. It refuses to overwrite an
  existing output and is useful when the IDA installation has a plugin that
  interferes with normal IDALIB save and close handling.
* `tools/ida_dump_function_evidence.py` emits read-only disassembly, incoming
  references, pseudocode, string references, and raw instruction windows for
  selected role-review functions. Compact mode is useful for large functions.
* `tools/` contains IDAPython, parsing, replay, and diagnostic patch helpers.
  `tools/encode_connector_query.py` reproduces the captured connector query
  without opening a socket. `tools/conpack_legacy_zip_compat.patch` records
  the small source change needed for the old client's ZIP reader, and
  `tools/repair_hexaparser_source.py` repairs the one known malformed block in
  pinned HexaParser output, while `tools/reverse_hexaparser_literals.py`
  records the narrow compiler adapter. `tools/patch_connector_bytecode_loading_clear.py`
  preserves the original
  VM stream while adding the tested login-time loading clear.
  `tools/patch_restore_premium_loading_test.py` restores the stock ARM64
  branch for a matched loading-state control.
  `tools/build_arm64_loopback_apk.py` applies the complete private diagnostic
  chain, packages only ARM64, signs it locally, and writes build hashes.
  `tools/build_arm64_trust_control.py` builds the narrower native-verification
  control with a caller-supplied trust bundle and an optional loading branch.
  `tools/patch_gs2_success_loading_clear.py` records the equivalent source
  edit for readable GS2 experiments; its compiled output remains unverified.
  `tools/decode_graalweb_cert_bundle.py` recovers certificate metadata from
  the original ARM64 library without contacting a service. The offline
  connector parser mirrors the native raw-digest RSA check, and
  `tools/patch_connector_test_public_key.py` supports a private controlled-key
  diagnostic without including a private key.
  `tools/patch_graalweb_trust_bundle.py` replaces the historical trust text
  with a user-supplied certificate-only PEM bundle while leaving CyaSSL
  verification enabled. `tools/make_tls_validity_fixture.py` creates a
  disposable SAN-matching certificate with explicit validity dates for a
  loopback control.
  `tools/patch_connector_tls_port_test.py` moves only the diagnostic HTTPS
  port for a loopback ADB reverse mapping for either the original or Spectron
  target, and
  `tools/build_spectron_loopback_apk.py` builds the private target-specific
  ARM64 loopback package with native verification preserved.
  `tools/patch_spectron_nonpremium_loading_test.py` selects the existing
  target loading-flag clear at `0x15fad8` for a separate private control, and
  `--force-nonpremium-loading` enables it in the combined builder.
  `tools/tls_capture_server.py` serves an archived response over a
  127.0.0.1-only TLS listener and records handshake failures without exposing
  a response body.
  `tools/compare_spectron_native.py` compares the supplied Spectron native
  library with the original ARM64 build without loading either one.
  `tools/audit_spectron_connector_endpoints.py` decodes the native connector
  URL fragments and compares the 1.8 and Spectron host pairs without opening
  a socket.
  `tools/match_spectron_function_signatures.py` checks whether the supplied
  Spectron ARM64 build offers any exact, unambiguous source-name matches for
  the original IDA default functions.
  `tools/ida_export_function_features.py` exports address-independent IDA
  function features for cross-build comparison.
  `tools/match_spectron_semantic_functions.py` builds the reviewed 1.8 to
  Spectron semantic map.
  `tools/generate_spectron_exact_name_anchors.py` records preserved exact
  function names, `tools/generate_spectron_network_anchors.py` records
  reviewed connector and socket correspondences, and
  `tools/generate_spectron_core_anchors.py` records reviewed resource, GUI,
  rendering, scripting, and client correspondences. The
  `tools/generate_spectron_runtime_path_anchors.py` generator records reviewed
  map, file-delivery, encrypted-script, text-control, and server-list roles.
  The `tools/generate_spectron_update_protocol_anchors.py` generator records
  reviewed download, update, server-modify, CRC, and modification-time roles.
  The `tools/generate_spectron_client_action_anchors.py` generator records
  reviewed action-packet serializers and their preserved format strings.
  The `tools/generate_spectron_client_outbound_anchors.py` generator records
  the remaining reviewed outbound client serializers and their target
  signatures.
  The `tools/generate_spectron_resource_anchors.py` generator records reviewed
  resource matching, stream, game-file, and encoded-key roles.
  The `tools/generate_spectron_script_bridge_anchors.py` generator records
  reviewed client script bridge roles and target shape checks.
  The `tools/generate_spectron_client_request_anchors.py` generator records
  reviewed client request and window-state serializer roles and target shape
  checks.
  The `tools/generate_spectron_client_inbound_anchors.py` generator records
  reviewed client inbound and state-transition roles and target shape checks.
  The `tools/generate_spectron_login_helper_anchors.py` generator records
  reviewed login, event, and small client-state roles and target shape checks.
  The `tools/generate_spectron_parse_wrapper_anchor.py` generator records the
  reviewed client encryption-in tail-thunk and its raw byte check.
  The `tools/generate_spectron_lookup_helper_anchors.py` generator records
  reviewed player and download lookup roles and target shape checks.
  The `tools/generate_spectron_connection_helper_anchors.py` generator records
  reviewed connection, SSL, and low-level field roles and exact shape checks.
  The `tools/generate_spectron_client_state_helper_anchors.py` generator
  records reviewed compact client-state and forwarding roles and exact shape
  checks.
  The `tools/generate_spectron_connection_state_anchors.py` generator records
  reviewed client connection-state and encrypted-file roles with exact hash
  checks.
  The `tools/generate_spectron_http_request_anchors.py` generator records
  reviewed HTTP request field, lifecycle, and outbound-buffer roles with exact
  hash checks.
  The `tools/generate_spectron_socket_state_anchors.py` generator records
  reviewed socket status, nonblocking, and address roles with exact hash
  checks.
  The `tools/generate_spectron_http_request_state_anchors.py` generator records
  reviewed request counter, timestamp, and download-state roles with exact
  hash checks.
  The `tools/generate_spectron_http_request_receive_anchors.py` generator
  records reviewed HTTP response read and data-parser roles with target class,
  field, call, string, and implementation-change evidence.
  The `tools/generate_spectron_server_list_connection_anchors.py` generator
  records the reviewed server-list getter and connection-handoff roles with
  exact normalized metrics, target setter/global relationships, and the
  handoff layout-change evidence.
  The `tools/generate_spectron_server_list_state_anchors.py` generator records
  the exact-shape server-list boolean and start-state methods with target
  global relationships and neighboring translated context.
  The `tools/generate_spectron_http_request_cleanup_anchors.py` generator
  records the request reset and request-properties destructor ABI roles with
  normalized metrics, lifecycle classifications, and target class evidence.
  The `tools/generate_spectron_tsocket_residual_anchors.py` generator records
  the residual socket client-list, destructor, error, and IP adapter roles with
  normalized metrics, target class context, and the clients-string evidence.
  The `tools/generate_spectron_game_environment_anchors.py` generator records
  the four TGameEnvironment startup and property callback roles with target
  registration-table evidence, normalized metrics, and the adventure-quit
  layout change.
  The `tools/generate_spectron_client_environment_graphics_anchors.py`
  generator records the exact-shape client-environment graphics initializer
  with target class and neighbor evidence.
  The `tools/generate_spectron_client_environment_static_clear_anchors.py`
  generator records the two exact-shape profiler cleanup callbacks with
  caller-local `atexit` registration and target-object evidence.
  The `tools/generate_spectron_client_environment_restart_state_anchors.py`
  generator records the saved-restart cleanup callback with target class,
  initializer, field, and layout-change evidence.
  The `tools/generate_spectron_particle_emitter_script_vars_anchors.py`
  generator records the exact-shape particle-emitter script-property
  initializer with target constructor, static-table, and neighbor evidence.
  The `tools/generate_spectron_resource_link_lists_anchors.py` generator
  records the exact-shape resource link-list initializer with target
  class, static-field, startup-table, and collision-resolution evidence.
  The `tools/generate_spectron_clear_cur_anis_anchors.py` generator records
  the current-animation-state cleanup correspondence with state extent,
  initializer, cleanup-table, and target consumer evidence.
  The `tools/generate_spectron_options_window_position_anchors.py` generator
  records the reviewed `TOptions` window-position initializer with its
  coordinate fields, target-only string field, and static-table evidence.
  The `tools/generate_spectron_displayed_gif_anchors.py` generator records the
  reviewed displayed-GIF state initializer with its pointer indirection,
  cleanup callback, and translated draw-consumer family.
  The `tools/generate_spectron_gui_button_types_anchors.py` generator records
  the reviewed GUI button-type table initializer with its property-table,
  string-table, and target cleanup evidence.
  The `tools/generate_spectron_gui_alignment_tables_anchors.py` generator
  records the reviewed `GuiGraalCtrl` alignment tables with their property
  metadata, static-table slots, and target-only string cleanup evidence.
  The `tools/generate_spectron_gui_stretch_modes_anchors.py` generator records
  the reviewed `GuiStretchCtrl` mode table with its property metadata,
  static-table slots, and target-only string cleanup evidence.
  The `tools/generate_spectron_tgui_render_colors_anchors.py` generator records
  the reviewed `TGUIRender` border colors with their render consumer,
  static-table slot, and target-only string cleanup evidence.
  The `tools/generate_spectron_thtml_definitions_defaults_anchors.py` generator
  records the reviewed HTML default initializer with its field stores,
  translated consumers, static-table slots, and explicit fingerprint delta.
  The `tools/generate_spectron_tclient_static_strings_anchors.py` generator
  records the reviewed TClient string-field order, cleanup pair, target-only
  field, and layout-change metrics.
  The `tools/generate_spectron_file_cache_property_anchors.py` generator
  records the six residual password, cache, and file-download properties,
  their source and target table records, feature comparisons, and target-only
  rows.
  The `tools/generate_spectron_tsocket_static_state_anchors.py` generator
  records the reviewed TSocket string-field order, cleanup pair, target-only
  field, and layout-change metrics.
  The `tools/generate_spectron_android_tapjoy_video_state_anchors.py` generator
  records the corrected Android, TapJoy, and video reset or cleanup pair,
  its shared state-field map, and target-only string lifetime.
  The `tools/generate_spectron_sounds_music_state_anchors.py` generator records
  the three `TSounds` music-state wrappers and the evidence that separates
  them from other shape-compatible target callbacks.
  The `tools/generate_spectron_sounds_effect_anchors.py` generator records the
  sound-effect constructor and cache lookup, including the target-only helper
  construction and direct-call evidence.
  The `tools/generate_spectron_sounds_control_anchors.py` generator records the
  two remaining `TSounds` control wrappers and their callback-table and
  virtual-slot evidence.
  The `tools/generate_spectron_tsound_effect_methods_anchors.py` generator
  records the seven-method `TSoundEffect` interface and complete feature
  checks.
  The `tools/generate_spectron_sound_java_small_methods_anchors.py` generator
  records the two `TSoundPlayerJava` and five `TSoundEffectJava` bridge
  methods with method-table, class, receiver, and complete feature checks.
  The `tools/generate_spectron_sound_java_destructor_anchors.py` generator
  records the Java sound D0 destructor pair with lifecycle, method-table, and
  complete-shape checks.
  The `tools/generate_spectron_sound_base_interface_anchors.py` generator
  records the 14 TSoundPlayer base methods and four Java capability methods
  with class-local table and complete feature checks.
  The `tools/generate_spectron_sounds_tail_anchors.py` generator records the
  remaining TSounds stop-SFX, script-pitch, and static-initializer methods
  with callback, registration, class-order, and layout-change checks.
  The `tools/generate_spectron_sound_java_d1_anchor.py` generator records the
  complete TSoundPlayerJava D1 destructor with adjacent D0 and method-table
  checks.
  The `tools/generate_spectron_html_page_anchors.py` generator records the
  eight small THTMLPage methods with exact feature and receiver-field checks.
  The `tools/generate_spectron_gui_text_list_anchors.py` generator records the
  eight small GuiTextListCtrl methods with exact feature, class, and table
  context checks.
  The `tools/generate_spectron_gui_text_list_entry_anchors.py` generator
  records the three exact GuiTextListEntry property helpers with pseudocode,
  receiver-field, and property-table checks.
  The `tools/generate_spectron_encryption_graalvar_anchors.py` generator
  records the compact TEncryption and TGraalVar helpers with exact feature,
  property-registration, class, and receiver-field checks.
  The `tools/generate_spectron_compact_residual_anchors.py` generator records
  13 compact property, wrapper, handler, cache, and script correspondences
  with table context, normalized-shape checks, and the folded-body note.
  The `tools/generate_spectron_t2d_matrix_manager_anchors.py` generator records
  the four-method AUzMgaePtJ matrix-manager block and its deferred initializer.
  The `tools/generate_spectron_mrandom_anchors.py` generator records the
  three-class random-generator block, lifecycle order, static global, and
  normalized feature checks.
  The `tools/generate_spectron_tstringlist_residual_anchors.py` generator
  records the residual list methods, wrapper conversions, class-local order,
  and the one layout-change check.
  The `tools/generate_spectron_server_object_lifecycle_anchors.py` generator
  records the seven server-object class blocks, destructor ABI roles, class
  order, and normalized feature checks.
  The `tools/generate_spectron_gui_ml_text_residual_anchors.py` generator
  records the residual GuiMLTextCtrl field, script, input, reflow, and
  destructor rows, including explicit layout-change checks.
  The `tools/generate_spectron_gui_residual_property_anchors.py` generator
  records the reviewed drawing-panel and show-image GUI property rows, along
  with the two nearby target-only cleanup helpers that were intentionally not
  assigned 1.8 names.
  The `tools/generate_spectron_gui_browser_property_anchors.py` generator
  records the remaining `GuiBrowserCtrl` allow-zoom, URL, and text getter
  correspondences with property-table and complete-feature checks.
  The `tools/generate_spectron_gui_context_menu_property_anchors.py` generator
  records the residual `GuiContextMenuCtrl` popup-height, close, open-state,
  and width callbacks with property-table and complete-feature checks.
  The `tools/generate_spectron_gui_array_popup_residual_anchors.py` generator
  records the residual array, context-menu rows, and popup callback block,
  including its explicit rebuilt-wrapper difference.
  The `tools/generate_spectron_hash_lifecycle_anchors.py` generator records
  six hash-container lifecycle helpers with constructor and destructor ABI,
  class context, direct field, and normalized-shape checks.
  The `tools/generate_spectron_npc_helper_anchors.py` generator records
  reviewed `TServerNPC` helper roles with exact hash checks and IDA-context
  evidence.
  The `tools/generate_spectron_html_atom_anchors.py` generator records
  reviewed `THTMLAtom` construction and buffer roles with exact hash checks.
  The `tools/generate_spectron_player_helper_anchors.py` generator records
  reviewed `TPlayer` attachment, update, freeze, and sprite roles with exact
  hash checks.
  The `tools/generate_spectron_input_window_anchors.py` generator records
  reviewed input and window bridge roles with exact hash checks.
  The `tools/generate_spectron_visual_helper_anchors.py` generator records
  reviewed animation, particle, and show-image roles with exact hash checks.
  The `tools/generate_spectron_script_runtime_anchors.py` generator records
  reviewed GS2-facing script-runtime roles with exact hash checks and IDA
  pseudocode context.
  The `tools/generate_spectron_core_helper_anchors.py` generator records
  reviewed level, script, network-policy, tile, particle, and native callback
  roles with exact hash checks and IDA pseudocode context.
  The `tools/generate_spectron_render_gui_anchors.py` generator records
  reviewed texture, OpenGL, drawing-panel, GUI-control, markup, and scrolling
  roles with exact hash checks and IDA pseudocode context.
  The `tools/generate_spectron_json_folder_anchors.py` generator records
  reviewed image callbacks, recursive folder loading, and YAJL JSON callback
  roles with exact hash checks or caller and callback-table context.
  The `tools/generate_spectron_gani_lifecycle_anchors.py` generator records
  the reviewed Gani object and TGraalAni teardown, virtual, state, ownership,
  script-cache, loading, and property roles.
  The `tools/generate_spectron_showimg_property_anchors.py` generator reads
  both TShowImg property tables, decodes their names, compares the direct
  getter and setter pointers, and records exact-shape or layout-aware
  correspondences. `tools/ida_dump_property_table.py` is the read-only IDA
  helper used to inspect the same `0x30`-byte records.
  The `tools/generate_spectron_showimg_residual_anchors.py` generator records
  the remaining TShowImg class-local methods and properties-class destructor
  rows with exact normalized metrics or common lifecycle metrics where
  vtable layout changed.
  The `tools/generate_spectron_server_object_scalar_anchors.py` generator
  records the exact-shape server-bomb, server-chest, server-flying, and
  explosion rows whose repeated accessor shapes require class-local context.
  The `tools/generate_spectron_static_clear_anchors.py` generator records the
  reviewed TClient and TSocket static cleanup callbacks, including their
  target-only fields and layout changes.
  The `tools/generate_spectron_static_callback_role_correction.py` generator
  records the data-reference correction for the old third static callback and
  keeps its unresolved target status explicit.
  The `tools/ida_dump_function_data_refs.py` helper prints read-only data
  references for selected IDA functions or an address range. It is useful for
  separating similar static cleanup groups in stripped builds.
  The `tools/generate_spectron_tplayer_core_anchors.py` generator records the
  reviewed TPlayer network-property serializer and constructor roles with
  exact metric and literal checks.
  The `tools/generate_spectron_resource_parser_anchors.py` generator records
  the reviewed Gani lexer, cached-resource path, and update-package parser
  roles with exact metric and literal checks.
  The `tools/generate_spectron_static_utility_anchors.py` generator records
  the reviewed statistics, profiler, GUI-style, ZIP-resource, and translation
  roles with exact metric and literal checks.
  The `tools/generate_spectron_font_bitmap_anchors.py` generator records the
  reviewed glyph, font-atlas, font-resource, and bitmap-loader roles with exact
  metric and literal checks.
  The `tools/generate_spectron_mng_animation_anchor.py` generator records the
  reviewed MNG animation-step decoder with exact metric, call-count, and
  adjacent-cluster checks.
  The `tools/generate_spectron_script_machine_tail_anchors.py` generator records
  the reviewed script-machine parameter and native callback roles with exact
  metric, call-count, and adjacency checks.
  The `tools/generate_spectron_gsfunctions_client_exact_residual_anchors.py`
  generator records the reviewed GSFunctionsClient table relocation and exact
  normalized-shape checks.
  The `tools/generate_spectron_gsfunctions_client_exact_residual_v2_anchors.py`
  generator records the second reviewed GSFunctionsClient table batch with
  the same relocation and shape checks.
  The `tools/generate_spectron_gsfunctions_client_exact_residual_v3_anchors.py`
  generator records the final already-bounded GSFunctionsClient batch with
  the same relocation and shape checks.
  The `tools/generate_spectron_gsfunctions_client_boundary_residual_anchors.py`
  generator records raw ARM64 boundaries, return paths, and table checks for
  the callbacks that IDA initially left unbounded.
  The `tools/generate_spectron_gsfunctions_client_exact_residual_v4_anchors.py`
  generator records the final Adventure, fullscreen, application-state, and
  URL callback batch.
  The `tools/generate_spectron_socket_behavior_comparison.py` generator
  records changed-size socket behavior without forcing an exact-match label.
  `tools/generate_spectron_symbol_table_audit.py` preserves the complete
  `.dynsym` inventory from the stripped Spectron library and records which
  static and debug sections survived.
  `tools/ida_apply_spectron_translation.py` and
  `tools/ida_apply_spectron_manual_anchors.py` write separate disposable IDA
  copies, while the matching verification scripts reopen and check them. The
  manual-anchor script accepts a different artifact type through
  `SPECTRON_MANUAL_EXPECTED_ARTIFACT`.
  `tools/patch_spectron_webtop_safe_commands.py` and
  `tools/build_spectron_webtop_safe_apk.py` build the private WebTop-safe
  runtime control without changing the supplied APK.
  `tools/decode_game_server_tls_certificate.py` decodes the separate
  game-server certificate from the recovered connector script without opening
  a socket. `tools/encode_game_server_tls_certificate.py` prepares a
  certificate-only replacement for the same script argument and verifies the
  native DES round trip. `tools/replace_game_server_tls_source.py` applies the
  same transform directly to recovered GS2 source for HexaParser. The
  resulting script still needs compilation, packaging, and an authorized
  signature.
  `tools/audit_classic_ssl_mode.py` checks whether the recovered Classic
  source actually enables the separate game-server TLS branch.
* `artifacts/` contains small metadata exports. APKs, certificates, private
  keys, captured credentials, and game assets are intentionally not included.

## Inputs used for the analysis

The primary input was the ARM64 library from the original Graal Online
Classic 1.8 APK. The x86_64 library from the same package was used only for
repeatable emulator experiments because the available Android emulator is
x86_64. A separate `spectron_client_1.0.2.apk` was compared as a reference,
not treated as proof that its routing or signing behavior belongs to the
original client.

Two helper repositories were also checked out locally during the work:

* `MorenoLand/GScript.Go-HexaParser`, used as a reference for GS2 bytecode
  tooling.
* `MorenoLand/Moreno.kahn`, used to validate the archived connector package
  and its `con.png` container.

Their source is not vendored here. The exact commits and the comparison
results are recorded in the research notes.

## Safety and scope

The tools are intended for an owned or otherwise authorized copy of the
client, and the runtime tests are designed to stay on loopback. The patch
helpers are diagnostic artifacts. They bypass stale package verification or
redirect a test endpoint, so they should not be installed as a general client
repair without first replacing the endpoint and trust material with values
that are independently verified.

Do not put account passwords, private keys, live server responses, or copied
game assets into commits. Hashes and structural metadata are enough to make
the analysis auditable without publishing secrets or a full game data set.

## Next investigation step

The highest-value remaining work is live-service and ARM64 validation. The
next checks are to verify the current connector trust and package-signing
chain, repeat the same packet sequence on a real ARM64 device, and compare a
live server's resource and login responses with the captured local trace.
Those tests should only use an endpoint and account that the operator is
authorized to test.
