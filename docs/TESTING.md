# Reproduction and testing notes

These steps describe the local protocol test used during the investigation.
They do not contact a live connector or game server. Run them only with an
authorized APK and keep the emulator disconnected from external services
unless a separate test has been explicitly approved.

## Inputs and environment

The working copy used an Android 36 x86_64 emulator with an ADB endpoint at
`127.0.0.1:5555`. The original ARM64 library was analyzed in IDA. The
x86_64 library was used for runtime tests because the emulator selects it.

The diagnostics use two ADB reverse mappings:

```text
tcp:18080 -> host connector replay
tcp:14900 -> host game responder
```

The production endpoint is not changed by these commands. The test APK is a
debug-signed copy with explicit loopback and stale-package diagnostic patches.
It is not a release artifact.

## Prepare local test files

Keep the original `.apk`, `.so`, and IDA database outside the public research
repository. Generate the small level fixtures from a known-good local coded
level:

```bash
python3 tools/make_level_code.py \
  /path/to/black.nw-14896.code \
  /tmp/graal-assets/coded/overworld_west_ocean_09.nw-14900.code \
  --source-level-name black.nw \
  --level-name overworld_west_ocean_09.nw \
  --server-ipstr 5034ec765552177b890e732a02e3b699 \
  --server-signature 73
```

Repeat for the other requested levels. The helper validates the container
length and checksum through its reimplementation of the native algorithm.

## ARM64 diagnostic native build

The following order applies the ARM64-only diagnostic edits to a private copy
of the original library. Each helper checks the expected original bytes before
writing, so a different library revision stops instead of being patched
silently:

```bash
python3 tools/patch_compatibility_repairs.py \
  --arch arm64-v8a \
  /path/to/original/arm64-v8a/libqplay.so \
  /tmp/libqplay.compat.so

python3 tools/patch_force_http_parser_test.py \
  --arch arm64-v8a --port 18080 \
  /tmp/libqplay.compat.so \
  /tmp/libqplay.http.so

python3 tools/patch_localhost_resolver_test.py \
  --arch arm64-v8a \
  /tmp/libqplay.http.so \
  /tmp/libqplay.loopback.so

python3 tools/patch_fixed_output_rc4_key_test.py \
  --arch arm64-v8a \
  /tmp/libqplay.loopback.so \
  /tmp/libqplay.diagnostic.so

python3 tools/patch_force_no_premium_loading_test.py \
  /tmp/libqplay.diagnostic.so \
  /tmp/libqplay.nonpremium.so

python3 tools/patch_render_loop_clear_loading_flag_test.py \
  /tmp/libqplay.diagnostic.so \
  /tmp/libqplay.render-boundary.so
```

Place the final file in a private ARM64 APK, keep the other ABI libraries out
of that diagnostic package when testing ARM64 selection, sign it for the local
emulator or device, and configure ADB reverse mappings for ports 18080 and
14900. The ARM64 fixed-key patch uses a trampoline at `0x1f2dcc` and resumes
the original function at `0x1fd6b8`; it is only for the offline responder.

The exact working ARM64 chain used on 2026-08-24 was compatibility repair,
HTTP parser redirect to port 18080, localhost resolver, fixed output RC4 test
key, and the non-premium loading-state candidate. The final native file has
SHA-256
`89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858`.

For the bounded package run, the original APK was staged privately with its
`META-INF` directory and non-ARM64 library directories removed. The final
ARM64 library was copied to `lib/arm64-v8a/libqplay.so`, the APK was zipaligned
and signed with a local debug key, and the resulting APK had SHA-256
`b1c52234b10fb5a4a2c6c58e85370ccab710b1c355574d295df30b5ed6edddcc`.
This package is an offline diagnostic artifact. Do not publish it as a
production client.

## Spectron 2.2 local loopback package

The supplied Spectron package uses `cong.quattroplay.com` rather than the
original `con.quattroplay.com`, and its native offsets are different. Build a
certificate for the target hostname, keeping the private key outside the
repository:

```bash
python3 tools/make_tls_validity_fixture.py \
  --output-prefix /tmp/graal-valid-cong \
  --hostname cong.quattroplay.com \
  --not-before 2025-01-01T00:00:00Z \
  --not-after 2035-01-01T00:00:00Z
```

Then build the target-specific package:

```bash
python3 tools/build_spectron_loopback_apk.py \
  /path/to/spectron_client_1.0.2.apk \
  /tmp/spectron_loopback_diagnostic.apk \
  --bundle /tmp/graal-valid-cong.crt \
  --port 18443 \
  --zipalign /path/to/android-sdk/build-tools/35.0.1/zipalign \
  --apksigner /path/to/android-sdk/build-tools/35.0.1/apksigner \
  --keystore /path/to/debug.keystore \
  --report /tmp/spectron_loopback_diagnostic.json
```

The builder checks the exact supplied APK, qplay, and libxposed hashes before
writing. It keeps only `arm64-v8a`, removes the original signing metadata,
stores `resources.arsc` uncompressed, normalizes ZIP timestamps, aligns the
package, and verifies the resulting signature. It preserves the connector
script and native certificate and hostname verification. The fixed RC4 key is
only for the private responder, and the default WebTop edit skips the
destructive `crash`, `freeze`, and `abort` commands found in the supplied
package. Use `--keep-webtop-commands` for an unmodified WebTop control.

The exact target byte guards are in
`artifacts/spectron_loopback_patch_audit_20260828.json`. The target resolver
is patched at `0x20c20c`, the HTTPS defaults at `0x2065e0` and `0x206764`, the
trust text at `0x2ea9e0`, and the outgoing-key trampoline uses `0x1c4000` for
the code cave and resumes the target function at `0x202fec`. The build check
is offline and does not resolve or contact `cong.quattroplay.com`.

To include the separate loading-state control, add
`--force-nonpremium-loading` to the same command. The builder then checks the
target branch at `0x15fad8`, replacing `B.LE 0x15fb1c` with an unconditional
branch to the existing loading-flag clear block. This is the target 2.2
equivalent of the older 1.8 diagnostic at `0x15ca7c`. An earlier scratch
attempt used `0x15faac`, but that address handles executable-path selection and
is not the premium-condition branch.

The corrected target control was run on the available Android 36 x86_64
emulator through its ARM64 translation layer. The local TLS responder received
`GET /con.png` with `Host: cong.quattroplay.com:18443`; the native certificate
and hostname checks remained enabled. The game responder completed two
encrypted connections, served `basepackage.gupd`, `classiciphone.gmap`, the
level containers, and image resources, and observed continuing heartbeat
frames. The stock target build stayed on the title/loading artwork. With the
corrected branch control, the screen showed the green tiled world with the
HUD and status indicators. The APK SHA-256 is
`6988410c57bcc4874b9e6932e82d1eeba3e9a39e684a26112b54586a76022b02`, and the
screen capture SHA-256 is
`08dc6793c3087caec00f1194e4966b1ab4753b53eacc0a1b2a86b92ad16c596e`.
The complete replay metadata is in
`artifacts/spectron_arm64_loopback_loading_replay_20260828.json`.

The test used only ADB reverse mappings for ports `18443` and `14900`, bound
both responders to loopback, and removed the mappings when it finished. The
private certificate key, signed APK, captures, and fixture assets are not part
of the repository.

### Clean external-cache replay

For a stronger resource-path check, the nine exact files created by the first
private run were copied out and then removed from the emulator's external game
cache. The directory was verified empty before launching the same rebuilt APK.
The client downloaded the map, the five level resources, the gray message
image, and the base package again, then continued sending heartbeat frames.
The APK's own `assets/offline/levels/tiles/pics1.png` meant that no separate
tile-sheet request was expected in this pass. The screen hash remained
`08dc6793c3087caec00f1194e4966b1ab4753b53eacc0a1b2a86b92ad16c596e`.

The clean replay used the same APK hash as the preceding run and is recorded
in `artifacts/spectron_arm64_clean_cache_replay_20260828.json`. This remains
a private translated-ARM64 loopback test. It does not validate a live service
or a physical ARM64 device.

## Reproduce the IDA name-coverage audit

The public archive keeps two complete name inventories for the translated
Spectron database. The v318 inventory records the nine final `nullsub_*`
defaults before the last naming pass. The v319 inventory records the same
11,695 functions after those rows were renamed to target-only
`spectron_nullsub_stub_0x...` labels.

The audit helper runs inside IDA or IDALIB and writes one JSON row per
function. It reports the function name, name origin, size, first instruction,
leading bytes, and xref count:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_NAME_COVERAGE_OUTPUT=/tmp/spectron-name-audit.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v318_residual_labels.i64 \
  -s tools/ida_audit_spectron_name_coverage.py
```

The null-stub label artifact is generated from the v318 audit and can be
applied to a fresh disposable IDA copy with
`tools/ida_apply_spectron_target_only_labels.py`. Set
`SPECTRON_TARGET_LABEL_APPLY=1` and provide a new
`SPECTRON_TARGET_LABEL_SAVE_PATH`; the script refuses to overwrite an
existing database. Reopen the saved copy with
`tools/ida_verify_spectron_target_only_labels.py` and then rerun the audit.
The expected result is nine verified labels, 11,695 functions, and zero
default names in the checked `sub_`, `nullsub_`, `j_`, `loc_`, and `unk_`
families.

The checked-in inputs and results are
`artifacts/spectron_name_coverage_audit_v318_20260828.json`,
`artifacts/spectron_nullsub_target_only_labels_20260828.json`, and
`artifacts/spectron_name_coverage_audit_20260828.json`. The result is naming
coverage, not evidence that the stripped target retained every original C++
source name.

## Reproduce the Spectron dynamic-boundary pass

The v320 pass uses the target's retained dynamic table as a boundary source.
It only considers section-defined `FUNC` rows with a positive ELF size. The
read-only helper compares those values with IDA's exact function starts:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_BOUNDARY_AUDIT_OUTPUT=/tmp/spectron-dynamic-boundaries.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v319_nullsub_labels.i64 \
  -s tools/ida_audit_dynamic_symbol_boundaries.py
```

The v319 result has 5,782 defined dynamic function rows, 5,770 exact IDA
starts, and 12 missing starts. Review the twelve rows before applying them.
The materializer validates the target library hash, every address, every ELF
size, and the expected retained name. It is review-only unless the apply flag
and a new output path are supplied:

```bash
cp /path/to/spectron_libqplay_translated_v319_nullsub_labels.i64 \
  /tmp/spectron_dynamic_materialize_v319.i64
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_DYNAMIC_FUNCTION_APPLY=1 \
  SPECTRON_DYNAMIC_FUNCTION_SAVE_PATH=/path/to/spectron_libqplay_translated_v320_dynamic_functions.i64 \
  SPECTRON_DYNAMIC_FUNCTION_REPORT=/tmp/spectron_dynamic_function_application.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_dynamic_materialize_v319.i64 \
  -s tools/ida_materialize_spectron_dynamic_functions.py
```

Open the new database again and rerun both audits. The expected v320 result is
11,707 functions, 5,782 exact dynamic `FUNC` starts, zero missing starts, and
zero audited default names. The joined inventory is rebuilt with:

```bash
python3 tools/generate_spectron_symbol_translation_inventory.py \
  --symbols artifacts/spectron_symbol_table_audit_20260827.json \
  --name-audit artifacts/spectron_name_coverage_audit_v320_20260828.json \
  --output /tmp/spectron_symbol_translation_inventory.json
```

To account for every named dynamic row, including data and imports, reopen a
v320 copy and run:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_DYNAMIC_SYMBOL_COVERAGE_OUTPUT=/tmp/spectron-dynamic-symbol-coverage.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v320_dynamic_functions.i64 \
  -s tools/ida_audit_spectron_dynamic_symbol_coverage.py
```

The expected complete result has 6,770 named rows and 6,600 defined rows.
Those defined rows resolve to 5,782 functions, 482 data items, and 336 other
non-code items. The 170 undefined imports have no target address and are
reported separately; 169 have exact IDA PLT veneer names and the `__sF` object
has no in-library veneer. The saved record is
`artifacts/spectron_dynamic_symbol_coverage_audit_20260828.json`.

The dynamic table has 6,770 named rows, but only 5,782 section-defined
function rows. The other named rows must remain classified as data, undefined
imports, or other non-function entries. The final checkpoint generator and
archive validator record this distinction:

```bash
python3 tools/generate_spectron_translation_checkpoint_v320.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260828_v319.json \
  --database /path/to/spectron_libqplay_translated_v320_dynamic_functions.i64 \
  --application-report artifacts/spectron_dynamic_function_application_20260828.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_20260828.json \
  --name-audit artifacts/spectron_name_coverage_audit_v320_20260828.json \
  --symbol-inventory artifacts/spectron_symbol_translation_inventory_20260828.json \
  --output artifacts/spectron_translation_checkpoint_20260828_v320.json

python3 tools/validate_research_archive.py
```

### v321 source-side GUI boundary translation

The v321 pass first restores the eleven original 1.8 GUI `FUNC` boundaries
that IDA had classified as data. Use a fresh copy of the translated source
database and keep the output separate from the source checkpoint:

```bash
cp /path/to/libqplay_translated_all_v4.i64 \
  /tmp/original_dynamic_materialize.i64
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  ORIGINAL_DYNAMIC_FUNCTION_APPLY=1 \
  ORIGINAL_DYNAMIC_FUNCTION_SAVE_PATH=/tmp/original_dynamic_materialized.i64 \
  ORIGINAL_DYNAMIC_FUNCTION_REPORT=/tmp/original_dynamic_function_application.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/original_dynamic_materialize.i64 \
  -s tools/ida_materialize_original_dynamic_functions.py
```

The source-side report must contain eleven rows, eleven materialized
boundaries, eleven readable source aliases, and zero failures. The feature
exports used for the review are disposable files, so their paths can be
changed to match the local IDALIB export run:

```bash
python3 tools/generate_spectron_gui_missing_function_anchors.py \
  --matcher artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v320_current.json \
  --source-boundary-report artifacts/original_dynamic_function_application_20260828.json \
  --target-boundary-report artifacts/spectron_dynamic_symbol_boundaries_20260828.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_gui_missing_function_manual_translation_anchors_20260828.json
```

The generator records ten high-confidence normalized-shape matches and one
medium-confidence class-slot match. Apply those reviewed aliases to a fresh
v320 copy with `tools/ida_apply_spectron_manual_anchors.py`, setting
`SPECTRON_MANUAL_EXPECTED_ARTIFACT` to
`spectron_gui_missing_function_manual_translation_anchors_20260828`, and then
reopen the result with `tools/ida_verify_spectron_manual_anchors.py`. The
expected verification is eleven names, 11,707 functions, and zero failures.
The final audit should report these v321 name origins:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export      1002
target_only_descriptive   417
translated_v18_alias     6228
```

The target boundary audit remains at 5,782 exact starts. The complete dynamic
symbol audit remains at 6,770 named rows and 6,600 defined rows, with 5,782
functions, 482 data items, 336 other non-code items, and 170 undefined
imports. The v321 checkpoint can then be rebuilt and checked offline:

```bash
python3 tools/generate_spectron_translation_checkpoint_v321.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260828_v320.json \
  --database /path/to/spectron_libqplay_translated_v321_gui_missing_function_aliases_final.i64 \
  --application-report artifacts/spectron_gui_missing_function_application_20260828.json \
  --verification-report artifacts/spectron_gui_missing_function_verification_20260828.json \
  --anchor-artifact artifacts/spectron_gui_missing_function_manual_translation_anchors_20260828.json \
  --name-audit artifacts/spectron_name_coverage_audit_v321_20260828.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v321_20260828.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v321_20260828.json \
  --semantic-map artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --source-boundary-report artifacts/original_dynamic_function_application_20260828.json \
  --output artifacts/spectron_translation_checkpoint_20260828_v321.json

python3 tools/validate_research_archive.py
```

### v322 TGraalVar runtime-gap translation

The v322 pass is a semantic review over a fresh copy of the verified v321
database. It does not change the APK or run the client. First export compact
Hex-Rays evidence for the source and target method sets. The evidence helper
accepts comma-separated addresses and writes a JSON snapshot when
`LIBQPLAY_EVIDENCE_OUT` is set:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x20d304,0x20e070,0x20e5c4,0x20ec60,0x20f014,0x20f17c,0x20f2ac \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-tgraalvar-evidence.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/source-evidence.i64 \
  -s tools/ida_dump_function_evidence.py
```

Run the same helper against the target for `0x2136c4,0x214520,0x214a78,
0x215148,0x2154e0,0x215660,0x2157a8,0x2158e4,0x2159f4,0x216174,0x216454,
0x216558`. The v322 generator combines those snapshots with the source and
target feature exports. It refuses a missing pseudocode row, a changed raw
symbol name, a duplicate source or target, or a row already present in the
automatic semantic match list:

```bash
python3 tools/generate_spectron_tgraalvar_runtime_gap_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v320_current.json \
  --semantic-map artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --source-evidence /tmp/graal-source-tgraalvar-evidence.json \
  --source-evidence /tmp/graal-source-tgraalvar-adjacent-evidence.json \
  --source-evidence /tmp/graal-source-getvarvalueasfloat-evidence.json \
  --target-evidence /tmp/graal-target-tgraalvar-evidence.json \
  --target-evidence /tmp/graal-target-tgraalvar-adjacent-evidence.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829.json
```

The generator should report twelve high-confidence anchors, twelve
pseudocode fingerprints on each side, and twelve layout-change rows. Apply
the reviewed names to a new database copy:

```bash
cp /path/to/spectron_libqplay_translated_v321_gui_missing_function_aliases_final.i64 \
  /tmp/spectron_v322_tgraalvar.i64
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v322_tgraalvar_runtime_gap_final.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_tgraalvar_runtime_gap_application.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v322_tgraalvar.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py
```

Reopen the saved copy with `tools/ida_verify_spectron_manual_anchors.py`. The
expected result is twelve verified names, 11,707 functions, and zero
failures. Then rerun the name, boundary, and complete dynamic-symbol audits.
The expected v322 name origins are:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export       990
target_only_descriptive   417
translated_v18_alias     6240
```

The dynamic-symbol audit remains at 6,770 named rows and 6,600 defined rows,
with 5,782 functions, 482 data items, 336 other non-code items, and 170
undefined imports. The twelve new aliases change only the name classification:
source-backed aliases rise to 4,564 and exact retained names fall to 1,878.
The v322 checkpoint is rebuilt offline with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v322.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260828_v321.json \
  --database /path/to/spectron_libqplay_translated_v322_tgraalvar_runtime_gap_final.i64 \
  --anchor-artifact artifacts/spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_tgraalvar_runtime_gap_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_tgraalvar_runtime_gap_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v322_20260829.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v322_20260829.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v322_20260829.json \
  --semantic-map artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v322.json

python3 tools/validate_research_archive.py
```

The final database hash for this checkpoint is
`af0f2361668f7cd375b33242a0b21591a53446c332c0e77c8a4e51e3c6bdf1ad`. The
anchor, application, verification, audit, and checkpoint records are all
offline artifacts. They do not establish live game-server compatibility.

### v323 TGraalVar runtime continuation

The v323 pass reviews the next 23 source and target methods from disposable
IDA copies of the v322 database. It does not modify the APK or contact a
server. Export compact pseudocode evidence for the source addresses
`0x20d7dc,0x20e598,0x20eaf0,0x20eb04,0x20eb2c,0x20eb54,0x210a8c,0x210b40,
0x210ce8,0x210f98,0x211178,0x211850,0x21190c,0x211c00,0x2124c0,0x21277c,
0x2135b0,0x213b10,0x213e48,0x213f04,0x213fc0,0x21407c,0x2140c0`:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x20d7dc,0x20e598,0x20eaf0,0x20eb04,0x20eb2c,0x20eb54,0x210a8c,0x210b40,0x210ce8,0x210f98,0x211178,0x211850,0x21190c,0x211c00,0x2124c0,0x21277c,0x2135b0,0x213b10,0x213e48,0x213f04,0x213fc0,0x21407c,0x2140c0 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-tgraalvar-next-evidence.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/source-evidence.i64 \
  -s tools/ida_dump_function_evidence.py
```

Run the same helper against target addresses
`0x213c84,0x214a4c,0x214fc4,0x214fec,0x215014,0x21503c,0x217198,
0x21727c,0x217444,0x217754,0x21797c,0x21805c,0x218134,0x218468,
0x218d70,0x219050,0x219ed0,0x21a64c,0x21a970,0x21aa0c,0x21aab0,
0x21ab98`, then export `0x21ab54` separately if it was not included in
that snapshot. The target-only helper at `0x214fd8` is intentionally not an
anchor. Combine the evidence with the current source and target feature
exports:

```bash
python3 tools/generate_spectron_tgraalvar_runtime_continuation_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v322_tgraalvar_runtime_gap.json \
  --semantic-map artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --source-evidence /tmp/graal-source-tgraalvar-next-evidence.json \
  --target-evidence /tmp/graal-target-tgraalvar-next-evidence.json \
  --target-evidence /tmp/graal-target-static-init-evidence.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829.json
```

The generator should report 23 high-confidence anchors, six exact metric
rows, seventeen layout-change rows, and pseudocode for all 46 source and
target sides. It also refuses a changed raw name, a duplicate address, a
missing pseudocode row, or a row already present in the v320 semantic match
list.

Apply the aliases to a new copy of the v322 database. Never apply this batch
on top of the v322 file in place:

```bash
cp /path/to/spectron_libqplay_translated_v322_tgraalvar_runtime_gap_final.i64 \
  /tmp/spectron_v323_tgraalvar.i64
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v323_tgraalvar_runtime_continuation_final.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_tgraalvar_runtime_continuation_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v323_tgraalvar.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py
```

Reopen the saved copy with `tools/ida_verify_spectron_manual_anchors.py`. The
expected result is 23 verified names, 11,707 functions, and zero failures.
Rerun the name, dynamic-boundary, and complete dynamic-symbol audits. The
expected v323 name origins are:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export       967
target_only_descriptive   417
translated_v18_alias     6263
```

The dynamic audit should still report 6,770 named rows, 6,600 defined rows,
5,782 exact function starts, 482 data items, 336 other non-code items, and
170 undefined imports. The continuation changes the classification to 4,587
source-backed aliases and 1,855 exact retained names. Rebuild the checkpoint
with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v323.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v322.json \
  --database /path/to/spectron_libqplay_translated_v323_tgraalvar_runtime_continuation_final.i64 \
  --anchor-artifact artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v323_20260829.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v323_20260829.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v323_20260829.json \
  --semantic-map artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v323.json

python3 tools/validate_research_archive.py
```

The expected v323 database hash is
`588e39f73c0946aea4ed45265820c9d95a73689339c365840b308170d36d0b4d`. The
application and audit reports are offline records. This pass does not change
the runtime conclusion or establish a live game-server login.

### v324 TScript runtime translation

The v324 pass continues from the verified v323 database and reviews 24
`TScriptFunction`, `TScript`, and `TScriptEnvironment` methods. It is an
offline IDA pass and does not modify the APK or contact a server. Export source
evidence for:

```text
0x2148dc,0x214a24,0x214a70,0x214aec,0x214b34,0x214b54,
0x21510c,0x215488,0x2157f4,0x215950,0x215a9c,0x215cc4,
0x215eac,0x216de8,0x216fa0,0x217108,0x217138,0x2176d8,
0x217908,0x2179a4,0x217af0,0x217b80,0x217cd8,0x217db4
```

Run the compact evidence exporter with the source list above, then repeat it
for target addresses:

```text
0x21b490,0x21b5f8,0x21b644,0x21b6c0,0x21b708,0x21b728,
0x21bd1c,0x21c0dc,0x21c460,0x21c5dc,0x21c758,0x21ca08,
0x21cc10,0x21db68,0x21dde0,0x21dff8,0x21e028,0x21e618,
0x21e848,0x21e8bc,0x21e9ec,0x21eaa0,0x21ec14,0x21ed10
```

The invocation pattern is the same as the earlier passes. Substitute the
address list and output path for each database:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x2148dc,0x214a24,0x214a70,0x214aec,0x214b34,0x214b54,0x21510c,0x215488,0x2157f4,0x215950,0x215a9c,0x215cc4,0x215eac,0x216de8,0x216fa0,0x217108,0x217138,0x2176d8,0x217908,0x2179a4,0x217af0,0x217b80,0x217cd8,0x217db4 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-tscript-evidence.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/source-tscript-evidence.i64 \
  -s tools/ida_dump_function_evidence.py
```

Generate the reviewed anchors from the v4 source features, the v323-derived
target features, and the two compact evidence files:

```bash
python3 tools/generate_spectron_tscript_runtime_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v324_tscript_runtime.json \
  --semantic-map /tmp/semantic_v323_current.json \
  --source-evidence /tmp/graal-source-tscript-evidence.json \
  --target-evidence /tmp/graal-target-tscript-evidence.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tscript_runtime_manual_translation_anchors_20260829.json
```

The generator should report 24 high-confidence anchors, three exact metric
rows, 21 layout-change rows, and pseudocode for every source and target side.
It rejects changed raw names, duplicate addresses, missing evidence, and
semantic matches that were already translated.

Apply the aliases to a copy of the v323 database and reopen the saved result:

```bash
cp /path/to/spectron_libqplay_translated_v323_tgraalvar_runtime_continuation_final.i64 \
  /tmp/spectron_v324_tscript_runtime.i64
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_tscript_runtime_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tscript_runtime_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v324_tscript_runtime_final.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_tscript_runtime_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v324_tscript_runtime.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py
```

The reopen report should show 24 verified names, 11,707 functions, and zero
failures. Re-run the name, dynamic-boundary, and dynamic-symbol coverage
audits. The expected v324 name origins are:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export       943
target_only_descriptive   417
translated_v18_alias     6287
```

The dynamic audit should still report 6,770 named rows, 6,600 defined rows,
5,782 exact function starts, 482 data items, 336 other non-code items, and
170 undefined imports. The v324 classification is 4,614 source-backed
aliases, 1,831 exact retained names, and 148 other retained target names.
Rebuild and validate the checkpoint with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v324.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v323.json \
  --database /path/to/spectron_libqplay_translated_v324_tscript_runtime_final.i64 \
  --anchor-artifact artifacts/spectron_tscript_runtime_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_tscript_runtime_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_tscript_runtime_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v324.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v324.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v324.json \
  --semantic-map artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v324.json

python3 tools/validate_research_archive.py
```

The expected v324 database hash is
`975367646c22c2f21d1c7ffc8380e0b48a6c259864a1f8b192e043c3e0992e06`. This
checkpoint is static evidence only. It has not been used to claim a new
runtime result or a live service login.

### v325 TScript destructor and profile cleanup translation

The v325 pass continues from the v324 database and reviews eight raw target
symbols. The source list is:

```text
0x214794,0x2150ec,0x2175b8,0x2175d4,
0x2175dc,0x217614,0x21761c,0x217630
```

The corresponding Spectron list is:

```text
0x21b324,0x21bcfc,0x21e4f8,0x21e514,
0x21e51c,0x21e554,0x21e55c,0x21e570
```

Export compact Hex-Rays evidence for both lists with
`tools/ida_dump_function_evidence.py`. The source copy should be based on the
1.8 translated database, and the target copy should be based on
`analysis/spectron_libqplay_translated_v324_tscript_runtime_final.i64`.
The target raw names must still be present when the anchor generator runs.

Generate the anchor artifact with:

```bash
python3 tools/generate_spectron_tscript_destructor_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v324_tscript_runtime.json \
  --semantic-map /tmp/semantic_v323_current.json \
  --source-evidence /tmp/graal-source-tscript-destructors.json \
  --target-evidence /tmp/graal-target-tscript-destructors.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tscript_destructor_manual_translation_anchors_20260829.json
```

The generator should report eight high-confidence anchors, three exact metric
rows, five layout-change rows, and pseudocode for all 16 sides. It also checks
that the automatic semantic map does not already claim either side. The source
property and profile names intentionally retain their historical IDA aliases;
the compact pseudocode comments identify the underlying D1, D2, and D0
destructor forms.

Apply the aliases to a new copy of v324:

```bash
cp /path/to/spectron_libqplay_translated_v324_tscript_runtime_final.i64 \
  /tmp/spectron_v325_tscript_destructors.i64
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_tscript_destructor_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tscript_destructor_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v325_tscript_destructor_final.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_tscript_destructor_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v325_tscript_destructors.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py
```

Reopen the saved copy with the matching verification helper. Use
`SPECTRON_MANUAL_VERIFY_REPORT` for its report path:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=0 \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_tscript_destructor_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tscript_destructor_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_tscript_destructor_manual_translation_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v325_tscript_destructor_final.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The expected verification result is eight names, 11,707 functions, and zero
failures. Re-run the name, dynamic-boundary, and complete dynamic-symbol
coverage audits on the reopened copy. The expected name origins are:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export       935
target_only_descriptive   417
translated_v18_alias     6295
```

The dynamic audit should report 6,770 named rows, 6,600 defined rows, 5,782
exact function starts, 482 data items, 336 other non-code items, and 170
undefined imports. The v325 status counts are 4,624 source-backed aliases,
1,823 exact retained names, and 146 other retained target names. Rebuild the
checkpoint with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v325.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v324.json \
  --database /path/to/spectron_libqplay_translated_v325_tscript_destructor_final.i64 \
  --anchor-artifact artifacts/spectron_tscript_destructor_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_tscript_destructor_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_tscript_destructor_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v325.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v325.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v325.json \
  --semantic-map artifacts/spectron_semantic_function_translation_v320_20260828.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v325.json

python3 tools/validate_research_archive.py
```

The expected v325 database hash is
`229e4729eed1be2759935c1604ac6e3987ffe6fbe91c2b5a0dca16ae344c0757`. This
checkpoint is static evidence only and does not change the runtime or live
service conclusions.

### v326 format-parameter and property runtime translation

The v326 pass reviews the format-parameter and property block immediately
after the v325 destructor work. It covers 20 source and target functions:

```text
source: 0x224248,0x22424c,0x224268,0x224270,0x2242a8,0x2242b0,
        0x224400,0x224448,0x224490,0x224498,0x2244e0,0x224528,
        0x224530,0x224538,0x2245cc,0x224638,0x224640,0x224660,
        0x224668,0x2246c8
target: 0x22c810,0x22c858,0x22c874,0x22c87c,0x22c8b4,0x22c8bc,
        0x22ca58,0x22caa0,0x22cae8,0x22caf0,0x22cb38,0x22cb80,
        0x22cb88,0x22cb94,0x22cc48,0x22ccbc,0x22ccc4,0x22cce4,
        0x22ce20,0x22cea0
```

The source evidence comes from the 1.8 translated IDA database. The target
evidence comes from the v325-derived database before these names are applied.
Run `tools/ida_dump_function_evidence.py` through IDALIB with
`LIBQPLAY_EVIDENCE_COMPACT=1`. The anchor generator checks names, function
ranges, pseudocode availability, and that the automatic semantic map has not
already claimed either side.

Generate the v326 anchor artifact with:

```bash
python3 tools/generate_spectron_format_parameters_property_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v325_tscript_destructors.json \
  --semantic-map /tmp/semantic_v323_current.json \
  --source-evidence /tmp/graal-source-format-parameters.json \
  --source-evidence /tmp/graal-source-property-block.json \
  --target-evidence /tmp/graal-target-property-block.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_format_parameters_property_manual_translation_anchors_20260829.json
```

The expected summary is 20 high-confidence anchors, 11 exact metric rows,
nine layout-change rows, and pseudocode for all 20 source and target rows.
The layout rows are intentional. The target format wrapper clears an added
string array, and the property writers use rebuilt string and container
classes.

Apply the aliases to a new v325-derived copy:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_format_parameters_property_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_format_parameters_property_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v326_format_parameters_property.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_format_parameters_property_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v325_tscript_destructor_final.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py
```

Reopen the saved v326 copy with the matching verification helper. Select the
verification report with `SPECTRON_MANUAL_VERIFY_REPORT`:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_format_parameters_property_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_format_parameters_property_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_format_parameters_property_manual_translation_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v326_format_parameters_property.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The expected application and reopen results are 20 rows, 20 resolved names,
20 renames, 20 evidence comments, 11,707 functions, and zero failures. Run
the name, dynamic-boundary, dynamic-symbol-coverage, and feature-export
helpers on the reopened copy. The expected name origins are:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export       915
target_only_descriptive   417
translated_v18_alias     6315
```

The dynamic audit should report 6,770 named rows, 6,600 defined rows, 5,782
exact function starts, 482 data items, 336 other non-code items, and 170
undefined imports. The v326 status counts are 4,647 source-backed aliases,
1,803 exact retained names, 143 other retained target names, seven
linker-boundary aliases, 169 PLT veneers, and one undefined `__sF` import.
The refreshed semantic feature map remains at 3,716 mapped functions, 3,656
high-confidence matches, 60 medium-confidence matches, 1,020 ambiguous
functions, and 608 unmatched functions.

Rebuild the v326 checkpoint with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v326.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v325.json \
  --database /path/to/spectron_libqplay_translated_v326_format_parameters_property.i64 \
  --anchor-artifact artifacts/spectron_format_parameters_property_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_format_parameters_property_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_format_parameters_property_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v326.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v326.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v326.json \
  --semantic-map artifacts/spectron_semantic_translation_v326.json \
  --feature-export /tmp/spectron_features_v326_format_parameters_property.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v326.json

python3 tools/validate_research_archive.py
```

The expected v326 database hash is
`08ae63229dfbcabf94d314cda677a2c45b60e17b9c2fee8351a298b3cf6eb991`. This
checkpoint is static evidence only. It does not change the loopback runtime
result, TLS diagnosis, or live-service boundary.

### v348 RSA public-encryption translation

The v348 pass is a static IDA checkpoint. It starts from the verified v347
database and resolves one source ambiguity using direct RSA algorithm calls.
The source row is `TEncryption_rsa_encrypt_TString_const_TString_const` at
`0xf7218`; the target row is `0xf94ac`, and the applied alias is
`v18_TEncryption_rsa_encrypt_TString_const_TString_const`.

The target function has raw symbol
`_ZN10cHovga0n1u10D855FaUMK1ERK10C8THgaTQxFS2_`. The source and target feature
records are identical after relocation normalization: 296 bytes, 74
instructions, 12 basic blocks, 14 branches, seven calls, and matching
mnemonic, opcode-shape, register-shape, and coarse shape hashes. The source
and target pseudocode both use public-key decode, RNG setup, RSA output-size
calculation, public encryption, output append, and key cleanup. The sibling at
target `0xf96f8` remains the private-signing row because its body uses
`RsaPrivateKeyDecode` and `RsaSSL_Sign`.

The anchor generator validates the source and target feature rows, both
pseudocode evidence records, the raw target symbol, the expected parent
ambiguity, and the `+0x2294` address delta:

```bash
python3 tools/generate_spectron_rsa_encrypt_anchor.py \
  --original-features /tmp/original_features_v3_current.json \
  --spectron-features artifacts/spectron_features_v347_encoded_string.json \
  --semantic-map artifacts/spectron_semantic_translation_v345.json \
  --source-evidence /tmp/graal-source-rsa-v347.json \
  --target-evidence /tmp/graal-target-rsa-v347.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_rsa_encrypt_manual_translation_anchor_20260829.json
```

Apply the one-row anchor to a fresh v347-derived IDA copy. The input and
output paths must differ:

```bash
cp /path/to/analysis/spectron_libqplay_translated_v347_encoded_string.i64 \
  /tmp/spectron_v348_anchor_apply_input.i64

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_rsa_encrypt_manual_translation_anchor_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_rsa_encrypt_manual_translation_anchor_20260829 \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  SPECTRON_MANUAL_REPORT=/path/to/libqplay/artifacts/spectron_rsa_encrypt_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v348_anchor_apply_input.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_rsa_encrypt_manual_translation_anchor_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_rsa_encrypt_manual_translation_anchor_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/path/to/libqplay/artifacts/spectron_rsa_encrypt_manual_translation_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The application report must show one resolved function, one rename, one
evidence comment, zero failures, and a successful save. The reopen report must
show one verified name in an 11,707-function database.

Refresh the feature and name-coverage audits against the saved v348 database:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FEATURES_OUT=/path/to/libqplay/artifacts/spectron_features_v348_rsa_encrypt.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  -s tools/ida_export_function_features.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_NAME_COVERAGE_OUTPUT=/path/to/libqplay/artifacts/spectron_name_coverage_audit_v348.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  -s tools/ida_audit_spectron_name_coverage.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_BOUNDARY_AUDIT_OUTPUT=/path/to/libqplay/artifacts/spectron_dynamic_symbol_boundaries_v348.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  -s tools/ida_audit_dynamic_symbol_boundaries.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_DYNAMIC_SYMBOL_COVERAGE_OUTPUT=/path/to/libqplay/artifacts/spectron_dynamic_symbol_coverage_audit_v348.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  -s tools/ida_audit_spectron_dynamic_symbol_coverage.py
```

Carry forward the semantic map from v345 while recording the one reviewed
source-backed addition:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v348.py \
  --parent-map artifacts/spectron_semantic_translation_v345.json \
  --target-features artifacts/spectron_features_v348_rsa_encrypt.json \
  --anchor-artifact artifacts/spectron_rsa_encrypt_manual_translation_anchor_20260829.json \
  --output artifacts/spectron_semantic_translation_v348.json
```

The expected v348 map contains 3,722 mapped pairs, 3,662 high-confidence
pairs, 60 medium-confidence pairs, 1,014 remaining ambiguities, and 608
unmatched source functions. Build the strict checkpoint and run the archive
validator:

```bash
python3 tools/generate_spectron_translation_checkpoint_v348.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v347.json \
  --database /path/to/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  --label-artifact artifacts/spectron_rsa_encrypt_manual_translation_anchor_20260829.json \
  --application-report artifacts/spectron_rsa_encrypt_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_rsa_encrypt_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v348.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v348.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v348.json \
  --semantic-map artifacts/spectron_semantic_translation_v348.json \
  --feature-export artifacts/spectron_features_v348_rsa_encrypt.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v348.json

python3 tools/validate_research_archive.py
```

The expected v348 database hash is
`40ff536a25df6624d1ac25bc9052e85d107dddb996dc5e46b791d1df936a75c0`. This
checkpoint is static IDA evidence only. It does not patch the APK, rerun the
loopback client, alter TLS behavior, contact a live endpoint, or request an
external resource.

### v347 target-only encoded string buffer

The v347 pass is static IDA work only. It starts from the verified v346 IDB
and reviews the 19-function `CanTfaz6bZ` copy-on-write XOR buffer cluster and
the two `C8THgaTQxF` bridge methods. It does not require an APK, emulator,
server, or live endpoint.

Direct target evidence was captured from the restarted IDA MCP through
disposable IDALIB copies. The evidence files were:

    /tmp/graal-target-encoded-string-cluster-v347.json
    /tmp/graal-source-encrypted-string-v347.json

The target addresses reviewed were `0xf37bc`, `0xf3888`, and
`0xf8b90..0xf9374`. The source evidence was used for context and metric
collision reporting only. Generate the reviewed target-only label artifact
with:

    python3 tools/generate_spectron_encoded_string_target_only_labels.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v346_resource_path_helper.json \
      --target-evidence /tmp/graal-target-encoded-string-cluster-v347.json \
      --source-evidence /tmp/graal-source-encrypted-string-v347.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v346.json \
      --symbol-table artifacts/spectron_symbol_table_audit_20260827.json \
      --semantic-map artifacts/spectron_semantic_translation_v345.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_encoded_string_target_only_labels_20260829.json

Apply the artifact to a fresh v346-derived copy and save it as
`analysis/spectron_libqplay_translated_v347_encoded_string.i64`. Set
`SPECTRON_TARGET_LABEL_APPLY=1`, point
`SPECTRON_TARGET_LABEL_PATH` at the generated artifact, set
`SPECTRON_TARGET_LABEL_EXPECTED_ARTIFACT` to
`spectron_encoded_string_target_only_labels_20260829`, and set
`SPECTRON_TARGET_LABEL_SAVE_PATH` and `SPECTRON_TARGET_LABEL_REPORT` to the
v347 IDB and application report paths. The application report must contain 19
resolved functions, 19 renames, 19 evidence comments, zero failures, and a
successful save. Reopen the saved copy with
`tools/ida_verify_spectron_target_only_labels.py`; the verification report
must contain 19 verified names and zero failures.

Refresh the feature export and audits with the existing IDALIB scripts, using
these output paths:

    artifacts/spectron_features_v347_encoded_string.json
    artifacts/spectron_name_coverage_audit_v347.json
    artifacts/spectron_dynamic_symbol_boundaries_v347.json
    artifacts/spectron_dynamic_symbol_coverage_audit_v347.json

The label artifact should report 19 high-confidence target-only labels, zero
source counterparts, zero semantic claims, and three exact or normalized
metric collisions. The v347 feature and audit outputs should retain 11,707
functions, 6,440 translated aliases, 439 target-only descriptive labels, 769
retained target names, 4,795 source-backed dynamic rows, 1,657 exact retained
dynamic names, and 5,782 exact dynamic function starts.

Build the checkpoint with:

    python3 tools/generate_spectron_translation_checkpoint_v347.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v346.json \
      --database analysis/spectron_libqplay_translated_v347_encoded_string.i64 \
      --label-artifact artifacts/spectron_encoded_string_target_only_labels_20260829.json \
      --application-report artifacts/spectron_encoded_string_target_only_label_application_20260829.json \
      --verification-report artifacts/spectron_encoded_string_target_only_label_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v347.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v347.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v347.json \
      --semantic-map artifacts/spectron_semantic_translation_v345.json \
      --feature-export artifacts/spectron_features_v347_encoded_string.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v347.json

Run `python3 tools/validate_research_archive.py` after the checkpoint is
written. The expected v347 database hash is
`fe1bbbdf27b25b2fe13d088fb01944a624e8fe8a11898a377ff66f49b892a59b`. The
semantic map is carried forward unchanged from v345 because the target-only
buffer has no demonstrated 1.8 counterpart.

This checkpoint is static evidence only. It does not change the verified
loopback runtime, the connector TLS diagnosis, or the live-service boundary.

### v346 target-only resource path helper

The v346 pass is static IDA work only. It starts from the verified v345
database and reviews target function `0xefbcc`, the raw exported symbol
`_ZN10f6WHgaQkAF10iaBygafTIxERK10C8THgaTQxFb`. It does not require an APK,
emulator, server, or live endpoint.

Capture the source and target pseudocode and the target dynamic-symbol data
window with the IDALIB scripts described earlier. The v346 evidence files are
kept in `/tmp`:

    /tmp/graal-source-resource-path-v346.json
    /tmp/graal-target-resource-helper-v346.json
    /tmp/graal-target-getgamefile-v346.json
    /tmp/graal-target-resource-v346-data.json

Generate the target-only label artifact from the v345 feature and audit
records:

    python3 tools/generate_spectron_resource_path_helper_target_only_labels.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v345_resource_object_static.json \
      --source-evidence /tmp/graal-source-resource-path-v346.json \
      --target-evidence /tmp/graal-target-resource-helper-v346.json \
      --target-game-file-evidence /tmp/graal-target-getgamefile-v346.json \
      --target-data-evidence /tmp/graal-target-resource-v346-data.json \
      --resource-anchor artifacts/spectron_resource_manual_translation_anchors_20260826.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v345.json \
      --symbol-table artifacts/spectron_symbol_table_audit_20260827.json \
      --semantic-map artifacts/spectron_semantic_translation_v345.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_resource_path_helper_target_only_labels_20260829.json

Apply the artifact to a fresh v345-derived copy and save it as
`analysis/spectron_libqplay_translated_v346_resource_path_helper.i64` with
`tools/ida_apply_spectron_target_only_labels.py`. Set
`SPECTRON_TARGET_LABEL_APPLY=1`, point
`SPECTRON_TARGET_LABEL_PATH` at the generated artifact, set
`SPECTRON_TARGET_LABEL_EXPECTED_ARTIFACT` to
`spectron_resource_path_helper_target_only_labels_20260829`, and set
`SPECTRON_TARGET_LABEL_SAVE_PATH` and `SPECTRON_TARGET_LABEL_REPORT` to the
v346 IDB and application report paths. The application report must contain
one resolved function, one rename, one evidence comment, zero failures, and
a successful save. Reopen the saved copy with
`tools/ida_verify_spectron_target_only_labels.py`; the verification report
must contain one verified name and zero failures.

Refresh the feature export and audits with the existing IDALIB scripts, using
these output paths:

    artifacts/spectron_features_v346_resource_path_helper.json
    artifacts/spectron_name_coverage_audit_v346.json
    artifacts/spectron_dynamic_symbol_boundaries_v346.json
    artifacts/spectron_dynamic_symbol_coverage_audit_v346.json

The v346 pass carries the v345 semantic map forward unchanged. Build the
checkpoint with:

    python3 tools/generate_spectron_translation_checkpoint_v346.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v345.json \
      --database /path/to/spectron_libqplay_translated_v346_resource_path_helper.i64 \
      --label-artifact artifacts/spectron_resource_path_helper_target_only_labels_20260829.json \
      --application-report artifacts/spectron_resource_path_helper_target_only_label_application_20260829.json \
      --verification-report artifacts/spectron_resource_path_helper_target_only_label_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v346.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v346.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v346.json \
      --semantic-map artifacts/spectron_semantic_translation_v345.json \
      --feature-export artifacts/spectron_features_v346_resource_path_helper.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v346.json

Run `python3 tools/validate_research_archive.py` after the checkpoint is
written. The expected v346 database hash is
`bfb7f36be1a572c5428192c90ee3288035805a2e34b7ead439437c4b1ccf2392`.
Expected totals are 6,440 translated aliases, 420 target-only descriptive
labels, 788 retained target names, 4,795 source-backed dynamic rows, 1,676
exact retained dynamic names, and 5,782 exact dynamic function starts. The
semantic map remains at 3,721 mapped pairs, 3,661 high-confidence pairs,
1,015 remaining automatic ambiguities, and 608 unmatched source functions.

This checkpoint is static evidence only. It does not change the verified
loopback runtime, the connector TLS diagnosis, or the live-service boundary.

### v345 resource-object static translation

The v345 pass is static IDA work only. It starts from the verified v344
database and reviews source methods at `0xf0434`, `0xf0464`, and `0xf04a4`
against target methods at `0xf1910`, `0xf1940`, and `0xf1980`. It does not
require an APK, emulator, server, or live endpoint.

Capture compact pseudocode with `tools/ida_dump_function_evidence.py` using
the IDALIB environment described in the earlier sections. Keep the evidence
files in `/tmp`:

    /tmp/graal-source-resource-object-v345.json
    /tmp/graal-target-resource-object-v345.json

Generate the reviewed three-row artifact:

    python3 tools/generate_spectron_resource_object_static_anchors.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v344_resource_stream.json \
      --semantic-map artifacts/spectron_semantic_translation_v344.json \
      --source-evidence /tmp/graal-source-resource-object-v345.json \
      --target-evidence /tmp/graal-target-resource-object-v345.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_resource_object_static_residual_manual_translation_anchors_20260829.json

Apply the artifact to a fresh v344-derived copy and save it as
`analysis/spectron_libqplay_translated_v345_resource_object_static.i64`. Use
`tools/ida_apply_spectron_manual_anchors.py` with the same IDALIB invocation
shown earlier and these variables:

    SPECTRON_MANUAL_APPLY=1
    SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_resource_object_static_residual_manual_translation_anchors_20260829.json
    SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_resource_object_static_residual_manual_translation_anchors_20260829
    SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v345_resource_object_static.i64
    SPECTRON_MANUAL_REPORT=/tmp/spectron_resource_object_static_manual_translation_application_20260829.json

Reopen the saved copy with `tools/ida_verify_spectron_manual_anchors.py` and
set `SPECTRON_MANUAL_VERIFY_REPORT` to
`/tmp/spectron_resource_object_static_manual_translation_verification_20260829.json`.
The application report must contain three resolved functions, three renames,
three evidence comments, zero failures, and a successful save. The reopen
report must contain three verified names in an 11,707-function database.

Refresh the feature export and audits with the IDALIB scripts from the v344
section, using these output paths:

    artifacts/spectron_features_v345_resource_object_static.json
    artifacts/spectron_name_coverage_audit_v345.json
    artifacts/spectron_dynamic_symbol_boundaries_v345.json
    artifacts/spectron_dynamic_symbol_coverage_audit_v345.json

Carry the semantic map forward and build the strict checkpoint:

    python3 tools/carry_forward_spectron_semantic_translation_v345.py \
      --parent-map artifacts/spectron_semantic_translation_v344.json \
      --target-features artifacts/spectron_features_v345_resource_object_static.json \
      --anchor-artifact artifacts/spectron_resource_object_static_residual_manual_translation_anchors_20260829.json \
      --output artifacts/spectron_semantic_translation_v345.json

    python3 tools/generate_spectron_translation_checkpoint_v345.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v344.json \
      --database /path/to/spectron_libqplay_translated_v345_resource_object_static.i64 \
      --anchor-artifact artifacts/spectron_resource_object_static_residual_manual_translation_anchors_20260829.json \
      --application-report artifacts/spectron_resource_object_static_residual_manual_translation_application_20260829.json \
      --verification-report artifacts/spectron_resource_object_static_residual_manual_translation_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v345.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v345.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v345.json \
      --semantic-map artifacts/spectron_semantic_translation_v345.json \
      --feature-export artifacts/spectron_features_v345_resource_object_static.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v345.json

    python3 tools/validate_research_archive.py

The expected v345 database hash is
`0b455dfb6777c8ca571f86e19612d30a7dca6c3d9b9e47590e31a6bfcea4442f`.
Expected totals are 6,440 translated aliases, 419 target-only descriptive
labels, 789 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,795 source-backed dynamic symbols, 1,677 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The semantic map has 3,721
mapped pairs, 3,661 high-confidence pairs, 1,015 remaining automatic
ambiguities, and 608 unmatched functions. The anchor summary is three
high-confidence rows, three normalized-shape matches, three layout-change
rows, three pseudocode-backed rows, and three resolved ambiguity rows.

The target D2 function has a D1 alternate dynamic spelling. Rebuilding the
dynamic audit therefore changes four names to source-backed aliases even
though the pass adds three function aliases. This is expected. The checkpoint
hash assumes the final IDB is not opened again after the last IDALIB audit,
because opening an IDB can update IDA metadata.

This checkpoint is static evidence only. It does not change the loopback
runtime result, TLS diagnosis, or live-service boundary.

### v344 resource-stream crypto translation

The v344 pass is static IDA work only. It starts from the verified v343
database and resolves the two adjacent resource-stream crypto methods. The
source addresses are `0xece78` and `0xecfa0`; the target addresses are
`0xede48` and `0xedf70`. It does not require an APK, emulator, server, or live
endpoint.

Capture source and target compact pseudocode with
`tools/ida_dump_function_evidence.py` using the IDALIB environment described
in the earlier sections. Keep the evidence files in `/tmp`:

```text
/tmp/graal-source-resource-v344.json
/tmp/graal-target-resource-v344.json
```

The generator requires the distinct encrypt-memory and decrypt-memory calls
in addition to the normalized feature records. Generate the two-row artifact:

```bash
python3 tools/generate_spectron_resource_stream_anchors.py \
  --original-features /tmp/original_features_v3_current.json \
  --spectron-features artifacts/spectron_features_v343_drawing_panel_residual.json \
  --semantic-map artifacts/spectron_semantic_translation_v343.json \
  --source-evidence /tmp/graal-source-resource-v344.json \
  --target-evidence /tmp/graal-target-resource-v344.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_resource_stream_residual_manual_translation_anchors_20260829.json
```

Apply the artifact to a fresh v343-derived copy and save it as
`analysis/spectron_libqplay_translated_v344_resource_stream.i64`. Use
`tools/ida_apply_spectron_manual_anchors.py` with the same IDALIB invocation
shown earlier and these variables:

```text
SPECTRON_MANUAL_APPLY=1
SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_resource_stream_residual_manual_translation_anchors_20260829.json
SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_resource_stream_residual_manual_translation_anchors_20260829
SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v344_resource_stream.i64
SPECTRON_MANUAL_REPORT=/tmp/spectron_resource_stream_manual_translation_application_20260829.json
```

Reopen the saved copy with `tools/ida_verify_spectron_manual_anchors.py` and
set `SPECTRON_MANUAL_VERIFY_REPORT` to
`/tmp/spectron_resource_stream_manual_translation_verification_20260829.json`.
The application report must contain two resolved functions, two renames, two
evidence comments, zero failures, and a successful save. The reopen report
must contain two verified names in an 11,707-function database.

Refresh the feature export and audits with the IDALIB scripts from the v343
section, using these output paths:

```text
artifacts/spectron_features_v344_resource_stream.json
artifacts/spectron_name_coverage_audit_v344.json
artifacts/spectron_dynamic_symbol_boundaries_v344.json
artifacts/spectron_dynamic_symbol_coverage_audit_v344.json
```

Carry the semantic map forward. Unlike earlier name-only passes, this pair
resolves two rows that were still in the automatic ambiguity set, so the
carry-forward helper promotes those explicit source-target rows into the
map:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v344.py \
  --parent-map artifacts/spectron_semantic_translation_v343.json \
  --target-features artifacts/spectron_features_v344_resource_stream.json \
  --anchor-artifact artifacts/spectron_resource_stream_residual_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v344.json
```

Build the strict checkpoint:

```bash
python3 tools/generate_spectron_translation_checkpoint_v344.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v343.json \
  --database /path/to/spectron_libqplay_translated_v344_resource_stream.i64 \
  --anchor-artifact artifacts/spectron_resource_stream_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_resource_stream_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_resource_stream_residual_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v344.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v344.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v344.json \
  --semantic-map artifacts/spectron_semantic_translation_v344.json \
  --feature-export artifacts/spectron_features_v344_resource_stream.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v344.json

python3 tools/validate_research_archive.py
```

The expected v344 database hash is
`d7d4887e86d0570d7f2518bd545d3caa139aa0a1c5e0ca5c39d5c00b50b7669a`.
Expected totals are 6,437 translated aliases, 419 target-only descriptive
labels, 792 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,791 source-backed dynamic symbols, 1,680 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The semantic map has 3,718
mapped pairs, 3,658 high-confidence pairs, 1,018 remaining automatic
ambiguities, and 608 unmatched functions. The anchor summary is two
high-confidence rows, two normalized-shape matches, two layout-change rows,
two pseudocode-backed rows, and two resolved ambiguity rows.

This checkpoint is static evidence only. It does not change the loopback
runtime result, TLS diagnosis, or live-service boundary.

### v343 TDrawingPanel residual translation

The v343 pass is static IDA work only. It starts from the verified v342
database and reviews source methods at 0x117e18, 0x118208, and 0x11a254
against target methods at 0x11a8c8, 0x11acb8, and 0x11cd54. It does not require
an APK, emulator, server, or live endpoint.

Capture compact pseudocode with tools/ida_dump_function_evidence.py, using the
same IDALIB environment shown in the v342 section. The source request is
0x117e18,0x118208,0x11a254. The target request is 0x11a8c8,0x11acb8,0x11cd54.

Generate the reviewed three-row artifact:

    python3 tools/generate_spectron_drawing_panel_core_residual_anchors.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v342_input_modifiers_residual.json \
      --semantic-map artifacts/spectron_semantic_translation_v342.json \
      --source-evidence /tmp/graal-source-drawingpanel-v343.json \
      --target-evidence /tmp/graal-target-drawingpanel-v343.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260829.json

Apply the artifact to a fresh copy of
spectron_libqplay_translated_v342_input_modifiers_residual.i64 and save
spectron_libqplay_translated_v343_drawing_panel_residual.i64 with
tools/ida_apply_spectron_manual_anchors.py. Use the same IDALIB environment
shown in the v342 section, with these variables:

    SPECTRON_MANUAL_APPLY=1
    SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260829.json
    SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_drawing_panel_residual_manual_translation_anchors_20260829
    SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v343_drawing_panel_residual.i64
    SPECTRON_MANUAL_REPORT=/tmp/spectron_drawing_panel_residual_manual_translation_application_20260829.json

Reopen the saved copy with tools/ida_verify_spectron_manual_anchors.py, using
the same anchor and expected-artifact variables and
SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_drawing_panel_residual_manual_translation_verification_20260829.json.
The application report must contain three resolved functions, three renames,
three evidence comments, zero failures, and a successful save. The reopen
report must contain three verified names in an 11,707-function database.

Refresh the feature export and the name and dynamic audits using the commands
in the v342 section, changing the output suffix to v343. Carry the semantic
map forward and build the strict checkpoint:

    python3 tools/carry_forward_spectron_semantic_translation_v343.py \
      --parent-map artifacts/spectron_semantic_translation_v342.json \
      --target-features artifacts/spectron_features_v343_drawing_panel_residual.json \
      --anchor-artifact artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260829.json \
      --output artifacts/spectron_semantic_translation_v343.json

    python3 tools/generate_spectron_translation_checkpoint_v343.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v342.json \
      --database /path/to/spectron_libqplay_translated_v343_drawing_panel_residual.i64 \
      --anchor-artifact artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260829.json \
      --application-report artifacts/spectron_drawing_panel_residual_manual_translation_application_20260829.json \
      --verification-report artifacts/spectron_drawing_panel_residual_manual_translation_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v343.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v343.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v343.json \
      --semantic-map artifacts/spectron_semantic_translation_v343.json \
      --feature-export artifacts/spectron_features_v343_drawing_panel_residual.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v343.json

    python3 tools/validate_research_archive.py

The expected v343 database hash is
`bb51b5b8ceb13acae2d5843019473ab988f0f931d2a5bce484f0ff3f32103ae8`.
Expected totals are 6,435 translated aliases, 419 target-only descriptive
labels, 794 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,789 source-backed dynamic symbols, 1,682 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The anchor summary is three
high-confidence rows, three exact metric matches, three pseudocode-backed
rows, and three new-context rows.

### v342 TInput modifier-state residual translation

The v342 pass is static IDA work only. It starts from the verified v341
database and reviews source methods at 0x168ff0, 0x169024, and 0x169058
against target methods at 0x16c9f0, 0x16ca24, and 0x16ca58. It does not
require an APK, emulator, server, or live endpoint.

Capture compact pseudocode with tools/ida_dump_function_evidence.py, using the
same IDALIB environment shown in the v341 section. The source request is
0x168ff0,0x169024,0x169058. The target request is 0x16c9f0,0x16ca24,0x16ca58.

Generate the reviewed three-row artifact:

    python3 tools/generate_spectron_input_modifiers_residual_anchors.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v341_colorset_residual.json \
      --semantic-map artifacts/spectron_semantic_translation_v341.json \
      --source-evidence /tmp/graal-source-input-mod-v342.json \
      --target-evidence /tmp/graal-target-input-mod-v342.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_input_modifiers_residual_manual_translation_anchors_20260829.json

Apply the artifact to a fresh copy of
spectron_libqplay_translated_v341_colorset_residual.i64 and save
spectron_libqplay_translated_v342_input_modifiers_residual.i64 with
tools/ida_apply_spectron_manual_anchors.py. Use the same IDALIB environment
shown in the v341 section, with these variables:

    SPECTRON_MANUAL_APPLY=1
    SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_input_modifiers_residual_manual_translation_anchors_20260829.json
    SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_input_modifiers_residual_manual_translation_anchors_20260829
    SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v342_input_modifiers_residual.i64
    SPECTRON_MANUAL_REPORT=/tmp/spectron_input_modifiers_residual_manual_translation_application_20260829.json

Reopen the saved copy with tools/ida_verify_spectron_manual_anchors.py, using
the same anchor and expected-artifact variables and
SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_input_modifiers_residual_manual_translation_verification_20260829.json.
The application report must contain three resolved functions, three renames,
three evidence comments, zero failures, and a successful save. The reopen
report must contain three verified names in an 11,707-function database.

Refresh the feature export and the name and dynamic audits using the commands
in the v341 section, changing the output suffix to v342. Carry the semantic
map forward and build the strict checkpoint:

    python3 tools/carry_forward_spectron_semantic_translation_v342.py \
      --parent-map artifacts/spectron_semantic_translation_v341.json \
      --target-features artifacts/spectron_features_v342_input_modifiers_residual.json \
      --anchor-artifact artifacts/spectron_input_modifiers_residual_manual_translation_anchors_20260829.json \
      --output artifacts/spectron_semantic_translation_v342.json

    python3 tools/generate_spectron_translation_checkpoint_v342.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v341.json \
      --database /path/to/spectron_libqplay_translated_v342_input_modifiers_residual.i64 \
      --anchor-artifact artifacts/spectron_input_modifiers_residual_manual_translation_anchors_20260829.json \
      --application-report artifacts/spectron_input_modifiers_residual_manual_translation_application_20260829.json \
      --verification-report artifacts/spectron_input_modifiers_residual_manual_translation_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v342.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v342.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v342.json \
      --semantic-map artifacts/spectron_semantic_translation_v342.json \
      --feature-export artifacts/spectron_features_v342_input_modifiers_residual.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v342.json

    python3 tools/validate_research_archive.py

The expected v342 database hash is
`ec767e7a86e12b169f0053d4d1b783aa01fc8b7efa90863b69912553aa451ae7`.
Expected totals are 6,432 translated aliases, 419 target-only descriptive
labels, 797 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,786 source-backed dynamic symbols, 1,685 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The anchor summary is three
high-confidence rows, three exact metric matches, three pseudocode-backed
rows, and three new-context rows.

### v341 GuiControl color-setter residual translation

The v341 pass is static IDA work only. It starts from the verified v340
database and reviews source methods at 0x1ba168, 0x1ba1ac, 0x1ba1f0, and
0x1ba234 against target methods at 0x1bea8c, 0x1bead0, 0x1beb14, and
0x1beb58. It does not require an APK, emulator, server, or live endpoint.

Capture compact pseudocode with tools/ida_dump_function_evidence.py, using the
same IDALIB environment shown in the v340 section. The source request is
0x1ba168,0x1ba1ac,0x1ba1f0,0x1ba234. The target request is
0x1bea8c,0x1bead0,0x1beb14,0x1beb58.

Generate the reviewed four-row artifact:

    python3 tools/generate_spectron_colorset_residual_anchors.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v340_tiles_residual.json \
      --semantic-map artifacts/spectron_semantic_translation_v340.json \
      --source-evidence /tmp/graal-source-colorset-v341.json \
      --target-evidence /tmp/graal-target-colorset-v341.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_colorset_residual_manual_translation_anchors_20260829.json

Apply the artifact to a fresh copy of
spectron_libqplay_translated_v340_tiles_residual.i64 and save
spectron_libqplay_translated_v341_colorset_residual.i64 with
tools/ida_apply_spectron_manual_anchors.py. Use the same IDALIB environment
shown in the v340 section, with these variables:

    SPECTRON_MANUAL_APPLY=1
    SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_colorset_residual_manual_translation_anchors_20260829.json
    SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_colorset_residual_manual_translation_anchors_20260829
    SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v341_colorset_residual.i64
    SPECTRON_MANUAL_REPORT=/tmp/spectron_colorset_residual_manual_translation_application_20260829.json

Reopen the saved copy with tools/ida_verify_spectron_manual_anchors.py, using
the same anchor and expected-artifact variables and
SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_colorset_residual_manual_translation_verification_20260829.json.
The application report must contain four resolved functions, four renames,
four evidence comments, zero failures, and a successful save. The reopen
report must contain four verified names in an 11,707-function database.

Refresh the feature export and the name and dynamic audits using the commands
in the v340 section, changing the output suffix to v341. Carry the semantic
map forward and build the strict checkpoint:

    python3 tools/carry_forward_spectron_semantic_translation_v341.py \
      --parent-map artifacts/spectron_semantic_translation_v340.json \
      --target-features artifacts/spectron_features_v341_colorset_residual.json \
      --anchor-artifact artifacts/spectron_colorset_residual_manual_translation_anchors_20260829.json \
      --output artifacts/spectron_semantic_translation_v341.json

    python3 tools/generate_spectron_translation_checkpoint_v341.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v340.json \
      --database /path/to/spectron_libqplay_translated_v341_colorset_residual.i64 \
      --anchor-artifact artifacts/spectron_colorset_residual_manual_translation_anchors_20260829.json \
      --application-report artifacts/spectron_colorset_residual_manual_translation_application_20260829.json \
      --verification-report artifacts/spectron_colorset_residual_manual_translation_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v341.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v341.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v341.json \
      --semantic-map artifacts/spectron_semantic_translation_v341.json \
      --feature-export artifacts/spectron_features_v341_colorset_residual.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v341.json

    python3 tools/validate_research_archive.py

The expected v341 database hash is
f892d0eb81a79a242c41aeb19742dc33693863fd0373217727d2bba154d33d73.
Expected totals are 6,429 translated aliases, 419 target-only descriptive
labels, 800 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,783 source-backed dynamic symbols, 1,688 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The anchor summary is four
high-confidence rows, four exact metric matches, four pseudocode-backed rows,
and four new-context rows.

### v340 TTilesBlock and TTilesPanel residual translation

The v340 pass is static IDA work only. It starts from the verified v339
database and reviews source methods at 0x230a2c, 0x230b5c, 0x230db4, and
0x230ea0 against target methods at 0x23a9a4, 0x23aad4, 0x23ad2c, and
0x23ae18. It does not require an APK, emulator, server, or live endpoint.

Capture compact pseudocode with tools/ida_dump_function_evidence.py, using the
same IDALIB environment shown in the v339 section. The source request is
0x230a2c,0x230b5c,0x230db4,0x230ea0. The target request is
0x23a9a4,0x23aad4,0x23ad2c,0x23ae18.

Generate the reviewed four-row artifact:

    python3 tools/generate_spectron_tiles_residual_anchors.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v339_geometry_residual.json \
      --semantic-map artifacts/spectron_semantic_translation_v339.json \
      --source-evidence /tmp/graal-source-tiles-v340.json \
      --target-evidence /tmp/graal-target-tiles-v340.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_tiles_residual_manual_translation_anchors_20260829.json

Apply the artifact to a fresh copy of
spectron_libqplay_translated_v339_geometry_residual.i64 and save
spectron_libqplay_translated_v340_tiles_residual.i64 with
tools/ida_apply_spectron_manual_anchors.py. Use the same IDALIB environment
shown in the v339 section, with these variables:

    SPECTRON_MANUAL_APPLY=1
    SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_tiles_residual_manual_translation_anchors_20260829.json
    SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tiles_residual_manual_translation_anchors_20260829
    SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v340_tiles_residual.i64
    SPECTRON_MANUAL_REPORT=/tmp/spectron_tiles_residual_manual_translation_application_20260829.json

Reopen the saved copy with tools/ida_verify_spectron_manual_anchors.py, using
the same anchor and expected-artifact variables and
SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_tiles_residual_manual_translation_verification_20260829.json.
The application report must contain four resolved functions, four renames,
four evidence comments, zero failures, and a successful save. The reopen
report must contain four verified names in an 11,707-function database.

Refresh the feature export and the name and dynamic audits using the commands
in the v339 section, changing the output suffix to v340. Carry the semantic
map forward and build the strict checkpoint:

    python3 tools/carry_forward_spectron_semantic_translation_v340.py \
      --parent-map artifacts/spectron_semantic_translation_v339.json \
      --target-features artifacts/spectron_features_v340_tiles_residual.json \
      --anchor-artifact artifacts/spectron_tiles_residual_manual_translation_anchors_20260829.json \
      --output artifacts/spectron_semantic_translation_v340.json

    python3 tools/generate_spectron_translation_checkpoint_v340.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v339.json \
      --database /path/to/spectron_libqplay_translated_v340_tiles_residual.i64 \
      --anchor-artifact artifacts/spectron_tiles_residual_manual_translation_anchors_20260829.json \
      --application-report artifacts/spectron_tiles_residual_manual_translation_application_20260829.json \
      --verification-report artifacts/spectron_tiles_residual_manual_translation_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v340.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v340.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v340.json \
      --semantic-map artifacts/spectron_semantic_translation_v340.json \
      --feature-export artifacts/spectron_features_v340_tiles_residual.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v340.json

    python3 tools/validate_research_archive.py

The expected v340 database hash is
24a96367fa0730d1a125d146f4fd8e304ba96f6676c15deb2807d085671734d1.
Expected totals are 6,425 translated aliases, 419 target-only descriptive
labels, 804 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,779 source-backed dynamic symbols, 1,692 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The anchor summary is four
high-confidence rows, four exact metric matches, four pseudocode-backed rows,
three semantic-map promotions, and one new-context row.

### v339 rectangle and region geometry residual translation

The v339 pass is static IDA work only. It starts from the verified v338
database and reviews source methods at 0x1e64f8, 0x1e6574, 0x1e65f0, and
0x1e65f8 against target methods at 0x1ea7e4, 0x1ea860, 0x1ea8dc, and
0x1ea8e4. It does not require an APK, emulator, server, or live endpoint.

Capture compact pseudocode with tools/ida_dump_function_evidence.py, using the
same IDALIB environment shown in the v338 section. The source request is
0x1e64f8,0x1e6574,0x1e65f0,0x1e65f8. The target request is
0x1ea7e4,0x1ea860,0x1ea8dc,0x1ea8e4.

Generate the reviewed four-row artifact:

    python3 tools/generate_spectron_geometry_residual_anchors.py \
      --original-features /tmp/original_features_v3_current.json \
      --spectron-features artifacts/spectron_features_v338_html_page_lifecycle.json \
      --semantic-map artifacts/spectron_semantic_translation_v338.json \
      --source-evidence /tmp/graal-source-geometry-v339.json \
      --target-evidence /tmp/graal-target-geometry-v339.json \
      --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
      --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
      --output artifacts/spectron_geometry_residual_manual_translation_anchors_20260829.json

Apply the artifact to a fresh copy of
spectron_libqplay_translated_v338_html_page_lifecycle.i64 and save
spectron_libqplay_translated_v339_geometry_residual.i64 with
tools/ida_apply_spectron_manual_anchors.py. The application environment is:

    env IDADIR=/path/to/ida-pro-9.3 \
      IDAUSR=/tmp/graal-idalib-user \
      SPECTRON_MANUAL_APPLY=1 \
      SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_geometry_residual_manual_translation_anchors_20260829.json \
      SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_geometry_residual_manual_translation_anchors_20260829 \
      SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v339_geometry_residual.i64 \
      SPECTRON_MANUAL_REPORT=/tmp/spectron_geometry_residual_manual_translation_application_20260829.json \
      /path/to/idalib-python /path/to/idalib/examples/idacli.py \
      -f /path/to/spectron_libqplay_translated_v338_html_page_lifecycle.i64 \
      -s tools/ida_apply_spectron_manual_anchors.py

Reopen the saved copy with tools/ida_verify_spectron_manual_anchors.py, setting
the same anchor and expected-artifact variables and
SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_geometry_residual_manual_translation_verification_20260829.json.
The application report must contain four resolved functions, four renames,
four evidence comments, zero failures, and a successful save. The reopen
report must contain four verified names in an 11,707-function database.

Refresh the feature export and the name and dynamic audits using the commands
in the v338 section, changing the output suffix to v339. Carry the semantic
map forward and build the strict checkpoint:

    python3 tools/carry_forward_spectron_semantic_translation_v339.py \
      --parent-map artifacts/spectron_semantic_translation_v338.json \
      --target-features artifacts/spectron_features_v339_geometry_residual.json \
      --anchor-artifact artifacts/spectron_geometry_residual_manual_translation_anchors_20260829.json \
      --output artifacts/spectron_semantic_translation_v339.json

    python3 tools/generate_spectron_translation_checkpoint_v339.py \
      --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v338.json \
      --database /path/to/spectron_libqplay_translated_v339_geometry_residual.i64 \
      --anchor-artifact artifacts/spectron_geometry_residual_manual_translation_anchors_20260829.json \
      --application-report artifacts/spectron_geometry_residual_manual_translation_application_20260829.json \
      --verification-report artifacts/spectron_geometry_residual_manual_translation_verification_20260829.json \
      --name-audit artifacts/spectron_name_coverage_audit_v339.json \
      --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v339.json \
      --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v339.json \
      --semantic-map artifacts/spectron_semantic_translation_v339.json \
      --feature-export artifacts/spectron_features_v339_geometry_residual.json \
      --output artifacts/spectron_translation_checkpoint_20260829_v339.json

    python3 tools/validate_research_archive.py

The expected v339 database hash is
d50a0755bb461dada6b011b4df4ca01f9a0cbaf0112805b0ff1e5ab48764bebe.
Expected totals are 6,421 translated aliases, 419 target-only descriptive
labels, 808 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,774 source-backed dynamic symbols, 1,696 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The anchor summary is four
high-confidence rows, four exact metric matches, four pseudocode-backed rows,
three semantic-map promotions, and one new-context row.

### v338 THTMLPage lifecycle residual translation

The v338 pass is static IDA work only. It starts from the verified v337
database and reviews source methods at `0x1d1318`, `0x1d1418`, `0x1d14b0`,
`0x1d14f8`, `0x1d169c`, `0x1d276c`, and `0x1d2ad0` against target methods at
`0x1d5f6c`, `0x1d606c`, `0x1d6104`, `0x1d614c`, `0x1d62f0`, `0x1d73c0`, and
`0x1d7724`. It does not require an APK, emulator, server, or live endpoint.

Capture compact pseudocode with `tools/ida_dump_function_evidence.py`, using
the same IDALIB environment shown in the v337 section. The source request is
`0x1d1318,0x1d1418,0x1d14b0,0x1d14f8,0x1d169c,0x1d276c,0x1d2ad0`. The target
request is
`0x1d5f6c,0x1d606c,0x1d6104,0x1d614c,0x1d62f0,0x1d73c0,0x1d7724`.

Generate the reviewed seven-row artifact:

```bash
python3 tools/generate_spectron_html_page_lifecycle_anchors.py \
  --original-features /tmp/original_features_v3_current.json \
  --spectron-features artifacts/spectron_features_v337_libjpeg_helper_residual.json \
  --semantic-map artifacts/spectron_semantic_translation_v337.json \
  --source-evidence /tmp/graal-source-html-page-life.json \
  --target-evidence /tmp/graal-target-html-page-life.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_html_page_lifecycle_manual_translation_anchors_20260829.json
```

Apply the artifact to a fresh copy of
`spectron_libqplay_translated_v337_libjpeg_helper_residual.i64` and reopen
verify the resulting
`spectron_libqplay_translated_v338_html_page_lifecycle.i64` with the manual
anchor scripts. The application report must contain seven resolved functions,
seven renames, seven evidence comments, zero failures, and a successful save.
The reopen report must contain seven verified names in an 11,707-function
database.

Carry the semantic map forward and build the strict checkpoint:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v338.py \
  --parent-map artifacts/spectron_semantic_translation_v337.json \
  --target-features artifacts/spectron_features_v338_html_page_lifecycle.json \
  --anchor-artifact artifacts/spectron_html_page_lifecycle_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v338.json

python3 tools/generate_spectron_translation_checkpoint_v338.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v337.json \
  --database /path/to/spectron_libqplay_translated_v338_html_page_lifecycle.i64 \
  --anchor-artifact artifacts/spectron_html_page_lifecycle_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_html_page_lifecycle_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_html_page_lifecycle_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v338.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v338.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v338.json \
  --semantic-map artifacts/spectron_semantic_translation_v338.json \
  --feature-export artifacts/spectron_features_v338_html_page_lifecycle.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v338.json

python3 tools/validate_research_archive.py
```

The expected v338 database hash is
`26584982aa976361088e7978b162d12e1be4bf2bf9991bf9484c56e92bba8c2d`.
Expected totals are 6,417 translated aliases, 419 target-only descriptive
labels, 812 retained target names, seven JNI exports, 4,052 other IDA or PLT
names, 4,769 source-backed dynamic symbols, 1,700 exact retained dynamic
symbols, and 5,782 exact dynamic function starts. The anchor summary is seven
high-confidence rows, seven exact metric matches, seven pseudocode-backed
rows, and no semantic-map promotions.

### v337 libjpeg helper residual translation

The v337 pass is static IDA work only. It starts from the verified v336
database and reviews source helpers at `0x294ee8`, `0x294ef0`, `0x294ef8`,
`0x294f00`, `0x294f08`, `0x294f10`, `0x294f38`, `0x294f40`, `0x297e40`,
`0x297e50`, `0x297ec8`, and `0x297edc` against target helpers at `0x2a2358`,
`0x2a2360`, `0x2a2368`, `0x2a2370`, `0x2a2378`, `0x2a2380`, `0x2a23a8`,
`0x2a23b0`, `0x2a52b0`, `0x2a52c0`, `0x2a5338`, and `0x2a534c`. It does not
require an APK, emulator, server, or live endpoint.

Capture compact pseudocode with `tools/ida_dump_function_evidence.py`, using
the same IDALIB environment shown in the v336 section. The source request is
`0x294ee8,0x294ef0,0x294ef8,0x294f00,0x294f08,0x294f10,0x294f38,0x294f40,0x297e40,0x297e50,0x297ec8,0x297edc`.
The target request is
`0x2a2358,0x2a2360,0x2a2368,0x2a2370,0x2a2378,0x2a2380,0x2a23a8,0x2a23b0,0x2a52b0,0x2a52c0,0x2a5338,0x2a534c`.

Generate the reviewed twelve-row artifact:

```bash
python3 tools/generate_spectron_libjpeg_helper_residual_anchors.py \
  --original-features /tmp/original_features_v3_current.json \
  --spectron-features artifacts/spectron_features_v336_format2_residual.json \
  --semantic-map artifacts/spectron_semantic_translation_v336.json \
  --source-evidence /tmp/graal-source-libjpeg-helper.json \
  --target-evidence /tmp/graal-target-libjpeg-helper.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_libjpeg_helper_residual_manual_translation_anchors_20260829.json
```

Apply the artifact to a fresh copy of
`spectron_libqplay_translated_v336_format2_residual.i64` and reopen-verify
the resulting
`spectron_libqplay_translated_v337_libjpeg_helper_residual.i64` with the
manual-anchor scripts. The application report must contain twelve resolved
functions, twelve renames, twelve evidence comments, zero failures, and a
successful save. The reopen report must contain twelve verified names in an
11,707-function database.

Refresh the feature export and name and dynamic audits using the commands in
the v336 section, changing the output suffix to `v337`. Carry the semantic map
forward and build the strict checkpoint:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v337.py \
  --parent-map artifacts/spectron_semantic_translation_v336.json \
  --target-features artifacts/spectron_features_v337_libjpeg_helper_residual.json \
  --anchor-artifact artifacts/spectron_libjpeg_helper_residual_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v337.json

python3 tools/generate_spectron_translation_checkpoint_v337.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v336.json \
  --database /path/to/spectron_libqplay_translated_v337_libjpeg_helper_residual.i64 \
  --anchor-artifact artifacts/spectron_libjpeg_helper_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_libjpeg_helper_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_libjpeg_helper_residual_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v337.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v337.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v337.json \
  --semantic-map artifacts/spectron_semantic_translation_v337.json \
  --feature-export artifacts/spectron_features_v337_libjpeg_helper_residual.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v337.json

python3 tools/validate_research_archive.py
```

The expected v337 database hash is
`391d3bb01245f636760daeb8cef80012e602dfc04423d104a44ceb8e1e4d7113`.
Expected audit totals are 6,410 translated aliases, 419 target-only
descriptive labels, 819 retained target names, seven JNI exports, 4,052
other IDA or PLT names, 4,762 source-backed dynamic symbols, 1,707 exact
retained dynamic symbols, and 5,782 exact dynamic function starts. The anchor
summary is twelve high-confidence rows, twelve exact metric matches, twelve
pseudocode-backed rows, and no semantic-map promotions.

### v336 GSFunctionsInitstaticscriptvars and TFormat2 residual translation

The v336 pass is static IDA work only. It starts from the verified v335
database and reviews source boundaries `0x20cd20`, `0x20ce88`, `0x20cf10`,
`0x20cfd0`, `0x20d040`, `0x20d0b0`, `0x20d0c4`, `0x20d148`, and `0x20d1d4`
against target boundaries `0x2130b0`, `0x213218`, `0x2132a0`, `0x213360`,
`0x2133d0`, `0x213440`, `0x213454`, `0x2134f0`, and `0x213598`. It does not
require an APK, a running emulator, a server, or a live endpoint.

Capture compact pseudocode with `tools/ida_dump_function_evidence.py`, using
the same IDALIB environment shown in the v335 section. The source request is
`0x20cd20,0x20ce88,0x20cf10,0x20cfd0,0x20d040,0x20d0b0,0x20d0c4,0x20d148,0x20d1d4`;
the target request is
`0x2130b0,0x213218,0x2132a0,0x213360,0x2133d0,0x213440,0x213454,0x2134f0,0x213598`.

Generate and apply the reviewed nine-row artifact:

```bash
python3 tools/generate_spectron_format2_residual_anchors.py \
  --original-features /tmp/original_features_current.json \
  --spectron-features artifacts/spectron_features_v335_adventure_static_residual.json \
  --semantic-map artifacts/spectron_semantic_translation_v335.json \
  --source-evidence /tmp/graal-source-format2-residual.json \
  --target-evidence /tmp/graal-target-format2-residual.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_format2_residual_manual_translation_anchors_20260829.json
```

Apply the artifact to a fresh copy of
`spectron_libqplay_translated_v335_adventure_static_residual.i64` and
reopen-verify the resulting
`spectron_libqplay_translated_v336_format2_residual.i64` with the manual-anchor
scripts. The application report must contain nine resolved functions, nine
renames, nine evidence comments, zero failures, and a successful save. The
reopen report must contain nine verified names in an 11,707-function database.

Refresh the feature export and name and dynamic audits using the commands in
the v335 section, changing the output suffix to `v336`. Carry the semantic map
forward and build the strict checkpoint:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v336.py \
  --parent-map artifacts/spectron_semantic_translation_v335.json \
  --target-features artifacts/spectron_features_v336_format2_residual.json \
  --anchor-artifact artifacts/spectron_format2_residual_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v336.json

python3 tools/generate_spectron_translation_checkpoint_v336.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v335.json \
  --database /path/to/spectron_libqplay_translated_v336_format2_residual.i64 \
  --anchor-artifact artifacts/spectron_format2_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_format2_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_format2_residual_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v336.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v336.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v336.json \
  --semantic-map artifacts/spectron_semantic_translation_v336.json \
  --feature-export artifacts/spectron_features_v336_format2_residual.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v336.json

python3 tools/validate_research_archive.py
```

The expected v336 database hash is
`55662a1b9e5989c1e14350ab585015ccb6af0af123f12fab0dcab414f54ca199`.
Expected audit totals are 6,398 translated aliases, 419 target-only
descriptive labels, 831 retained target names, 7 JNI exports, 4,052 other
IDA or PLT names, 4,750 source-backed dynamic symbols, 1,719 exact retained
dynamic symbols, and 5,782 exact dynamic function starts.

### v335 GSFunctionsClient and TAdventure residual translation

The v335 pass is static IDA work only. It starts from the verified v334
database and reviews source boundaries `0x15ae0c`, `0x15b4d0`, `0x15bf38`,
and `0x15c224` against target boundaries `0x15de64`, `0x15e528`, `0x15ef90`,
and `0x15f27c`. It does not require an APK, a running emulator, a server, or
a live endpoint.

Capture compact pseudocode with `tools/ida_dump_function_evidence.py`, using
the same IDALIB environment shown in the v334 section. The source request is
`0x15ae0c,0x15b4d0,0x15bf38,0x15c224`; the target request is
`0x15de64,0x15e528,0x15ef90,0x15f27c`.

Generate and apply the reviewed four-row artifact:

```bash
python3 tools/generate_spectron_adventure_static_residual_anchors.py \
  --original-features /tmp/original_features_current.json \
  --spectron-features artifacts/spectron_features_v334_bitmap_jpeg_static.json \
  --semantic-map artifacts/spectron_semantic_translation_v334.json \
  --source-evidence /tmp/graal-source-gsfunctions-static.json \
  --source-evidence /tmp/graal-source-adventure-residual.json \
  --target-evidence /tmp/graal-target-gsfunctions-static.json \
  --target-evidence /tmp/graal-target-adventure-residual.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_adventure_static_residual_manual_translation_anchors_20260829.json
```

Apply the artifact to a fresh copy of
`spectron_libqplay_translated_v334_bitmap_jpeg_static.i64` and reopen-verify
the resulting
`spectron_libqplay_translated_v335_adventure_static_residual.i64` with the
manual-anchor scripts. The application report must contain four resolved
functions, four renames, four evidence comments, zero failures, and a
successful save. The reopen report must contain four verified names in an
11,707-function database.

Refresh the feature export and name and dynamic audits using the commands in
the v334 section, changing the output suffix to `v335`. Carry the semantic map
forward and build the strict checkpoint:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v335.py \
  --parent-map artifacts/spectron_semantic_translation_v334.json \
  --target-features artifacts/spectron_features_v335_adventure_static_residual.json \
  --anchor-artifact artifacts/spectron_adventure_static_residual_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v335.json

python3 tools/generate_spectron_translation_checkpoint_v335.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v334.json \
  --database /path/to/spectron_libqplay_translated_v335_adventure_static_residual.i64 \
  --anchor-artifact artifacts/spectron_adventure_static_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_adventure_static_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_adventure_static_residual_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v335.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v335.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v335.json \
  --semantic-map artifacts/spectron_semantic_translation_v335.json \
  --feature-export artifacts/spectron_features_v335_adventure_static_residual.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v335.json

python3 tools/validate_research_archive.py
```

The expected v335 database hash is
`dae970eb4edf7237544073da7badb3cfe0bd9d3ccb03e8ec9bde5b5c7de73a16`.
Expected audit totals are 6,389 translated aliases, 419 target-only
descriptive labels, 840 retained target names, 7 JNI exports, 4,052 other
IDA or PLT names, 4,740 source-backed dynamic symbols, 1,728 exact retained
dynamic symbols, and 5,782 exact dynamic function starts.

### v334 bitmap JPEG static translation

The v334 pass is static IDA work only. It starts from the verified v333
database and reviews the JPEG static property initializer at source
`0x151394` and target `0x1541bc`. It does not require an APK, an emulator, a
server, or a live endpoint.

Capture compact pseudocode from the source and target copies:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x151394 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-bitmap-jpeg-static.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/libqplay_translated_all_v4.i64 \
  -s tools/ida_dump_function_evidence.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x1541bc \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-target-bitmap-jpeg-static.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v333_hashintvar_residual.i64 \
  -s tools/ida_dump_function_evidence.py
```

Generate the reviewed anchor artifact:

```bash
python3 tools/generate_spectron_bitmap_jpeg_static_anchors.py \
  --original-features /tmp/original_features_current.json \
  --spectron-features artifacts/spectron_features_v333_hashintvar_residual.json \
  --semantic-map artifacts/spectron_semantic_translation_v333.json \
  --source-evidence /tmp/graal-source-bitmap-jpeg-static.json \
  --target-evidence /tmp/graal-target-bitmap-jpeg-static.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_bitmap_jpeg_static_manual_translation_anchors_20260829.json
```

The expected artifact contains one high-confidence layout-change row with
source and target pseudocode, zero exact full-metric rows, zero semantic-map
promotions, and the alias
`v18_TBitmap_jpeg_initStaticScriptVars_void` at target `0x1541bc`.

Apply it to a separate copy and reopen-verify with the same
`tools/ida_apply_spectron_manual_anchors.py` and
`tools/ida_verify_spectron_manual_anchors.py` workflow used in the v333
section. Change the input and output names to
`spectron_libqplay_translated_v333_hashintvar_residual.i64` and
`spectron_libqplay_translated_v334_bitmap_jpeg_static.i64`, and change the
anchor, application, and verification report names to the v334 artifacts.
The application report must contain one resolved function, one rename, one
evidence comment, zero failures, and a successful save. The reopen report must
contain one verified name in an 11,707-function database.

Refresh the target feature export and the four name and dynamic audits as
described in the v333 section, using the v334 suffix. Carry the semantic map
forward and build the strict checkpoint:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v334.py \
  --parent-map artifacts/spectron_semantic_translation_v333.json \
  --target-features artifacts/spectron_features_v334_bitmap_jpeg_static.json \
  --anchor-artifact artifacts/spectron_bitmap_jpeg_static_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v334.json

python3 tools/generate_spectron_translation_checkpoint_v334.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v333.json \
  --database /path/to/spectron_libqplay_translated_v334_bitmap_jpeg_static.i64 \
  --anchor-artifact artifacts/spectron_bitmap_jpeg_static_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_bitmap_jpeg_static_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_bitmap_jpeg_static_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v334.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v334.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v334.json \
  --semantic-map artifacts/spectron_semantic_translation_v334.json \
  --feature-export artifacts/spectron_features_v334_bitmap_jpeg_static.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v334.json

python3 tools/validate_research_archive.py
```

The expected v334 database hash is
`c2002066a0412b180afd6abb36fe08f0873403d3068a2a0bdd88deb997101398`.
The audits should report 6,385 translated aliases, 419 target-only
descriptive labels, 844 retained target names, 7 JNI exports, 4,052 other
IDA or PLT names, 4,736 source-backed dynamic symbols, 1,732 exact retained
dynamic symbols, and 5,782 exact dynamic function starts. This checkpoint is
static evidence only. It does not change the loopback runtime result, TLS
diagnosis, or live-service boundary.

### v333 THashIntVar residual translation

The v333 pass is static IDA work only. It starts from the verified v332
database and reviews the two raw destructor entries between the translated
`THTMLColors` and `TImageAnimation` blocks. It does not require an APK, a
running emulator, a server, or a live endpoint.

Capture compact pseudocode from the source and target copies:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x11b438,0x11b44c \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-hashintvar.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/libqplay_translated_all_v4.i64 \
  -s tools/ida_dump_function_evidence.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x11df60,0x11df74 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-target-hashintvar.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  -s tools/ida_dump_function_evidence.py
```

Generate the reviewed two-row anchor artifact:

```bash
python3 tools/generate_spectron_hashintvar_residual_anchors.py \
  --original-features /tmp/original_features_current.json \
  --spectron-features artifacts/spectron_features_v332_paneloperation_residual.json \
  --semantic-map artifacts/spectron_semantic_translation_v332.json \
  --source-evidence /tmp/graal-source-hashintvar.json \
  --target-evidence /tmp/graal-target-hashintvar.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json
```

Both rows are high-confidence layout matches. The artifact records zero exact
full-metric rows, two register-detail layout rows, pseudocode for both source
and target functions, and no prior semantic-map promotion.

Apply to a separate input copy and reopen-verify with:

```bash
cp /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  /tmp/spectron_v333_anchor_apply_input.i64

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_hashintvar_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v333_hashintvar_residual.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_hashintvar_residual_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v333_anchor_apply_input.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_hashintvar_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/path/to/libqplay/artifacts/spectron_hashintvar_residual_manual_translation_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v333_hashintvar_residual.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The application report must contain two resolved functions, two renames, two
evidence comments, zero failures, and a successful save. The reopen report
must contain two verified names in an 11,707-function database. Refresh the
target feature export and the four name and dynamic audits as described in the
v332 section, changing the output suffix to `v333`.

The semantic map is carried forward from v332 because the current source
IDALIB export has 11,297 functions while the reviewed source snapshot has
11,308. Run:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v333.py \
  --parent-map artifacts/spectron_semantic_translation_v332.json \
  --target-features artifacts/spectron_features_v333_hashintvar_residual.json \
  --anchor-artifact artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v333.json
```

Build the strict checkpoint and validate the archive:

```bash
python3 tools/generate_spectron_translation_checkpoint_v333.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v332.json \
  --database /path/to/spectron_libqplay_translated_v333_hashintvar_residual.i64 \
  --anchor-artifact artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_hashintvar_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_hashintvar_residual_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v333.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v333.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v333.json \
  --semantic-map artifacts/spectron_semantic_translation_v333.json \
  --feature-export artifacts/spectron_features_v333_hashintvar_residual.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v333.json

python3 tools/validate_research_archive.py
```

The expected v333 database hash is
`c6f31412206a9a893fedf594fac90dff2f13be69f2db28fcda80cc2c67ad7f4d`.
The audits should report 6,384 translated aliases, 419 target-only
descriptive labels, 845 retained target names, 7 JNI exports, 4,052 other
IDA or PLT names, 4,735 source-backed dynamic symbols, 1,733 exact retained
dynamic symbols, and 5,782 exact dynamic function starts. This checkpoint is
static evidence only. It does not patch the APK, rerun the loopback client,
alter TLS behavior, contact a game server, or test a live endpoint.

### v332 TPanelOperation residual translation

The v332 pass is static IDA work only. It starts from the verified v331
database and reviews the next contiguous `TPanelOperation` and
`TDrawingPanelProperties` block. It does not require an APK, a running
emulator, a server, or a live endpoint.

The compact evidence was captured from the source block around
`0x11a810` and the target block around `0x11d318`. The target evidence includes
the raw obfuscated operation methods, explicit D1 and D0 destructor symbols,
the properties thunks, and the derived resource-operation destructors. The
anchor generator checks all 20 function boundaries, normalized metrics, raw
names, and source and target pseudocode before writing the artifact.

Generate the reviewed anchors with:

```bash
python3 tools/generate_spectron_paneloperation_residual_anchors.py \
  --original-features /tmp/original_features_current.json \
  --spectron-features artifacts/spectron_features_v331_tscript_var_residual.json \
  --semantic-map artifacts/spectron_semantic_translation_v331.json \
  --source-evidence /tmp/graal-source-paneloperation.json \
  --target-evidence /tmp/graal-target-paneloperation.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json
```

The output has 20 high-confidence rows, 13 exact metric matches, seven
register-detail layout rows, 17 new context anchors, three prior semantic-map
corroborations, and pseudocode for all 20 source and target pairs.

Apply the aliases to a separate input copy. The applier refuses to overwrite
an existing IDA database:

```bash
cp /path/to/spectron_libqplay_translated_v331_tscript_var_residual.i64 \
  /tmp/spectron_v332_anchor_apply_input.i64

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_paneloperation_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_paneloperation_residual_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v332_anchor_apply_input.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py
```

Reopen the saved copy and verify names and function boundaries with the
dedicated verifier:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_paneloperation_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/path/to/libqplay/artifacts/spectron_paneloperation_residual_manual_translation_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The application report must contain 20 resolved functions, 20 renames, 20
evidence comments, zero failures, and a successful save. The reopen report
must contain 20 verified names in an 11,707-function database.

Refresh the target feature export and audits with:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FEATURES_OUT=/path/to/libqplay/artifacts/spectron_features_v332_paneloperation_residual.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  -s tools/ida_export_function_features.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_NAME_COVERAGE_OUTPUT=/path/to/libqplay/artifacts/spectron_name_coverage_audit_v332.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  -s tools/ida_audit_spectron_name_coverage.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_BOUNDARY_AUDIT_OUTPUT=/path/to/libqplay/artifacts/spectron_dynamic_symbol_boundaries_v332.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  -s tools/ida_audit_dynamic_symbol_boundaries.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_DYNAMIC_SYMBOL_COVERAGE_OUTPUT=/path/to/libqplay/artifacts/spectron_dynamic_symbol_coverage_audit_v332.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  -s tools/ida_audit_spectron_dynamic_symbol_coverage.py
```

The source feature snapshot used by the earlier semantic map is not currently
available in `/tmp`. A fresh IDALIB export reports 11,297 source functions,
whereas the reviewed v331 snapshot records 11,308. Because v332 changes
target names only, carry the reviewed semantic map forward and refresh its
target-feature provenance instead of rerunning the matcher against the
different source export:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v332.py \
  --parent-map artifacts/spectron_semantic_translation_v331.json \
  --target-features artifacts/spectron_features_v332_paneloperation_residual.json \
  --anchor-artifact artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v332.json
```

The carry-forward is explicit in the artifact. It keeps 3,716 mapped
functions, 3,656 high-confidence matches, 60 medium-confidence matches, 1,020
ambiguous functions, and 608 unmatched functions. It refreshes the three
target names that were already present in the old automatic map.

Build the strict checkpoint and run the offline archive validator:

```bash
python3 tools/generate_spectron_translation_checkpoint_v332.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v331.json \
  --database /path/to/spectron_libqplay_translated_v332_paneloperation_residual.i64 \
  --anchor-artifact artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_paneloperation_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_paneloperation_residual_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v332.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v332.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v332.json \
  --semantic-map artifacts/spectron_semantic_translation_v332.json \
  --feature-export artifacts/spectron_features_v332_paneloperation_residual.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v332.json

python3 tools/validate_research_archive.py
```

The expected v332 database hash is
`f77edbe5076211bd3bd5a18c549f0c3cbaeeb88d2da7bc9c52a2733c1d87cdc2`.
The audits should report 6,382 translated aliases, 419 target-only
descriptive labels, 847 retained target names, 7 JNI exports, 4,052 other
IDA or PLT names, 4,732 source-backed dynamic symbols, 1,735 exact retained
dynamic symbols, and 5,782 exact dynamic function starts. This checkpoint is
static evidence only. It does not patch the APK, rerun the loopback client,
alter TLS behavior, contact a game server, or test a live endpoint.

### v331 static-variable residual translation

The v331 pass is static IDA work only. It starts from the verified v330
database and reviews the complete static-variable and property-destructor
sequence. The target has raw obfuscated C++ names, so the evidence capture
includes the surrounding translated methods as context.

Capture compact pseudocode from disposable copies with:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x22d240,0x22d254,0x22d270,0x22d278,0x22d2b0,0x22d2b8,0x22d2d4,0x22d2e8,0x22d318,0x22d31c,0x22d338,0x22d3dc,0x22d490,0x22d4c0,0x22d53c,0x22d56c,0x22d58c,0x22d6fc,0x22d784,0x22d7d4,0x22d804,0x22d8e4,0x22d900,0x22d908,0x22d924,0x22d92c,0x22d964,0x22d96c,0x22d9a4,0x22d9ac,0x22d9c0,0x22d9f0 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-tscriptvar-residual.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/libqplay_translated_all_v4.i64 \
  -s tools/ida_dump_function_evidence.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x236d04,0x236d18,0x236d34,0x236d3c,0x236d74,0x236d7c,0x236d98,0x236dac,0x236ddc,0x236de0,0x236dfc,0x236ea0,0x236f80,0x236fb0,0x23702c,0x23705c,0x23707c,0x2371ec,0x237274,0x2372c4,0x2372f4,0x2373d4,0x2373f0,0x2373f8,0x237414,0x23741c,0x237454,0x23745c,0x237494,0x23749c,0x2374b0,0x2374e0,0x237598 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-target-tscriptvar-residual.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v330_tscript_universe_residual.i64 \
  -s tools/ida_dump_function_evidence.py
```

Generate the reviewed anchor artifact from the source and v330 target feature
exports. The generator checks the target names, function boundaries, all
recorded normalized metrics, and the pseudocode rows before writing the
artifact:

```bash
python3 tools/generate_spectron_tscript_var_residual_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features artifacts/spectron_features_v330_tscript_universe_residual.json \
  --semantic-map /tmp/semantic_v330_current.json \
  --source-evidence /tmp/graal-source-tscriptvar-residual.json \
  --target-evidence /tmp/graal-target-tscriptvar-residual.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tscript_var_residual_manual_translation_anchors_20260829.json
```

Apply the 22 aliases to a temporary input copy and save to a new v331 path.
The input and output must be different because the applier refuses to
overwrite an existing IDA database:

```bash
cp /path/to/spectron_libqplay_translated_v330_tscript_universe_residual.i64 \
  /tmp/spectron_v331_anchor_apply_input.i64

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_tscript_var_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tscript_var_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v331_tscript_var_residual.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_tscript_var_residual_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v331_anchor_apply_input.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_tscript_var_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tscript_var_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_tscript_var_residual_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v331_tscript_var_residual.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The expected application result is 22 resolved functions, 22 renames, 22
evidence comments, zero failures, and a successful save. The reopen result is
22 verified names in an 11,707-function database. Refresh the target feature
export, name-origin audit, dynamic boundary audit, dynamic-symbol coverage,
and semantic map, then rebuild the checkpoint with
`tools/generate_spectron_translation_checkpoint_v331.py`.

The v331 anchor summary is 22 high-confidence rows, ten exact metric matches,
twelve register-detail layout rows, and pseudocode for all 44 source and
target rows. The resulting name audit should report 6,362 translated aliases,
419 target-only descriptive labels, 867 retained target names, seven JNI
exports, 4,052 other IDA or PLT names, and zero default names. Dynamic
coverage should report 4,706 source-backed aliases, 1,755 exact retained
names, and 5,782 exact function starts. The v331 database hash is
`f6bb72c43b0022b372d6d98e4143aa920a7e3c43cd5a89ede10e7510cd00178c`.

The complete v331 records are
`artifacts/spectron_tscript_var_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v331_tscript_var_residual.json`,
`artifacts/spectron_name_coverage_audit_v331.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v331.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v331.json`,
`artifacts/spectron_semantic_translation_v331.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v331.json`.

This checkpoint is static evidence only. It does not patch the APK, rerun the
loopback client, alter TLS behavior, contact a game server, or test a live
endpoint.

### v330 TScriptUniverse residual translation

The v330 pass is static IDA work only. It starts from the verified v329
database and reviews six source and target pseudocode pairs in the
`TScriptUniverse` block. It does not require an APK, a running emulator, a
TLS responder, or any network access.

Capture compact pseudocode from disposable copies with:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x22b1f8,0x22b3b4,0x22b3d0,0x22b614,0x22c068,0x22c210 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-tscriptuniverse-residual.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/libqplay_translated_all_v4.i64 \
  -s tools/ida_dump_function_evidence.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x234bc0,0x234d98,0x234db4,0x235000,0x235a50,0x235bf8 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-target-tscriptuniverse-residual.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v329_tscript_space_residuals.i64 \
  -s tools/ida_dump_function_evidence.py
```

Export the source feature file and target features from the v329 database.
The reviewed anchor generator then records the source and target metrics,
pseudocode fingerprints, direct-call context, and the reason for each alias:

```bash
python3 tools/generate_spectron_tscript_universe_residual_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v329_tscript_space_residuals.json \
  --semantic-map /tmp/semantic_v329_current.json \
  --source-evidence /tmp/graal-source-tscriptuniverse-residual.json \
  --target-evidence /tmp/graal-target-tscriptuniverse-residual.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tscript_universe_residual_manual_translation_anchors_20260829.json
```

Apply the six aliases to a fresh v329 copy, saving the result under a new
name. Reopen that result with the verification helper before refreshing the
feature and name audits:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_tscript_universe_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tscript_universe_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v330_tscript_universe_residual.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_tscript_universe_residual_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v329_tscript_space_residuals.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/libqplay/artifacts/spectron_tscript_universe_residual_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_tscript_universe_residual_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_tscript_universe_residual_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v330_tscript_universe_residual.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The expected application result is six resolved functions, six renames, six
evidence comments, zero failures, and a successful save. The reopen result is
six verified names in an 11,707-function database. Refresh the target feature
export, name-origin audit, dynamic boundary audit, dynamic-symbol coverage,
and semantic map, then rebuild the checkpoint:

```bash
python3 tools/generate_spectron_translation_checkpoint_v330.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v329.json \
  --database /path/to/spectron_libqplay_translated_v330_tscript_universe_residual.i64 \
  --anchor-artifact artifacts/spectron_tscript_universe_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_tscript_universe_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_tscript_universe_residual_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v330.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v330.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v330.json \
  --semantic-map artifacts/spectron_semantic_translation_v330.json \
  --feature-export artifacts/spectron_features_v330_tscript_universe_residual.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v330.json

python3 tools/validate_research_archive.py
```

The v330 anchor summary is six high-confidence rows, four exact metric
matches, two register-detail layout rows, and pseudocode for all twelve
source and target functions. The name audit should report 6,340 translated
aliases, 419 target-only descriptive labels, 888 retained target names, seven
JNI exports, 4,053 other IDA or PLT names, and zero default names. Dynamic
coverage should report 4,679 source-backed aliases, 1,776 exact retained
names, and 5,782 exact function starts. The v330 database hash is
`be32d09e08a76b3641beff951644ec78167fcc2735d5fc5ea58f9ee12acf97a1`.

This checkpoint is static evidence only. It does not patch the APK, rerun the
loopback client, alter TLS behavior, contact a game server, or test a live
endpoint.

### v329 TScriptSpace residual translation

The v329 pass continues from the verified v328 database and reviews the next
raw `N67CMatrxw` TScriptSpace boundaries. The source-backed pairs are
`0x227454 -> 0x230198` for `freeSuspendedStates` and
`0x229f44 -> 0x233114` for `joinClass(..., bool)`. The target-only boundaries
are `0x23332c`, a `receiveEvent` overload with a `CanTfaz6bZ` event-name
argument, and `0x2339b4`, a no-argument helper that clears scheduled events
and marks pending actions canceled.

Capture compact pseudocode from disposable copies with:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x227454,0x229f44,0x229ea0,0x22a0b4,0x22a134,0x22a204 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-tspacescheduling.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/libqplay_translated_all_v4.i64 \
  -s tools/ida_dump_function_evidence.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x230198,0x233070,0x233114,0x2332ac,0x23332c,0x2339b4,0x233a68 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-target-tspacescheduling.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v328_script_machine_static_tail.i64 \
  -s tools/ida_dump_function_evidence.py
```

The source evidence also needs the later source rows at `0x22981c` and
`0x229898`, and the target evidence needs the later rows at `0x232944` and
`0x2329c0`, so the companion evidence files used for this checkpoint contain
those neighboring methods. Export target features from the v328 database to
`/tmp/spectron_features_v328_script_machine_static_tail.json`, then generate
the two v329 artifacts:

```bash
python3 tools/generate_spectron_tscript_space_residual_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v328_script_machine_static_tail.json \
  --semantic-map /tmp/semantic_v328_current.json \
  --source-evidence /tmp/graal-source-tspacescheduling.json \
  --source-evidence /tmp/graal-source-tspacescheduling-extra.json \
  --target-evidence /tmp/graal-target-tspacescheduling.json \
  --target-evidence /tmp/graal-target-tspacescheduling-extra.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tscript_space_residual_manual_translation_anchors_20260829.json

python3 tools/generate_spectron_tscript_space_residual_labels.py \
  --spectron-features /tmp/spectron_features_v328_script_machine_static_tail.json \
  --target-evidence /tmp/graal-target-tspacescheduling-extra.json \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_tscript_space_residual_labels_20260829.json
```

Apply the source aliases to a fresh v328 copy with the manual-anchor helper,
then apply the target-only labels to that result with the target-label helper.
Reopen the final database with both verification helpers. The expected result
is two source aliases, two target-only labels, four successful reopen checks,
and 11,707 functions.

After reopening, refresh the feature export and audits. The expected name
origins are:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export       894
target_only_descriptive   419
translated_v18_alias     6334
```

Dynamic coverage remains at 6,770 named rows, 6,600 defined rows, 5,782
exact function starts, 482 data items, 336 other non-code items, and 170
undefined imports. It reports 4,673 source-backed aliases, 1,782 exact
retained names, 136 other retained target names, two target-only descriptive
rows, seven linker-boundary aliases, 169 PLT veneers, and one undefined
`__sF` import. The semantic map remains at 3,716 mapped functions, 3,656
high-confidence matches, 60 medium-confidence matches, 1,020 ambiguous
functions, and 608 unmatched functions.

Rebuild and validate the v329 checkpoint with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v329.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v328.json \
  --database /path/to/spectron_libqplay_translated_v329_tscript_space_residuals.i64 \
  --anchor-artifact artifacts/spectron_tscript_space_residual_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_tscript_space_residual_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_tscript_space_residual_manual_translation_verification_20260829.json \
  --label-artifact artifacts/spectron_tscript_space_residual_labels_20260829.json \
  --label-application-report artifacts/spectron_tscript_space_residual_label_application_20260829.json \
  --label-verification-report artifacts/spectron_tscript_space_residual_label_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v329.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v329.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v329.json \
  --semantic-map artifacts/spectron_semantic_translation_v329.json \
  --feature-export artifacts/spectron_features_v329_tscript_space_residuals.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v329.json

python3 tools/validate_research_archive.py
```

The expected v329 database hash is
`c84c8bd4abe51302092c82db16003712e870b0ed8a541a9417f6c563f540b6ee`. This
is a static translation checkpoint only. It does not patch the APK, rerun the
loopback client, alter TLS behavior, contact a game server, or test a live
endpoint.

### v328 TScriptMachine static-tail translation

The v328 pass continues from the verified v327 database and reviews two
adjacent target functions. The source addresses are `0x21f30c` and `0x21f394`.
The target addresses are `0x227780` and `0x227808`.

Export compact pseudocode for the source pair and target pair with
`tools/ida_dump_function_evidence.py`:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x21f30c,0x21f394 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-next-block.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/libqplay_translated_all_v4.i64 \
  -s tools/ida_dump_function_evidence.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x227780,0x227808 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-target-next-block.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v327_property_constructor_destructor.i64 \
  -s tools/ida_dump_function_evidence.py
```

Export source features to `/tmp/original_features_v4_v3_materialized_v2.json`
and target features to
`/tmp/spectron_features_v327_property_constructor_destructor.json` with
`tools/ida_export_function_features.py`. Generate the v328 anchors with:

```bash
python3 tools/generate_spectron_script_machine_static_tail_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v327_property_constructor_destructor.json \
  --semantic-map /tmp/semantic_v327_current.json \
  --source-evidence /tmp/graal-source-next-block.json \
  --target-evidence /tmp/graal-target-next-block.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_script_machine_static_tail_manual_translation_anchors_20260829.json
```

The expected summary is two high-confidence anchors, one exact normalized
metric row, one layout-change row, and pseudocode for both source and target
functions. Apply them to a fresh v327 copy and reopen the result with the
manual-anchor helpers. The expected application and reopen results are two
renames, two evidence comments, 11,707 functions, and zero failures.

The static initializer is recorded as a layout change because the target
allocates a 0x68-byte rebuilt property object where 1.8 allocates 0x58 bytes.
The deleting `TCallStackEntry` destructor is an exact normalized match. The
nearby target overload at `0x221928` converts `C8THgaTQxF` into `CanTfaz6bZ`
and forwards to the main resolver. It remains outside the source-backed alias
set because the source database has no separate function boundary for that
adapter.

Run the name, boundary, dynamic-symbol, and semantic-map refreshes on the
reopened copy. The expected v328 name origins are:

```text
ida_named_or_other       4053
target_jni_export           7
target_named_export       898
target_only_descriptive   417
translated_v18_alias     6332
```

The dynamic audit remains at 6,770 named rows, 6,600 defined rows, 5,782
exact function starts, 482 data items, 336 other non-code items, and 170
undefined imports. It reports 4,671 source-backed aliases, 1,786 exact
retained names, 136 other retained target names, seven linker-boundary
aliases, 169 PLT veneers, and one undefined `__sF` import.

Rebuild and validate the v328 checkpoint with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v328.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v327.json \
  --database /path/to/spectron_libqplay_translated_v328_script_machine_static_tail.i64 \
  --anchor-artifact artifacts/spectron_script_machine_static_tail_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_script_machine_static_tail_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_script_machine_static_tail_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v328.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v328.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v328.json \
  --semantic-map artifacts/spectron_semantic_translation_v328.json \
  --feature-export /tmp/spectron_features_v328_script_machine_static_tail.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v328.json

python3 tools/validate_research_archive.py
```

The expected v328 database hash is
`01e5dc66c7446c46101a09486f23c1a86822e9973b57b5897fa93a4d1f11526a`. This is
a static translation checkpoint only. It does not change the loopback runtime
result, the TLS diagnosis, or the live-service boundary.

### v327 property-construction and cleanup translation

The v327 pass continues from the verified v326 database and reviews the next
15 target functions in the property runtime. The source addresses are
`0x225c14,0x225cb8,0x225ea0,0x225ee8,0x22693c,0x226950,0x226964,
0x226994,0x2269d4,0x226a1c,0x226a5c,0x226aa4,0x226ae4,0x226b2c,0x226b6c`.
The target addresses are
`0x22e49c,0x22e568,0x22e748,0x22e790,0x22f540,0x22f554,0x22f568,
0x22f598,0x22f5d8,0x22f620,0x22f660,0x22f6a8,0x22f6e8,0x22f730,0x22f770`.

Export compact feature records and pseudocode for both sides. The target
evidence must come from a v326-derived copy before the v327 names are applied:

```bash
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x225c14,0x225cb8,0x225ea0,0x225ee8,0x22693c,0x226950,0x226964,0x226994,0x2269d4,0x226a1c,0x226a5c,0x226aa4,0x226ae4,0x226b2c,0x226b6c \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-source-property-constructors.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/libqplay_translated_all_v4.i64 \
  -s tools/ida_dump_function_evidence.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FUNCTION_EVIDENCE=0x22e49c,0x22e568,0x22e748,0x22e790,0x22f540,0x22f554,0x22f568,0x22f598,0x22f5d8,0x22f620,0x22f660,0x22f6a8,0x22f6e8,0x22f730,0x22f770 \
  LIBQPLAY_EVIDENCE_COMPACT=1 \
  LIBQPLAY_EVIDENCE_OUT=/tmp/graal-target-property-constructors.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v326_format_parameters_property.i64 \
  -s tools/ida_dump_function_evidence.py
```

Export the matching compact feature files with
`tools/ida_export_function_features.py`, using
`LIBQPLAY_FEATURES_OUT=/tmp/original_features_v4_v3_materialized_v2.json` for
the source and
`LIBQPLAY_FEATURES_OUT=/tmp/spectron_features_v327_property_constructor_destructor.json`
for the target. Then generate the reviewed anchor artifact:

```bash
python3 tools/generate_spectron_property_constructor_destructor_anchors.py \
  --original-features /tmp/original_features_v4_v3_materialized_v2.json \
  --spectron-features /tmp/spectron_features_v327_property_constructor_destructor.json \
  --semantic-map /tmp/semantic_v327_current.json \
  --source-evidence /tmp/graal-source-property-constructors.json \
  --target-evidence /tmp/graal-target-property-constructors.json \
  --original-binary-sha256 9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8 \
  --spectron-binary-sha256 f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219 \
  --output artifacts/spectron_property_constructor_destructor_manual_translation_anchors_20260829.json
```

The expected anchor summary is 15 high-confidence rows, zero exact metric
rows, 15 layout-change rows, and pseudocode for all 15 source and target
functions. Apply the aliases to a fresh v326 copy and reopen the result with
the existing manual-anchor helpers:

```bash
cp /path/to/spectron_libqplay_translated_v326_format_parameters_property.i64 \
  /tmp/spectron_v327_property_constructor_destructor.i64
env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_property_constructor_destructor_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_property_constructor_destructor_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_SAVE_PATH=/path/to/spectron_libqplay_translated_v327_property_constructor_destructor.i64 \
  SPECTRON_MANUAL_REPORT=/tmp/spectron_property_constructor_destructor_manual_translation_application_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /tmp/spectron_v327_property_constructor_destructor.i64 \
  -s tools/ida_apply_spectron_manual_anchors.py

env IDADIR=/path/to/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/path/to/artifacts/spectron_property_constructor_destructor_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_property_constructor_destructor_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/tmp/spectron_property_constructor_destructor_manual_translation_verification_20260829.json \
  /path/to/idalib-python /path/to/idalib/examples/idacli.py \
  -f /path/to/spectron_libqplay_translated_v327_property_constructor_destructor.i64 \
  -s tools/ida_verify_spectron_manual_anchors.py
```

The expected application and reopen results are 15 rows, 15 resolved names,
15 renames, 15 evidence comments, 11,707 functions, and zero failures. The
v327 name audit should report 6,330 translated aliases, 900 retained target
names, 417 target-only descriptive names, seven JNI exports, and zero IDA
default names. The dynamic audit should still report 6,770 named rows, 6,600
defined rows, 5,782 exact function starts, 482 data items, 336 other non-code
items, and 170 undefined imports. The source-backed dynamic count is 4,669,
with 1,788 exact retained names and 136 other retained target names.

Rebuild the v327 checkpoint with:

```bash
python3 tools/generate_spectron_translation_checkpoint_v327.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v326.json \
  --database /path/to/spectron_libqplay_translated_v327_property_constructor_destructor.i64 \
  --anchor-artifact artifacts/spectron_property_constructor_destructor_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_property_constructor_destructor_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_property_constructor_destructor_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v327.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v327.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v327.json \
  --semantic-map artifacts/spectron_semantic_translation_v327.json \
  --feature-export /tmp/spectron_features_v327_property_constructor_destructor.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v327.json

python3 tools/validate_research_archive.py
```

The expected v327 database hash is
`cc731360c7c08f825a7905c760897d3a7aede1dccdb4322d56d72f5c2e0c2f13`. This is
a static translation checkpoint only. It does not change the loopback runtime
result, the TLS diagnosis, or the live-service boundary.

The complete private chain can be rebuilt with the single offline helper:

```bash
python3 tools/build_arm64_loopback_apk.py \
  /path/to/GraalOnline+Classic_1.8_APKPure.apk \
  /tmp/GraalClassic_arm64_loopback.apk \
  --zipalign /path/to/android-sdk/build-tools/35.0.1/zipalign \
  --apksigner /path/to/android-sdk/build-tools/35.0.1/apksigner \
  --keystore /path/to/debug.keystore \
  --report /tmp/GraalClassic_arm64_loopback.json
```

The helper removes the other ABI directories, preserves the original
connector script, applies the five tested native diagnostics, normalizes ZIP
timestamps, and verifies the signed output. Its default local package uses
the RSA result bypass. Pass `--skip-rsa-bypass` when the saved response or an
authorized current package is already known to pass the native RSA check. The
builder has no live-service behavior and no network side effects. The fresh
default build and loopback replay are recorded in
`artifacts/arm64_reproducible_builder_validation_20260826.json`.

For a loading-sequence negative control, apply
`tools/patch_loading_screen_getter_test.py` after the native diagnostic edits.
On ARM64 it patches `TClientEnvironment::getLoadingScreenEnabled` at
`0x15d35c`. The observed result was no connector request and no world render,
so this patch is not part of the working replay.

The render-boundary diagnostic is a separate local test. It hooks the getter
call at `0x244228` after timers and packet processing, uses the zero-filled
cave at `0x1f9508`, clears the loading byte through GOT slot `0x375e30`, and
returns to `0x24422c`. This leaves the original conditional branch in place
and lets the normal game-draw path run after network and resource work. It
displayed the tiled ARM64 world and HUD through the available x86_64
translation layer. It is not a release patch because it clears the byte on
each render iteration.

The preferred candidate for a state-oriented test is
`tools/patch_force_no_premium_loading_test.py`. It changes only the branch at
`0x15ca7c`, forcing the existing initialization path that clears the loading
byte at `0x15cac8`. With the exact `classiciphone.gmap` fixture, this candidate
renders through the ordinary JNI branch. The first apparent failure of this
candidate used a map name without the `.gmap` suffix and should not be used as
evidence against it.

The matched negative control starts from the same diagnostic library after the
non-premium edit and restores the original branch:

```bash
python3 tools/patch_restore_premium_loading_test.py \
  /tmp/libqplay.nonpremium.so \
  /tmp/libqplay.stock-loading.so
```

With the original connector script and the same local fixtures, this control
completed the resource and heartbeat path but kept the title/loading artwork.
The exact package, native library, and capture hashes are in
`artifacts/arm64_native_stock_original_script_control_20260826.json`.

## Replacing the historical trust bundle

The certificate-skip patch is useful for isolating later protocol stages, but
it is not the production-compatible route. When an authorized current PEM
chain is available, patch a private library copy while leaving the native TLS
verification code intact:

```bash
python3 tools/patch_graalweb_trust_bundle.py \
  --arch arm64-v8a \
  --bundle /path/to/current-authorized-chain.pem \
  /path/to/original/arm64-v8a/libqplay.so \
  /tmp/libqplay.current-trust.so
```

The tool accepts certificate blocks only, rejects private keys, checks the
original embedded string hash, and verifies its own native DES/Base64
round-trip. It does not contact the endpoint or prove that the supplied chain
matches the current service. Do not use the historical
`analysis/graalweb.cert.pem` as a current replacement.

## Native TLS trust replacement replay

The trust replacement path has now been exercised through the native ARM64
TLS implementation. This is a local proof of the patch and handshake path,
not a claim that the historical client can reach a current service.

The test certificate was self-signed for the local responder with the exact
hostname used by the client:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /tmp/graal-local-con.key \
  -out /tmp/graal-local-con.crt \
  -subj /CN=con.quattroplay.com \
  -addext subjectAltName=DNS:con.quattroplay.com \
  -addext basicConstraints=critical,CA:TRUE
```

Apply the patches to private copies in this order. The RSA branch remains
unchanged because the archived response passes the native raw-digest check.
The deterministic RC4 key and non-premium branch are local responder and
render diagnostics, not production changes:

```bash
python3 tools/patch_graalweb_trust_bundle.py \
  --arch arm64-v8a \
  --bundle /tmp/graal-local-con.crt \
  /path/to/original/arm64-v8a/libqplay.so \
  /tmp/libqplay.trust.so

python3 tools/patch_localhost_resolver_test.py \
  --arch arm64-v8a \
  /tmp/libqplay.trust.so \
  /tmp/libqplay.loopback.so

python3 tools/patch_connector_tls_port_test.py \
  --arch arm64-v8a --port 18443 \
  /tmp/libqplay.loopback.so \
  /tmp/libqplay.tls.so

python3 tools/patch_fixed_output_rc4_key_test.py \
  --arch arm64-v8a \
  /tmp/libqplay.tls.so \
  /tmp/libqplay.tls-key.so

python3 tools/patch_force_no_premium_loading_test.py \
  /tmp/libqplay.tls-key.so \
  /tmp/libqplay.tls-full.so
```

The port helper changes only the two ARM64 `MOV W1,#443` instructions at
`0x200df0` and `0x200f74`. It leaves the HTTPS flag, hostname, native trust
verification, and RSA branch intact. The resolver helper then routes the
legacy hostname to loopback. Do not use the port or resolver edits for a
release endpoint.

For the private APK run, include only the ARM64 library, sign the package with
a local test key, and configure these reverse mappings:

```bash
adb reverse tcp:18443 tcp:18443
adb reverse tcp:14900 tcp:14900
```

Start the public TLS responder with the archived connector body and start the
game responder on `14900`:

```bash
python3 tools/tls_capture_server.py \
  --certificate /tmp/graal-local-con.crt \
  --private-key /tmp/graal-local-con.key \
  --response /path/to/analysis/live_connector_response_local.bin \
  --port 18443 \
  --count 1

python3 tools/game_handshake_server.py \
  --port 14900 \
  --script /path/to/analysis/StartScript_Connector.dec.bin \
  --output /tmp/graal-tls-game \
  --package-file /tmp/basepackage-script.gupd \
  --file-root /tmp/graal-assets \
  --level-code-root /tmp/graal-assets/coded \
  --server-signature 73 \
  --file-transfer-mode single \
  --connection-timeout 60 \
  --extra-frame-once 178:2c636c61737369632c3132372e302e302e312c3134393030 \
  --extra-frame-after-first 9:202474657374 \
  --extra-frame-after-first '190:' \
  --extra-frame-after-first 49:2020522020636c61737369636970686f6e652e676d6170 \
  --frame-after-map 49:2020522020636c61737369636970686f6e652e676d6170
```

The verified ARM64 native hashes for this chain were, in order,
`3a28098407ee2322ddd0d12a178ce4cc7b3f5751b3e6024fcf48dbf09d9eee30` after
hostname routing, `41e69dd8a7ea70606ec3f299776bca40a9a212767f14f2b1633866da1a19b459`
after the TLS port move, `f002828554b70f87eed78e469324be3f0f13b28e16f7aa51024e5408e708935f`
after the local RC4 key diagnostic, and
`22a0fd4801f71f29f7c53a7ba77f0c4db669a83fc1ae5a5f53e3ce9b95f33e9a` after the
loading-state candidate. The debug-signed APK hash was
`2984a6d4b7698a2ab444166265939a75a61c43b679dfd87b0d7a063bf7fd0759`.

The TLS responder saw a 196-byte request for `/con.png` with
`Host: con.quattroplay.com:18443`. The native client received the archived
16,446-byte body without a certificate error, then reached `Serverwarp...` and
completed two encrypted game connections. The second connection requested
`classiciphone.gmap`, three level containers, and `pics1.png`, and continued
with packet-24 heartbeats. The final translated-ARM64 screenshot has SHA-256
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.

The responder is hard-coded to `127.0.0.1`. Stop both responders and remove
the reverse mappings after the test. Do not publish the self-signed private
key, the debug APK, or captured login data.

## Native-verification working control

The manual chain above is useful when each edit needs to be inspected. The
same test can be built with one helper while keeping the important security
checks intact:

```bash
python3 tools/build_arm64_trust_control.py \
  /path/to/GraalOnline+Classic_1.8_APKPure.apk \
  /tmp/GraalClassic_arm64_native_verified.apk \
  --bundle /tmp/graal-valid-con.crt \
  --port 18443 \
  --zipalign /path/to/android-sdk/build-tools/35.0.1/zipalign \
  --apksigner /path/to/android-sdk/build-tools/35.0.1/apksigner \
  --keystore /path/to/debug.keystore \
  --force-nonpremium-loading \
  --report /tmp/GraalClassic_arm64_native_verified.json
```

The helper never applies the connector RSA bypass. It also leaves the native
certificate parser and hostname verification enabled. The default form does
not touch the loading branch, which makes it a useful transport-only control.
`--force-nonpremium-loading` selects the tested startup path that clears the
native loading flag at `0x15cac8`; it is included here only to reproduce the
local rendered-world control.

On 2026-08-26 the working form used a one-certificate SAN-matching test chain
valid from 2025-01-01 through 2035-01-01. It sent the expected connector
request, completed the two local game connections, loaded the map, level
containers, and image assets, continued packet-24 heartbeats, and displayed
the tiled world and HUD. The APK SHA-256 was
`183ef83ed2772872288c1aa639e0501b5a645df395b0f89887a38ce56c0266f0`; its
ARM64 native library SHA-256 was
`7cffcbd8380d5e19324eb6d392e6cd942ce696b9470bbaaa74b037827ebecee7`.

The paired transport-only build used the same trust bundle, responder, and
fixtures but restored the original loading branch. It made the same connector
and resource requests and continued heartbeats, but remained on the title or
loading artwork. Its APK SHA-256 was
`2dcc8687743bc9c3caf5b995f051e64cb67c39ddad16f4408ba3ea4c67624b76` and its
native SHA-256 was
`614e43bbf92c7b8fc5bc550584956eed2dcb62fa01879721df5e6e02576247cb`.
This is the cleanest local separation so far between connector trust and the
later loading-state decision. The full record is in
`artifacts/arm64_native_verification_working_control_20260826.json`.

## Certificate validity control

Static extraction shows that the original native connector trust bundle
contains certificates that are no longer valid. To separate certificate-date
validation from later HTTP and game-protocol problems, a paired control was
run on 2026-08-26. Both private packages used the same original APK, the same
ARM64 diagnostic edits, the same hostname, and the same loopback port. The
only TLS input changed was the certificate installed in the native trust
bundle and presented by the local responder.

Create disposable self-signed fixtures with explicit dates. The certificate
must have the exact hostname in both its common name and subject alternative
name. Marking it as a CA keeps the fixture suitable for the trust-bundle slot
used by this old client:

```bash
python3 tools/make_tls_validity_fixture.py \
  --output-prefix /tmp/graal-expired-con \
  --hostname con.quattroplay.com \
  --not-before 2020-01-01T00:00:00Z \
  --not-after 2021-01-01T00:00:00Z

python3 tools/make_tls_validity_fixture.py \
  --output-prefix /tmp/graal-valid-con \
  --hostname con.quattroplay.com \
  --not-before 2025-01-01T00:00:00Z \
  --not-after 2035-01-01T00:00:00Z
```

For each fixture, apply the trust-bundle replacement followed by the
loopback resolver, port, deterministic responder-key, and native loading
candidate edits shown above. Keep the input library path separate from every
output path. Package each final library privately as the only ARM64 native
ABI, sign it with a local test key, and run the TLS responder with the matching
certificate and private key:

```bash
python3 tools/tls_capture_server.py \
  --certificate /tmp/graal-expired-con.crt \
  --private-key /tmp/graal-expired-con.key \
  --response /path/to/archived-response.bin \
  --port 18443 \
  --count 3 \
  --accept-timeout 90
```

The responder prints `TLS_CAPTURE_REQUEST` only after the TLS handshake and
HTTP header read have completed. It prints `TLS_CAPTURE_HANDSHAKE_ERROR` for
a client that closes during TLS, then continues accepting the requested
number of connections. This distinction avoids treating a TCP accept as a
successful connector request.

The exact expired fixture used in the paired run was valid from 2020-01-01
through 2021-01-01 and had PEM SHA-256
`633e4599f946aeec39b6a050ddb75660b26205e90416d79853a0ccd87d96dace`. The
valid control was valid from 2025-01-01 through 2035-01-01 and had PEM
SHA-256 `a55c4ec36f6c5708948d6f1e257b7782153ea85032b184fe7180adc00d347f75`.
The generated keys and both APKs remained in `/tmp` and are not part of the
repository.

The expired package reached the local TCP listener, but the client closed
with no HTTP request. The responder recorded
`SSLZeroReturnError: TLS/SSL connection has been closed (EOF)`. The matching
valid package completed TLS and sent `GET /con.png` with
`Host: con.quattroplay.com:18443` and `User-Agent: Graal/6.15401`. This is
strong local evidence that certificate validity is checked before connector
HTTP in the translated ARM64 path. It is not proof of the exact production
error code, current server chain, or behavior on a physical ARM64 device.

The paired package and process hashes are preserved in
`artifacts/connector_tls_expiry_control_20260826.json`. Do not replace a live
service certificate from this test. For a production-compatible repair, use
an authorized current certificate chain and leave the native verification
code enabled.

## Connector replay

The responder defaults to legacy-looking lowercase headers, but this is not a
hard requirement. IDA decompilation shows that `THTTPRequest_preParseData`
lowercases each response header line before matching it. A valid
`Content-Length` is recommended when the response connection remains open,
but the parser can also use EOF. This helper half-closes its write side after
the body, so the no-length variant is a bounded test. `Connection: keep-alive`
is the conservative default; `Connection: close` is also accepted in the
bounded replay.

```bash
python3 tools/connector_capture_server.py \
  --port 18080 \
  --con-png /tmp/con.png \
  --count 12 \
  --accept-timeout 180
```

To compare response formatting without changing the body, use:

```bash
python3 tools/connector_capture_server.py \
  --port 18080 \
  --con-png /tmp/con.png \
  --header-case title \
  --connection-value close
```

The local test matrix completed the connector and game replay with lowercase
or title-case names, with either connection value, and without
`Content-Length` when the responder supplied an EOF boundary.

When `--output-dir` points to a new directory, the responder creates it before
accepting requests. This keeps capture setup separate from the protocol test.

The `con.png` body should be an archived response that has already been
parsed offline. Do not treat an invalid RSA signature as a production fix.
It is accepted in the diagnostic APK only to reach the next native stage.

When generating a replacement body with the supplied `conpack_wsl.c`, apply
`tools/conpack_legacy_zip_compat.patch` before compiling the helper. This old
client expects the archived ZIP's flag `0x0002`, DOS time and date `0xffff`,
and central-directory version-made-by value `0`. The original connector
bytecode was repacked with those fields and reached the game responder.

## Rebuilding the connector script

The recovered source first needs the one-brace repair emitted by the pinned
HexaParser decompiler. Run the checked helper, then apply the observed
literal-order adapter before compiling:

```bash
python3 tools/repair_hexaparser_source.py \
  /tmp/StartScript_Connector.hexaparser.gs2 \
  /tmp/StartScript_Connector.repaired.gs2

python3 tools/reverse_hexaparser_literals.py \
  /tmp/StartScript_Connector.repaired.gs2 \
  /tmp/StartScript_Connector.native-order.gs2

cd /tmp/GScript.Go-HexaParser
go run . compile \
  -grammar gs2 \
  -type weapon \
  -name StartScript_Connector \
  -o /tmp/StartScript_Connector.native-order.gs2bc \
  /tmp/StartScript_Connector.native-order.gs2
```

The adapter is intentionally limited to same-line brace literals. It is
based on the checked connector fixture, where HexaParser printed handler
arrays, server lists, and a two-element handler pair in reverse order. Compare
the generated source with the native-order reconstruction before applying it
to another script.

The adapted source is useful for review, but the clean runtime control did not
reproduce the earlier adapted replay. Under the same native library, Kahn test
signer, TLS fixture, and game responder, the adapted package requested the
connector and opened no connection to the expected `14900` listener. Removing
the compiler-added trailing `0x0a` did not change that result. Its output has
3,582 instructions after the trailer is removed, while the original stream
has 3,143, so the literal adapter is not currently a complete compiler repair.

To preserve the original VM stream, patch the decoded bytecode directly:

```bash
python3 tools/patch_connector_bytecode_loading_clear.py \
  /path/to/graal-decomp/analysis/StartScript_Connector.dec.bin \
  /tmp/StartScript_Connector.loading-clear.dec.bin \
  --report /tmp/StartScript_Connector.loading-clear.json
```

This copies the existing six-byte `loadingscreenenabled = false` sequence from
`printDisconnectError` into `onServerLogin` before the `reconnections` reset,
then updates shifted function offsets and branch targets. It produced a
15,587-byte stream with SHA-256
`3c8286ece57d96ecf088f6ba01b6a6094f6d317dda451369392bfa731aa0fb2f`. Pack it
with the compatible ZIP creator and the matching private test signer only in a
private diagnostic workspace:

```bash
/tmp/conpack_wsl \
  /tmp/Moreno.kahn/kahn-private.rsa.der \
  /tmp/StartScript_Connector.loading-clear.dec.bin \
  /tmp/StartScript_Connector.loading-clear.con \
  NPCS/StartScript_Connector \
  /tmp/script-key /tmp/original.rk /tmp/original.t
```

The local ARM64 replay of this direct patch made two `14900` game connections,
completed encrypted login, received `classiciphone.gmap`, three level files,
and continuing heartbeat traffic. The title/loading artwork remained in the
bounded screenshot because the synthetic responder stops at a post-login
resource boundary. Treat this as script and protocol evidence, not as proof
of live login or final rendering. The complete public hash record is in
`artifacts/bytecode_loading_clear_replay.json`.

Do not copy private signing keys into the repository or into an APK intended
for distribution. The static HexaParser hashes and the corrected runtime
status are in `artifacts/helper_toolchain_replay.json`.

## Two-connection game replay

Packet 178 is the server-warp instruction. The responder must send it on the
first connection and wait for the client to reconnect before sending the map
and level sequence. On the second connection, packet 190 is the local
connecting-window completion event and packet 49 starts the GMAP transition.
The second packet 49 below is sent after the map response because the tested
client caches the map before it re-enters the pending transition:

```bash
python3 tools/game_handshake_server.py \
  --port 14900 \
  --script /path/to/StartScript_Connector.dec.bin \
  --output /tmp/graal-game-capture \
  --package-file /tmp/basepackage-script.gupd \
  --file-root /tmp/graal-assets \
  --level-code-root /tmp/graal-assets/coded \
  --server-signature 73 \
  --file-transfer-mode single \
  --connection-timeout 60 \
  --extra-frame-once 178:2c636c61737369632c3132372e302e302e312c3134393030 \
  --extra-frame-after-first 9:202474657374 \
  --extra-frame-after-first '190:' \
  --extra-frame-after-first 49:2020522020636c61737369636970686f6e652e676d6170 \
  --frame-after-map 49:2020522020636c61737369636970686f6e652e676d6170
```

The x86_64 diagnostic APK reaches the rendered tile field and HUD using the
original no-swap handler table. The normal packet-190 handler removes the blue
connecting control. This is a local synthetic success, and several historical
x86 diagnostic APKs used a loading-getter override, so it is not evidence for
stock x86 loading-state ownership. The ordinary ARM64 build completes the
connector, server warp, encrypted login, map and level requests, image
request, and heartbeat path under the x86_64 emulator's translation layer, but
remains on the title or loading image. The ARM64 IDA audit attributes that
split to the native loading byte and its startup clear path. The separate
render-boundary diagnostic displays the ARM64 world and HUD. ARM64 behavior
on a real device and live login remain unverified.

The `--frame-after-client` option accepts
`CLIENTTYPE@OCCURRENCE:TYPE:HEXBODY`. The occurrence is one-based and defaults
to one. The `--frame-after-map` option accepts `TYPE:HEXBODY` and sends the
frame after each `.gmap` response. Both options are useful for bounded local
experiments because they avoid timing guesses.

## Game responder

The local game responder implements only the frames needed for a bounded
protocol test. Its command line includes a packet-178 server-warp, a minimal
packet-9 player property update, packet 190 completion, a packet-49 map
selection, and encrypted fixture files. File responses use packet 102 in
single mode or the native 68, 84, 102, 69 sequence in big mode. Review the
script before changing the packet sequence.

```bash
python3 tools/game_handshake_server.py \
  --port 14900 \
  --file-root /tmp/graal-assets \
  --level-code-root /tmp/graal-assets/coded \
  --server-signature 73
```

The exact packet bodies used in the longer test are documented in
`docs/PROTOCOL.md`. Captures should be written to a temporary directory and
deleted or retained privately. Never commit login envelopes or account data.

## Useful checks

Before relying on a published count or hash, validate the archive summaries:

```bash
python3 tools/validate_research_archive.py
```

This check is local-only. It reads the checked-in JSON artifacts, verifies the
shared ARM64 input hash and count partitions, and confirms that no artifact
claims to have contacted a network.

Validate a connector body without opening a socket:

```bash
python3 tools/parse_connector_response.py /tmp/con.png
```

The report's `rsa_signature_valid` field mirrors the native wolfSSL
`RsaSSL_Verify` path. It checks a PKCS#1 type-1 block containing the raw
SHA-256 digest of the encrypted payload. `standard_rsa_signature_valid` is
kept as a comparison field for the ASN.1 `DigestInfo` form used by common
high-level Python APIs. The saved archived response passes
`rsa_signature_valid` and fails only the standard comparison field. A response
signed by another key can fail the native field. A local test package signed
with a matching controlled key also passes the native field when the library's
embedded key is replaced with `tools/patch_connector_test_public_key.py` in a
private copy.

For the saved response, pass `--skip-rsa-bypass` to
`tools/patch_compatibility_repairs.py` so the native package check remains
unchanged while the expired certificate diagnostic is applied.

Decode a previously captured NewGraal stream with the known diagnostic
outgoing key:

```bash
python3 tools/decode_game_handshake_capture.py \
  /tmp/graal-handshake-2.in.bin \
  --key-hex 30313233343536373839616263646566
```

The decoder prints frame metadata and hashes by default. Use the option that
explicitly permits login-field output only on private captures.

## Final ARM64 translated replay record

The full-asset package was installed on the Android 36 x86_64 emulator with
ADB reverse mappings for ports 18080 and 14900. The emulator log included:

```text
Initialized OpenGL.
Connecting to the login server...
Serverwarp...
```

The connector request capture SHA-256 was
`3586b24ea8f0b90b722bc988c4a7e126ee8e0664f2b06d1cb6e7ab8338e6759f`.
The game responder recorded two connections. The first capture was 525 bytes
in and 401 bytes out. The second was 841 bytes in and 16,377 bytes out. The
second connection requested `classiciphone.gmap`, three level-code files, and
continued sending packet 24 heartbeats. The private capture hashes were:

```text
first inbound   ea99abfc5ba94c2236d1a397902bf520b6d3556c369ec4366ef2bf6434459fea
first outbound  e9802e18635259baa04eee2eab0e9a962ce1d3abc14839a34c0e6e353c97977e
second inbound  c3408fc4f5fe41c04cc73c3f2511292bef3f1f211bc1307dcb83396c4228e042
second outbound e7f8291522951a1dd78f570bb368992bca5fa82ac548619144ed563e2cf15a47
screenshot      fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e
```

The responder was bound to loopback only. No live connector, live game
server, account, or remote Spectron page was used.

## Package-preserving RSA replay

The saved connector response passes the native wolfSSL raw-digest RSA check,
so the package-preserving ARM64 candidate can be tested with the RSA branch
unchanged. The private candidate used here has APK SHA-256
`dad598e0cec03b501ff8cc30648ad843346fa3a331db3087ffa54ff92938af3a`, native
library SHA-256
`888a236bb839eef7ab094196b924796680d23d857a0d7533487bcd3786efb308`, and
original RSA branch bytes `dc 00 00 35` at ARM64 `0x22c5c8`.

With the existing Android 36 x86_64 emulator, the test app data was cleared,
the compatibility warning was dismissed, and the two loopback reverse
mappings were restored. The fresh run captured the normal connector request
with SHA-256
`3586b24ea8f0b90b722bc988c4a7e126ee8e0664f2b06d1cb6e7ab8338e6759f`, made two
game connections, requested `classiciphone.gmap`, three level containers, and
`pics1.png`, and continued sending heartbeats. The first game capture hashes
were:

```text
in  3bd0db0749df7e73715a03bfd34a5ca8e984eb3f7ac869f3c6e05653e684c536
out a5555ffd8b4e83f528d53f692c58a92991f2247e4037148a43779cc068316d55
```

The rendered screenshot SHA-256 was
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`, the
same as the earlier RSA-bypass diagnostic run. This confirms that the saved
fixture does not require bypassing the native package-signature result. It
does not validate the current service, and the certificate and loopback
patches remain diagnostic controls.

## Held-connection encrypted-level replay

The latest ARM64 checkpoint used the same local-only responder with a private
fixture root. The map was copied under `classiciphone.gmap`, and the level
helper re-keyed a cached `black.nw-14900.code` container into matching files
for the three level names emitted by that map. The responder sent packet 49
again after the map response, served the encrypted containers through packet
102, and held the second connection open while the emulator was captured.

The client accepted the map, `login.gupd`, all three level containers,
`pics1.png`, and the package metadata, then sent packet-24 heartbeats. The
captured frame showed the green tiled world, HUD, and status icons. The
screen hash was
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.

This test uses cached local inputs and does not claim that they match the live
server's revision. The full capture and fixture hash record is in
`artifacts/arm64_local_fixture_render_replay.json`. Keep the raw captures and
fixture bodies private.

## What counts as a successful test

There are four separate milestones:

1. The connector HTTP response is framed and parsed.
2. The game socket completes the key exchange and logs `Connected.`.
3. The client requests and accepts the map and level files.
4. The player enters a rendered world and a live server accepts the login.

The current work has reproduced milestones 1 through 3 locally and has also
rendered a synthetic world with the x86_64 client HUD. The ARM64-only
candidate rendered the same world through Android's x86_64 translation layer.
The live-login part of milestone 4 remains open. A local responder can prove
native control flow, but it cannot prove account authentication, server
compatibility, or current service availability.

## v349 exact sound-wrapper pass

The v349 pass is offline. It does not need the APK, an emulator, a socket, or
an authorized server endpoint. It uses the source feature export, the v348
target feature export, the v348 semantic map, and the direct IDA pseudocode
evidence captured during the review.

Generate the ten-row artifact. The generator checks the complete feature
record for every pair and rejects a row unless it is still an explicit v348
ambiguity candidate:

```bash
python3 tools/generate_spectron_sounds_exact_anchors_v349.py \
  --original-features /tmp/original_features_v3_current.json \
  --spectron-features artifacts/spectron_features_v348_rsa_encrypt.json \
  --semantic-parent artifacts/spectron_semantic_translation_v348.json \
  --target-evidence /tmp/graal-target-sounds-v348.json \
  --output artifacts/spectron_sounds_exact_manual_translation_anchors_20260829.json
```

The expected artifact summary is ten high-confidence exact-shape rows, zero
layout-change rows, zero target-default rows, and these address deltas:
`+0xbb0` four times, `+0xbd4` twice, `+0xbe8` once, and `+0xbf0` three
times.

Carry the semantic map forward:

```bash
python3 tools/carry_forward_spectron_semantic_translation_v349.py \
  --parent-map artifacts/spectron_semantic_translation_v348.json \
  --target-features artifacts/spectron_features_v348_rsa_encrypt.json \
  --anchor-artifact artifacts/spectron_sounds_exact_manual_translation_anchors_20260829.json \
  --output artifacts/spectron_semantic_translation_v349.json
```

The expected semantic totals are 3,732 mapped pairs, 3,672 high-confidence
pairs, 1,004 remaining ambiguities, and 608 unmatched source functions. The
target feature count remains 11,707.

Apply the artifact to a fresh v348-derived IDA copy. Do not overwrite an
existing checkpoint:

```bash
cp /home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v348_rsa_encrypt.i64 \
  /tmp/spectron_v349_sounds_anchor_apply_input.i64

env IDADIR=/home/v/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_APPLY=1 \
  SPECTRON_MANUAL_ANCHORS=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_sounds_exact_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_sounds_exact_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_SAVE_PATH=/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v349_sounds_exact.i64 \
  SPECTRON_MANUAL_REPORT=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_sounds_exact_manual_translation_application_20260829.json \
  /home/v/.codex/plugins/cache/mrexodia/ida-pro-mcp/0.1.0/.venv/bin/python \
  /home/v/ida-pro-9.3/idalib/examples/idacli.py \
  -f /tmp/spectron_v349_sounds_anchor_apply_input.i64 \
  -s /home/v/Desktop/graal-decomp/libqplay/tools/ida_apply_spectron_manual_anchors.py
```

All ten target names already exist in the v348-derived copy. Therefore the
expected application report is ten resolved functions, zero new renames, nine
new comments, zero failures, and a successful save. The nine-comment result
means one identical review comment was already present; it is not a missing
anchor.

Reopen and verify the saved copy:

```bash
env IDADIR=/home/v/ida-pro-9.3 \
  IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_MANUAL_ANCHORS=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_sounds_exact_manual_translation_anchors_20260829.json \
  SPECTRON_MANUAL_EXPECTED_ARTIFACT=spectron_sounds_exact_manual_translation_anchors_20260829 \
  SPECTRON_MANUAL_VERIFY_REPORT=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_sounds_exact_manual_translation_verification_20260829.json \
  /home/v/.codex/plugins/cache/mrexodia/ida-pro-mcp/0.1.0/.venv/bin/python \
  /home/v/ida-pro-9.3/idalib/examples/idacli.py \
  -f /home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v349_sounds_exact.i64 \
  -s /home/v/Desktop/graal-decomp/libqplay/tools/ida_verify_spectron_manual_anchors.py
```

The reopen report must show ten verified names, zero failures, and 11,707
functions.

Refresh the post-pass inventories one at a time. Opening an IDA database can
update IDA metadata, so calculate the final database hash only after the last
audit:

```bash
env IDADIR=/home/v/ida-pro-9.3 IDAUSR=/tmp/graal-idalib-user \
  LIBQPLAY_FEATURES_OUT=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_features_v349_sounds_exact.json \
  /home/v/.codex/plugins/cache/mrexodia/ida-pro-mcp/0.1.0/.venv/bin/python \
  /home/v/ida-pro-9.3/idalib/examples/idacli.py \
  -f /home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v349_sounds_exact.i64 \
  -s /home/v/Desktop/graal-decomp/libqplay/tools/ida_export_function_features.py

env IDADIR=/home/v/ida-pro-9.3 IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_NAME_COVERAGE_OUTPUT=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_name_coverage_audit_v349.json \
  /home/v/.codex/plugins/cache/mrexodia/ida-pro-mcp/0.1.0/.venv/bin/python \
  /home/v/ida-pro-9.3/idalib/examples/idacli.py \
  -f /home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v349_sounds_exact.i64 \
  -s /home/v/Desktop/graal-decomp/libqplay/tools/ida_audit_spectron_name_coverage.py

env IDADIR=/home/v/ida-pro-9.3 IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_BOUNDARY_AUDIT_OUTPUT=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_dynamic_symbol_boundaries_v349.json \
  /home/v/.codex/plugins/cache/mrexodia/ida-pro-mcp/0.1.0/.venv/bin/python \
  /home/v/ida-pro-9.3/idalib/examples/idacli.py \
  -f /home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v349_sounds_exact.i64 \
  -s /home/v/Desktop/graal-decomp/libqplay/tools/ida_audit_dynamic_symbol_boundaries.py

env IDADIR=/home/v/ida-pro-9.3 IDAUSR=/tmp/graal-idalib-user \
  SPECTRON_DYNAMIC_SYMBOL_COVERAGE_OUTPUT=/home/v/Desktop/graal-decomp/libqplay/artifacts/spectron_dynamic_symbol_coverage_audit_v349.json \
  /home/v/.codex/plugins/cache/mrexodia/ida-pro-mcp/0.1.0/.venv/bin/python \
  /home/v/ida-pro-9.3/idalib/examples/idacli.py \
  -f /home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v349_sounds_exact.i64 \
  -s /home/v/Desktop/graal-decomp/libqplay/tools/ida_audit_spectron_dynamic_symbol_coverage.py
```

The v349 audits retain 11,707 functions, zero default names, 6,441 translated
aliases, 439 target-only descriptive labels, 5,782 exact dynamic function
starts, and 4,796 source-backed dynamic rows. Build the strict checkpoint:

```bash
python3 tools/generate_spectron_translation_checkpoint_v349.py \
  --parent-checkpoint artifacts/spectron_translation_checkpoint_20260829_v348.json \
  --database /home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v349_sounds_exact.i64 \
  --label-artifact artifacts/spectron_sounds_exact_manual_translation_anchors_20260829.json \
  --application-report artifacts/spectron_sounds_exact_manual_translation_application_20260829.json \
  --verification-report artifacts/spectron_sounds_exact_manual_translation_verification_20260829.json \
  --name-audit artifacts/spectron_name_coverage_audit_v349.json \
  --boundary-audit artifacts/spectron_dynamic_symbol_boundaries_v349.json \
  --dynamic-symbol-coverage artifacts/spectron_dynamic_symbol_coverage_audit_v349.json \
  --semantic-map artifacts/spectron_semantic_translation_v349.json \
  --feature-export artifacts/spectron_features_v349_sounds_exact.json \
  --output artifacts/spectron_translation_checkpoint_20260829_v349.json

python3 tools/validate_research_archive.py
```

The expected v349 database SHA-256 is
`ede4f9187e01c4a415181f423dd9c7b8467deb38595d399dcb19341fd9203faf`.
The archive validator must finish with `research archive validation: ok`.
The five layout-change candidates above are not part of this checkpoint and
must not be silently added to the exact-shape count.
