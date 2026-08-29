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
