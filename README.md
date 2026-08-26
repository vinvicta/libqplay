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

The exported-symbol translation pass is complete. The ARM64 IDA database
contains 8,601 translated and applied ELF names with zero rename failures:

| Kind | Count |
| --- | ---: |
| Functions | 4,714 |
| PLT thunks | 3,183 |
| Jump thunks | 199 |
| Data symbols | 505 |
| Total translated symbols | 8,601 |

The old connector has a concrete compatibility problem. Its embedded
GraalWeb certificate expired on 2023-07-29, so the original HTTPS path cannot
be trusted by a current clock. The saved connector fixture is structurally
valid and passes the native wolfSSL raw-digest RSA check against this APK's
embedded public key. An earlier parser reported the opposite because it used
the standard ASN.1 `DigestInfo` form. The certificate problem remains real,
and both it and any response signed by a different key must stay separate from
the game-server protocol.

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
* `symbols/libqplay.symbols.csv` is the searchable symbol table.
* `symbols/libqplay.symbols.json` is the machine-readable equivalent.
* `symbols/libqplay.symbols.summary.json` records the translation counts.
* `symbols/libqplay.function_inventory.csv` and
  `symbols/libqplay.function_inventory.json` preserve the pre-persistence
  inventory of all 11,272 IDA function starts, including the 1,645
  analysis-created `sub_` entries that had no surviving ELF name at that point.
* `symbols/libqplay.function_inventory.summary.json` records the input hash
  and the boundary between translated symbols and IDA-created functions in
  that original inventory.
* `artifacts/unresolved_function_profile.json` profiles the 488 default
  `sub_` entries in the pre-persistence snapshot that lacked source names. It
  separates likely static library internals, compiler-generated cleanup
  wrappers, init/fini array entries, a compiler branch veneer, the PLT resolver
  slot, and the 28 application or engine entries that were later given role
  aliases.
* `artifacts/ida_residual_profile.json` accounts for the final 459 default
  `sub_` entries in the persisted 11,297-function IDA copy. It records every
  residual address and explains why no source name is claimed for it.
* `artifacts/ida_semantic_labels.json` records 467 evidence-backed names
  applied to formerly unnamed login, file-download, handler-table, UI, TLS,
  HTTP, socket, animation, sound, network-thread, update-package, and JNI
  bridge helpers.
* `artifacts/ida_translation_validation.json` records the disposable-copy
  IDALIB audit of the expanded callback naming pass. It includes the five
  native FDE ranges, the twenty script-table FDE ranges, the two split
  functions, zero apply failures, and the hash of the persisted translated
  database copy. The live desktop IDA database was not changed.
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
* `tools/generate_ida_residual_profile.py` derives the exact 459-entry
  residual report after the role aliases and IDA thunk reclassification.
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
  `tools/patch_gs2_success_loading_clear.py` records the equivalent source
  edit for readable GS2 experiments; its compiled output remains unverified.
  `tools/decode_graalweb_cert_bundle.py` recovers certificate metadata from
  the original ARM64 library without contacting a service. The offline
  connector parser mirrors the native raw-digest RSA check, and
  `tools/patch_connector_test_public_key.py` supports a private controlled-key
  diagnostic without including a private key.
  `tools/patch_graalweb_trust_bundle.py` replaces the historical trust text
  with a user-supplied certificate-only PEM bundle while leaving CyaSSL
  verification enabled.
  `tools/patch_connector_tls_port_test.py` moves only the diagnostic HTTPS
  port for a loopback ADB reverse mapping, and
  `tools/tls_capture_server.py` serves an archived response over a
  127.0.0.1-only TLS listener.
  `tools/compare_spectron_native.py` compares the supplied Spectron native
  library with the original ARM64 build without loading either one.
  `tools/match_spectron_function_signatures.py` checks whether the supplied
  Spectron ARM64 build offers any exact, unambiguous source-name matches for
  the original IDA default functions.
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
