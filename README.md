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
  port for a loopback ADB reverse mapping, and
  `tools/tls_capture_server.py` serves an archived response over a
  127.0.0.1-only TLS listener and records handshake failures without exposing
  a response body.
  `tools/compare_spectron_native.py` compares the supplied Spectron native
  library with the original ARM64 build without loading either one.
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
  The `tools/generate_spectron_socket_behavior_comparison.py` generator
  records changed-size socket behavior without forcing an exact-match label.
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
