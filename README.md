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
