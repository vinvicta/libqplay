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

The symbol pass is complete for every name retained in the ELF export. The
final ARM64 IDA copy also contains the reviewed callback, script-table,
static-library, and exact embedded-library source aliases. The counts are:

| Kind | Count |
| --- | ---: |
| Retained ELF symbols translated | 8,601 |
| Additional reviewed function aliases | 1,551 |
| IDA functions in the saved copy | 11,296 |
| Remaining default `sub_` functions | 124 |

The retained ELF count includes 4,714 implementation functions, 3,183 PLT
thunks, 199 jump thunks, and 505 data symbols. The 124 remaining `sub_`
entries are code that IDA discovered without a preserved source symbol. They
are kept address-based rather than being assigned guesses. The exact source
role pass covers 141 FreeType 2.3.6 functions, 153 IJG libjpeg 6b functions,
one zlib 1.2.5 function, and one static giflib GIF decoder helper. The compact
verification record is `artifacts/ida_translation_verification_20260902.json`.

The active-IDB scope check found zero default names in the Android bridge
range, zero among the 1,779 unique script callback addresses, and zero direct
calls from a remaining default function into the selected socket, file,
process, or update imports. The broader application-core range contains 23
short static-state or cleanup wrappers, which are documented without invented
source names. The check is preserved in
`artifacts/ida_active_translation_scope_check_20260902.json`.

The old connector has a concrete compatibility problem. Its embedded
GraalWeb certificate expired on 2023-07-29, so the original HTTPS path cannot
be trusted by a current clock. The archived connector fixture is structurally
valid and passes the native RSA check when verified with the recovered wolfSSL
raw-digest format. An earlier generic ASN.1 `DigestInfo` check reported a
mismatch because it used the wrong signature format. Certificate freshness
and package verification are separate from the game-server protocol, and any
diagnostic changes remain private to the local test build.

The symbolized handler-table investigation also produced an important
correction. The original `setInDataHandlers` instructions are correct for this
client revision. The earlier x86_64 `xchg` patch and the matching ARM64
operand swap were a false lead caused by reading the intermediate bytecode
array in the wrong order. The decoded runtime pairs are packet type first,
handler index second, and the unmodified table accepts the normal local
sequence.

The corrected two-connection replay now renders the level tile field, player
HUD, and status icons. The client accepts a server-warp, a player-properties
packet, the connecting-window completion packet, the map transition, three
encrypted level containers, and `pics1.png`. The file response is packet 102,
not packet 59. A direct packet-59 parser jump was retained only as a negative
control because it breaks the normal request sequence.

The game has not yet been verified against a live game server. The local test
proves that the native client can reach a rendered world through a bounded
loopback responder. Live endpoint availability, current package signing, and
account authentication remain open.

The Android lifecycle review adds an important first diagnostic checkpoint.
The connector is downstream of the GL surface, window focus, runtime
permission completion, and the first render frame. A compatibility dialog or
permission state can therefore make the app look offline before any TLS code
has run. The native Java bridge and ARM64 JNI evidence are in
`artifacts/original_android_lifecycle_review_20260830.json`.

The incoming deep-link path has a separate mismatch. Android accepts
`graalclassic://` and `graalclassicplus://`, while the native start parser only
normalizes `graal://` and `graal3://`. The full URI is also delivered to the
script event `onStartedWithURL`. This is now documented as a compatibility lead
and a conditional destination-control concern in
`artifacts/original_intent_launch_review_20260830.json`.

The native HTTP redirect pass found another destination-control boundary.
Responses with status 300 through 303, 305, or 307 can replace the request's
host, port, path, and scheme from a `Location` value. The retry limit is ten,
but the old code does not compare the new destination with the original one
or prevent an HTTPS-to-HTTP downgrade. This is a confirmed static finding,
not a live-service result. The evidence is in
`artifacts/original_http_redirect_review_20260830.json`.

The script-to-Android URL pass found a separate outbound capability. The
`openurl` and `openurl2` callbacks reach `QPlayActivity.openURL`; non-legacy
inputs become `ACTION_VIEW` intents without a visible scheme or host
allowlist, while `canopenurl` reports whether Android has a matching handler.
The server-mediated `opengraalurl` path normally sends a game message, but it
falls back to the same bridge when no active client exists. The static evidence
is in `artifacts/original_external_url_review_20260830.json`.

The HTTP framing pass confirms that the 8,192-byte native read size is only a
chunk size. Header lines and accumulated response data have no general cap,
and the parser does not decode `Transfer-Encoding: chunked`. Legacy
`Content-Length` and close-delimited responses work in the bounded local
replay, but a current server's framing still needs to be verified. The
evidence is in `artifacts/original_http_framing_review_20260830.json`.

The Facebook bridge pass found that the Android script table exposes more than
login status. An activated script can read the current Facebook access token,
request additional read or publish permissions, issue authenticated Graph GET,
POST, or DELETE requests, and use the `graph2` path to upload eligible game
resources. The SDK builds HTTPS Graph URLs by default, but transport security
does not remove the risk of handing a bearer token to script code. The focused
IDA and DEX review is in
`artifacts/original_facebook_bridge_review_20260830.json`.

The Google Play pass found a separate legacy billing bridge. The Android
script table can start an in-app purchase with caller-supplied SKU and
developer-payload text. The store still controls availability and signs the
result, but the activity reports the immediate launch Boolean before the
asynchronous result is known. The later callback sends status, SKU, original
purchase JSON, and signature back into native script events even when the
purchase signature was rejected. The focused review is in
`artifacts/original_billing_bridge_review_20260830.json`.

The legacy partner pass found that the remaining TapJoy, Distimo, Fabzat, and
TrialPay entries are compatibility remnants in this APK. Their Java methods
are no-ops or return false, while five Fabzat callbacks are native nullsubs.
The native TapJoy setters still retain script-provided strings in process
memory, but the stock Java bridge never sends them to a working SDK. The
focused evidence is in
`artifacts/original_partner_bridge_review_20260830.json`.

The Android device and media pass found two useful compatibility details. The
script table can read the Android release, manufacturer, model, and display
metrics, while the native video path is only partly wired: the activity's
video open and stop methods are no-ops and the rectangle setter has no matching
static method in the reviewed `Natives` class. Keyboard closure is still a
real asynchronous input path. The focused evidence is in
`artifacts/original_android_device_media_review_20260830.json`.

The offline ELF loader inventory adds one more compatibility lead. All four
packaged native variants declare `libstdc++.so`, but the APK does not package a
library with that name. The ARM64 library uses `0x10000` ELF `LOAD` alignment;
the other three use `0x1000`. The earlier x86_64 replay loaded successfully, so
this does not identify the current failure by itself. An ARM64 device logcat is
still needed to distinguish a missing or incompatible runtime dependency from
the separate stale-certificate problem. The expanded records are in
`artifacts/original_apk_security_audit_20260830.json`.

The native init/fini review confirms that `libqplay.so` runs a fixed 20-entry
constructor array before `QPlayMain` and a 10-entry teardown array on unload.
The callbacks initialize resource lists, texture state, GUI defaults, client
state, and video globals. None of the callbacks directly reaches the selected
socket, resolver, file, or process boundaries. Their decompiler output is
preserved in `artifacts/original_native_init_review_20260830.json`.

The AArch64 import pass now inventories every direct `BL` and unconditional
`B` tail transfer from the original `.text` section to a PLT import. It found
167 undefined ELF symbols, 3,186 transfer sites, and 301 tail calls. The
`TSocket` property table exposes `bind`, `connect`, `send`, and `sendudp`; the
native socket helper contains `socket`, `bind`, `listen`, `accept`, TCP, and
UDP branches. The static constructor clears the bind and outbound-socket
allowlist strings before the script setters can replace them. This is a
conditional local-listener and datagram capability, not proof that the stock
connector starts a listener or contacts an endpoint. The compact inventory is
in `artifacts/original_aarch64_import_callsite_inventory_20260830.json`,
generated by `tools/audit_aarch64_import_calls.py`.

The remaining Android callback pass closes the native side of the Java bridge.
It records the touch, key, text, surface, lifecycle, script-registration,
purchase, legacy-provider, video, and generic event callbacks. In particular,
`onAppPause` can set the native close flag before a client exists or while the
client is still in its early loading states, and the next `QPlayLoop` exits the
process. That is a startup compatibility lead that can look like an offline
failure. The native export is in
`artifacts/original_android_callback_review_20260830.json`.

The companion DEX inventory finds 18 public static native methods in the
`Natives` class, 14 with 21 direct `invoke-*` callsites. Four exported methods
have no direct DEX caller in this APK: `onAddScriptFunction`, `onRegisterEvent`,
`onVideoFinished`, and `onVideoLoaded`. That does not rule out reflection or
native-to-Java callbacks, but it keeps their active reachability unproven.
The compact record is
`artifacts/original_dex_native_surface_review_20260830.json`, generated by
`tools/audit_dex_native_surface.py`.

## Repository layout

* `docs/RESEARCH_NOTES.md` is the chronological investigation record.
* `docs/PROTOCOL.md` describes the connector and NewGraal wire formats.
* `docs/LEVEL_CONTAINER.md` describes the encrypted `.code` level container.
* `docs/SYMBOLS.md` explains the symbol export and naming policy.
* `docs/RUNTIME_STATUS.md` lists verified milestones and open blockers.
* `docs/TESTING.md` describes local-only reproduction without contacting a
  live game service.
* `docs/SECURITY.md` records the original APK and ARM64 native trust-boundary
  review.
* `docs/DEPENDENCY_PROVENANCE.md` records the bundled compression, font, and
  image-library versions and their input paths.
* `artifacts/original_dex_webview_review_20260830.json` records the local smali
  review that separates the game WebView, Bolts bridge, and Facebook SSL-error
  path.
* `artifacts/connector_http_flow_review_20260830.json` preserves the compact
  IDA export for the original connector request lifecycle.
* `artifacts/game_connection_flow_review_20260830.json` preserves the compact
  IDA export for the connector-to-game socket lifecycle.
* `artifacts/original_libc_callsite_review_20260830.json` records the direct
  libc call sites and focused buffer review for the original ARM64 library.
* `artifacts/original_level_parser_review_20260830.json` records the encrypted
  level, board, and line-oriented entity parser review.
* `artifacts/original_download_cache_flow_review_20260830.json` records the
  server-file response, resource resolution, and cache save flow.
* `artifacts/original_update_package_path_review_20260830.json` records the
  update-package manifest parser, package path policy, cache path mapping, and
  local file writers.
* `artifacts/original_update_integrity_review_20260830.json` records the
  request-side CRC fields, download scheduler, response accumulation, and
  package completion boundary.
* `artifacts/original_script_package_review_20260830.json` records the signed
  connector script package parser and activation path. Embedded crypto
  literals are redacted from this public report.
* `artifacts/original_game_login_review_20260830.json` records the NewGraal
  key setup, framing, sequence, and packet-54 login transition. Fixed key-like
  literals are redacted from this public report.
* `artifacts/original_credential_storage_review_20260830.json` records the
  native option store, reversible value transform, and script-facing account,
  password, and cookie boundaries.
* `artifacts/original_script_capability_review_20260830.json` records the
  embedded script callbacks that reach local files, uploads, HTTP requests,
  protocol controls, and dynamic class loading.
* `artifacts/original_image_parser_review_20260830.json` records the downloaded
  image-resource path and the native PNG, GIF, JPEG, BMP, and TGA decoder
  boundaries. It is a static review and contains no fuzzing results.
* `artifacts/original_dependency_provenance_20260830.json` records the exact
  bundled zlib, bzip2, and FreeType version evidence, compression callsites,
  font paths, and conservative dependency findings.
* `artifacts/ida_freetype_source_matches_20260901.json` records 141 exact
  FreeType 2.3.6 source matches with address, size, xref, and source-line
  evidence.
* `artifacts/ida_libjpeg_source_matches_20260902.json` records 153 exact IJG
  libjpeg 6b source matches, including the corrected marker-reader roles.
* `artifacts/ida_zlib_source_matches_20260902.json` records the exact
  `inflate_fast` match at `0x28a2f4`.
* `artifacts/ida_giflib_source_matches_20260902.json` records the static
  `DGifDecompressLine` role at `0x2acb20` while leaving the exact giflib
  release open.
* `artifacts/gif_decoder_security_review_20260902.json` records the GIF LZW
  bounds-check comparison, the conditional review of three upstream giflib
  CVEs, and the independent `DGifSlurp` dimension-arithmetic and extension-
  accumulation findings plus the unbounded `SavedImages` frame-array review.
  The same review records a conditional bitmap-copy overflow candidate.
* `artifacts/static_library_role_audit_20260901.json` records 30 high-
  confidence bundled-library role aliases, including the final bzip2 stream
  callbacks.
* `artifacts/original_residual_semantic_review_20260830.json` records the
  historical address-level behavior of the two selected FreeType diagnostic
  helpers. Both helpers are now source-labeled in the current IDA copy.
* `artifacts/original_android_lifecycle_review_20260830.json` records the
  Activity, GLThread, renderer, and ARM64 JNI startup and pause boundaries.
* `artifacts/original_intent_launch_review_20260830.json` records the Android
  custom-scheme entrypoint, native URI parser, and script-visible start fields.
* `artifacts/original_http_redirect_review_20260830.json` records native HTTP
  redirect handling, destination replacement, and transport downgrade behavior.
* `artifacts/original_external_url_review_20260830.json` records script URL
  callbacks, Android intent construction, and installed-handler probing.
* `artifacts/original_http_framing_review_20260830.json` records response
  accumulation, header limits, transfer coding, and body completion behavior.
* `artifacts/original_facebook_bridge_review_20260830.json` records the
  Facebook session, permission, Graph request, and game-resource upload
  callbacks. It contains no real token or login result.
* `artifacts/original_billing_bridge_review_20260830.json` records the legacy
  Google Play billing script, JNI, purchase verification, and callback path.
  It contains no purchase data, signature, or embedded key material.
* `artifacts/original_partner_bridge_review_20260830.json` records the
  TapJoy, Distimo, Fabzat, TrialPay, Amazon, and Mobiroo compatibility paths,
  including their Java no-op behavior.
* `artifacts/original_android_device_media_review_20260830.json` records the
  Android build-info, display-metric, virtual-keyboard, and legacy video
  bridges. It contains no device-collected values or media data.
* `artifacts/original_native_init_review_20260830.json` records the fixed ELF
  init/fini callback arrays and their static-state behavior.
* `artifacts/original_aarch64_import_callsite_inventory_20260830.json` records
  direct AArch64 import transfers, including tail calls, and their containing
  functions.
* `artifacts/original_android_callback_review_20260830.json` records the
  remaining native Android JNI callback bodies and their behavior summaries.
* `artifacts/original_dex_native_surface_review_20260830.json` records the
  Natives class access flags and direct Java bytecode callsites.
* `artifacts/ida_translation_verification_20260902.json` records the final
  packed IDA copy, pass counts, hashes, and zero-failure verification result.
* `artifacts/ida_final_residual_audit_20260902.json` records the current
  compact address-level residual audit.
* `artifacts/ida_active_translation_scope_check_20260902.json` records the
  active-IDB check that separates remaining static wrappers from app-boundary
  functions.
* `symbols/libqplay.symbols.csv` is the searchable symbol table.
* `symbols/libqplay.symbols.json` is the machine-readable equivalent.
* `symbols/libqplay.symbols.summary.json` records the translation counts.
* `tools/` contains IDAPython, parsing, replay, and diagnostic patch helpers.
* `artifacts/` contains small metadata exports. APKs, certificates, private
  keys, captured credentials, and game assets are intentionally not included.

## Inputs used for the analysis

The primary input was the ARM64 library from the original Graal Online
Classic 1.8 APK. The x86_64 library from the same package was used only for
repeatable emulator experiments because the available Android emulator is
x86_64.

Two helper repositories were also checked out locally during the work:

* `MorenoLand/GScript.Go-HexaParser`, used as a reference for GS2 bytecode
  tooling.
* `MorenoLand/Moreno.kahn`, used to validate the archived connector package
  and its `con.png` container.

Their source is not vendored here. The exact commits and their role in the
local validation are recorded in the research notes.

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
local path is already complete through world rendering, so the next checks are
to verify the current connector trust and package-signing chain, repeat the
same packet sequence on a real ARM64 device, and compare the live server's
resource and login responses with the captured local trace. Those tests should
only use an endpoint and account that the operator is authorized to test.
