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
final ARM64 IDA copy also contains the reviewed callback, script-table, and
static-library aliases. The counts are:

| Kind | Count |
| --- | ---: |
| Retained ELF symbols translated | 8,601 |
| Additional reviewed function aliases | 1,249 |
| IDA functions in the saved copy | 11,297 |
| Remaining default `sub_` functions | 421 |

The retained ELF count includes 4,714 implementation functions, 3,183 PLT
thunks, 199 jump thunks, and 505 data symbols. The 421 remaining `sub_`
entries are code that IDA discovered without a preserved source symbol. They
are kept address-based rather than being assigned guesses. The compact
verification record is `artifacts/ida_translation_verification_20260830.json`.

The old connector has a concrete compatibility problem. Its embedded
GraalWeb certificate expired on 2023-07-29, so the original HTTPS path cannot
be trusted by a current clock. The archived connector package also fails the
RSA check against this APK's embedded public key. Both findings are separate
from the game-server protocol and are handled only by private diagnostic
patches in the local test build.

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
* `artifacts/ida_translation_verification_20260830.json` records the final
  packed IDA copy, pass counts, hashes, and zero-failure verification result.
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
