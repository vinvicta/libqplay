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

The recovered source first needs the missing closing brace documented in
`docs/HELPER_TOOLCHAIN.md`. After that parser repair, apply the observed
HexaParser literal-order adapter before compiling:

```bash
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
