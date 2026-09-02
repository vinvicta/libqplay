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

To test response formatting without changing the body, use:

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

## TLS error and mode-3 fallback control

The static retry review shows that a CyaSSL error in connector mode 1 or 2 can
skip the remaining HTTPS attempt and enter mode 3, which uses plain HTTP. The
existing expiry control used only the TLS listener, so it did not capture this
second leg. A bounded follow-up needs two local responders and two reverse
mappings:

```bash
python3 tools/tls_capture_server.py \
  --certificate /tmp/expired.crt \
  --private-key /tmp/expired.key \
  --response /tmp/con.png \
  --port 18443 \
  --count 1
```

In a second terminal, start the existing HTTP capture on an unprivileged host
port. If the test should continue beyond the request observation, place the
same archived package at `/tmp/conf.gs` as well:

```bash
cp /tmp/con.png /tmp/conf.gs
python3 tools/connector_capture_server.py \
  --port 18080 \
  --count 2 \
  --accept-timeout 180
```

For an ARM64 library, set both device-side defaults explicitly in a private
copy. The x86_64 parser uses one folded arithmetic expression, so the same
pair is valid there because `18443 - 363 = 18080`:

```bash
python3 tools/patch_connector_tls_port_test.py \
  --arch arm64-v8a \
  --port 18443 \
  --fallback-port 18080 \
  /path/to/libqplay.so \
  /tmp/libqplay.two-port.so
```

To package the same control with the original APK, use the private builder.
The bundle may be a deliberately expired test certificate when the goal is to
observe fallback, or an authorized current chain when the goal is to test a
real service. The builder preserves native certificate and RSA verification;
`--force-nonpremium-loading` adds the separate loading-state diagnostic.

```bash
python3 tools/build_arm64_trust_control.py \
  /path/to/GraalOnline+Classic_1.8_APKPure.apk \
  /tmp/GraalClassic_arm64_two_port_debug_signed.apk \
  --bundle /path/to/test-chain.pem \
  --port 18443 \
  --fallback-port 18080 \
  --zipalign /path/to/android-sdk/build-tools/35.0.1/zipalign \
  --apksigner /path/to/android-sdk/build-tools/35.0.1/apksigner \
  --keystore /path/to/debug.keystore \
  --force-nonpremium-loading
```

The output is a debug-signed, ARM64-only diagnostic package. Keep it outside
the repository and uninstall the stock package before installing it if the
signing key differs. Do not use a diagnostic trust bundle or the forced
loading branch in a release client.

On the private emulator, map the connector's HTTPS port and the device's
plain HTTP fallback port separately:

```bash
adb reverse tcp:18443 tcp:18443
adb reverse tcp:18080 tcp:18080
```

Use the expired-trust diagnostic package, with the local resolver patch and
the connector HTTPS port set to 18443. The observed result on the private
x86_64 emulator is a TCP and TLS arrival on the first listener, no HTTP request
on that TLS connection, and then a plain `GET /conf.gs` on the second listener.
The full metadata is in
`artifacts/connector_fallback_runtime_control_20260902.json`.

The first control returned the archived `/con.png` package for `/conf.gs`.
The client remained at `Connecting to the login server...` and made no game
connection. Repeating the response with title-case headers and
`Connection: close` produced the same result. This is a useful boundary, not
a proof that the package parser or script VM rejects a real `conf.gs` body.
The current endpoint response must be obtained from an authorized source
before making a release repair. This is a local control only. It does not
validate the current service or justify disabling certificate verification.

For the package boundary, use a role-correct private fixture. The supplied
Moreno.kahn workbench at commit
`e1f49b5ce6fa46b41354d9a81f75994f91d3ff16` pairs the `conf.gs` role with
`StartScript_Fail` and the `con.png` role with `StartScript_Connector`. The
successful control generated a 959-byte signed package containing `.rk`, `.t`,
and `NPCS/StartScript_Fail`, then paired the diagnostic library with the
matching public test key. Native RSA verification and certificate checks were
left enabled. After the expired TLS leg, the emulator requested plain
`/conf.gs` and logged `MODE3_FAIL_SCRIPT_REACHED` from the failure script's
`onCreated` event. The compact record is
`artifacts/connector_mode3_fail_script_runtime_control_20260902.json`.

This fixture is deliberately a failure-script control, so it should not open
a game connection. It proves the local mode-3 framing, signature check, ZIP
unpack, script installation, and script execution. It does not establish what
the current service returns or provide a production signing key. Keep the
private keys and generated package outside this repository.

When `--output-dir` points to a new directory, the responder creates it before
accepting requests. This keeps capture setup separate from the protocol test.

The `con.png` body should be an archived response that has already been
parsed offline. Do not treat an invalid RSA signature as a production fix.
It is accepted in the diagnostic APK only to reach the next native stage.

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
connecting control. This is a local synthetic success. ARM64 runtime behavior
and live login remain unverified.

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

Decode a previously captured NewGraal stream with the known diagnostic
outgoing key:

```bash
python3 tools/decode_game_handshake_capture.py \
  /tmp/graal-handshake-2.in.bin \
  --key-hex 30313233343536373839616263646566
```

The decoder prints frame metadata and hashes by default. Use the option that
explicitly permits login-field output only on private captures.

## Malformed base-package negative control

The base package is not just a header. A local test that returned only
`GRPKG001`, `NAME`, `VERSION`, and `PLATFORM` reached the script-space setup
path and then crashed the x86_64 diagnostic build in
`TScriptSpace::receiveEvent`. The native stack was
`TScriptSpace::receiveEvent` -> `invokeCreatedEvent` -> `TScriptSpace` ->
`TGraalVar::createScriptSpace` -> `TClient::processIncomingPackages`.

This is a useful fixture warning and a conditional robustness finding. It
does not prove that the production service can deliver the same bytes, that a
live client has the same build, or that the crash is remotely reachable. Use
a package containing the required file and script records for render tests.
The private hashes and exact response sequence are in
`artifacts/synthetic_basepackage_crash_20260902.json`; raw APKs, captures, and
package bodies remain outside the repository.

## What counts as a successful test

There are four separate milestones:

1. The connector HTTP response is framed and parsed.
2. The game socket completes the key exchange and logs `Connected.`.
3. The client requests and accepts the map and level files.
4. The player enters a rendered world and a live server accepts the login.

The current work has reproduced milestones 1 through 3 locally and has also
rendered a synthetic world with the client HUD. The live-login part of
milestone 4 remains open. A local responder can prove native control flow, but
it cannot prove account authentication, server compatibility, or current
service availability.
