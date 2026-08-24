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

python3 tools/patch_localhost_resolver_test.py \
  --arch arm64-v8a \
  /tmp/libqplay.compat.so \
  /tmp/libqplay.loopback.so

python3 tools/patch_force_http_parser_test.py \
  --arch arm64-v8a --port 18080 \
  /tmp/libqplay.loopback.so \
  /tmp/libqplay.http.so

python3 tools/patch_fixed_output_rc4_key_test.py \
  --arch arm64-v8a \
  /tmp/libqplay.http.so \
  /tmp/libqplay.diagnostic.so

python3 tools/patch_render_loop_clear_loading_flag_test.py \
  /tmp/libqplay.diagnostic.so \
  /tmp/libqplay.render-boundary.so
```

Place the final file in a private ARM64 APK, keep the other ABI libraries out
of that diagnostic package when testing ARM64 selection, sign it for the local
emulator or device, and configure ADB reverse mappings for ports 18080 and
14900. The ARM64 fixed-key patch uses a trampoline at `0x1f2dcc` and resumes
the original function at `0x1fd6b8`; it is only for the offline responder.

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
connecting control. This is a local synthetic success. The ordinary ARM64
build completes the connector, server warp, encrypted login, map and level
requests, image request, and heartbeat path under the x86_64 emulator's
translation layer, but remains on the title or loading image. The separate
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

Decode a previously captured NewGraal stream with the known diagnostic
outgoing key:

```bash
python3 tools/decode_game_handshake_capture.py \
  /tmp/graal-handshake-2.in.bin \
  --key-hex 0123456789abcdef
```

The decoder prints frame metadata and hashes by default. Use the option that
explicitly permits login-field output only on private captures.

## What counts as a successful test

There are four separate milestones:

1. The connector HTTP response is framed and parsed.
2. The game socket completes the key exchange and logs `Connected.`.
3. The client requests and accepts the map and level files.
4. The player enters a rendered world and a live server accepts the login.

The current work has reproduced milestones 1 through 3 locally and has also
rendered a synthetic world with the x86_64 client HUD. The ARM64-only build
reproduced the same network and resource-request milestones under translation,
but did not render the world. The live-login part of milestone 4 remains open.
A local responder can prove native control flow, but it cannot prove account
authentication, server compatibility, or current service availability.
