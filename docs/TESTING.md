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

The responder must use legacy lowercase headers. The old parser searches for
header names such as `content-length:` and `connection: keep-alive`.

```bash
python3 tools/connector_capture_server.py \
  --port 18080 \
  --con-png /tmp/con.png \
  --count 12 \
  --accept-timeout 180
```

The `con.png` body should be an archived response that has already been
parsed offline. Do not treat an invalid RSA signature as a production fix.
It is accepted in the diagnostic APK only to reach the next native stage.

## Two-connection game replay

Packet 48 is a server-warp instruction. The responder must therefore send it
on the first connection and wait for the client to reconnect before sending the
map and level sequence. The event-driven option below sends packet 182 after
the first ordinary client packet, which is useful for testing completion
candidates without guessing a delay:

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
  --basepackage-responses 4 \
  --extra-frame-once 48:2c636c61737369632c3132372e302e302e312c3134393030 \
  --extra-frame-after-first 7:2020636c61737369636970686f6e652e676d6170 \
  --extra-frame-after-first 55:2024746573742e20202f2020302020 \
  --frame-after-client 2:182:
```

The x86_64 diagnostic APK then reaches the rendered tile field and HUD. It
still leaves the blue connecting control visible, and ARM64 runtime behavior
has not been tested yet. Keep the trap and force-hide patchers in the private
working tree. They are investigation aids, not release repairs.

## Game responder

The local game responder implements only the frames needed for a bounded
protocol test. Its command line includes a server-warp, a minimal player
property update, a map selection, and the encrypted fixture files. Review
the script before changing the packet sequence.

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
  --outgoing-key 0123456789abcdef
```

The decoder prints frame metadata and hashes by default. Use the option that
explicitly permits login-field output only on private captures.

## What counts as a successful test

There are four separate milestones:

1. The connector HTTP response is framed and parsed.
2. The game socket completes the key exchange and logs `Connected.`.
3. The client requests and accepts the map and level files.
4. The player enters a rendered world and a live server accepts the login.

The current work has reproduced milestones 1 through 3 locally. Milestone 4
is intentionally still open. A local responder can prove native control flow,
but it cannot prove account authentication, server compatibility, or current
service availability.
