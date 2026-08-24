# Runtime status

This is the short handoff view. The full reasoning and command history are in
`RESEARCH_NOTES.md`.

## Verified locally

1. The original APK launches on the Android 36 x86_64 emulator after the
   compatibility warning is dismissed.
2. The native library initializes OpenGL and starts the connector path.
3. The connector request shape is known, including the `p=` query, the
   legacy HTTP/1.0 headers, and the three fallback modes.
4. The archived connector body has valid framing and decrypts to a valid
   three-entry ZIP. Its RSA signature does not match the embedded public key,
   which is why the diagnostic replay uses an explicit test-only bypass.
5. Lowercase legacy HTTP response headers are required by the old parser. A
   corrected local replay reaches `Connected.`.
6. The repaired x86_64 client completes the NewGraal `fd` and `fc` exchange,
   receives an encrypted login-success packet, and logs `Connected.`.
7. Packet 48 causes the expected server-warp transition and a second game
   connection.
8. On the second connection, the client requests `classiciphone.gmap`, three
   `.code` level containers, `pics1.png`, and sends the normal heartbeat
   packets.
9. The emulator renders the level tile field and the game HUD. This proves the
   map, player-property, level-container, image, and renderer paths can all run
   in a controlled local test.
10. The symbol translation pass applied 8,601 names to the ARM64 IDA database
    with zero rename failures.

## Not verified

* A live game-server login.
* That the current live connector still accepts the 2019 client query.
* That the current server's certificate and package-signing chain can be
  replaced safely without changing protocol behavior.
* ARM64 runtime behavior on a real ARM64 device.
* Whether the live server sends the same completion sequence as the local
  responder.

## Current blocker

The local client renders the world but keeps the centered blue `Connecting to
classic...` control visible. The responder sends a NewGraal type 182 frame
after the first ordinary client packet. The complete outgoing capture contains
that frame, but an x86_64 trap at the native handler mapped to packet 182 is not
hit. A matching trap at the known packet 48 server-warp handler is hit, so the
probe is exercising native dispatch correctly.

The most likely remaining issue is that the packet 182 entry is missing or
overwritten in the input-handler table after the connector client is replaced
for the game connection. The static ARM64 table maps packet 182 to handler
index 14, `sub_1EB4C0`, which calls
`TGUIScriptLoader_hideConnectingWindow`. That static mapping and the local
runtime behavior do not yet agree.

The level loader is no longer the first suspect. The tile field and HUD render
after the corrected two-connection sequence. The next focused experiment is to
inspect or instrument the live `indatahandlers[182]` value on the second
connection, then test the same sequence on ARM64.

An attempted shortcut that routed every packet 59 directly to the apparent
file-parser address was rejected by comparison. It changed the client's first
connection from update-aware packet 47 requests to ordinary packet 23 requests
and prevented the second connection from reaching the map and level sequence.
The working local build leaves packet 59 under the repaired native handler
table.
