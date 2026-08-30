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
5. The response parser lowercases header lines before matching them. Local
   replay variants with lowercase or title-case names, and with either
   `Connection: keep-alive` or `Connection: close`, all reached the game
   responder. A no-`Content-Length` variant also worked when the local
   responder half-closed the response after the body.
6. The repaired x86_64 client completes the NewGraal `fd` and `fc` exchange,
   receives an encrypted login-success packet, and logs `Connected.`.
7. Packet 178 causes the expected server-warp transition and a second game
   connection. Packet 48 is a trigger-action path in this client table.
8. On the second connection, packets 9, 190, and 49 lead to requests for
   `classiciphone.gmap`, three `.code` level containers, and `pics1.png`.
   The responder returns each file through packet 102 and the client sends the
   normal heartbeat packets.
9. The emulator renders the level tile field and the game HUD. This proves the
   map, player-property, level-container, image, and renderer paths can all run
   in a controlled local test.
10. The original no-swap handler table routes packet 190 to the native
    connecting-window completion wrapper. The rendered world remains visible
    without the centered connecting control.
11. The symbol translation pass applied all 8,601 retained ELF names, then
    1,249 reviewed function aliases. The final packed copy has 11,297
    functions, 421 address-only `sub_` entries, and zero verification failures.

The Android lifecycle review now gives a pre-network checkpoint. The GL thread
must have a surface and window focus, and the permission callback must set
`Natives.downloaded`, before the first `QPlayMain` call can occur. The Android
compatibility warning was dismissed in the successful local replay. The full
startup and pause evidence is in
`artifacts/original_android_lifecycle_review_20260830.json`.

## Not verified

* A live game-server login.
* That the current live connector still accepts the 2019 client query.
* That the current server's certificate and package-signing chain can be
  replaced safely without changing protocol behavior.
* ARM64 runtime behavior on a real ARM64 device.
* Whether the live server sends the same completion sequence as the local
  responder.

## Current blocker

The local native path is no longer blocked. The no-swap table has been checked
against IDA and the emulator, and the final replay reaches a rendered world.
The earlier xchg handler-table patch and packet-182 hide hypothesis are closed
as false leads. Packet 182 maps to the process or window-list path, while
packet 190 reaches the connecting-window completion wrapper.

The remaining blockers are external validation rather than an identified
local parser failure:

* the current connector certificate and package-signing chain have not been
  tested against a live service;
* no live game-server login has been attempted or verified;
* the working replay uses an x86_64 diagnostic APK, so ARM64 device behavior
  still needs a controlled run.

The packet-59 shortcut remains rejected. The working file path is packet 102,
with optional large-file framing 68, 84, 102, 69. The local responder also
needs to send packet 49 again after the GMAP response because the tested client
otherwise caches the map without completing the pending transition.
