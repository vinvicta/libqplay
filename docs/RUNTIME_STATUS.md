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
   three-entry ZIP. Its RSA signature passes the embedded public-key check
   when the native wolfSSL raw-digest format is reproduced. An earlier generic
   ASN.1 verifier used the wrong format, so the first diagnostic replay used a
   bypass that the saved fixture does not need.
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
    1,551 reviewed aliases, including 141 exact FreeType 2.3.6 matches, 153
    exact IJG libjpeg 6b matches, one zlib match, and one giflib role match.
    The current packed copy has 11,296 named functions, zero default `sub_`
    entries, and 124 stable descriptive residual labels. Verification has
    zero failures.

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
* Whether the ARM64 loader and its fixed init-array callbacks complete on a
  current device image.
* Whether the live server sends the same completion sequence as the local
  responder.
* Whether an activated script can pass the native socket allowlist checks and
  create a listener or use the UDP branch.
* Four exported Android callbacks have no direct DEX `invoke-*` caller in the
  static scan. Reflection and native-to-Java callback reachability were not
  covered.
* The early-pause callback behavior has not been rerun on a current ARM64
  device with activity, permission, and surface timestamps captured.
* A 2.2 `libqplay` binary is not present in the current workspace. No
  cross-version symbol, protocol, or behavior mapping has been applied.
* The four 1.8 native ABI variants were compared statically. They share the
  connector trust text and marker set, but no non-ARM64 or physical ARM64
  runtime was executed in this pass.

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

## Device diagnostic order

The native error string collapses several independent failures into the same
message. A private ARM64 run should record these checkpoints in order:

1. Confirm that the permission callback sets `Natives.downloaded`, the GL
   thread has a surface and focus, and `QPlayRenderer.loadLibrary` reaches
   `Natives.QPlayMain`. If this stage is absent, the connector has not run.
2. Confirm that `QPlayMain` returns and that the Java side records
   `Natives.loaded`. A dynamic-linker error, missing legacy C++ runtime, or an
   early native initialization failure belongs here, before TLS.
3. Record the first connector destination and whether the native socket reaches
   TCP connect completion. A DNS or socket error is distinct from a TLS error.
4. For HTTPS, check whether the responder sees a ClientHello and whether the
   client sends `GET /con.png` afterward. The paired local validity control
   reached TCP but sent no HTTP request with the expired trust material, while
   a matching valid bundle sent the GET. A live device that stops at this
   boundary should not be debugged by disabling certificate checks. Also
   record the next connector mode and destination. Static analysis shows that
   a nonzero CyaSSL error in mode 1 or 2 jumps directly to mode 3 and may send
   plain `GET /conf.gs`, so the missing first GET is not by itself proof that
   the state machine stopped. The focused record is
   `artifacts/connector_fallback_review_20260902.json`.
5. If HTTP completes, check the binary envelope, RSA result, ZIP dispatch, and
   `StartScript_Connector`. A valid HTTP response that never emits
   `onServerWarp` is a connector package or script activation problem.
6. If `onServerWarp` fires, record the game address, port, socket status 4 to 5
   transition, and the first `fd` and `fc` frames. No second socket attempt
   points to the connector script handoff or address fields; a socket that
   remains at status 4 points to transport or firewall behavior; a completed
   socket with no protocol frames points to the game-server handshake.
7. After packet 178, check the second connection and the packet-9, packet-190,
   packet-49, and file-request sequence. If the map or level request is made
   but loading fails, inspect the external cache under the native reported
   application-files directory. The cache writer does not check `fwrite`, so a
   partial file can survive as an apparently completed resource. The focused
   review is `artifacts/cache_filename_policy_review_20260902.json`.

This order keeps the strongest current hypotheses separate: Android startup
gates, legacy loader compatibility, expired connector trust, package parsing,
game protocol state, and corrupted downloaded resources. It is a diagnostic
checklist, not a claim that the live service accepts the 2019 client.
