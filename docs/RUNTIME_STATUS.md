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
   three-entry ZIP. Its RSA signature passes the native wolfSSL raw-digest
   check against the embedded public key. The first replay used an explicit
   RSA bypass because the original offline checker used the wrong signature
   format; a package-preserving replay should leave that branch unchanged.
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
9. The x86_64 diagnostic build renders the level tile field and the game HUD.
   This proves the map, player-property, level-container, image, and renderer
   paths can all run in a controlled local test with that native library. It
   is not a stock loading-state result because several historical x86 test
   APKs used a loading-getter override.
10. The original no-swap handler table routes packet 190 to the native
    connecting-window completion wrapper. The rendered world remains visible
    without the centered connecting control.
11. The symbol translation pass applied 8,601 names to the ARM64 IDA database
    with zero rename failures.
12. An ARM64-only diagnostic build running through the x86_64 emulator's native
    translation layer completes the connector, server warp, encrypted login,
    map, three level-file requests, image request, and heartbeat path. The
    expected map, level, and image files appear in the external cache.
13. A one-instruction ARM64 diagnostic candidate forces the existing
    non-premium initialization branch at `0x15ca7c`. With the exact `.gmap`
    fixture, the normal render loop displays the tiled world, player HUD, and
    status icons through the translated ARM64 draw path.
14. A separate render-boundary diagnostic clears the loading byte only after
    timer and packet processing. It produces the same visible result and
    remains available as a control for the initialization candidate.
15. The supplied conpack tool now produces a client-compatible legacy ZIP
    when its four header fields are matched to the archived package. The
    original connector bytecode survives repack and reaches the same local
    two-connection game replay.
16. Raw HexaParser output is parseable and packable, but its same-line brace
    literals are reversed relative to the native-order reconstruction. In a
    two-port negative control it opened three connections to the alternate
    `14896` listener and none to the expected `14900` listener.
17. `tools/reverse_hexaparser_literals.py` restores the observed literal
    order for the connector fixture. The adapted bytecode reaches two
    `14900` connections, the map, three level files, `pics1.png`, and
    continuing heartbeats. Its rendered screenshot exactly matches the
    original-bytecode compatibility replay. This is a fixture-level compiler
    parity result, not proof for arbitrary scripts.
18. A full-asset, ARM64-only debug APK built from the original 1.8 package and
    the five-step diagnostic chain was installed on the x86_64 emulator. Its
    APK SHA-256 is
    `b1c52234b10fb5a4a2c6c58e85370ccab710b1c355574d295df30b5ed6edddcc`, and
    its packaged ARM64 `libqplay.so` SHA-256 is
    `89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858`.
    Android logged Berberis loading the ARM64 process and `qplay` reached
    OpenGL initialization. The private responder observed the connector
    request, two game connections, encrypted login, the map, three level
    files, `pics1.png`, and continuing heartbeat packets. The captured screen
    reached the tiled world and HUD. The screenshot SHA-256 is
    `fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
    This is a local translated-ARM64 result, not a release APK or a physical
    ARM64-device result.
19. The corrected offline parser reproduces the native raw-digest RSA check.
    The saved connector response passes with the embedded key, so the RSA
    bypass used by the first replay is not required for that fixture.
20. A private package-preserving x86_64 candidate was built with the original
    RSA bytes, the certificate diagnostic, loopback transport patches, and the
    fixed local handshake key. Its APK SHA-256 is
    `e794a8c096de46d14e2a98142fd8082c003d4b05e30fd9735e187c365d8e86ab`.
    It has not been rerun because the local emulator is no longer available.
21. A matching ARM64-only package-preserving candidate was also built with
    the loading-state candidate. Its APK SHA-256 is
    `dad598e0cec03b501ff8cc30648ad843346fa3a331db3087ffa54ff92938af3a`,
    and its native SHA-256 is
    `888a236bb839eef7ab094196b924796680d23d857a0d7533487bcd3786efb308`.
    Its original RSA branch bytes are `dc 00 00 35`. This package is prepared
    for a future translated or physical ARM64 runtime check only.
22. The trust-bundle replacement tool was checked against the original ARM64,
    armeabi, x86, and x86_64 libraries. A one-certificate standard PEM bundle
    encoded at each architecture-specific offset and decoded byte-for-byte.
    These checks were offline and did not establish compatibility with a live
    endpoint.
23. The IDA audit of the nonblocking connector path confirms that status 4
    `EINPROGRESS` completion reaches `TSocketConnection_setStatus_int` with
    status 5, which starts CyaSSL when SSL is enabled. The earlier blocking-I/O
    experiment remains rejected because it froze the renderer.

## Not verified

* A live game-server login.
* That the current live connector still accepts the 2019 client query.
* That the current server's certificate and package-signing chain can be
  replaced safely without changing protocol behavior.
* ARM64 runtime behavior on a real ARM64 device, especially renderer entry.
* Whether forcing the non-premium branch is the intended production state
  transition on a physical ARM64 device. The embedded marker statically
  decodes to `classic`, and the ordinary translated ARM64 run remains on the
  title or loading image, while both diagnostics display the world.
* Whether an unmodified x86_64 build clears its loading state without the
  getter override present in several historical diagnostic APKs.
* Whether the live server sends the same completion sequence as the local
  responder.
* Whether the literal-order adapter generalizes to scripts with different
  syntax or multiline literals. Only the recovered connector fixture has
  passed the adapted runtime replay.

## Current blocker

The local native path is complete through rendered-world entry for the x86_64
diagnostic build. The no-swap table has been checked against IDA and the
emulator, and the earlier xchg handler-table patch and packet-182 hide
hypothesis are closed as false leads. Packet 182 maps to the process or
window-list path, while packet 190 reaches the connecting-window completion
wrapper. The recovered connector source also reaches the same local replay
after the targeted literal-order adapter; the raw HexaParser output does not.

The ARM64 diagnostic run establishes a narrower result. Under the available
x86_64 emulator, Android translated the ARM64 native code far enough to make
both game connections, accept the encrypted login, request the map and level
files, cache the image, and keep the heartbeat alive. The ordinary build did
not leave the title or loading image. The native audit shows why: the flag at
`0x37a549` starts enabled, the normal `classic` initialization path skips its
clear, and the packet-190 completion wrapper does not change it. The
non-premium initialization candidate and the independent render-boundary
control both displayed the world and HUD. A real ARM64 device is still
needed for final runtime validation.

One earlier blocker has been removed from the list. The saved connector
response was initially treated as unsigned because the offline checker used
the wrong RSA encoding. IDA and the corrected parser show that it passes the
native wolfSSL raw-digest check. The remaining connector concerns are the
expired HTTPS trust bundle and the behavior of the current live endpoint, not
the saved fixture's RSA branch.

The remaining blockers are external validation rather than an identified
local parser failure:

* the current connector certificate and package-signing chain have not been
  tested against a live service;
* no live game-server login has been attempted or verified;
* the rendered replay uses an x86_64 emulator with Android's ARM64
  translation layer;
* the ARM64-only replay needs a real ARM64 device run to separate native
  renderer behavior from the emulator translation layer.

The packet-59 shortcut remains rejected. The working file path is packet 102,
with optional large-file framing 68, 84, 102, 69. The local responder also
needs to send packet 49 again after the GMAP response because the tested client
otherwise caches the map without completing the pending transition.
