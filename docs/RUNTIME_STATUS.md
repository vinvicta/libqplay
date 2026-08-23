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
7. A local server-warp reaches the game server. The client requests
   `classiciphone.gmap` and then requests the expected `.nw` levels.
8. The client receives the re-keyed `.code` responses. The files round-trip
   through a local implementation of the native DES and checksum algorithm.

## Not verified

* A live game-server login.
* That the current live connector still accepts the 2019 client query.
* That the current server's certificate and package-signing chain can be
  replaced safely without changing protocol behavior.
* A world render after the synthetic level responses.
* ARM64 runtime behavior on a real ARM64 device.

## Current blocker

The test client stays on the splash image after the map and level requests.
The external Android cache contains the sent files, but no final world
transition is visible. The remaining possibilities are narrow:

* packet 35 may be received but not dispatched to the download handler;
* the native level loader may reject a field in the re-keyed container;
* the player warp and property sequence may be too small to enter the normal
  renderer path; or
* the client may be waiting for an additional package or script that the
  local responder does not send.

The next experiment should log the return value and identity fields at
`TServerLevel_LoadEncrypted`, rather than adding more guessed packets.

