# Diagnostic repair matrix

This page keeps the tested changes separate from the changes that would be
appropriate for a release client. Every patch was applied to a private copy,
and the patch scripts check the original bytes before changing them.

The most important result is that there is not one failure with one switch.
The old connector has an expired trust bundle. A response signed by another
connector key can fail its RSA check, but the saved archived fixture passes the
native raw-digest check. After the trust boundary is handled in a loopback
replay, the ARM64 client still has a loading-state gate that can keep drawing
the title or loading image after network and resource work has completed.

## Connector diagnostics

| Test | Change | Result | Status |
| --- | --- | --- | --- |
| Certificate skip | Return from `TSocketConnection::setVerifyGraalWebCert` at ARM64 `0x20ab20` or x86_64 `0x222270` | The HTTPS attempt reached port 443, but the client still stayed on the splash screen | Useful isolation test, not sufficient |
| Trust bundle replacement | Encrypt a user-supplied certificate-only PEM bundle with the native `jhOdx9SY` rule at ARM64 `0x2dcef8` or x86_64 `0x2fca80` | The original encoded text decodes exactly, and a shorter standard-marker certificate bundle round-trips through the native decoder. Live endpoint compatibility is not tested | Production-compatible path, pending authorized current chain |
| TLS port-only loopback test | Change only the HTTPS port constants at ARM64 `0x200df0` and `0x200f74` with `tools/patch_connector_tls_port_test.py` | A SAN-matching local certificate reached the native TLS request on port `18443` while the HTTPS flag, hostname checks, and RSA branch remained intact | Loopback diagnostic only |
| Game-server TLS material audit | Decode the `setSSLParameters` certificate literal and trace native callback `0x1eb964` | The game-server verify buffer is the same expired Eurocenter Games certificate as connector trust-bundle entry 0. The script selects `RC4-SHA` and `SSLv23` only when `usessl` is true; the recovered Classic branch forces it false | Real stale material for other branches, not an active Classic blocker |
| Game-server certificate encoder | Prepare a certificate-only replacement for script string 143 with the native `NakFpz15` transform | The replacement round-trips offline with peer verification left enabled | Compile, package, sign, and validate only for an authorized endpoint |
| Game-server GS2 source replacement | Replace both recovered `setSSLParameters` certificate literals before HexaParser compilation | The original certificate gives an identity source and bytecode result; a 1,072-character offline test certificate compiles successfully | Source preparation only, no live endpoint test |
| Delayed TLS path audit | Recheck `O_NONBLOCK`, status 4 to 5 completion, `SO_ERROR`, and the status setter's SSL call in IDA | The delayed path does start CyaSSL through `TSocketConnection_setStatus_int`; no blocking-I/O repair is justified | False lead closed |
| Longer connect poll | Change the x86_64 zero-second poll timeout to five seconds | The client still stayed on the splash screen | Not the complete cause |
| HTTP transport redirect | Force the recognized HTTPS parser result to port 80 with SSL disabled | The local HTTP request was received, but transport alone did not advance the client | Not a repair |
| Spectron endpoint audit | Compare the native connector fragments instead of reusing 1.8 host assumptions | Spectron selects `cong.quattroplay.com` and `cong2.quattroplay.com`, while paths and transport modes remain the same | Static finding, live status unknown |
| Spectron local loopback package | Use target-specific trust, resolver, HTTPS-port, and fixed-key patches with `tools/build_spectron_loopback_apk.py` | The exact supplied APK built, aligned, and passed APK signature verification; no runtime claim was made because no emulator was connected for this build check | Private offline diagnostic only |
| Native RSA path retained | Leave the RSA branch at its original bytes and use the saved response, which passes the native raw-digest check | The package-preserving ARM64 candidate retained original bytes `dc 00 00 35` and completed a fresh translated-ARM64 loopback replay without the RSA bypass | Verified local package test, live service still open |
| RSA result bypass | Accept a response that fails the native package-signature check at ARM64 `0x22c5c8` or x86_64 `0x245009` | Used by the early replay before the raw wolfSSL format was identified. The saved archived fixture passes without it | Unnecessary for the saved fixture, diagnostic only for mismatched packages |
| Controlled connector key | Replace the encrypted embedded key at ARM64 `0x2e1798` or x86_64 `0x3003d8` in a private library copy, then sign a local package with the matching test key | The generated 16,446-byte package passed the native wolfSSL raw-digest RSA check without bypassing the result branch | Diagnostic only |
| Blocking socket I/O | Make all socket operations blocking | The renderer froze | Rejected |

The certificate skip is narrowly scoped to the connector path. IDA shows that
`THTTPRequest::sendRequest` calls `setVerifyGraalWebCert` only for its
connector request. The ordinary game connection is created by
`TGraalConnection::connectToServer`, which supplies its own certificate field
through `TGraalConnection::setSSLVerifyCert`. This is why the two trust paths
must not be described as one global Android SSL-pinning problem.

The preferred certificate path is a replacement trust bundle, not the skip.
`tools/patch_graalweb_trust_bundle.py` refuses a different library revision,
refuses private-key material, and keeps peer and hostname verification in the
native code. The supplied bundle must come from an authorized current endpoint
or its operator. The repository contains no replacement production chain.

The replacement path has a complete local replay record. A one-certificate
PEM bundle for `con.quattroplay.com` was encoded into a private ARM64 copy,
the HTTPS port was moved to `18443` only for ADB reverse, and the local TLS
responder observed the native request. With the original RSA branch retained,
the same APK completed the game handshake, loaded the map and assets, kept the
heartbeat alive, and rendered the translated ARM64 world. The exact hashes
and capture scope are in `artifacts/diagnostic_patch_matrix.json`. This
removes the local TLS path from the list of unknowns, but it does not validate
the expired historical chain against a current authorized service.

The archived package's RSA result is a separate boundary. The saved fixture
passes it when checked in the native format, so a package-preserving replay
should leave the branch unchanged. Skipping it remains useful for studying a
package from another key, but it removes an authenticity check. A release
client needs a current package signed with the key it is authorized to trust.
The local package used for the first replay was signed with a temporary
diagnostic key and must not be treated as a release artifact.

The controlled-key experiment is a stronger test of the parser and packer,
not a replacement for the bypass. `tools/patch_connector_test_public_key.py`
rewrites the native DES-wrapped key text only after checking the original
360-character value. The local raw PKCS#1 public-key DER is 270 bytes with
SHA-256
`5dff27a209730bdc52b4c182e85411dcdf584659d94dddca25062cfdae149cd9`.
The matching package has SHA-256
`d26035d9569789c2d6a60fb52673e91877a58e221117ca987a08dcbd674045be`.
The private test key is not committed, and no runtime APK using this key was
treated as a production build.

The Spectron package has its own checked offset map. The target trust bundle is
at `0x2ea9e0`, the resolver entry is at `0x20c20c`, and the two HTTPS port
instructions are at `0x2065e0` and `0x206764`. Its outgoing-key diagnostic
uses the 128-byte zero-filled cave at `0x1c4000` and the target
`setEncryptionOut` entry at `0x202fe8`. These offsets are guarded against the
exact target library hash and are not interchangeable with the 1.8 values.
The target-specific plan and byte guards are recorded in
`artifacts/spectron_loopback_patch_audit_20260828.json`.

## Loading-state diagnostics

| Test | Change | Result | Status |
| --- | --- | --- | --- |
| Getter override | Return false from `getLoadingScreenEnabled` | The startup sequence was disrupted and no connector request was observed | Negative control |
| Original-stream script clear | Copy the existing `loadingscreenenabled = false` bytecode sequence into `onServerLogin` with `tools/patch_connector_bytecode_loading_clear.py` | The original VM stream loaded, reached two `14900` game connections, accepted login, received the map and three level files, and sent heartbeats. The bounded screenshot still showed title/loading artwork | Strong local script and protocol candidate, render state still open |
| Original-stream script clear plus native startup clear | Combine the direct script patch with the existing branch edit at ARM64 `0x15ca7c` | The same script and native chain reached the map, level files, image path, heartbeats, and a translated-ARM64 world/HUD screenshot | Historical combined diagnostic |
| Non-premium branch with original script | Change the conditional at ARM64 `0x15ca7c` so the existing clear at `0x15cac8` runs, while serving the original connector stream unchanged | The translated ARM64 client rendered the tiled world, HUD, and status icons with the exact `.gmap` fixture. No script-level loading clear was present | Leading isolated local candidate |
| Stock premium branch with original script | Restore the original `B.LE` bytes at ARM64 `0x15ca7c` with `tools/patch_restore_premium_loading_test.py` | The same translated client completed the map, three level files, image request, and heartbeat path, but retained the title/loading artwork | Matched negative control |
| Spectron 2.2 non-premium branch with original script | Change the target conditional at `0x15fad8` from `B.LE 0x15fb1c` to an unconditional branch to the existing clear block | The target-specific ARM64 package completed the same local connector and game replay, then rendered the green tiled world with the HUD and status indicators | Verified translated-ARM64 loopback control |
| Render-boundary clear | Hook the getter call at `0x244228`, clear the flag through GOT slot `0x375e30`, then return to `0x24422c` | The translated ARM64 client rendered the same world and HUD | Control only |

The native flag starts enabled at `0x37a549`. The marker decodes to
`classic`, and the normal premium-option path skips the startup clear. The
packet-190 connecting-window completion wrapper does not write this byte. The
JNI loop reads it before choosing the loading or game draw path. That evidence
points to initialization state, rather than a missing map or failed level
download, as the local cause of the remaining visual split.

The non-premium branch is the smallest state-oriented experiment because it
reuses the client's own initialization and leaves the render loop unchanged.
The Spectron equivalent is at `0x15fad8`, not the earlier target path at
`0x15faac`. The latter selects an executable-path fallback and was rejected
after the full target pseudocode was reviewed. The target control was run
through Android's x86_64 ARM64 translation layer. It is still not called a
production fix, and the meaning of the premium branch needs to be confirmed on
a physical ARM64 device and an authorized current service. The exact target
replay is recorded in
`artifacts/spectron_arm64_loopback_loading_replay_20260828.json`.

## Rejected handler-table repair

An earlier experiment swapped the two values loaded from each bytecode handler
pair. The x86_64 patch used `xchg ecx, edx` at `0x202ea5`; the matching ARM64
change swapped the lookup and store instructions at `0x1ea7ac` and `0x1ea7b4`.
That interpretation was wrong. The runtime pair layout is:

```text
packet type, handler index
```

The original ARM64 instructions, the decoded connector script, and the
successful no-swap replay all agree. The swap script remains in the repository
only as a negative control.

## Exact patch data

The machine-readable version is
`artifacts/diagnostic_patch_matrix.json`. The public diagnostic patcher
contains only the connector RSA and certificate edits. The loading-state
experiments have separate names so a test operator cannot accidentally assume
that a renderer control is part of the connector repair.

The first complete private replay used these controls:

1. connector RSA diagnostic bypass;
2. connector certificate diagnostic bypass;
3. loopback connector and game responders;
4. deterministic outgoing RC4 key for the local responder;
5. non-premium initialization branch.

It reached two game connections, `classiciphone.gmap`, three level containers,
`pics1.png`, continuing heartbeats, and a rendered world. The APK and native
hashes, plus the screenshot hash, are in the JSON artifact and
`docs/RUNTIME_STATUS.md`. The corrected parser shows that the RSA bypass was
not required for the saved archived response. A later clean-data replay of the
package-preserving ARM64 candidate retained the native RSA branch, made the
same connector request, opened two game connections, and produced the same
render screenshot. No live service or physical ARM64 device was used.

For the main ARM64 target, a package-preserving ARM64-only candidate was also
built with the original RSA bytes and the non-premium loading candidate. Its
APK SHA-256 is
`dad598e0cec03b501ff8cc30648ad843346fa3a331db3087ffa54ff92938af3a`.
Its native library has SHA-256
`888a236bb839eef7ab094196b924796680d23d857a0d7533487bcd3786efb308`, and the
original RSA branch bytes are `dc 00 00 35`. It was installed after clearing
only the emulator app data, the Android compatibility dialog was dismissed,
and the fresh loopback replay rendered the world with screenshot SHA-256
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
This is still a translated-ARM64 diagnostic result, not a live-service or
physical-device result.

## What a real repair still needs

The next production-compatible sequence is deliberately external to this
repository's loopback tests:

1. capture the current response to the exact 2019 client query from an
   endpoint the operator is authorized to test;
2. verify the package signature with the current authorized public key;
3. update the connector trust material to a current authorized chain while
   retaining hostname and peer verification;
4. test the loading-state candidate on a physical ARM64 device;
5. repeat login and resource requests with an authorized account.

Until those checks are complete, the honest result is a reproducible local
render proof and a well-bounded set of compatibility candidates, not a live
client repair.
