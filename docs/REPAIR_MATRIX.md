# Diagnostic repair matrix

This page keeps the tested changes separate from the changes that would be
appropriate for a release client. Every patch was applied to a private copy,
and the patch scripts check the original bytes before changing them.

The most important result is that there is not one failure with one switch.
The old connector has an expired trust bundle and a stale archived package can
fail its RSA check. After those boundaries are passed in a loopback replay,
the ARM64 client still has a loading-state gate that can keep drawing the
title or loading image after network and resource work has completed.

## Connector diagnostics

| Test | Change | Result | Status |
| --- | --- | --- | --- |
| Certificate skip | Return from `TSocketConnection::setVerifyGraalWebCert` at ARM64 `0x20ab20` or x86_64 `0x222270` | The HTTPS attempt reached port 443, but the client still stayed on the splash screen | Useful isolation test, not sufficient |
| Longer connect poll | Change the x86_64 zero-second poll timeout to five seconds | The client still stayed on the splash screen | Not the complete cause |
| HTTP transport redirect | Force the recognized HTTPS parser result to port 80 with SSL disabled | The local HTTP request was received, but transport alone did not advance the client | Not a repair |
| RSA result bypass | Accept the archived package at ARM64 `0x22c5c8` or x86_64 `0x245009` | The local script could be studied and the game-server handoff could be reached | Diagnostic only |
| Blocking socket I/O | Make all socket operations blocking | The renderer froze | Rejected |

The certificate skip is narrowly scoped to the connector path. IDA shows that
`THTTPRequest::sendRequest` calls `setVerifyGraalWebCert` only for its
connector request. The ordinary game connection is created by
`TGraalConnection::connectToServer`, which supplies its own certificate field
through `TGraalConnection::setSSLVerifyCert`. This is why the two trust paths
must not be described as one global Android SSL-pinning problem.

The archived package's RSA result is a separate boundary. Skipping it was
useful for replaying the package locally, but it removes an authenticity check.
A release client needs a current package signed by the key it is authorized to
trust. The local package used for the final replay was signed with a temporary
diagnostic key and must not be treated as a release artifact.

## Loading-state diagnostics

| Test | Change | Result | Status |
| --- | --- | --- | --- |
| Getter override | Return false from `getLoadingScreenEnabled` | The startup sequence was disrupted and no connector request was observed | Negative control |
| Non-premium branch | Change the conditional at ARM64 `0x15ca7c` so the existing clear at `0x15cac8` runs | The translated ARM64 client rendered the tiled world, HUD, and status icons with the exact `.gmap` fixture | Leading local candidate |
| Render-boundary clear | Hook the getter call at `0x244228`, clear the flag through GOT slot `0x375e30`, then return to `0x24422c` | The translated ARM64 client rendered the same world and HUD | Control only |

The native flag starts enabled at `0x37a549`. The marker decodes to
`classic`, and the normal premium-option path skips the startup clear. The
packet-190 connecting-window completion wrapper does not write this byte. The
JNI loop reads it before choosing the loading or game draw path. That evidence
points to initialization state, rather than a missing map or failed level
download, as the local cause of the remaining visual split.

The non-premium branch is the smallest state-oriented experiment because it
reuses the client's own initialization and leaves the render loop unchanged.
It is still not called a production fix. The test ran through Android's
x86_64 ARM64 translation layer, and the meaning of the premium branch needs to
be confirmed on a physical ARM64 device and an authorized current service.

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

The complete private replay used these controls:

1. connector RSA diagnostic bypass;
2. connector certificate diagnostic bypass;
3. loopback connector and game responders;
4. deterministic outgoing RC4 key for the local responder;
5. non-premium initialization branch.

It reached two game connections, `classiciphone.gmap`, three level containers,
`pics1.png`, continuing heartbeats, and a rendered world. The APK and native
hashes, plus the screenshot hash, are in the JSON artifact and
`docs/RUNTIME_STATUS.md`. No live service or physical ARM64 device was used.

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
