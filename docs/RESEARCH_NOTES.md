# Reverse-engineering research notes

This document is the long-form record of the investigation. It is deliberately
more conversational than a disassembly listing because the useful part of this
project is the chain of evidence: what the binary says, what the emulator did,
and where the two still disagree.

## Starting point

The primary APK is an old Graal Online Classic 1.8 build. Its package is
`com.quattroplay.GraalClassic`, version code 6158, version name 1.8, with
launcher activity `com.quattroplay.GraalClassic.QPlayActivity`. The APK
contains ARM64 and x86_64 native libraries. The ARM64 `libqplay.so` was loaded
into IDA because that is the architecture with the most useful symbol
information. The available emulator is x86_64, so the x86_64 library was used
for runtime checks against the same application family.

The original files are kept in the private working directory and are not
committed here. The public archive contains hashes, symbol exports, scripts,
and notes, but not the APK or a copied game data set.

The supplied `spectron_client_1.0.2.apk` is a comparison point. It contains
custom routing and packaging behavior, but it is not automatically a correct
replacement for the original client. The two helper projects were checked out
locally at these commits:

* `GScript.Go-HexaParser` at `ad9bd3657feece825b5f5a888f5db34ffe37afb9`.
* `Moreno.kahn` at `5e3a05fc8fbcf3c3f72b3c263238b2ed275fc66d`.

The custom `con` tool produced the same ZIP payload as the independent
decoder. That cross-check separated a package parsing mistake from a client
compatibility problem.

## Symbol pass

The first pass was intentionally mechanical. It extracted the surviving ELF
symbols, demangled the C++ names, classified implementation functions, thunks,
and data, and applied aliases to the ARM64 IDA database. The final summary is:

* translated symbols: 8,601;
* renamed functions: 4,714;
* PLT thunks: 3,183;
* jump thunks: 199;
* data symbols: 505;
* rename failures: 0.

The complete machine-readable result is in `symbols/`. Keeping the original
mangled name beside the demangled name preserves a useful lookup key. A thunk
is named separately from its target so cross-references do not become
ambiguous.

The translated symbols changed the pace of the rest of the investigation.
Instead of guessing from strings, the connector and login flow could be
followed by name. Important ARM64 addresses include:

* `TServerList_login` at `0x204420`;
* `TServerList_enterNextConnectorMode_int` at `0x203df4`;
* `TClient_connectToGameServer` at `0x1e7058`;
* `TGraalConnection_connectToServer` at `0x1feb98`;
* `TSocketConnection_connectSocket` at `0x206bd8`;
* `TSocketConnection_checkConnecting` at `0x206a48`;
* `TSocketConnection_enableSSLOnSocket` at `0x206450`;
* `THTTPRequest_sendRequest` at `0x1ffde8`;
* `THTTPRequest_saveDownloadedData` at `0x200010`;
* `THTTPRequest_runScript` at `0x2025a0`;
* `TClient_parse` at `0x1e7cd0`;
* `TServerLevel_LoadEncrypted_void` at `0x1aa198`.

## Connector and TLS

The startup path creates an HTTP request for one of three connector modes.
Modes 1 and 2 use HTTPS. Mode 3 uses an older HTTP fallback. The client sends
the version, build date, platform, and a DES plus Base64 parameter list. It
also sends a `p=` query generated for the request rather than a constant URL
parameter.

The HTTPS path is native CyaSSL. The certificate is not supplied by Android's
Java trust store. `TSocketConnection_setVerifyGraalWebCert` decrypts an
embedded certificate and supplies it to the CyaSSL context. The certificate
expired on 2023-07-29, and the verifier's date routine consults the current
clock. That is a real compatibility failure for a current device.

An expired certificate does not explain every observed failure. A diagnostic
build that forced the parser through plain HTTP still did not advance until
the response format was made compatible. Certificate repair is necessary for
the old HTTPS path, but it is not sufficient evidence of a working client.

## Connector package

The response named `con.png` is a binary package. Its first four bytes are a
big-endian signature length, followed by a 256-byte signature, a second
big-endian payload length, and the encrypted ZIP. The archived body is 16,446
bytes and decrypts to a valid ZIP containing `.rk`, `.t`, and
`NPCS/StartScript_Connector`.

The body does not validate against the public key recovered from this APK.
The package is therefore a stale or mismatched artifact for a strict client.
The local test has a narrowly scoped RSA branch bypass so the script compiler
can be studied. That bypass is not a safe release repair.

The next surprise came from the HTTP response headers. The old parser stores
literal lowercase header names such as `content-length:` and
`connection: keep-alive`. The first replay responder used conventional
capitalized headers and `Connection: close`. The client accepted the TCP
connection, but never recognized the body and timed out through four short
polls. Once the responder used the legacy lowercase names, the client logged
`Connected.` and ran the connector script. This was a protocol-format issue,
not a cryptographic issue.

That correction is encoded in `tools/connector_capture_server.py` and is
called out in `docs/TESTING.md` so a future test does not repeat it.

## Script to native handler boundary

The decoded connector script installs inbound handler pairs. The pair for
server login is `(54, 10)`. Static inspection of the native setter showed a
reversed lookup and store on this build. The lookup uses the second value and
the store uses the first value, leaving packet 54 without `onServerLogin`.

The ARM64 instructions at `0x1ea7ac` and `0x1ea7b4` use the wrong register
indices. The local repair changes the bytes from `00 d8 62 f8` to
`00 d8 61 f8`, and from `40 d8 21 f8` to `40 d8 22 f8`. The x86_64 repair is
an `xchg ecx,edx` replacement at `0x202ea5`. The patch helper checks original
bytes before writing.

This bug is independent of the expired connector certificate. Keeping the two
findings separate prevents an overly broad patch from hiding which layer
actually failed.

## NewGraal key exchange

The local game responder initially used a guessed frame sequence. Static
tracing of `setProtocol_NewGraal`, `setEncryptionIn`, and `setEncryptionOut`,
followed by capture decoding, established the actual behavior:

* `GNP1905C` identifies the protocol;
* the first client exchange is an outer type `0xfd` frame;
* the server returns type `0xfc` with encrypted key setup;
* the client then emits an encrypted login envelope;
* the first ordinary server sequence is zero after key setup;
* RC4 state is continuous across the direction, not recreated per frame.

The test responder uses a deterministic outgoing key only in the diagnostic
APK. That lets the local server decode the client's login envelope without
implementing the server's private RSA path. The key is not a real account
credential and is not included in this repository.

## Server warp and packet mapping

The connector script selected a login host and port. To keep the test local,
the responder sends packet 48 with a comma-separated destination that points
to `127.0.0.1:14900`. The client prints `Serverwarp...`, reconnects, and
replays its login sequence.

Packet 7 was initially sent with a bare `.nw` name. Static analysis of the
handler showed that it sets the active player's level name but only takes the
map entry path when the name ends in `.gmap`. The responder was corrected to
send `classiciphone.gmap` after the two coordinate bytes. The client then
requested the map and emitted level requests.

Packet 55 carries player properties. A minimal valid nickname property begins
with property code zero encoded as `0x20`, followed by a length byte encoded as
length plus 32, then the nickname. The local body for `test` is
`20 24 74 65 73 74`. It is enough to exercise the property parser, but it may
not be enough to construct all state the normal login script expects. That is
one possible reason the renderer does not leave the splash screen.

## Level loader investigation

The client requested these levels in the corrected local trace:

* `overworld_west_ocean_09.nw`;
* `overworld_west_ocean_02.nw`;
* `overworld_west_ocean_10.nw`.

The responder returned files named with the port suffix, such as
`overworld_west_ocean_09.nw-14900.code`. The files were made by taking a
known-good cached `black.nw-14896.code` container, decrypting it, changing the
server identity, signature, and level-name field, then re-encrypting it under
the new level filename.

The container helper passed a round trip against the original file and the
client's external cache contains the exact 316-byte files that were sent. The
client still shows the splash image, so there is now a sharper question:
does the loader reject the container, or does the client never call the loader
after packet 35?

The next test should answer that directly by instrumenting the return value of
`TServerLevel_LoadEncrypted` and the packet-35 handler. It is more useful than
adding another guessed packet to the responder.

## Cache path correction

There was a misleading intermediate result when files were placed in
`/data/user/0/com.quattroplay.GraalClassic/files`. The Java application data
directory exists and is readable through `run-as`, but the native downloader
reports and uses the external path under
`/storage/emulated/0/Android/data/com.quattroplay.GraalClassiC/files` for game
assets. The external path contains the map, image, update-package, and level
caches. The private internal directory mostly contains `creationtime.dat`.

This corrected the test procedure. It also explains why an exact-looking file
could be present in the private directory without changing the result. Future
notes should always name the complete cache root, not just the relative
`weblevels` directory.

## Spectron comparison

The supplied Spectron APK was inspected as a related client. It includes
custom routing and signing-related strings, and it bundles an Xposed library.
The presence of a loopback address or a signing string is not enough to prove
that every original connection is redirected in the same way. The comparison
was useful for understanding the intended package format, but the original
client's own symbolized library remains the source of truth for this task.

## Evidence levels used in this archive

The notes use three informal evidence levels:

* **Static** means a name, string, cross-reference, or instruction was read
  from the library or IDA database.
* **Local runtime** means a controlled emulator test observed the behavior
  using loopback responders and a diagnostic APK.
* **Live** would mean the unmodified or properly repaired client connected to
  the real service and completed an actual login. No live result is claimed
  yet.

This vocabulary is intentionally repetitive. Reverse-engineering notes become
hard to trust when a local synthetic response is described as if it came from
the production server.

## Update package and script follow-up

The update-package path is now mapped far enough to explain why a synthetic
`FILE StartConnectMessage` line alone does not produce an immediate package
request. `requestUpdatePackage_void` at ARM64 `0x209020` creates or loads
`updatepackages/basepackage.gupd`. `TUpdatePackage_load` at `0x209fa4` parses
the `GRPKG001` header and fields such as `NAME`, `VERSION`, `PLATFORM`,
`SUBPACKAGE`, and `FILE`. A `SUBPACKAGE` entry starts another download during
the load, while a `FILE` entry adds a file to the package's file list.

`TClient_sendRequestUpdatePackage` at `0x1f8e78` sends the package name,
install separator, and one five-byte checksum per listed file. The normal file
request helpers remain separate: `TClient_sendWantImage` uses the packet 23
path, `TClient_sendWantImageUpdateCRC` uses packet 47, and
`TClient_sendPreloadLevel` uses packet 35. The local responder currently
answers the ordinary map, level, and base-package requests directly. It does
not claim to reproduce a complete production package installation sequence.

The decoded built-in `StartScript_GraalGui` bytecode contains the GUI setup but
does not contain `onPackagesDownloaded`. That explains why adding a minimal
synthetic `StartConnectMessage` package did not by itself hide the native
connecting control. The package path is still worth preserving for future
tests, but it is no longer the leading explanation for the rendered-world
result.

## Corrected two-connection runtime trace

The first useful local run sent the map and player properties on the same
socket as packet 48. That was wrong because packet 48 is a server-warp
instruction and the client intentionally closes the socket before reconnecting.
The corrected responder sends packet 48 on connection one, then sends packet 7
and packet 55 on connection two. The resulting trace is:

```text
connection 1: login, packet 48 server-warp, reconnect
connection 2: login, packet 7 classiciphone.gmap
connection 2: packet 55 minimal player properties
connection 2: packet 47 map request
connection 2: packet 35 overworld_west_ocean_09.nw
connection 2: packet 35 overworld_west_ocean_02.nw
connection 2: packet 35 overworld_west_ocean_10.nw
connection 2: packet 34 level completion or acknowledgement
connection 2: client packet 2, then server packet 182 test
connection 2: client heartbeat packets 24
```

The x86_64 emulator screenshot after this sequence shows the green tile field,
the player HUD, and the three top-right status icons. The centered blue
`Connecting to classic...` control is still present. This is a stronger result
than the earlier splash-only observation because it proves the renderer path
has run.

The server capture contains an encrypted type 182 frame with sequence 10 and
an empty body. Static ARM64 analysis maps packet 182 to handler index 14 and
the handler table entry points to `sub_1EB4C0`, which calls the native hide
routine and invokes `onServerListerConnect`. An x86_64 test build with a trap
at that handler does not trap, while an otherwise identical trap at the known
packet 48 handler does trap. The current working theory is therefore that the
packet 182 table entry is absent or overwritten after the connector client is
replaced for the game connection. This remains a local diagnostic result, not
a claim about the live service's completion packet.

One negative control is worth preserving. A test build routed packet 59
directly to the apparent x86_64 parser block at `0x2096f0`, bypassing the
repaired handler table. That build did not reproduce the working exchange. On
connection one it returned to ordinary packet 23 resource requests, and on
connection two it stopped after the map response. The control build, which
leaves packet 59 in the repaired table, requests the three level containers and
`pics1.png` and renders the tile field. The direct jump is therefore rejected
as a repair even though the address itself still looks like the packet-59
parser in static disassembly.

The public game responder now accepts `--frame-after-client
CLIENTTYPE[@OCCURRENCE]:TYPE:HEXBODY`. The occurrence is one-based and
defaults to one. This makes the test event-driven, so a completion candidate
can be sent after a real client milestone instead of relying on a fragile
wall-clock delay.
