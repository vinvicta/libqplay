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

The native call chain is now confirmed in IDA rather than inferred from the
certificate strings. `THTTPRequest_sendRequest` at `0x1ffde8` selects the
socket transport and calls `TSocketConnection_setVerifyGraalWebCert` when the
request asks for verification. `TSocketConnection_enableSSLOnSocket` at
`0x206450` creates a CyaSSL client context, loads the supplied verify buffer
through `CyaSSL_CTX_load_verify_buffer`, configures verification, and calls
`CyaSSL_connect`. The game-server path reaches the same socket class through
`TGraalConnection_connectToServer` at `0x1feb98`, but its trust buffer and SSL
flag are separate fields. This is why a connector certificate repair alone is
not a complete game-server repair.

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

The response-header finding needed a correction after a second IDA pass. The
function `THTTPRequest_preParseData_void` at `0x201d68` lowercases each header
line with `TString::lower` before matching `server:`, `content-length:`,
`content-type:`, and the other fields. Header-name capitalization is therefore
not a client compatibility requirement.

The same local diagnostic APK and connector body were then tested with three
response variants. Lowercase names plus `Connection: keep-alive`, title-case
names plus `Connection: keep-alive`, and lowercase names plus
`Connection: close` all reached the game responder, completed both game
connections, and requested the GMAP and three level files. The parser does
recognize the exact lowercased value `connection: keep-alive` as a reuse hint,
but a close response with a valid `Content-Length` still completed this
bounded replay. A fourth replay without `Content-Length` also completed when
the responder half-closed its write side, giving the stream parser an EOF
boundary. The old note that lowercase names were required is withdrawn.

The replay tool keeps lowercase names and `keep-alive` as conservative legacy
defaults, and exposes `--header-case` and `--connection-value` for controlled
comparison tests. It also exposes `--omit-content-length` for the EOF case.
The earlier capitalized-header failure was confounded by another response or
timing difference that has not been reproduced, so it should not be treated as
evidence of a header-case rule.

## Script to native handler boundary

The decoded connector script installs inbound handler pairs. The pair for
server login is `(54, 10)`. The first reading of the setter treated the VM
array as reversed and suggested swapping the two values. That interpretation
was disproved by the live IDA table and by the successful no-swap replay.

The original ARM64 instructions at `0x1ea7ac` and `0x1ea7b4` are the correct
lookup and store for this library revision:

```text
0x1ea7ac: 00 d8 62 f8
0x1ea7b4: 40 d8 21 f8
```

The x86_64 build likewise retains the original bytes around `0x202ea0`,
including `83 f9 5e 7f 96 48 63 c9`. The `xchg ecx,edx` patch at `0x202ea5`
was a negative control. It changed the table enough to break the normal
protocol sequence, so it is no longer included in the compatibility patcher.

This conclusion is independent of the expired connector certificate and the
stale package signature. Keeping those diagnostics separate makes it clear
which changes are needed to study the client and which bytes are already
correct.

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
the responder sends packet 178 with a comma-separated destination that points
to `127.0.0.1:14900`. The client prints `Serverwarp...`, closes the first game
socket, reconnects, and replays its login sequence. Packet 48 is a trigger
action in this client table, not the server-warp instruction.

The final second connection sends packet 9 with a minimal own-player property,
packet 190 with an empty body, and packet 49 with the GMAP transition. The
packet 9 body for the test name `test` is `20 24 74 65 73 74`. Packet 190
reaches `sub_1EB4C0`, which hides the connecting window and invokes the
server-list connection callback. This corrected the earlier assumption that
packet 182 was the completion event. Static analysis maps packet 182 to the
process or window-list path at handler index 15.

The packet 49 body contains five encoded coordinate bytes followed by the
map name. The local body is:

```text
20 20 52 20 20 63 6c 61 73 73 69 63 69 70 68 6f 6e 65 2e 67 6d 61 70
```

The map name is deliberately `classiciphone.gmap`. An earlier experiment sent
a bare `.nw` name through packet 7, a client-specific level-selection path,
which did not enter the same GMAP transition. The final replay uses packet 49
and does not rely on packet 7.

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
final replay then loaded all three containers and rendered the tile field and
HUD. This closes the earlier loader-versus-dispatch question for the local
path. The remaining uncertainty is whether a live server provides the same
identity, signature, and resource sequence.

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
custom routing and signing-related strings, a newer obfuscated native library,
and a bundled `libxposed.so` with an ARM64 hook loader and WebTop JNI exports.
The presence of a loopback address or a signing string is not enough to prove
that every connection is redirected in the same way. The full hashes,
addresses, and runtime observations are in
[SPECTRON_COMPARISON.md](SPECTRON_COMPARISON.md). The original client's own
symbolized library remains the source of truth for this task.

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
`TClient_sendPreloadLevel` uses packet 35. The local responder answers these
requests with the native packet 102 file parser. Its multi-packet mode uses
the sequence 68, 84, 102, 69, while the final replay uses one packet 102 per
file. It does not claim to reproduce a complete production package
installation sequence.

The decoded built-in `StartScript_GraalGui` bytecode contains the GUI setup but
does not contain `onPackagesDownloaded`. That explains why adding a minimal
synthetic `StartConnectMessage` package did not by itself hide the native
connecting control. The package path is still worth preserving for future
tests, but it is no longer the leading explanation for the rendered-world
result. The final local run hides the connecting control through packet 190 in
the normal no-swap table.

## Corrected two-connection runtime trace

The first useful local run sent the map and player properties on the same
socket as packet 48. That was wrong because packet 48 is a trigger-action
packet. Static analysis and the successful replay established that packet 178
is the server-warp instruction. The corrected responder sends packet 178 on
connection one, then sends packets 9, 190, and 49 on connection two.

The final trace is:

```text
connection 1: login, packet 178 server-warp, reconnect
connection 2: login, packet 9 minimal player properties
connection 2: packet 190 empty connecting-window completion
connection 2: packet 49 classiciphone.gmap transition
connection 2: client requests basepackage and classiciphone.gmap
connection 2: server returns classiciphone.gmap as packet 102
connection 2: server repeats packet 49 after the map response
connection 2: client requests three level containers through packets 46 and 35
connection 2: server returns each level as packet 102
connection 2: client requests pics1.png through packet 23
connection 2: server returns pics1.png as packet 102
connection 2: client heartbeat packets 24
```

The map response alone left the client with a cached GMAP but did not
immediately re-enter the pending transition. The responder therefore sends a
second packet 49 after returning the map. That event-driven retry causes the
client to request the three level containers and then `pics1.png`.

The x86_64 emulator screenshot after this sequence shows the green tile field,
the player HUD, and the three top-right status icons. The centered blue
`Connecting to classic...` control is absent through the normal packet 190
handler. This proves that the renderer, map cache, level loader, image loader,
and connecting-window transition all run in the bounded local test.

## ARM64 diagnostic replay

The ARM64 diagnostic build uses four independent native edits. The connector
compatibility patch accepts the stale package signature at `0x22c5c8` and skips
the expired GraalWeb certificate setup at `0x20ab20`. The loopback resolver at
`0x206108` returns network-order `127.0.0.1`. The HTTP parser test patch forces
the connector request through port `18080` without TLS at `0x200de0`,
`0x200df0`, `0x200df4`, `0x200f74`, and `0x200f78`.

The offline handshake responder also needs a deterministic outgoing RC4 key.
The corrected ARM64 trampoline branches from `0x1fd6b4` to the zero-filled
code cave at `0x1f2dcc`, rewrites the existing output-key `TString` backing
buffer with `0123456789abcdef`, and resumes at `0x1fd6b8`. It repeats the
overwritten `SUB SP, SP, #0x30` before resuming the original prologue. That
stack instruction matters; an earlier trampoline draft omitted it and was not
valid. Incoming encryption remains unchanged.

The corrected ARM64-only APK was installed on the available Android 36
x86_64 emulator. Android loaded `lib/arm64/libqplay.so` through its native
translation layer. The first connection logged the connector login and packet
178 server warp. The second connection logged the `fd` and `fc` exchange,
encrypted login result, packet 9, packet 190, packet 49, the map request, all
three encrypted level-file requests, the `pics1.png` request, and continuing
packet 24 heartbeats. The external cache contained these verified fixture
hashes:

```text
classiciphone.gmap                    bc061465a7705bad074e7ae872bd9d0da14ce3d420f395fc4084760c48b682a8
overworld_west_ocean_02.nw-14900.code  9003d2474c556fb69b04a6f019523dd738b1bad6701099a08274fe5be2b30779
pics1.png                              fe2dff5c4af86179d0cf83306a40c7e7b92d728a99f1f73a5ec2cf9c897764eb
```

The process stayed alive and continued heartbeats, but screenshots from the
ARM64-only build remained on the original title or loading image. This is
strong evidence for the ARM64 connector, game framing, server-warp, and
resource-request path under translation. It does not establish that the
ARM64 renderer or level transition works on real ARM64 hardware. The exact
warp body is also significant: `,classic,127.0.0.1,14900` caused the second
connection, while the earlier colon form did not.

## Loading-screen getter negative control

The symbolized ARM64 library exposes `TClientEnvironment::getLoadingScreenEnabled`
at `0x15d35c`. Its callers include `TGUIScriptLoader::showConnectingWindow`,
`GuiCanvas::prerenderFrame`, and the JNI render loop. A diagnostic patch at that
getter returns false without changing the connector or game packet code.

On the corrected ARM64 loopback build, this patch did not expose a rendered
world. It also suppressed the normal `Connecting to the login server...` log
and generated no request at the local connector port, while the process and
OpenGL context stayed alive. That makes the getter part of startup and UI
sequencing, not an isolated loading-overlay switch. The test is retained as a
negative control in `tools/patch_loading_screen_getter_test.py` and should not
be used as a compatibility repair.

## ARM64 non-premium initialization candidate

The static initializer explains why the loading flag can remain set. At
`0x15ca7c`, `TClientEnvironment::sigcheck` branches to `0x15cac0` only when
the decoded premium option is zero or negative. That target stores zero into
`loadingscreenenabled` at `0x15cac8` and then continues through the ordinary
environment setup. A diagnostic helper,
`tools/patch_force_no_premium_loading_test.py`, changes only the conditional
branch to an unconditional branch to `0x15cac0`.

The option is a string marker, not an integer comparison. IDA displays the
printable prefix `a9a` at `0x2ce1d0`, but the native `strlen` call sees the full
seven-byte sequence `61 39 61 15 11 35 49` before its NUL terminator. Applying
the ARM64 `codesimplefix0` and `decodesimple` helpers to all seven bytes yields
the string `classic`. The decoded value matches the `g=classic` connector
query. `sigcheck` tests the resulting string length loaded at `0x15ca70`, so
the original code takes the enabled branch and leaves the initial loading byte
set to one. The machine-readable details are in
`artifacts/premium_option.json`.

The first run of this candidate was not a valid rejection. Its responder sent
the map name without the `.gmap` suffix, so the client never received the map
fixture. With the exact `classiciphone.gmap` body and the normal render loop,
the candidate requested the map, all three level containers, and `pics1.png`,
then continued sending packet 24 heartbeats. The screen showed the same tiled
world, HUD, and status icons as the later render-boundary diagnostic.

The resulting ARM64 library SHA-256 was:

```text
89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858
```

This one-instruction candidate is currently a better local repair than the
per-frame render hook because it restores the flag during initialization and
leaves the normal render decision intact. It is still a diagnostic patch. The
decoded value is now statically confirmed as `classic`. The correct production
entitlement behavior and whether this client should take the non-premium
branch on a current service still need confirmation before using the patch
outside the bounded test.

## ARM64 render-boundary state diagnostic

The next experiment kept the getter and startup path intact. The JNI render
loop at `0x244224` runs `TClientEnvironment::runTimers`, calls the loading
getter at `0x244228`, converts the result at `0x24422c`, and branches to the
loading-screen path at `0x244230` when the value is nonzero. The loading flag's
GOT slot is `0x375e30`.

A first diagnostic replaced the conditional branch at `0x244230` with a NOP.
That forced the normal game-draw path and produced a rendered ARM64 world in
the translated emulator. It proved that the translated code can execute the
map and GUI drawing code, but it did not tell us whether the global state was
being read too early or whether the branch itself was the only issue.

The stronger test is `tools/patch_render_loop_clear_loading_flag_test.py`. It
replaces the getter call at `0x244228` with a branch to the zero-filled cave at
`0x1f9508`. The cave loads the flag pointer through the existing GOT, stores a
zero byte, sets `w0` to zero, and branches back to `0x24422c`. The original
`UXTB` and conditional branch therefore remain in the loop. Because the hook
runs after timers and packet processing, it does not change connector startup,
packet dispatch, or the map transition.

The final ARM64 loopback build used the corrected compatibility, resolver,
HTTP parser, and deterministic RC4-key diagnostics followed by this render
boundary patch. Its library SHA-256 was:

```text
9a8a7cd30ca27849469f5d4e5602c6cda9071d18f621fade56d94ef02bc1440a
```

The local responder sent the comma-separated warp body
`,classic,127.0.0.1,14900`. The map packet and fixture used the exact name
`classiciphone.gmap`, including the `.gmap` suffix, and packet 49 was sent
again after the map response. The omission of that suffix caused earlier runs
to stop before map requests, so it is part of the reproduction contract. The
ARM64 process then requested the map, all three level containers, and
`pics1.png`, and continued sending packet 24 heartbeats. The external cache
contained:

```text
classiciphone.gmap                    bc061465a7705bad074e7ae872bd9d0da14ce3d420f395fc4084760c48b682a8
overworld_west_ocean_02.nw-14900.code  9003d2474c556fb69b04a6f019523dd738b1bad6701099a08274fe5be2b30779
pics1.png                              fe2dff5c4af86179d0cf83306a40c7e7b92d728a99f1f73a5ec2cf9c897764eb
```

The screenshot showed the tiled green world, the player HUD, and the status
icons. This is the first ARM64 test in this investigation that preserves the
normal packet sequence and reaches visible game drawing under translation.
It is still a diagnostic patch because it clears the flag on every render
iteration. A physical ARM64 device and a live service remain unverified.

One negative control is worth preserving. A test build routed packet 59
directly to the apparent x86_64 parser block at `0x2096f0`. That build did not reproduce the
working exchange. It changed the first connection to ordinary packet 23
requests and stopped before the normal second-connection sequence. The direct
jump is therefore rejected as a repair. The working responder uses packet 102
for a complete file response and can also emit the native 68, 84, 102, 69
large-file sequence.

The public game responder accepts `--frame-after-client` and
`--frame-after-map`. The first is useful for event-driven packet experiments.
The second was used here to send packet 49 only after the GMAP response, which
made the successful replay deterministic without a wall-clock delay.

## Exact connector query

The captured ARM64 request's `p=` value can be decoded offline with the native
DES key rule. Its plaintext list is:

```text
g=classic,p=android,v=6.15401,"b=Jul  4 2019 09:35:48"
```

The quote begins before `b=` because `TStringList_GetCommaText2` calls
`escaped34` on the whole list item. The native DES implementation reverses
the bits in each key byte and encrypts only complete eight-byte blocks. The
final six bytes of this 54-byte plaintext remain unchanged before Base64 and
URL escaping. `tools/encode_connector_query.py` reproduces the value from
these rules and provides a safer offline check than trying to infer the query
from a live request.

## Helper repository verification

The two supplied helper repositories were cloned with Git and tested at fixed
commits. `MorenoLand/GScript.Go-HexaParser` was checked at
`ad9bd3657feece825b5f5a888f5db34ffe37afb9`, and
`MorenoLand/Moreno.kahn` was checked at
`5e3a05fc8fbcf3c3f72b3c263238b2ed275fc66d`. The exact commands and hashes
are in `docs/HELPER_TOOLCHAIN.md`.

HexaParser's Go tests passed with Go 1.22.2. Its decompiler converted the
15,581-byte decoded connector script into 552 lines of readable GS2, exposing
the same endpoint selection, login, packet-handler, reconnect, and resource
logic found through the native and instruction-level analysis. Its compiler
also passed the repository's Issue 37 fixture. The generated connector source
needed one missing closing brace after `printDisconnectError`; adding that
brace produced the repaired 25,683-byte source recorded in
`docs/HELPER_TOOLCHAIN.md`, and the complete source then compiled to a
16,141-byte script.

Moreno.kahn's Linux `contool` built cleanly. Its `conn-extract` output for
`analysis/live_connector_response_local.bin` has SHA-256
`fc937afa039dff52ff4ae7f2e3ad809d75c19f5698875d862e5646644446b2b5`, exactly
matching `analysis/live_connector_payload_local.zip`. The archive lists `.rk`,
`.t`, and `NPCS/StartScript_Connector`, which independently confirms the
outer length wrapper and RC4 extraction. This command does not verify the
embedded RSA signature, so the existing stale-signature finding remains
unchanged.

The optional `conpack_wsl.c` creator was built after wolfSSL was checked out at
commit `cb138b22a2e9111e5ac9fb9e13a690762c86b884`. The helper's
`outer-private.rsa.der` derives to public-key SHA-256
`07714f7eac2ff6e3236f2887ebab9c367714120c834acff3f745e674ccd46d1a`, which is
different from the APK's embedded public DER SHA-256
`35e7245d68e6ab6c84bd55061704fe2d3d16800cbe0a671aceae6c85e1301b82`.
That creator is suitable for generating test containers with its own key, but
it is not a drop-in signer for the original client.

## HexaParser runtime parity correction

The first complete compile was not the end of the toolchain check. The raw
HexaParser source and the native-order reconstruction showed a consistent
ordering difference in same-line brace literals. The recovered script's
handler and server-list data is stored as a sequence of values, so reversing
the list changes behavior even though the bytecode remains structurally
parseable.

The comparison was easiest to see in the connector setup:

```text
native-order setOutDataHandlers: {158, 161, 157, ..., 163}
HexaParser output:               {163, 44, 162, ..., 158}

native-order setInDataHandlers: {178, 0, 9, 1, ..., 94}
HexaParser output:              {94, 108, ..., 9, 0, 178}

native-order onData pair: {42, 18}
HexaParser output:        {18, 42}
```

The Classic login-server lists showed the same reversal. This observation
also explains why the old operand-swap theory was attractive but wrong. The
native setter stores the original pair order. The reversed values came from
the script literal representation, not from the ARM64 load and store
instructions. The no-swap native bytes remain the correct bytes for this
library.

The new public helper `tools/reverse_hexaparser_literals.py` performs the
narrow repair. It reads the repaired HexaParser source, reverses only
comma-separated brace literals that fit on one line, skips bodies that look
like statement blocks or function calls, and writes a separate source file.
It is an adapter for the observed output, not a replacement GS2 parser.

The checked hashes are:

* repaired source input: `a30f9eca136e3b8ff827bfb1bfe13fb442bd2e882963bf9863cd8de5f2669e68`;
* adapted source: `e3a825b81bde930b8b26625ee7f14d3035d7b0dafb1015ee5d8df23591059572`;
* adapted bytecode: `ab5b500216b560603ba433618c85a3d8e38ac06ad12c42a978f923930c79742a`;
* adapted connector package: `d4dc4fc9969daeed648a671b92934606d6b54f0f86620c7ec82fa0d1676ca297`.

The adapted package used the compatible ZIP-header source patch and the
archived `.rk` and `.t` metadata. Its bytecode retained a final `0x0a` byte,
which the native loader accepted. This closes the earlier uncertainty about
whether the trailer itself was the runtime problem.

The raw and adapted packages were then compared under the same local
conditions. Both made the connector request with query capture SHA-256
`3586b24ea8f0b90b722bc988c4a7e126ee8e0664f2b06d1cb6e7ab8338e6759f`. With
both candidate game ports listening, the raw package made zero connections to
`14900` and three to `14896`, producing a wrong-endpoint or reconnect loop.
The adapted package made two `14900` connections and completed the expected
encrypted login, server warp, map request, three level-file requests,
`pics1.png`, and continuing packet-24 heartbeats.

The adapted render screenshot has SHA-256
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`, exactly
matching the earlier original-bytecode compatibility screenshot. This is a
strong local integration result: recovered source, compiler, compatible
container, native script loader, protocol responder, and translated renderer
all agree for this fixture. It is still a loopback diagnostic. It does not
verify a live server, current trust material, account login, arbitrary GS2
scripts, or a physical ARM64 renderer.
