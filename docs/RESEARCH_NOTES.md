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

The follow-up inventory keeps the coverage boundary explicit. IDA reports
11,272 function starts in this database. The translated ELF rows account for
8,096 function starts and the remaining rows are 1,645 default `sub_` names
plus 1,531 names that IDA created without a matching ELF symbol. The 505
remaining ELF rows are data symbols. `symbols/libqplay.function_inventory.csv`
and its JSON counterpart record every function start, its size, segment,
incoming references, flags, and source category. The `sub_` rows are not
missing from the archive; they are unnamed because this stripped portion of
the file provides no reliable semantic name for them.

The cumulative follow-up artifact now records reliable behavior names for 467
of those IDA-created functions. The labels cover the two server-login callbacks, the
packet-190 server-list completion wrapper, file-download bookkeeping, the
inbound handler-table loader and clearer, weapon and encrypted-script updates,
level and map transitions, player login and logout, NPC movement and
projectiles, object and effect dispatch, text controls, board modification
paths, NPC or hurt-state helpers, player-state wrappers, NPC or leader-state
helpers, map and level transitions, object and effect creation, and text or
handler dispatch. The latest pass covers every IDA-created function in the
core `TClient` protocol region from `0x1e9000` through `0x1f3000`. For example,
`TClient_handleServerLoginPacket`
decodes the incoming signature and invokes `onServerLogin`, while
`TClient_finishFileDownload` emits `onFileDownloaded` and advances the cached
download. The labels are applied in the IDB and reflected in the function
inventory, but they are not presented as original ELF symbols. The complete
list with confidence and evidence is in
`artifacts/ida_semantic_labels.json`.

A separate JNI sweep labels 35 native-to-Java wrappers in
`0x24025c..0x242df0` from exact method strings in the call sites. The labels
cover Facebook, TrialPay, Fabzat, TapJoy, Distimo, Google Play, URL,
keyboard, device-model, and OS-version paths. `JNI_onScriptFunctionCall` at
`0x241628` forwards the two script buffers to Java, and
`JNI_setVideoPlayerRectangle` at `0x242df0` caches the render rectangle before
resolving the Java video method. The two cache-string setters at `0x2401f4`
and `0x240204` remain unnamed because their semantic caller names are not yet
proven.

The sound subsystem provided another useful static naming anchor. The native
`THashList::encodesimple` routine at `0xe9f60` transforms registered script
names before they enter the encoded hash table. Applying that transform in
reverse to the `TSounds_initStaticScriptVars` table identifies the wrappers
for `play2`, `playlooped`, `playlooped2`, `setsoundpitch`, and
`setsoundpitchbynote`. Their bodies confirm the names: the first group either
uses the active action NPC or explicit world coordinates, and the pitch helper
converts note and octave strings into a twelve-tone frequency ratio. The
neighboring wrapper at `0xe2008` is labeled `TSounds_script_play` from the
play and `play2` table pair plus its action-NPC-centered behavior. This is a
semantic alias, not a claim that the stripped function retained a C++ source
symbol.

The same encoded-table method recovered the environment wrappers. The
`TEncryption_initStaticScriptVars` table at `0x376498` maps `md5` to
`0xe5d6c`, where the wrapper calls `TEncryption::getMD5Digest`. The game
environment table maps `adventure_quit` to `0xe9d1c`, which sets
`closeapplication`, and maps both `getclassicversion` and
`getgamesubversion` to `0xe9d30`, which returns `googleplay`. The
identification table maps `adventure_getosid`, `adventure_getnetworkid`, and
`adventure_getsystemid` to wrappers around the corresponding native methods.

The input and level-object property tables supplied another reliable naming
anchor. The TInput table at `0x37af58` maps `enablehardwarekeyboard` to
`0x168af0` and `0x168b00`. The TControlBindingProperties table at `0x37ae98`
maps `action`, `keycode`, `keytext`, and `slot` to their four accessors. The
TLevelObject table at `0x37b048` maps `level`, `x`, `y`, `z`, and `layer` to the
accessors at `0x1698b0` through `0x169a28` and `0x169a80`. Their bodies confirm
tile-coordinate scaling, ordinary-object clamping, layer remapping, and the
vtable position calls. The `z` getter at `0x169a08` was a referenced code
pointer without a function boundary in IDA, so it was defined from the property
table reference before being labeled.

The `GuiControlProperties` constructor at `0x1b45c8` registers 55 properties
from `0x3806a0`, which provides a particularly useful render-path map. Its
callbacks expose bounds, extent, client dimensions, clipping, color, profile,
visibility, animation state, sizing, and position. The companion script table
at `0x3810f0` contains 28 entries, including control lookup, coordinate
conversion, resize, repaint, visibility, and responder operations. Eleven
formerly unnamed callbacks from that table now carry script-prefixed labels.
The `minextent` and `minsize` entries share their callback pair. The table
entry that decodes to `showhint` uses the same one-byte encoded-zero sentinel
seen in other old script tables. The decoder models the native
`codesimplefix0` repair, so the script name is recovered exactly.

The file-scripting table at `0x376bd0` is another strong naming anchor.
`TFileScripting_initStaticScriptVars` at `0xfd1d0` registers 27 entries,
and 22 of the callbacks were IDA-created functions. The wrappers now expose
exact names for the script-access filename, file existence and size, filename
escaping, file update, resource cleanup, file searches, extension and path
helpers, timestamps, application folders, file contents, folder lists, default
viewers, deletion, and decompression. The bodies also preserve an important
runtime distinction: paths with explicit filesystem components use `TFiles`,
while packaged level content is resolved through `TResourceFunctions` and
`TResourceObject`.

The next native naming anchor is the zlib bridge. The disassembly of
`TStream_fillZipFunctions` at `0xf0e98` writes seven function pointers into
the standard callback layout. The targets at `0xf075c`, `0xf0564`, `0xf04f0`,
`0xf04f8`, `0xf0548`, and `0xf0550` are respectively the read, write, tell,
seek, close, and error callbacks. The slot at `0xf04ec` is an identity open
callback that returns the opaque stream handle. This explains how packaged
resource decompression can use the in-memory `TStream` implementation without
opening a second file descriptor. Nearby compiler-generated helpers clear
static path, client, socket, and flying-object strings, initialize the two
resource-link hash lists, and clear restart state. The complete candidate list
is kept separate in `artifacts/native_callback_candidates.json` until the IDA
bridge accepts the corresponding rename batch.

The latest native audit extends the same evidence standard beyond the packet
core. It labels the `TGraalConnection` and `THTTPRequest` accessors used by
the connector and request registry, the `TSocket` policy, error, address, and
plain-I/O helpers, and the `TGaniObject` or `TGaniParam` accessors used by the
animation path. Most of these aliases preserve the proven field offset or
virtual slot instead of inventing a source-level member name. This makes the
inventory more useful for tracing TLS and resource loading while keeping the
remaining uncertainty explicit.

The same pass now covers the client network-thread entry point and the
script-facing update-package bridge. The package helpers expose the global
base package, the active download count, aggregate byte counters, metadata
such as NAME, VERSION, PLATFORM, MODE, and DESCRIPTION, and the two wrappers
that call `TUpdatePackage::update(false)` or `TUpdatePackage::update(true)`.
The undocumented package fields remain offset-based aliases, so they can be
corrected later without implying a source member name that the binary does not
prove.

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

The decoder was checked more closely after the first certificate extraction.
`TEncryption_initStaticVars` at `0xe6b40` installs the standard
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` alphabet.
The decoded ciphertext is 9,615 bytes. `des_decryptmemory` processes 9,608
bytes in DES-ECB blocks and leaves a seven-byte tail untouched, matching the
native loop condition. Decrypting with the bit-reversed key bytes for
`jhOdx9SY` produces a 9,615-byte bundle with six certificate blocks. The
fourth block has the historical markers `BEGINCERTIFICATE` and
`ENDCERTIFICATE` without the usual space. The decoder normalizes those two
markers only for x509 parsing and records the raw block hash separately. The
unprocessed tail is `45 2d 2d 2d 2d 2d 0a`, which completes the final PEM
delimiter. The first certificate is the self-signed Eurocenter Games
certificate, with SHA-256 fingerprint
`2e6425395e91baab7be95d9918de198684bcb718800bff07113e7f336d06ce56` and
`notAfter` `2023-07-29T07:37:32Z`. The second is AddTrust External CA Root,
which expired in 2020. The full metadata is in
`artifacts/graalweb_trust_bundle.json`, and the extraction is reproducible
with `tools/decode_graalweb_cert_bundle.py`.

A later pass counted the bundle markers rather than relying on the original
five-entry regular expression. There are six certificate blocks. The fourth
is an AlphaSSL intermediate whose PEM markers omit the space between `BEGIN`
or `END` and `CERTIFICATE`; its DER parses after marker normalization, while
the raw bytes remain part of the historical trust buffer. The AlphaSSL
intermediate expired in 2024, and the GlobalSign root that follows it expires
in 2028. This correction is recorded with raw and normalized hashes in the
trust-bundle artifact.

The new `tools/patch_graalweb_trust_bundle.py` performs the inverse native
DES/Base64 transform for a user-supplied certificate-only bundle. It refuses a
different original library revision, rejects private-key material, and
round-trips the replacement through the same full-block and short-tail rule.
It intentionally requires standard PEM markers, so the recovered historical
bundle is useful as an exact transform control only after its malformed marker
block is normalized. A current authorized chain is still needed for a
production-compatible HTTPS test.

The native call chain is now confirmed in IDA rather than inferred from the
certificate strings. `THTTPRequest_sendRequest` at `0x1ffde8` selects the
socket transport and calls `TSocketConnection_setVerifyGraalWebCert` when the
request asks for verification. `TSocketConnection_enableSSLOnSocket` at
`0x206450` creates a CyaSSL client context, loads the supplied verify buffer
through `CyaSSL_CTX_load_verify_buffer`, configures verification, and calls
`CyaSSL_connect`. The game-server path reaches the same socket class through
`TGraalConnection_connectToServer` at `0x1feb98`, but its trust buffer and SSL
flag are separate fields. That separate field matters only when the script
enables game-server SSL; the recovered Classic branch leaves it disabled.

The game-server trust material can now be traced back to the recovered script.
`StartScript_Connector` calls `client.setSSLParameters` with a 960-character
Base64 literal, `RC4-SHA`, `SSLv23`, and an enabled flag. The native callback at
`0x1eb964` decrypts that certificate argument with the bit-reversed DES key
`NakFpz15`, then stores the SSL protocol, cipher list, and verify buffer. The
result is a 718-byte DER certificate whose SHA-256 is
`2e6425395e91baab7be95d9918de198684bcb718800bff07113e7f336d06ce56`. Its
subject and issuer are the self-signed Eurocenter Games certificate, and it
expired on 2023-07-29. That hash exactly matches certificate 0 in the
connector's decrypted `jhOdx9SY` trust bundle. This is the first direct link
between the two stale trust paths. The recovery is offline and recorded in
`artifacts/game_server_tls.json`.

The same script selects the old `RC4-SHA` cipher and `SSLv23` protocol for the
game connection when its `usessl` flag is true. The recovered source now makes
the Classic case explicit: its `classic` branch sets `this.usessl = false`,
`sendLoginNewProtocol` calls `setSSLParameters` only under that flag, and a
final unconditional assignment also sets it to false. The stale game-server
certificate is therefore not on the main Classic login path. It remains a
real compatibility concern for other legacy modes or a modified script that
enables SSL, but it is not evidence of why the Classic client fails to reach
its connector today. The source-level control-flow result is recorded in
`artifacts/game_server_tls.json`.

A focused IDA re-audit checked whether the nonblocking socket itself prevented
TLS from starting. `TSocketConnection_setNonBlocking` at `0x206320` calls
`fcntl(fd, F_SETFL, O_NONBLOCK)`, and `TSocketConnection_connectSocket` at
`0x206bd8` uses status 4 for `EINPROGRESS`. That path is completed by
`TSocketConnection_checkConnecting` at `0x206a48`, which uses a zero-timeout
`select` and checks `SO_ERROR`. A successful check calls
`TSocketConnection_setStatus_int` at `0x2067b4` with status 5. The status setter
then invokes `enableSSLOnSocket` when the socket's SSL flag is set. The delayed
connect path therefore does initialize CyaSSL; making every socket operation
blocking is not the missing repair and already froze the renderer in a local
test.

The same audit found two details worth keeping visible. The TLS setup uses the
per-socket trust buffer, enables peer verification when that buffer is present,
checks the configured hostname, and starts `CyaSSL_connect` with nonblocking
I/O. If `CyaSSL_CTX_load_verify_buffer` fails, the client logs `Error
initializing SSL (1)` but continues toward `CyaSSL_new` and `CyaSSL_connect`,
so replacement tooling must validate the bundle before it reaches the native
loader. For an immediately completed TCP connect, `setStatus(5)` can also call
the TLS initializer before the explicit call at `0x206d04`; this apparent
duplicate initialization was not runtime-tested and is recorded as a native
quirk rather than treated as the primary failure.

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

The saved body validates against the public key recovered from this APK when
the native wolfSSL raw-digest format is reproduced. The first local replay
still used a narrowly scoped RSA branch bypass because the initial offline
checker used the standard ASN.1 `DigestInfo` form. That bypass is not needed
for this saved fixture, although it remains a diagnostic for a package signed
by another key.

There was a second parser correction here. The first offline checker used
Python's standard PKCS#1 signature API, which looks for an ASN.1 `DigestInfo`
prefix. The native code does something more specific: it hashes the encrypted
payload, calls wolfSSL `RsaSSL_Verify`, and compares the recovered message with
the raw 32-byte digest. IDA confirms that comparison in
`TEncryption_rsa_verify` at `0xf758c` and its equality helper at `0xf1da8`.
The parser now mirrors the native type-1 block and reports the standard form
separately, so a valid native signature will not be mislabeled as invalid just
because it uses the old wolfSSL API.

To test that conclusion without changing the production key, a new helper
can replace the embedded connector public key in a private copy of the
library. The replacement is generated from a local test key, and a matching
`con.png` made by the supplied `Moreno.kahn` tool passes the native raw-digest
check. The test package is 16,446 bytes with SHA-256
`d26035d9569789c2d6a60fb52673e91877a58e221117ca987a08dcbd674045be`.
The raw PKCS#1 public-key DER used for this bounded test is 270 bytes with
SHA-256 `5dff27a209730bdc52b4c182e85411dcdf584659d94dddca25062cfdae149cd9`.
The private key stays outside the repository. This proves the parser and
packer agree on the native format, not that the old production key or live
connector is still accepted.

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
corrected package-signature result. Keeping those diagnostics separate makes
it clear which changes are needed to study the client and which bytes are
already correct.

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
reaches `TGUIScriptLoader_finishServerListConnect`, which hides the connecting window and invokes the
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

The follow-up IDA pass names the package bridge around this path. The network
thread entry is `TClient_networkThreadMain` at `0x208920`. The script-facing
accessors begin with `TClient_getBasePackage` at `0x208a70` and
`TClient_getDownloadingPackageCount` at `0x208a80`; package metadata accessors
cover the parsed NAME, VERSION, PLATFORM, MODE, filename, and DESCRIPTION
fields. `TClient_getTotalDownloadBytes` at `0x208c94` and
`TClient_getDownloadedBytes` at `0x208d08` aggregate the same per-package
fields used by the download progress UI. The wrappers at `0x20993c` and
`0x209944` call `TUpdatePackage::update(false)` and
`TUpdatePackage::update(true)`, respectively. This is static evidence of the
native bridge, not proof that the old package server still provides compatible
update contents.

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

The ARM64 diagnostic build uses four independent native edits. The first
replay used the connector compatibility patch at `0x22c5c8` and skipped the
expired GraalWeb certificate setup at `0x20ab20`. The corrected native parser
shows that the saved connector fixture would pass without the RSA edit; the
patcher now supports `--skip-rsa-bypass` for that package-preserving variant.
The loopback resolver at
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

## ARM64 loading-state ownership audit

The follow-up IDA pass traced every native access to the loading byte. The
`TClientEnvironment::loadingscreenenabled` data at `0x37a549` is initialized
to `1`, and its GOT slot is `0x375e30`. The getter at `0x15d35c` only reads
that byte. The setter at `0x15d370` writes it and, when disabling the screen
while `loadingstate` is at most `2`, advances the state to `3`.

In `TClientEnvironment::sigcheck` at `0x15ca08`, the decoded premium option
is tested at `0x15ca70`. The branch at `0x15ca7c` reaches the clear at
`0x15cac8` only for an empty option. The marker at `0x2ce1d0` decodes to
`classic`, so the normal native path skips that clear. The data xrefs show
the byte being accessed by sigcheck, the getter, and the setter, with no later
native store found in the successful connector and resource path.

The setter's PLT call xrefs are limited to the message-box path at `0x16882c`
and the connect-failure path at `0x2037c0`. Packet 190 reaches
`TGUIScriptLoader_finishServerListConnect` at `0x1eb4c0`, which hides the connecting window and invokes the
server-list callback, but does not clear `loadingscreenenabled`. The JNI
loop calls the getter at `0x244228` after `runTimers` and branches at
`0x244230` to the loading-screen draw path when the result is nonzero.

This explains the ordinary ARM64 replay without requiring a missing-resource
hypothesis: the transport and resource requests can complete while the native
draw gate remains set. The evidence is architecture-specific and is based on
the native writers visible in IDA. It does not rule out a GS2 VM write from an
external package. The recovered connector source has no successful-login
clear; its visible assignment is in the disconnect error handler.

The x86 comparison also needs care. Its original library starts with the
loading byte enabled and contains the same premium-option branch. Several
historical x86 diagnostic APKs used in the rendered replay set override the
getter at `0x16ee80` to return false. Their screenshots remain useful
downstream renderer evidence, but they should not be described as proof of
unmodified x86 loading-state behavior.

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
outer length wrapper and RC4 extraction. The corrected offline parser
separately verifies the embedded RSA signature in the native wolfSSL format.
The saved response passes that check. The standard ASN.1 verifier still
reports false because it is not the format used by this client.

The optional `conpack_wsl.c` creator was built after wolfSSL was checked out at
commit `cb138b22a2e9111e5ac9fb9e13a690762c86b884`. The helper's
`outer-private.rsa.der` derives to public-key SHA-256
`07714f7eac2ff6e3236f2887ebab9c367714120c834acff3f745e674ccd46d1a`, which is
different from the APK's embedded public DER SHA-256
`35e7245d68e6ab6c84bd55061704fe2d3d16800cbe0a671aceae6c85e1301b82`.
That creator is suitable for generating test containers with its own key, but
it is not a drop-in signer for the original client.

## HexaParser literal-order experiment (historical record)

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

An earlier comparison report recorded the raw package making zero connections
to `14900` and three to `14896`, while the adapted package was reported to make
two `14900` connections and render a matching screenshot. Those values are
kept here as historical observations, but the adapted result was not
reproduced by the later clean control. The corrected interpretation and the
current direct-bytecode result are recorded in the final section below. The
literal-order adapter remains a useful source experiment, not a proven
runtime repair.

## Source-level game-server TLS replacement

The bytecode string-table encoder was useful for proving the native
`NakFpz15` transform, but the supplied HexaParser workflow starts from GS2
source. I added `tools/replace_game_server_tls_source.py` so the same repair
can be applied at that boundary without manually editing a very long string.

The helper locates the Base64 value inside each recovered
`setSSLParameters` call. It requires two occurrences by default, decrypts and
validates each existing value as an X.509 certificate, accepts one
certificate-only PEM replacement, and writes a new source file. It preserves
the source's newline style, refuses to overwrite the input, leaves native
verification enabled, and records `network_contacted: false` in its optional
report.

The recovered certificate was used as an identity test. Both occurrences were
found, the output source hash remained
`a30f9eca136e3b8ff827bfb1bfe13fb442bd2e882963bf9863cd8de5f2669e68`, and the
compiled output remained the known 16,141-byte file with SHA-256
`67b70c449f87d6e3b71ef0fe92ba73fff9fe5fe7a1ad63aedb34e9daf4a7b752`. A
self-signed offline certificate produced a 1,072-character replacement and
compiled to 16,253 bytes with SHA-256
`119653464dc0692cc2fc478d7edc6ea1080096559fbac7b9e24a993a2862235d`.
Applying the existing literal-order adapter to that source also compiled to
16,253 bytes. These checks show that the source-level path accepts a longer
certificate and composes with the known fixture adapter. They do not claim
that the test certificate is trusted by any service.

## Clean package-preserving ARM64 replay

The local Android emulator became available again during the continuation. It
was an Android 36 x86_64 device running the ARM64 package through Berberis.
The first launch was stopped by the normal Android compatibility warning; the
warning was dismissed, only the test app data was cleared, and fresh loopback
responders were started on the connector and game reverse ports.

The package-preserving ARM64 candidate has APK SHA-256
`dad598e0cec03b501ff8cc30648ad843346fa3a331db3087ffa54ff92938af3a` and native
SHA-256
`888a236bb839eef7ab094196b924796680d23d857a0d7533487bcd3786efb308`. Its
RSA result site still contains the original `dc 00 00 35` bytes. The clean
run made the connector request with capture SHA-256
`3586b24ea8f0b90b722bc988c4a7e126ee8e0664f2b06d1cb6e7ab8338e6759f`, then
completed two game connections. The first game capture hashes were
`3bd0db0749df7e73715a03bfd34a5ca8e984eb3f7ac869f3c6e05653e684c536` inbound
and `a5555ffd8b4e83f528d53f692c58a92991f2247e4037148a43779cc068316d55`
outbound. The responder observed the map, three encrypted level containers,
`pics1.png`, and continuing packet-24 heartbeats.

The screen reached the same tiled world and HUD as the earlier diagnostic
run. Its screenshot SHA-256 was
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
Because the native RSA branch was not changed and the response passed the
native raw-digest check, this is the stronger local evidence that the saved
connector fixture does not need the RSA bypass. The certificate skip,
loopback endpoint changes, deterministic test key, and loading-state edit are
still present, so this remains a controlled replay rather than a live-client
repair.

## Native TLS trust replacement replay

The next test kept the connector's native TLS verification path enabled. A
private self-signed certificate with subject and SAN `con.quattroplay.com` was
encoded with `tools/patch_graalweb_trust_bundle.py`. The canonical PEM bytes
were 1,208 bytes with SHA-256
`1fb27a4fa0662069e4d7e1b85700eb4a8c3262f50fbef4c3eea16263ab6e8e2f`; the
native encoded replacement was 1,612 bytes with SHA-256
`1d45d76d892175f6e1efd1cc225ebd6348f8244ce4173ff1a006830613a51464`.
The trust patch itself produced ARM64 library SHA-256
`be6c9fbfbe4c18c2835e3f142d2141d155985e5e4d815d8b88754f7a3a535661`.

The public `tools/patch_connector_tls_port_test.py` changed the two HTTPS
port constants at `0x200df0` and `0x200f74` from `443` to `18443`. It did not
change the HTTPS flag, host name, native peer checks, or the RSA result
branch. The resolver then routed the requested host to loopback. This port
move exists only because ADB reverse cannot expose a privileged host port
inside this emulator.

The final private ARM64 chain added the deterministic outgoing RC4 key needed
by the synthetic game responder and the existing non-premium loading-state
candidate. The intermediate hashes were:

```text
resolver patch       3a28098407ee2322ddd0d12a178ce4cc7b3f5751b3e6024fcf48dbf09d9eee30
TLS port patch        41e69dd8a7ea70606ec3f299776bca40a9a212767f14f2b1633866da1a19b459
fixed output key     f002828554b70f87eed78e469324be3f0f13b28e16f7aa51024e5408e708935f
full diagnostic      22a0fd4801f71f29f7c53a7ba77f0c4db669a83fc1ae5a5f53e3ce9b95f33e9a
debug APK            2984a6d4b7698a2ab444166265939a75a61c43b679dfd87b0d7a063bf7fd0759
```

The local TLS responder saw the request with
`Host: con.quattroplay.com:18443` and delivered the saved 16,446-byte body.
There was no certificate-skip patch and no RSA bypass. The game responder
then recorded two encrypted connections. The second connection requested the
exact GMAP name `classiciphone.gmap`, three encrypted level containers, and
`pics1.png`, followed by packet-24 heartbeats. The capture hashes were:

```text
first inbound    52ae6c7a57aa51d13faba5f96e3907d17fa9e5ca9651c0f1dd1da8b9d1f7bf24
first outbound   1602c8206ac42ce7db6c20726f9c3725e28fbf981a0243edd431e1bfc5f03ff8
second inbound   c2d391774dd38d370c143d462993c6a92859d6c91e075c7f3239b44fd780a91d
second outbound  6e593a89015b41cf00ef781419e0714b3238b037cce2f08528697b3da216d239
screenshot       fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e
```

This is the strongest local end-to-end result so far. It shows the native TLS
trust replacement, encrypted NewGraal exchange, resource delivery, and
translated ARM64 rendering in one bounded replay. It does not validate the
historical game-server `RC4-SHA` certificate against a live service, an
authorized account, or a physical ARM64 renderer. The test certificate,
private key, APK, and captures remain outside the repository.

## Correction: clean HexaParser control and direct bytecode patch

The earlier HexaParser parity section above recorded an adapted replay that
could not be reproduced when the test was rerun with clean, freshly stopped
loopback responders. The exact same native library, Kahn test key, TLS
certificate, fixed responder key, and emulator were used for the comparison.
The adapted stream requested the connector but never reached the expected
`14900` listener. Stripping its compiler-added trailing `0x0a` did not help.

The reason is broader than the visible list reversal. The original decoded
stream has 3,143 instructions and record lengths `4/553/8293/6699`. The
adapted stream has 3,582 instructions after the trailer is removed and record
lengths `4/553/8271/7280`. Its function names are recognizable, but its
function boundaries and opcode stream are not a byte-for-byte-compatible
rebuild of the old VM format. The literal adapter remains useful for reading
and comparing source data, but its runtime status is now unverified.

To keep the proven VM stream, I added
`tools/patch_connector_bytecode_loading_clear.py`. It copies the existing
six-byte `loadingscreenenabled = false` sequence from `printDisconnectError`
into `onServerLogin`, immediately before the `reconnections` reset. The tool
updates only shifted function offsets and branch targets, refuses to overwrite
the input, and opens no socket. The resulting decoded script has SHA-256
`3c8286ece57d96ecf088f6ba01b6a6094f6d317dda451369392bfa731aa0fb2f` and the
Kahn-signed package has SHA-256
`7473bac833911005821d210874be2e53df6eeed0d1ae8831dfa0fdf713f27e9e`.

The direct bytecode candidate passed the next local boundary. The ARM64-only
package made one TLS connector request, two game connections on `14900`,
completed the encrypted login exchange, received `classiciphone.gmap`, three
level files, and continuing heartbeats. The app logged `Serverwarp...` and did
not crash. The screenshot still showed the title/loading artwork because the
synthetic responder stopped at a bounded post-login resource boundary. This
is therefore a strong script-loader and protocol result, but not proof that
the direct insertion alone produces the final visible world. The complete
hash record is `artifacts/bytecode_loading_clear_replay.json`.

The next private check combined the direct bytecode package with the existing
one-instruction native startup candidate at ARM64 `0x15ca7c`. The combined
native library hash is
`8f7b343d81a1cd8eef390d0a494912f86ab03f7a22f4fe4a2f2bb170409d6722`, and the
debug APK hash is
`57e6987a920b261c9a6b9abeb909cd4156c4995bb4dd6930422b87a27adc3dde`. It again
made two game connections, received the map and three level files, followed
the image path, and kept sending heartbeats. The translated ARM64 renderer
displayed the green world field, HUD, and status icons. Its screenshot hash is
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.

This combination is useful because the direct script patch did not regress the
known render candidate. It does not isolate the visual cause: the native
startup branch is still present, and the direct script assignment alone left
the title/loading artwork visible in the preceding bounded run. The native
ownership audit therefore remains the best explanation for the visual split in
this fixture.

## ARM64 loading-state call-site audit

The active IDA database now has comments at the state ownership boundaries.
The native byte at `0x37a549` starts at `1`, and the GOT slot at `0x375e30`
points to it. `TClientEnvironment_sigcheck_TString_const_bool` at `0x15ca08`
clears it at `0x15cac8` only when the decoded premium option is empty. The
recovered marker decodes to `classic`, so the normal startup branch skips that
store.

The getter is read at three meaningful call sites: the connecting-window
builder at `0x168154`, the GUI pre-render function at `0x1b188c`, and the JNI
loop at `0x244228`. The JNI loop reads it after `runTimers` at `0x244224`; a
nonzero result goes to `drawDefaultScreen`, while zero continues to
`TClientEnvironment_drawGame_bool`.

The native setter has only two post-startup call sites in this revision. The
message-box path calls it at `0x16882c`, and the connect-failure path calls it
at `0x2037d4`. The packet-190 wrapper at `0x1eb4c0` hides the connecting window,
invokes `universe.onServerListerConnect`, and sets
`TServerList::allowpreloginreconnects` to `-1`; it does not write the native
loading byte. The address-level evidence is in
`artifacts/loading_state_ownership.json`.

## Offline static-initializer follow-up

The IDA bridge did not answer during the next bounded health probe, so the
symbol pass continued against the original ARM64 ELF and a local AArch64
disassembler. Four compiler-generated routines in the early text region have
now been tied to named global objects through the ELF relocation table rather
than by proximity alone.

* `0xe0770` creates the 0x18-byte list object stored in
  `TDrawTexture::textures` through the relocation at `0x3756b8`.
* `0xe083c` clears the complete 248-byte `curanis` object referenced through
  the relocation at `0x375a48`.
* `0xe08e4` sets both coordinates of `TOptions::windowpos` to `-1`, using the
  relocation at `0x375ed8`.
* `0xe08fc` initializes the `displayedgif` pointer to null through the
  relocation at `0x374cd8`.

These observations are recorded in
`artifacts/native_callback_candidates.json` under `static_initializers`.
The application script now reviews all candidate groups, but remains
review-only by default. No IDA names or comments were changed during this
offline pass, and no network endpoint was contacted.

The same region also contains three useful sound wrappers. At `0xe0af8`, the
wrapper reads `TSounds::soundplayer` and calls the address-point-adjusted
`TSoundPlayerJava::isMusicPlaying` vtable slot. The result is narrowed to a
boolean. The adjacent `0xe0bf8` and `0xe0c08` routines load and store the
exported `TSounds::soundoffscreendistance` double through the relocation at
`0x3754b0`. These are recorded under `sound_wrappers` in the candidate
artifact.

A closer read of the next three table entries corrected an earlier address
interpretation. The GOT slot used by `0xe0c18` is `0x3757e0`, which resolves to
`TSounds::soundplayer`, not `TServerList::servername`. The wrapper reads the
player's filename field and lowercases it, matching the script-facing
`getmusicfilename` entry and the exported `TSounds::getMusicFilename` helper.
The adjacent property entry uses GOT slot `0x374cb0`, which resolves to
`TSounds::disabledsoundeffects`. Its getter at `0xe0c84` calls
`TStringList::GetCommaText2`, and its setter at `0xe0c70` calls
`TStringList::SetCommaText2`. These three high-confidence names are recorded
under `sound_table_followup`. They bring the unapplied candidate plan to 25
entries. The previous TServerList interpretation was not applied to IDA and is
not retained in the candidate artifact.

The same table also gives two short wrappers with unambiguous roles. The
callback at `0x0e0fa8` is registered as `stopsounds`; it forces the first
`TSounds::stopSFXs` flag and forwards the caller's boolean as the second flag.
The callback at `0x0e1350` is registered as `setmusicvolume`, loads two doubles,
and tail-calls `TSounds::setMusicVolume`. They are included in the candidate
artifact as `TSounds_stopSounds` and `TSounds_setMusicVolume`, bringing the
unapplied plan to 27 entries.

## TServerLevel script registration table

The next offline pass reached a much larger, self-describing table in the
server-level implementation. `TServerLevelProperties::TServerLevelProperties`
at `0x1a1128` installs six property records from `0x37fce0`. The names decode
through the library's own `THashList::decodesimple` routine at `0xea100`:
`height`, `isnopkzone`, `issparringzone`, `nopkzone`, `tilelayercount`, and
`width`. The callback bodies match the names and expose a few useful layout
facts:

* `0x19f948` reads the active layer height and scales it by 64 pixels, with a
  64-pixel fallback when no layer is active.
* `0x19f978` and `0x19f980` are the shared getter and setter for the no-PK
  flag at object offset `0x12a`. The table intentionally exposes the same
  pair under both `isnopkzone` and `nopkzone`.
* `0x19f988` reads the separate sparring-zone byte at offset `0x129`.
* `0x19f990` follows the layer list at offset `0x70` and returns its count.
* `0x19f99c` reads the active layer width and applies the same 64-pixel
  scaling as the height getter.

The same constructor installs eighteen script functions from `0x37fe00`.
Their names and callback starts are listed below. This is stronger evidence
than a nearby string match because each name is tied to a registration record,
and each body reaches the corresponding exported server-level method or list.

| Script name | Callback | What the body confirms |
| --- | ---: | --- |
| `getmappartfile` | `0x19fad8` | Bounds-checks map coordinates and returns a map-part filename or the level fallback path. |
| `findareanpcs` | `0x1a5150` | Calls `getOnNPC` for four bounds and converts the result into a script variable. |
| `putbomb` | `0x1a6764` | Builds the optional image string and calls `TServerLevel::putBomb`. |
| `putbomb2` | `0x1a6728` | Normalizes the short form and tail-calls `putBomb`. |
| `putexplosion` | `0x1a7fd8` | Plays the effect sound and calls `makeExplosion`. |
| `putexplosion2` | `0x1a7ecc` | Handles the variant effect arguments before calling `makeExplosion`. |
| `reflectarrow` | `0x1a0110` | Reverses arrow motion, updates its state, and forwards a shot through `TClient::sendShot`. |
| `removearrow` | `0x1a00ac` | Deletes an indexed arrow and invokes its virtual cleanup path. |
| `removebomb` | `0x19ffe8` | Deletes an indexed bomb from the level list and releases it. |
| `removeexplo` | `0x19ff84` | Deletes an indexed explosion from the level list and releases it. |
| `removeitem` | `0x19febc` | Deletes an indexed item and calls its virtual destructor. |
| `shoot` | `0x1a97d0` | Forwards projectile coordinates, strings, flags, and player context to `shootProjectile`. |
| `testbomb` | `0x1a5ddc` | Calls `isOnBomb` and returns the matching list index. |
| `testexplo` | `0x1a5898` | Calls `isOnExplosion` for the supplied coordinates. |
| `testitem` | `0x1a5760` | Calls `isOnExtra` for the supplied coordinates. |
| `testsign` | `0x1a560c` | Calls `isOnSign`, returning `-1` when no active level exists. |
| `testnpc` | `0x1a4e98` | Calls `isOnNPC` and returns the matching NPC index. |
| `tiletype` | `0x1a45a8` | Directly forwards to `TServerLevel::getTileType`. |

In the initial pass, two bytes in the encoded `reflectarrow` record decoded to
zero under the normal formula. The table stores nonzero replacements instead,
so that first literal decoder reported two unknown characters even though the
callback behavior and expected script name were clear. This is the same old
string-table terminator quirk seen in the GUI tables. The decoder now models
`THashList::codesimplefix0` and restores those bytes, so the current inventory
treats `reflectarrow` as exact. The legacy names `removeexplo` and `testexplo`
are retained rather than silently expanding them to modern-sounding spellings.

These twenty-four names are now in
`artifacts/native_callback_candidates.json` under
`server_level_properties` and `server_level_functions`. They are not counted
as applied IDA labels because the bridge is still unavailable. With the earlier
zlib, static-state, and sound entries, the review-only candidate set contains
51 native names. No live endpoint was contacted during this pass.

## TServerPlayer property and function tables

The player property constructor at `0x18b9bc` installs 52 records from
`0x37ce00`, followed by six script functions from `0x37d7c0`. The property
names decode to account, AP, attachment state, bombs, buddy state, chat and
chat offset, darts, hearts and HP, glove and weapon power, currency, guild and
head images, identity and channel flags, language, level name, message bubble,
MP, nickname, pause state, platform, player-list metadata, ratings, shield and
sword images, coordinates, and the six related image or state aliases. The
complete record-to-address map is in the candidate artifact.

This table also shows where the old client intentionally aliases script
properties:

* `fullhearts` and `maxhp` share getter `0x18a784`.
* `gralats` and `rupees` share getter `0x18a698` and setter `0x18b1c8`.
* `head` and `headimg` share getter `0x18abfc` and setter `0x18a6b8`.
* `hearts` and `hp` share getter `0x18a6d8`.

Those shared targets are represented as one candidate each, so the batch does
not assign two incompatible names to the same native function. The `nick`
getter at `0x18acec` is included, while its setter is already a surviving ELF
jump to `TServerPlayer::setNick` at `0x18e164` and is intentionally not
duplicated. The raw `attachedtoobject` record contains the familiar encoded-zero
sentinel. The decoder now applies `THashList::codesimplefix0` and restores the
spelling exactly; the table context and paired setter remain useful cross-checks.

The six function entries decode to `isguildpm`, `ismasspm`, `pmswaiting`,
`openexternalhistory`, `openexternalpm`, and `showprofile`. Their callback
starts are `0x18add0`, `0x18ad7c`, `0x18aa68`, `0x18aa88`, `0x18aa90`, and
`0x18aeec`. The saved IDA inventory has no function boundary for
`0x18aa68`, but the callback pointer is present in the registration record, so
it is retained as a candidate with that database limitation called out.

The new player entries are stored under `server_player_properties` and
`server_player_functions`. They add 74 unique native addresses and raise the
review-only candidate set from 51 to 125. No IDA names were changed during
this pass, and no live endpoint was contacted.

## TServerNPC property and function tables

The NPC constructor at `0x183c18` installs 26 property records from
`0x37be28` and 57 script functions from `0x37c308`. The property table covers
action-player lookup, health and dimensions, horse and hurt state, image and
layer state, collision flags, pelt checks, save state, weapon power, visibility,
and coordinates. The function table covers carry and push rules, image and
shape changes, drawing modes, movement and messaging, weapon and projectile
actions, display helpers, inventory operations, and image lookup or hiding.

Four table callbacks did not have function boundaries in the saved IDA
inventory: `npcsindex` at `0x180e50`, `width` at `0x18402c`, `hideimgs` at
`0x181d58`, and `testnpc` at `0x1a4e98`. They are still recorded because the
registration pointers are authoritative. The application helper will report
those four for boundary recovery instead of pretending a rename was applied.

Two other targets already have surviving ELF names and are not duplicated:
the `image` setter is the `TServerNPC::setImageName` jump at `0x18547c`, and
the `sprite` getter is the `TGaniObject::getGaniOldSprite` jump at `0x180c90`.
The other 37 property accessors and all 57 script callbacks are new
review-only candidates. Encoded table bytes with a zero terminator replacement
occur in `peltwithbush`, `peltwithsign`, `peltwithvase`, `canbecarried`, and
`showtext`; the surrounding records recover the intended spellings without
changing the original bytes.

The NPC function names are preserved in their script-facing form: `destroy`,
the carry and blocking predicates, `carryobject`, the `changeimg*` family,
`drawaslight`, `drawoverplayer`, `drawunderplayer`, the show and hide helpers,
the `set*` family, projectile helpers such as `shootfireblast` and `shootnuke`,
the `showani`, `showimg`, `showpoly`, and `showtext` overloads, `take` and
`take2`, `throwcarry`, `timereverywhere`, `findimg`, `hideimg`, and `hideimgs`.
The full address map is kept in the candidate artifact so the names can be
reviewed against the table without relying on a long prose list.

The new NPC groups add 94 unique addresses and raise the review-only native
candidate set from 125 to 219. No IDA names were changed during this pass, and
no live endpoint was contacted.

## Smaller server-object property tables

The next compact audit covered the property constructors for several of the
objects created by `TServerLevel`. Each constructor passes an encoded table to
`TScriptProperty::addProps`, which gives an exact script-facing name and its
getter or setter address without relying on nearby strings.

| Class | Constructor | Table | Records | Recovered properties |
| --- | ---: | ---: | ---: | --- |
| `TServerWeaponProperties` | `0x190ca4` | `0x37d8e0` | 1 | `isweapon` |
| `TServerBombProperties` | `0x23d1e0` | `0x38b058` | 3 | `power`, `time`, `image` |
| `TExplosionProperties` | `0x23ca04` | `0x38afc8` | 3 | `power`, `time`, `dir` |
| `TServerChestProperties` | `0x23e344` | `0x38b0e8` | 2 | `isopen`, `item` |
| `TServerExtraProperties` | `0x23e9e0` | `0x38b148` | 2 | `time`, `type` |
| `TServerFlyingProperties` | `0x23edc8` | `0x38b1a8` | 5 | `dir`, `dx`, `dy`, `type`, `from` |
| `TServerSignProperties` | `0x23fff4` | `0x38b298` | 1 | `text` |

The bomb, flying-object, and sign records contain both getter and setter
callbacks. The other records are read-only in this table. The candidate names
use the class prefix because names such as `power`, `time`, and `type` recur
across different object classes and therefore do not identify a unique native
function on their own.

Two nearby constructors are useful negative evidence. `TServerCarryProperties`
at `0x23d694` and `TServerLeapProperties` at `0x23fde8` initialize their
`TProperties` state and vtable pointers but do not call `addProps` in this
revision. They therefore contribute no script-property callbacks to the
candidate set. This keeps the table inventory faithful to what the binary
actually registers.

The seven new groups are stored in
`artifacts/native_callback_candidates.json`. They add 23 unique native targets,
raising the review-only candidate set from 219 to 242. No IDA names were
changed during this pass, and no live endpoint was contacted.

## Projectile, level-link, and tile-layer tables

The following constructor pass covered the remaining compact property tables
near the level-object code. `TProjectileProperties::TProjectileProperties` at
`0x19ecac` registers ten read-only records from `0x37f6d8`: `x`, `y`, `z`,
`angle`, `speed`, `zspeed`, `horiz`, `fromplayer`, `fromplayerid`, and
`params`.

`TServerLevelLinkProperties::TServerLevelLinkProperties` at `0x1a0494`
registers seven read-only records from `0x37f9b0`: `destlevel`, `destx`,
`desty`, `height`, `width`, `x`, and `y`. These names describe the link object,
not the similarly named properties on `TServerLevel` itself, so the proposed
native names retain the class prefix.

`TTilesLayerProperties::TTilesLayerProperties` at `0x1a0df4` installs nine
records from `0x37fb00` and one script function from `0x37fcb0`. The properties
are `alpha`, `blue`, `green`, `layerindex`, `offset`, `red`, `x`, `y`, and `z`.
All except `layerindex` have setters in the table. The function record decodes
to `updateboard` and points to `0x19fbf0`, so it is kept under a separate
script-function group rather than being mistaken for a property callback.

The three new groups add 35 unique native targets, raising the review-only
candidate set from 242 to 277. No IDA names were changed during this pass, and
no live endpoint was contacted.

## Full static script-table inventory

I broadened the audit from individual server classes into a complete offline
scan of the library's direct calls to the imported
`TScriptProperty::addProps` and `TScriptProperty::addFuncs` stubs. The scan
found 132 registration calls: 70 property tables and 62 function tables. Their
declared counts cover 678 property records and 777 function slots. One Android
`onAddScriptFunction` path is dynamic and has no static table pointer, leaving
776 function records that can be decoded directly from the binary.

Every static record uses a 0x30-byte stride. The first field points to the
script name, the property records keep their getter and setter at offsets
0x10 and 0x18, and function records keep their callback at offset 0x18. The
name decoder preserves ordinary literal strings and applies the inverse of
`THashList::encodesimple` to transformed strings. It also models
`THashList::codesimplefix0`, which restores encoded zero bytes represented by
the old table sentinel. The raw bytes remain in the inventory as evidence,
but all 1,454 statically decoded record names now decode exactly. The 1,455th
declared slot is the dynamic Android registration path and has no static table
pointer.

Across those records there are 1,779 unique callback targets. The existing
semantic-label artifact covers 411 of them, the curated callback artifact
covers another 258, and 204 already have non-default names in the saved IDA
inventory. The remaining 906 targets are split into 886 exact names with
saved function boundaries and 20 exact callback pointers without saved
boundaries. The full record map and these coverage states are in
`artifacts/script_table_inventory.json`.

The ELF `.eh_frame` section contains an FDE beginning at each of those 20
callback addresses and ending at the next proven code boundary. The inventory
retains those start and end values as
independent boundary evidence. The regular rename applier intentionally skips
these entries; `tools/ida_apply_script_table_boundaries.py` provides a separate
review-only path that can define the ranges first and then apply the exact
names. `tools/test_script_table_inventory.py` covers ordinary encoded names,
sentinel-bearing names, and the `$pref::` form used by the client.

The overlay at `artifacts/symbol_translation_overlay.json` joins the saved
1,645 default `sub_` functions with the table evidence. It gives 886 of them
exact script-table names and 271 of them curated callback candidates, leaving
488 default functions without a defensible name. Those 488 entries are kept
as an explicit work list. `tools/generate_symbol_translation_overlay.py`
rebuilds the overlay without needing an IDA session.

`tools/generate_script_table_inventory.py` reproduces the map from the local
ARM64 library and saved inventory without contacting a network. The companion
`tools/ida_apply_script_table_inventory.py` builds a review-only rename plan
for the 886 exact, bounded targets. It leaves the 20 missing function
boundaries untouched. The IDA bridge was unavailable during this scan, so no
database names were changed.

## Held-connection ARM64 resource replay

The runtime path was revisited after the offline sound-table pass. The earlier
fixture staging directory had been cleaned up, so a private fixture root was
rebuilt from local cached Graal4 data. The map was copied under the protocol
name `classiciphone.gmap`. Because that map names three `main_*.nw` levels, the
local level helper re-keyed one cached `black.nw-14900.code` container into
matching `main_aa-02.nw-14900.code`, `main_ab-01.nw-14900.code`, and
`main_ab-02.nw-14900.code` files. No fixture body was added to the repository.

The ARM64-only diagnostic APK then made two game connections through the
x86_64 emulator's ARM64 translation layer. The second connection accepted the
map, `login.gupd`, all three encrypted level containers, `pics1.png`, and the
remaining package metadata. The responder sent the map transition again after
the map file, and the client continued with packet-24 heartbeats. A screenshot
taken while the socket was open shows the green tiled world, HUD, and status
icons. The screenshot SHA-256 is
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.

This closes the local resource-loader and draw-path gap for a matching set of
encrypted test containers. It does not establish that the local cache matches
the APK's original server revision, and it does not prove live authentication.
The packet, fixture, and capture hashes are kept in
`artifacts/arm64_local_fixture_render_replay.json`.

## Unresolved helper follow-up

The unresolved profile was refined with a second offline disassembly pass. The
small helper at `0xe01a0` is called by `gpc_tristrip_clip` and formats the GPC
allocation failure message for tristrip node creation. The pass also isolated
the shared LibTomCrypt DES block transform at `0x246b50`, which is called by
the exported DES and 3DES ECB routines, and two minizip internals at
`0x24840c` and `0x249580`, which sit behind the central-directory and current
file APIs. These addresses are categorized by library family, but their
original static source names were not present in the ELF.

Four application or engine helpers were strong enough to record as role
candidates. `0xf9028` compares profiler entries by non-sub total time,
`0xf9060` recursively formats the profiler function tree, and `0xf9944`
recursively clears the profiler tree after the dump. The helper at `0x213088`
is the recursive worker used by `TGraalVar::loadFolder`; it enumerates folders,
creates `TGraalVar` entries, and records file size and folder state.

A second call-site pass added thirteen more role candidates. Six belong to the
TBitmap GIF and JPEG stream or error callback setup at `0x150a30` through
`0x150f44`. The remaining entries are the generated animation lexer fatal path
at `0x1925e4`, three TServerLevel spatial-query predicates at `0x19fc88`,
`0x19fcbc`, and `0x19fe34`, the player draw-list predicate at `0x17b9bc`,
the scroll-control property resolver at `0x1c042c`, and the actionnpc or
activeplayer script-object resolver at `0x217e68`. Their roles are supported by
callback assignments, direct call sites, or the nearby exported method. They
are still analysis aliases, not recovered source names.

A final structural pass resolved the remaining eleven application or engine
entries as role candidates. The helper at `0xe01d0` is the flex-style
`yy_get_previous_state` equivalent used by `lex_load`: it walks the animation
scanner's DFA tables and updates the generated lexer state. The comparator at
`0x20ac18` accepts two objects, computes their squared draw distance, and uses
field `0x2ec` as a priority tie-breaker. Its behavior is clear, but its class
owner and direct call site are not, so that candidate is marked medium
confidence. The other nine addresses are the complete YAJL callback set at
`0x387e20`, passed to `yajl_alloc` by `TGraalVar::readJSON` at `0x22e2c0`:
null, boolean, number, string, start-map, map-key, end-map, start-array, and
end-array. Their callback slots provide stronger evidence than their local
instruction patterns alone.

`artifacts/unresolved_function_candidates.json` stores all 28 proposed
roles with their call-site evidence, function sizes, and input hash.
`tools/generate_unresolved_function_candidates.py` regenerates it from the
saved inventory and unresolved profile. The companion
`tools/ida_apply_unresolved_function_candidates.py` is deliberately disabled
by default and is intended for review once the IDA bridge is available. No IDA
names changed during this pass, and no endpoint was contacted.

The same profile pass also recognized 104 compiler-generated cleanup wrappers
that had been mixed into the application queue. Each wrapper computes a fixed
global object address and tail-calls a known destructor or clear method. The
targets are `TString::clear` for 97 entries, `TStringList::~TStringList` for 5,
and `TGraalVar::~TGraalVar` for 2. The same profile now classifies the isolated
bzip2 helper at `0xe02ac`, the JPEG marker helper at `0xe0454`, and the
four-byte branch veneer at `0x1f94fc`, which targets the exact
`TCachedStream_get_minfilecachesize` callback at `0x1fa4fc`. This is a
structural classification rather than recovery of an original ELF source name,
but it removes noise from the manual queue and leaves 28 application or engine
entries for follow-up.
