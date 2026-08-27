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

The first pass was intentionally mechanical. It extracted the names that IDA
exposed from the ELF, demangled the C++ names, classified implementation
functions, thunks, and data, and applied readable aliases to the ARM64 IDA
database. The final alias summary is:

* translated symbols: 8,601;
* renamed functions: 4,714;
* PLT thunks: 3,183;
* jump thunks: 199;
* data symbols: 505;
* rename failures: 0.

There is an important count distinction here. The APK's native library is
reported as stripped. It has no `.symtab` or DWARF sections, and its defined
dynamic symbol table contains 6,506 rows. The 8,601 figure above is the
applied alias inventory. It includes the dynamic names that IDA exposed plus
separate PLT, jump-thunk, and data aliases. The complete audit is in
`artifacts/elf_symbol_table_audit_20260826.json`.

The complete machine-readable result is in `symbols/`. Keeping the original
mangled name beside the demangled name preserves a useful lookup key. A thunk
is named separately from its target so cross-references do not become
ambiguous.

The follow-up inventory keeps the coverage boundary explicit. IDA reports
11,272 function starts in this database. The alias rows account for 8,096
function starts and the remaining rows are 1,645 default `sub_` names plus
1,531 names that IDA created without a matching alias row. The 505 data aliases
are included in the alias total rather than the function total.
`symbols/libqplay.function_inventory.csv` and its JSON counterpart record
every function start, its size, segment, incoming references, flags, and source
category. The `sub_` rows are not missing from the archive; they are unnamed
because this stripped portion of the file provides no reliable semantic name
for them.

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

The date behavior is now confirmed in the native parser rather than inferred
only from the certificate dates. `CyaInt_ValidateDate` at `0x2b53b8` accepts
UTCTime tag 23 and GeneralizedTime tag 24, calls `time(nullptr)` and `gmtime`,
and compares the result with the current UTC clock. `CyaInt_DecodeToKey` at
`0x2b56cc` calls it with mode zero for `notBefore` and mode one for `notAfter`.
Mode zero accepts a time at or before the current clock. Mode one accepts a
time at or after the current clock. When the strict validity flag is active,
the parser retains `-140` for a `notBefore` failure and `-151` for a
`notAfter` failure.

The handshake reaches this code through `CyaInt_CyaSSL_connect` at `0x2c563c`
and `CyaInt_ProcessReply` at `0x2cb030`. Certificate record type 11 enters the
chain helper at `0x2ca940`, which calls `CyaInt_ParseCertRelative` and then
`CyaInt_DecodeToKey`. The trust-buffer loader reaches the same parser through
`CyaInt_CyaSSL_CertManagerVerifyBuffer` at `0x2c4d34`. The complete function
map is in `artifacts/connector_tls_parser_analysis_20260826.json`, with a
shorter explanation in `docs/CONNECTOR_TLS.md`.

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
field `0x2ec` as a priority tie-breaker. IDA now ties it to both
`GSFunctionsInitstaticscriptvars_script_getnearestplayers` at `0x20b580` and
`GSFunctionsInitstaticscriptvars_script_findnearestplayers` at `0x20bb88`.
Each wrapper passes the comparator to `TList::Sort` after copying the runtime
universe list, so the role is a nearest-player result comparator. The other
nine addresses are the complete YAJL callback set at
`0x387e20`, passed to `yajl_alloc` by `TGraalVar::readJSON` at `0x22e2c0`:
null, boolean, number, string, start-map, map-key, end-map, start-array, and
end-array. Their callback slots provide stronger evidence than their local
instruction patterns alone.

`artifacts/unresolved_function_candidates.json` stores all 28 proposed
roles with their call-site evidence, function sizes, and input hash.
The generator records an explicit 28-of-28 coverage check against the
`app_or_engine_unknown` profile category, so a later profile change cannot
silently leave a role candidate stale.
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

## Disposable IDA translation validation

The IDA bridge remained unavailable, but the local installation includes IDA
9.3's IDALIB interface. I copied the packed ARM64 database to a private
temporary directory and ran the native callback, exact script-table, FDE
boundary, and unresolved-role appliers together in one process. Keeping the
passes in one process matters because the IDALIB command wrapper does not
reopen its unpacked state with the same labels after the process exits.

The in-memory audit checked the final name and function start for every one of
277 native callback candidates, 886 bounded script-table candidates, 20
script-table callbacks without saved boundaries, and 28 unresolved application
or engine roles. It found zero mismatches. The native pass created five exact
`.eh_frame` ranges. The script-table boundary pass created all twenty ranges,
including two callbacks that began inside larger saved IDA functions. It
shortened those two larger ranges at the exact FDE starts before creating the
callbacks. The final temporary database contained 11,297 function starts and
459 remaining `sub_` names.

The run also exposed one naming collision that the generator now handles
deterministically. Both `0x16ca18` and `0x16db28` came from a `findweapon`
script slot and initially proposed `TPlayer_script_findweapon`. The constructor
owned target is now labeled `TPlayerProperties_script_findweapon`, while the
static initializer keeps `TPlayer_script_findweapon`. The generator regression
test and the archive validator check that the 906 exact proposed names stay
unique.

This validates the address map, the FDE ranges, the collision handling, and the
IDAPython scripts without modifying the user's active IDA database. The active
unpacked database was still locked by the desktop session. The compact result
is in `artifacts/ida_translation_validation.json`; no database, APK, asset,
certificate, or network response was added to the repository.

The validation was then repeated through IDALIB's normal database closer. The
first trial used the example runner's rollback option and correctly discarded
the changes, so the final run explicitly enabled save-on-close with `-p true`.
The translated disposable copy was saved as a packed IDA 9.3 database and
reopened in a separate read-only process. That process verified all 1,211
prepared names, the 20 newly created script callback boundaries, 11,297 total
function starts, and 459 remaining default `sub_` entries. The local 56 MB
handoff copy is at
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_all_v2.i64` and
has SHA-256
`0306a53f164fc9f860f24eb248039a94172959053daa6464d4a1effe35026a89`.
It remains outside the public repository because it is a generated database,
while the hash and verification status are kept in the public artifact.

An inventory export from that saved copy reports 8,096 ELF-backed functions,
2,742 named non-ELF functions, and 459 remaining default names. This is the
strongest local symbol-coverage count so far because it was generated after
the boundary and rename passes had been persisted, then checked against the
same input hash. The inventory JSON has SHA-256
`2f9f4d2ddeeac15f52c64e5c5868190937f3559283ce19738ed576eeaa885e28`.

### Handoff copy from the active desktop snapshot

The public validation above was originally built from a disposable copy. To
remove any ambiguity about its relationship to the user's open IDA file, I
also hashed the active desktop database before touching it, copied that exact
snapshot, and ran the same four passes in the copy. The source snapshot was
`GraalOnline+Classic_1.8_APKPure/lib/arm64-v8a/libqplay.so.i64` with SHA-256
`56da88101fe904ca298dcadf31e90433a69c43818c681ccb72364c66ac99eaa4`.

The saved handoff copy is
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_from_active.i64`.
A clean IDA 9.3 process saved it as a packed database, then a separate clean
process reopened it and verified all 1,211 prepared names. The reopened copy
contained 11,297 function starts and 459 default `sub_` names, with zero
verification failures. The active desktop database remained unchanged.

The installed MCP plugin caused the IDALIB writer to stop before saving when
it was present in the headless environment. The final handoff therefore used
a temporary clean IDA view with that plugin disabled. This did not alter the
installed IDA files or the desktop session. The machine-readable details are
in `artifacts/ida_translation_validation.json`, and the reusable save helper
is `tools/ida_apply_all_translations_save.py`.

## Packaged ARM64 replay revalidation

The complete local replay was repeated on 2026-08-25 using the packaged
ARM64-only diagnostic APK, rather than only its extracted native library. The
APK installed successfully after the Android 36 compatibility warning was
dismissed. Android loaded `libqplay.so` through its ARM64 translation layer on
the x86_64 emulator, initialized OpenGL, and produced no fatal native crash.

The connector responder saw one `/con.png` request. The first game connection
received the server-warp control packet and the second received the connecting
completion and map transition sequence. Both connections completed the
`fd`/`fc` exchange and encrypted login. The second connection then requested
`classiciphone.gmap`, three encrypted level containers, and `pics1.png`. The
responder sent packet 49 once more after the map response, and packet-24
heartbeats continued while the socket stayed open.

The screenshot again showed the green tiled world, player HUD, and status
icons. This run used the exact signed APK hash and native hash from the
earlier successful replay, so it is a repeatability check rather than a new
binary claim. The bounded responder used a minimal synthetic basepackage and
therefore needed a local GUI image copied under the requested
`guigames_graymessage2.png` name. That placeholder was not treated as a
historical game asset and was not added to the repository.

The full metadata record, including package-signature results, responder
capture hashes, fixture provenance, patch fingerprint, and the screenshot
hash, is in
`artifacts/arm64_diagnostic_apk_revalidation_20260825.json`. Raw captures,
the diagnostic APK, certificates, keys, and fixture bodies remain private.

## Spectron hook bridge deep pass

The supplied Spectron package was then followed beyond its package metadata.
Its `libxposed.so` constructor at `0x864b0` starts a worker at `0x862d4`. The
worker waits for `libqplay.so`, and the resolver at `0x80fe4` uses `dlopen` and
`dlsym` to look up nine obfuscated qplay exports. The generic wrapper at
`0x7deec` hands each target to the ARM64 inline-hook backend at `0xa6068`.
The backend changes page permissions with `mprotect`, builds a trampoline,
and patches the target entry. This is a complete native hook layer, not only
a WebView helper.

Three resolved targets receive explicit replacement functions. The slot at
`off_12B040` points to qplay `0x18446c` and is replaced by `0x7ffdc`, which
calls the original and then dispatches registered callbacks. The slot at
`off_12B030` points to qplay `0x227c80` and is replaced by `0x804d8`, which
dispatches through a registration list before calling the original. The final
`DetectFridaLoop1bbb` lookup resolves qplay `0x24a2e8` and is replaced by
`0x80fbc`. The remaining six lookups are resolved and stored but are not
explicitly replaced in the visible installation sequence. Their exact
mangled names, addresses, sizes, and slots are in
`artifacts/spectron_hook_analysis.json`.

The two qplay functions selected for callback dispatch are not connector
certificate routines. The first is a string and registry lookup that builds a
`::` key, searches a list, and recurses through a parent relationship. The
second is an obfuscated function whose exported size is known, but IDA did
not create a boundary in the Spectron image. The anti-Frida export is
explicitly named by its symbol. Nothing in this hook set provides a proven
address or source-name mapping for the original 1.8 ARM64 database.

The WebTop JNI path is separate from the qplay hook loader. The exported
`Java_com_WebTop_getMainUrl` at `0x85f84` decodes the device fragment `NOID`
and formats `https://spectronnative-page.onrender.com?device=%s`, returning
`https://spectronnative-page.onrender.com?device=NOID` for the supplied
package. The dispatcher at `0x842e4` compares six command strings:
`crash`, `freeze`, `abort`, `load_menu`, `setscript`, and `gs2call`. The first
three are destructive controls. The other three forward WebTop data to native
helpers. The URL was reconstructed from the local binary and was not opened.

The detailed pass confirms that Spectron is a separate 2.2 modding layer with
obfuscated qplay exports, a generic inline-hook engine, an anti-Frida hook,
and a remote-control WebTop bridge. It is useful for understanding what a
working modified package adds, but it is not a safe source of direct 1.8
patch addresses. The static result and the no-network marker are preserved in
`artifacts/spectron_hook_analysis.json` and
`docs/SPECTRON_COMPARISON.md`.

## Persisted residual-function audit

The four IDALIB passes were followed by a close-and-reopen export of the
translated disposable database. The original pre-persistence queue contained
488 default `sub_` entries. The 28 high-confidence application or engine role
aliases were applied and verified, and IDA reclassified the four-byte branch
veneer at `0x1f94fc` as the named thunk
`j_TCachedStream_get_minfilecachesize`. The base persisted copy therefore
contains 11,297 function starts and 459 default names.

The final 459 are fully categorized: 335 bundled-library internals, 19 ELF
initialization or finalization entries, 104 fixed-global cleanup wrappers, and
one AArch64 PLT resolver slot. The library breakdown is 150 libjpeg, 144
FreeType, 14 zlib, 11 CyaSSL or bundled crypto, 4 GPC, 4 bzip2, 3 GIF, 2
YAJL, 1 LibTomCrypt DES, and 2 minizip. The cleanup breakdown is 97
`TString::clear` wrappers, 5 `TStringList` destructor wrappers, and 2
`TGraalVar` destructor wrappers. No application or engine function remains in
the final residual queue.

The original APK's `armeabi`, `x86`, and `x86_64` libraries were also checked.
After grouping ABI-specific C++ mangling differences by demangled function
stem, the other copies added no application or engine source stem missing from
ARM64. Their raw extra names are compiler-runtime or 32-bit ABI variants.
Because the layouts differ, this does not permit address copying. It does
rule out the simplest cross-ABI route to more ARM64 source names.

The exact residual addresses, sizes, category evidence, applied role list,
database hash, and this accounting are in
`artifacts/ida_residual_profile.json`. The generator is
`tools/generate_ida_residual_profile.py`; it reads only repository JSON and
does not execute the native library or access a network.

## CyaSSL static role audit

The 11 CyaSSL entries in the base residual list were the next useful target.
They sit in the certificate and TLS implementation between recognizable
exported CyaSSL routines, so their callers and decompiled bodies give much
more information than a bare library-family label. I reviewed all eleven in a
clean IDA 9.3 IDALIB process before changing any names.

The strongest match is `0x2b6384`. It selects MD5, SHA-1, or SHA-256 from the
certificate algorithm, checks the RSA key identifier, decodes the public key,
calls `RsaSSL_VerifyInline`, builds the expected encoded digest, and compares
the result. That is the old CyaSSL `ConfirmSignature` role. The historical
[CyaSSL ASN.1 implementation](https://nest-open-source.googlesource.com/nest-yale-lock/1.2/freertos/%2B/b9a7305351d35e2d3076d0b4ab3ec121f0aa8d52/FreeRTOS-Plus/Source/CyaSSL/ctaocrypt/src/asn.c)
provides a useful source-level comparison for that sequence.

The next three bodies are the bundled digest compression transforms:

| Address | Alias | Evidence |
| --- | --- | --- |
| `0x2bdc74` | `CyaInt_Md5Transform` | 64 MD5 rounds and four-word state, called by the MD5 update and final paths |
| `0x2c0408` | `CyaInt_ShaTransform` | 80 SHA-1 rounds and five-word state, called by the SHA-1 update and final paths |
| `0x2c2f1c` | `CyaInt_Sha256Transform` | 64 SHA-256 rounds with the eight-word state and ARM NEON operations |

The certificate-loading pair is also clear. `0x2c47e0` repeatedly calls
`CyaInt_PemToDer`, handles more than one PEM certificate, builds the native
three-byte-length chain representation, calls `CyaInt_AddCA`, and decodes RSA
private keys. It is labeled `CyaInt_ProcessBuffer`, matching the historical
CyaSSL buffer-processor role. `0x2c50ac` is a smaller path helper that calls
`CyaInt_ProcessFile` for a named file or walks a directory with `opendir`,
`readdir`, and `stat`. Its exact original source name is not claimed, so the
local alias is `CyaInt_ProcessVerifyPath` with medium confidence. The old
[ProcessBuffer history](https://code.brunner.ninja/wolfSSL/wolfssl/commit/c3c341913838ebcd3178977630772bdde4908211)
was used as a role comparison, not as proof that this APK was built from that
exact revision.

The TLS key schedule exposes the next group. `0x2c6514` performs the repeated
HMAC expansion and legacy MD5 plus SHA-1 XOR path, while its callers use the
client and server Finished labels as well as the master-secret and key-block
inputs. It is labeled `CyaInt_PRF`, matching the historical CyaSSL `PRF`
role. The current [wolfSSL TLS source](https://code.brunner.ninja/wolfSSL/wolfssl/blame/commit/ef72bae2ffe1a6b0ab7397488d0544a850ed3608/src/tls.c)
was useful for comparing the TLS 1.2 and legacy branches.

The remaining four aliases are deliberately descriptive. `0x2c84bc` is the
record-MAC callback stored by `CyaInt_InitSSL` at context offset 1128;
`0x2c8710` checks CBC padding and invokes that callback; and `0x2c8a20`
computes Finished verify-data from the accumulated MD5 and SHA-1 states, using
`CyaInt_BuildTlsFinished` for TLS 1.2. They are labeled
`CyaInt_TLSRecordMac`, `CyaInt_VerifyRecordMac`, and
`CyaInt_ComputeFinishedVerifyData`. The peer certificate parser at `0x2ca940`
reads the three-byte certificate list, parses each chain member, checks signer
relationships, and stores the peer RSA state. It is labeled
`CyaInt_ProcessPeerCerts`, matching the historical role name. The current
[wolfSSL internal source](https://os.mbed.com/users/wolfSSL/code/wolfSSL/docs/tip/internal_8c_source.html)
and [TLS source](https://os.mbed.com/users/wolfSSL/code/wolfSSL/docs/tip/tls_8c_source.html)
were used to compare these helper roles, while the medium-confidence names
remain explicitly local aliases.

The aliases were applied to a new disposable packed IDA copy, not to the
active desktop database. The application report resolved and renamed all 11
entries and added 11 evidence comments with zero failures. A separate clean
reopen found all eleven names at their expected function starts, retained
11,297 total functions, and reduced the default-name count from 459 to 448.
The latest database hash is
`1db52b8b2169250852fcd1a5a2acfda859b81038e92b47158029ecc886356874`, and the
exported inventory hash is
`e6045dc5b63f215c51e13ec3b62472ee415dee87533e225ced04812439959a87`.
The machine-readable record is
`artifacts/cyassl_static_role_audit_20260826.json`; the reusable scripts are
`tools/generate_cyassl_static_role_audit.py`,
`tools/ida_apply_cyassl_static_aliases.py`, and
`tools/ida_verify_cyassl_static_aliases.py`.

## Fresh HexaParser rerun

The supplied HexaParser checkout was rerun on 2026-08-26 at commit
`ad9bd3657feece825b5f5a888f5db34ffe37afb9`. The local Go 1.22.2 toolchain
passed `go test ./...`, including the `gsbyte` package. Its two declared
modules were fetched into temporary caches for this check. That network use
was limited to the Go module proxy; no game, connector, or other service
endpoint was contacted.

Decompiling the saved `StartScript_Connector` stream again produced the exact
previous 552-line source hash
`cf60e41536ddebed89ca1c3b3342476763b3d28c1cc9fff29e211931a080afa5`.
The output has one known malformed block after `printDisconnectError`. The
new offline helper `tools/repair_hexaparser_source.py` checks for that exact
sequence and inserts only its missing brace. The repaired source hash is
`a30f9eca136e3b8ff827bfb1bfe13fb442bd2e882963bf9863cd8de5f2669e68`, and it
compiles to the same 16,141-byte result with hash
`67b70c449f87d6e3b71ef0fe92ba73fff9fe5fe7a1ad63aedb34e9daf4a7b752`.

The rebuilt stream was parsed once more for a layout comparison. Ignoring
the compiler's trailing `0x0a`, the original record lengths are
`4/553/8293/6699` and the rebuilt lengths are `4/553/8271/7280`. The original
has 3,143 instructions; the rebuilt stream has 3,582. The source names remain
recognizable, but this is not a bytecode-preserving round trip. The
`14896` connections seen in the negative control are consistent with the
recovered Classic server-list literal, which assigns the `loginclassic...`
list after the Android-only `loginclassicweb...` list. That observation does
not support another handler-order swap. The clean rebuilt-stream control
still failed to reproduce the expected `14900` resource replay, so the
original stream plus the direct loading-state insertion remains the tested
compatibility path.

The fresh hashes, record lengths, command result, and network scope are in
`artifacts/helper_toolchain_replay.json`. The source repair is intentionally
separate from `tools/reverse_hexaparser_literals.py`: the first fixes syntax,
while the second handles the observed same-line literal ordering for static
comparison.

## Native-only loading-state isolation

The earlier rendered ARM64 replay combined two changes: the direct
`onServerLogin` bytecode insertion and the native branch edit at `0x15ca7c`.
That proved the script insertion was compatible, but it left an avoidable
causal ambiguity. On 2026-08-26 I repeated the loopback test with the same
ARM64 diagnostic library and the original 15,581-byte connector script. The
script-level loading assignment was absent.

The result reached the same two game connections, accepted the synthetic
server-warp and connecting-window frames, requested `classiciphone.gmap`,
three encrypted level containers, and `pics1.png`, and continued sending
heartbeat packets. A screen capture taken while the second socket remained
open again showed the green tiled world, player HUD, and status icons. The
capture hash was
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`, matching
the combined run.

This is the cleanest local separation so far. The native branch edit at
`0x15ca7c`, which forces the existing clear at `0x15cac8`, is sufficient to
leave the loading artwork in this environment. The direct six-byte script
insertion remains a valid VM compatibility experiment, but it is not needed
for the observed render transition. The test still used loopback responders,
the x86_64 emulator's ARM64 translation layer, and synthetic cached assets, so
it does not establish the intended production behavior. The exact package,
script, capture, and screenshot hashes are in
`artifacts/arm64_native_only_original_script_replay_20260826.json`.

## Matched stock-branch control

To close the remaining causal gap, I repeated the native-only replay with the
same original connector script, diagnostic transport edits, responder, map,
level containers, image, and emulator state. The only native loading change
was restored: `0x15ca7c` contained the original `B.LE` bytes `2d 02 00 54`,
which leaves the branch on the path that skips the clear at `0x15cac8` for the
decoded `classic` option.

The stock branch still made one connector request and two game connections.
It accepted the server-warp and connecting-window frames, requested
`classiciphone.gmap`, all three encrypted level containers, and `pics1.png`,
and continued sending packet-24 heartbeats. A screenshot taken while the
second socket was open showed the original Graal Online Classic title/loading
artwork rather than the tiled world. The APK hash was
`fd7c8676939dcf83d929fd5707536d98dbfd8bae009aec9e4f80c71dbaad0031`, the
native library hash was
`f36ab1dc978861b26cb7ec3d9ebb9215b8450ffd73f957275a500de7f6492776`, and the
screen capture hash was
`70e6573244e58125d4092d8265c8acc4e2074dd866bd9cd5897ddf079d39e135`.

This is a stronger comparison than the earlier handshake-only control. It
holds the protocol and resource path constant while changing only the native
startup branch. Together with the native-only render capture, it supports the
conclusion that the visible local transition is controlled by the native
branch at `0x15ca7c`. The test still uses synthetic local assets, emulator
ARM64 translation, and compatibility patches for the archived connector, so
it does not establish production behavior. The full capture record is in
`artifacts/arm64_native_stock_original_script_control_20260826.json`.

## Reproducible diagnostic package build

The individual native patch commands were already documented, but a single
build path makes the result easier to reproduce without accidentally adding a
different ABI or a different script. On 2026-08-26 I added
`tools/build_arm64_loopback_apk.py`. It takes the original APK, stages only
its ARM64 library and non-library contents, applies the compatibility edits,
loopback HTTP and resolver redirects, deterministic output-key patch, and
native loading-state candidate, then zipaligns and signs the result with a
caller-supplied local keystore.

The helper uses fixed ZIP timestamps and sorted entries. Two independent
default builds therefore produced the same APK SHA-256
`394d9ac33fe7b81638029064f2b8ff2183405729f9b5fd94f6808facc13221fc`. The
patched native library matched the earlier tested hash
`89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858`. The
freshly built package passed v1, v2, and v3 signature verification and the
zip-alignment check.

I installed that exact output on the Android 36 x86_64 emulator, configured
only the temporary reverse mappings for ports 18080 and 14900, and served the
same local connector response and cached resource fixtures. The client made
one connector request, two game connections, requested the map, three level
containers, and `pics1.png`, continued heartbeats, and reproduced the
green-world screenshot with SHA-256
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`. The
builder and replay hashes are preserved in
`artifacts/arm64_reproducible_builder_validation_20260826.json`.

This is a private loopback package, not a release client. The default build
also applies the local RSA-result bypass so it can operate with the controlled
fixture. The `--skip-rsa-bypass` option retains the native branch for a
package-preserving test when the response is known to pass the native check.

## Certificate expiry control

The static trust-bundle result identified a concrete age problem: the first
certificate in the historical GraalWeb bundle expired on 2023-07-29. Static
evidence alone does not show whether the old native TLS code enforces the
certificate validity dates, because a client can also reject a chain for its
name, key usage, signature, or trust-anchor shape. I therefore built a
minimal paired control instead of changing the production-oriented repair.

Both private ARM64 packages started from the restored original library with
the same local-only edits: a one-certificate trust bundle, hostname routing
to `127.0.0.1`, connector port `18443`, the deterministic responder RC4 key,
and the native loading-state candidate at `0x15ca7c`. The native certificate
check at `0x20ab20` stayed intact in both packages. Each self-signed test
certificate used `con.quattroplay.com` as its common name and subject
alternative name.

The expired certificate was valid from 2020-01-01 through 2021-01-01. Its PEM
SHA-256 was
`633e4599f946aeec39b6a050ddb75660b26205e90416d79853a0ccd87d96dace`. The
valid control was valid from 2025-01-01 through 2035-01-01. Its PEM SHA-256
was `a55c4ec36f6c5708948d6f1e257b7782153ea85032b184fe7180adc00d347f75`.
The reproducible helper `tools/make_tls_validity_fixture.py` creates the same
certificate shape with caller-selected dates. Keys are generated randomly and
must remain outside the repository.

The valid control reached the loopback TLS responder and produced:

```text
GET /con.png?... HTTP/1.0
Host: con.quattroplay.com:18443
User-Agent: Graal/6.15401
```

The query value is omitted from the public record. The responder then returned
the deliberately minimal test body. The expired control reached the listener
at the TCP layer, but the client closed during the TLS handshake. The improved
responder recorded `SSLZeroReturnError` and no `TLS_CAPTURE_REQUEST` line.
The client-side milestones stopped at native library activation and OpenGL
initialization, with no connector HTTP request. This paired result is strong
evidence that validity dates are checked before HTTP in the translated ARM64
path. It does not establish the exact error code on a physical ARM64 device,
and it does not show that a current service will accept a replacement chain.

The exact expired control package hash is
`e7615fcb37112cb86e8d768f51143149b98dcde83c12a5b734ca65e336f29e36`; its
packaged native library hash is
`16fa26de513129e480f49885008219616c8749d1ea8948082b4efccdcc5a44fe`. The
valid control package hash is
`183ef83ed2772872288c1aa639e0501b5a645df395b0f89887a38ce56c0266f0`; its
packaged native library hash is
`7cffcbd8380d5e19324eb6d392e6cd942ce696b9470bbaaa74b037827ebecee7`.
The comparison metadata is in
`artifacts/connector_tls_expiry_control_20260826.json`.

This result strengthens the stale native trust bundle diagnosis, but the
correct next production experiment remains a private package with an
authorized current chain and the native verification routine left enabled.
The loopback port, resolver, responder key, and loading-state edits are test
controls only. No live endpoint was contacted.

## Native-verification working control

The validity control showed that an expired certificate stops the connector
before HTTP, while a valid SAN-matching certificate reaches the request. I
followed that with a package that kept the native RSA result branch and the
native certificate verifier intact all the way through the game replay.

The new `tools/build_arm64_trust_control.py` helper starts from the original
APK, retains only the ARM64 library, replaces the old native trust bundle,
routes the connector hostname to loopback, moves the HTTPS port to `18443`,
and installs the fixed output RC4 key used by the local responder. It never
applies the RSA bypass. Its optional `--force-nonpremium-loading` switch
applies the previously isolated branch edit at `0x15ca7c`.

The working package used the valid one-certificate test chain from the
earlier control. The chain covered `con.quattroplay.com` and was valid from
2025-01-01 through 2035-01-01. The native library produced by the full chain
was `7cffcbd8380d5e19324eb6d392e6cd942ce696b9470bbaaa74b037827ebecee7`, and
the signed ARM64 package was
`183ef83ed2772872288c1aa639e0501b5a645df395b0f89887a38ce56c0266f0`.

The local TLS responder saw the same request shape as the earlier valid
control: `/con.png`, host `con.quattroplay.com:18443`, and user agent
`Graal/6.15401`. The client then opened two encrypted game connections. The
responder sent the server-warp and completion frames, returned
`basepackage.gupd`, `guigames_graymessage2.png`, `classiciphone.gmap`, three
encrypted level containers, and `pics1.png`, then observed packet-24
heartbeats. The final screenshot showed the tiled world, player HUD, and
status icons. Its SHA-256 was
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.

The paired form with the same valid trust chain and transport edits, but
without the loading-branch edit, made the same connector and resource
requests and kept sending heartbeats. It stayed on the title/loading artwork.
That makes the result useful as a two-part isolation: the trust replacement
fixes the pre-HTTP connector failure, while the native startup branch controls
the observed transition into the translated ARM64 game draw path. Neither
control proves the production entitlement meaning of that branch, live
service compatibility, or behavior on a physical ARM64 device. The complete
hash and capture record is in
`artifacts/arm64_native_verification_working_control_20260826.json`.

## Static library role audit

After the CyaSSL pass, I reviewed the remaining unnamed routines whose
callers and bodies placed them inside bundled third-party libraries. This
second audit resolved 27 entries across seven families: 14 zlib routines, 4
bzip2 routines, 2 minizip helpers, 1 GPC helper, 2 CyaSSL ASN.1 helpers, 1
LibTomCrypt DES routine, and 3 YAJL allocator callbacks. Every alias is a
high-confidence source-role match. These are analysis names applied to a
disposable IDA copy. They do not claim that the original stripped ELF
contained those source names.

The zlib group includes the three deflate strategies, the inflate table
builder, the dynamic-tree emitters, the block helpers, and the allocator
callbacks. One earlier role guess was corrected during this pass:
`0x288908` is zlib `_tr_init`, not `lm_init`. Its body initializes the pending
tree descriptors, bit state, frequency tables, and end-block code, while the
actual `lm_init` role initializes the sliding-window and hash state elsewhere.
The bzip2 entries are the two sorting paths, `mainGtU`, and
`sendMTFValues`. The minizip entries are the central-directory information
helper and the current-file header coherency helper. The GPC entry is
`build_lmt`, identified by its seven-argument edge-table construction and
the literal error messages it uses. The DES entry contains the initial and
final permutations, all 16 rounds, and the S-box lookups. The YAJL entries
are the direct `malloc`, `free`, and `realloc` callbacks installed by the
default allocator setup.

The address-boundary profile had five stale family classifications. The two
CyaSSL ASN.1 helpers had been placed in a YAJL bucket, and the three YAJL
allocator callbacks had been placed in a GIF bucket. The decompiled behavior,
callback installation sites, and source comparisons corrected those entries.
The source comparisons used the relevant [zlib sources](https://github.com/madler/zlib/blob/develop/trees.c),
[bzip2 block-sort source](https://sources.debian.org/src/bzip2/1.0.5-1%2Blenny1/blocksort.c/),
[minizip source](https://github.com/madler/zlib/blob/develop/contrib/minizip/unzip.c),
[GPC source](https://github.com/rickbrew/GeneralPolygonClipper/blob/main/gpc.c),
[CyaSSL ASN.1 source](https://nest-open-source.googlesource.com/nest-yale-lock/1.2/freertos/%2B/b9a7305351d35e2d3076d0b4ab3ec121f0aa8d52/FreeRTOS-Plus/Source/CyaSSL/ctaocrypt/src/asn.c),
[LibTomCrypt DES source](https://android.googlesource.com/platform/external/dropbear/+/refs/heads/donut-release/libtomcrypt/src/ciphers/des.c),
and [YAJL allocator source](https://sources.debian.org/src/yajl/2.1.0-3/src/yajl_alloc.c).

The aliases were applied to `analysis/libqplay_translated_all_v4.i64`. A
clean IDA 9.3 reopen verified all 27 names and comments, retained 11,297
functions, and reduced the default-name count from 448 to 421. The final
database SHA-256 is
`089e588389206929cbcbd7d1d65dd477e0c69eed0841b430636bb7c947594ac3`, and
the exported inventory SHA-256 is
`5d25001293e816e7a2d91261ba9140b9f891df952b3427fd67343c643ed87496`.
The machine-readable record is
`artifacts/static_library_role_audit_20260826.json`. The reusable helpers
are `tools/generate_static_library_role_audit.py`,
`tools/ida_apply_static_library_aliases.py`, and
`tools/ida_verify_static_library_aliases.py`.

## Spectron runtime crash control

I installed the supplied `spectron_client_1.0.2.apk` beside the original
package on the Android 36 x86_64 emulator and launched
`com.quattroplay.GraalClassiC/com.quattroplay.GraalClassic.QPlayActivity`.
The custom menu appeared. After tapping Start, the process died at
`2026-08-26 12:17:35.134` with `SIGSEGV` and fault address `0x0`.

The native backtrace pointed to `libxposed.so+0x84348`, called from
`Java_com_WebTop_onmsg+104` at `0x85d9c`. I checked the supplied stripped
`libxposed.so` in a clean IDA process. The dispatcher at `0x842e4` compares
the WebTop message with `crash` at `0x84338`, and the selected path reaches
`0x84348`, where it stores through a null address and loops. This explains
the exact runtime death as an intentional modding-layer command rather than
a qplay TLS or renderer crash.

The same run logged qplay failures while writing external scoped-storage
assets, including
`.../files/levels/images/classiciphone/classiciphone_pics5c.png`. Those
failures are recorded as a separate observation. The run had ordinary
emulator networking enabled, but network contact was not independently
audited, so it is not a no-network control and does not establish a playable
world. The structured record is
`artifacts/spectron_runtime_crash_control_20260826.json`.

To separate the crash from the rest of the mod, I built a private signed
control with `tools/build_spectron_webtop_safe_apk.py`. It changes only the
three ARM64 `libxposed.so` branches that select `crash`, `freeze`, and
`abort`, making each skip to the next dispatcher comparison. The qplay
library and the other three WebTop command branches remain unchanged.

The control APK SHA-256 is
`d8b44281f2c2a3e8ab6f40358e28d017052a967cdf2a5b9b0c3383535ef07de3`, and its
patched ARM64 hook library SHA-256 is
`ba6023c42e501c9f1dae17f7d65973d09b399f4f4c8f1acf1e43487b1b01a50c`.
After Start, the process stayed alive and qplay logged activation, OpenGL
initialization, login-server connection, two server-warps, and Connected.
The custom green menu then led to a welcome dialog and several tutorial
dialogs. After advancing those dialogs, the client rendered a stable local
game scene with the player, map furniture, HUD controls, and status icons.
The emulator had ordinary networking enabled, but network contact was not
independently audited. This proves local game entry for the supplied 2.2
package under the safe WebTop control, not live-service compatibility. The
structured record is
`artifacts/spectron_webtop_safe_runtime_20260826.json`.

## Spectron semantic translation pass

The supplied Spectron ARM64 library is a separate 2.2 rebuild. Its
application C++ names are mostly obfuscated, so direct symbol transfer is
not possible. I added `tools/ida_export_function_features.py`, a read-only
IDAPython exporter that records normalized instruction shape, register shape,
basic blocks, strings, and direct call names. PC-relative addresses are
removed from the feature keys so the comparison is not tied to the original
layout.

`tools/match_spectron_semantic_functions.py` compared the original v4
translated database with the Spectron ARM64 library. The original has 11,297
function starts and Spectron has 11,678. The matcher produced 3,700 unique
target mappings for named 1.8 functions: 3,641 high-confidence rows and 59
medium-confidence rows. It left 1,019 functions ambiguous and 614 without a
usable target. The automated labels use the `v18_` prefix and retain both
addresses and the obfuscated target name in the map.

The 1,008 one-to-one shared-name functions provide an internal validation set.
The unique matcher reproduced 396 of those names with zero wrong matches. That
supports the feature normalization, but it is not a license to treat every
obfuscated row as proven. Ambiguous and medium-confidence rows remain
review-only.

I applied the 3,641 high-confidence labels to
`analysis/spectron_libqplay_translated_v1.i64`, then added four separately
reviewed context anchors to
`analysis/spectron_libqplay_translated_v2.i64`:

* `TGameEnvironment_getPremiumOption_void` maps to the Spectron function
  that builds the same encoded `a9a` marker and is called by sigcheck.
* `TClientEnvironment_getLoadingScreenEnabled_void` maps to the getter for
  the byte written by the paired translated setter and read by QPlayLoop.
* `TGUIScriptLoader_showConnectingWindow_void` maps to the function owning
  the Connecting and StartConnectMessage string set, with matching block and
  call counts.
* `Java_com_quattroplay_GraalClassic_Natives_QPlayLoop` retains its exact
  exported JNI name in both builds and remains a direct runtime anchor.

The second database was reopened and all four manual anchors verified. Its
SHA-256 is
`fab82bedbafb864513dfbfc144f657d7542816d2ff883abe1a55c16753f55618`.
The map, checkpoint, manual evidence, and application scripts are
`artifacts/spectron_semantic_function_translation_20260826.json`,
`artifacts/spectron_translation_checkpoint_20260826.json`,
`artifacts/spectron_manual_translation_anchors_20260826.json`,
`tools/ida_export_function_features.py`,
`tools/match_spectron_semantic_functions.py`,
`tools/ida_apply_spectron_translation.py`,
`tools/ida_apply_spectron_manual_anchors.py`, and
`tools/ida_verify_spectron_manual_anchors.py`.

## Spectron exact-name and network anchors

The strict semantic matcher is not the only useful cross-build evidence. I
compared the non-default function names in both IDA feature exports and found
1,008 names that occur exactly once in each build. The set contains 396 rows
already accepted by the semantic matcher and 612 rows that are preserved
exact-name anchors only. The breakdown is 381 PLT or import names, 27 JNI
names, and 600 other readable names. Because the target already has the exact
name, these rows do not need an invented `v18_` alias. The complete inventory
is `artifacts/spectron_exact_shared_name_anchors_20260826.json`, generated by
`tools/generate_spectron_exact_name_anchors.py`.

The small-name gap is not evidence that all 612 functions are unrelated. Many
are four-instruction PLT wrappers, while others changed size or boundary in
the 2.2 rebuild. The inventory therefore keeps exact-name evidence separate
from inferred semantic translation. It records both addresses, function
sizes, instruction counts, and basic-block counts so later IDA review can use
the names as context without copying an address.

I then reviewed six network-path candidates in clean IDA output. The 2.2
function at `0x2094c0` performs the connector-mode parameter construction. The
function at `0x205958` handles HTTP download completion and the same response
status families. The function at `0x20c59c` creates the CyaSSL context and
applies the certificate, cipher, domain, and nonblocking settings. The
function at `0x20ccd8` creates the socket, resolves the host, and performs the
nonblocking connect. The function at `0x204274` reads the game stream and
dispatches to the protocol parsers. The function at `0x20d614` contains the
plain, UDP, and CyaSSL read branches with the expected error handling.

These six rows are manual context anchors, not guessed symbols. Each carries
the original 1.8 range, the Spectron range, the obfuscated current name, and
the reason it was selected. The artifact is
`artifacts/spectron_network_manual_translation_anchors_20260826.json`. The
existing manual-anchor IDA scripts accepted its artifact type through
`SPECTRON_MANUAL_EXPECTED_ARTIFACT` and applied it to
`analysis/spectron_libqplay_translated_v3.i64`. A clean reopen verified all
six names with zero failures. The resulting database SHA-256 is
`3e85fe26f63574232b445c249775f52b53efb12a71a5e046375ea216b61d1c95`.

## Spectron core anchors

The next pass reviewed 16 functions that connect downloaded resources and
client state to the visible game. The review covered two resource-refresh
methods, two static tables, the draw boundary, the main GUI loader, connecting
and message-box helpers, the failed-safe connector, input focus, file upload,
game logging, web-script execution, and the server-list transition.

The resource pair at Spectron `0xee558` and `0xef090` preserves the extension
dispatch, map-header checks, `webfiles` path handling, resource lookup, and
linked-object refresh behavior. The static initializers at `0xf0058` and
`0xff65c` preserve the image, executable, archive, path, and package
extension tables. The target at `0xff028` is an IDA default `sub_` function,
but its pseudocode walks resource entries, performs decompression, refreshes
objects, and reports `Unzipped ... into ... files`, which makes the restored
`TFileScripting_script_decompressFile` role well supported.

The rendering and GUI rows are similarly direct. Spectron `0x16027c` owns the
`RenderGUI` profiler label, render-manager clearing, and normal success return.
`0x16b848` loads `StartScript_GraalGui` and installs `GUIContainer`,
`GraalControl`, and `GraalControl3D`. `0x16bed8` hides the active
`StartConnectMessage` dialog. `0x16bf80` creates the message-box script,
`0x16c0ac` assigns `MessageBoxDialog_Text` and displays the dialog, and
`0x16c3a0` activates `StartScript_Connector`. The input helper at `0x16cac8`
checks `ChatBar` and `ChatBar3D`, which ties the UI translation to keyboard
focus behavior.

The remaining rows preserve client support behavior. `0x1ed4c4` enforces the
20,000,000-byte upload limit and queues accepted files. `0x1f6538` logs each
line to the `game` channel. `0x207db8` reads and parses web-script responses,
enforces the size guard, and runs accepted scripts. `0x2092a0` resolves
`ServerListGui`, updates the GUI container, and calls the connecting and game
GUI paths in the same transition sequence.

The full evidence is in
`artifacts/spectron_core_manual_translation_anchors_20260826.json`, generated
by `tools/generate_spectron_core_anchors.py`. All 16 names were applied to
`analysis/spectron_libqplay_translated_v4.i64` and verified after reopening.
The database SHA-256 is
`3d4f217fcd20e21839957f4bd68a5fefa3998294fb6eebe93df760dd06e966b3`.

## Spectron runtime-path anchors

The following review followed the live-client path from map and file packets
into scripts, text controls, and the server-list state machine. Thirteen
additional functions were strong enough to anchor from clean pseudocode.

The map-entry rows are Spectron `0x1eead4`, `0x1ef0a0`, and `0x1f6108`.
They normalize or decode `.gmap` names, copy map metadata into the active
player, select the first level, reset the transition state, and enter the
level. This gives the v5 database a readable path through the local world
transition instead of leaving those target functions as `sub_` labels.

The file-delivery rows are `0x1ef8fc` and `0x1f1074`. They preserve the
download completion and file-chunk roles, including cache creation, byte
accounting, `onFileChunkReceived` and `onFileDownloaded`, `.gupd` package
updates, resource-key validation, and requested-file cleanup.

The text-control pair at `0x1f6670` and `0x1f73d0` handles the same
GraalEngine and QEngine vocabulary. Both support `getstats`, format a QEngine
statistics response, and route ordinary controls to the active weapon through
`receivetext`. Their different argument layouts and 12 versus 10 block
shapes support separate roles rather than duplicate labels.

The encrypted-script pair at `0x1f696c` and `0x1f6dec` decodes the same compact
coordinates and length fields. One routes weapon data to the encrypted setter
and class data to the script-universe add path. The other routes weapon data to
the encrypted loader and class data to the class-request path. Both preserve
the class, gani, and weapon strings and were IDA default `sub_` functions in
the target.

The server-list rows at `0x2087f4`, `0x20a010`, and `0x2089d0` complete the
transition context. They preserve disconnect cleanup and SSL error reporting,
server-warp event arguments, reconnect notifications, socket timeout handling,
incoming package processing, and deleted-player cleanup. The static client
initializer at `0x1ec294` preserves the loopback default, client lists, and
download tables while adding 2.2 state that was absent from the shorter 1.8
initializer.

The full artifact is
`artifacts/spectron_runtime_path_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_runtime_path_anchors.py`. All 13 names
were applied to `analysis/spectron_libqplay_translated_v5.i64` and verified
after reopening. The database SHA-256 is
`2c059f8bc96b90e46542f3fb3d05a6cd5a99af112acd516751f42b1bf4c0e421`.

## Spectron update and protocol anchors

The v6 review added five high-confidence anchors for the update queue, server
modification handling, and image-update requests. These functions are useful
for following the request path even when the 2.2 application symbols are
obfuscated.

The queue functions at Spectron `0x1ecd80` and `0x1ecef0` preserve separate
download and update de-duplication tables. Both retain `.gupd` priority
insertion and the same capacity guard before dispatching the next image
request. The server-modify handler at `0xecba0` keeps the active-player
transition reset and chooses between entering the new level and applying
server modifications in place.

The image checksum and modification-time helpers at `0x1f8cc0` and
`0x1f911c` preserve resource lookup, URL handling, compact request encoding,
offline event branches, and timestamp or checksum state. The checksum helper
also retains the local `.gupd` CRC path and its five-character transport
encoding. These are semantic anchors, not claims that a current server still
uses the same request sequence.

The full evidence is in
`artifacts/spectron_update_protocol_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_update_protocol_anchors.py`. All five
names were applied to `analysis/spectron_libqplay_translated_v6.i64` and
verified after reopening. The database SHA-256 is
`a8b96aeb48438b222828348b990ee944252e14c02763bfe097d63dc8bab4bbe3`.

## Spectron client action anchors

The v7 pass followed 11 client action packet serializers that remain outside
the strict semantic map. Each target keeps a protocol format string and a
mangled parameter signature that agrees with the readable 1.8 role.

The target at `0x1f7968` is the level-warp modification-time serializer. It
retains the `ddsu` format, compact coordinate encoding, and the split between
the connector diagnostic path and the ordinary game-server path. The board
helpers at `0x1fa098` and `0x1fa3b0` retain `iiiiis` and `siiiiis`, including
the short board values and long-payload escape handling.

The action cluster then continues through the bomb helper at `0x1fa7a4`
(`ffiibs`), trigger action at `0x1fb89c` (`offss`), projectile helper at
`0x1fbc80` (`dddddddsss`), shot helper at `0x1fcdc8` (`ddiiibb`), player-hurt
helper at `0x1fd43c` (`ooddi`), weapon-hit helper at `0x1fd8e0` (`dddo`), and
explosion helper at `0x1fdde0` (`iiddb`). The text serializer at `0x1fe670`
retains `ssss` and the long-string container.

These rows are semantic anchors for local packet serialization. They do not
prove that a current external server still accepts the old packet protocol.
The full artifact is
`artifacts/spectron_client_action_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_action_anchors.py`. All 11 names
were applied to `analysis/spectron_libqplay_translated_v7.i64` and verified
after reopening. The database SHA-256 is
`dff0fadfadfbbd4cb815b013ad589965545acb6b521518af091b61e89b266a64`.

## Spectron remaining client outbound anchors

The v8 review covered the remaining outbound methods in the readable client
cluster. It produced 29 high-confidence rows. Twenty-eight rows add new
context labels, and one row, `TClient_sendWantImageUpdate_TString_const` at
Spectron `0x1f943c`, independently corroborates the strict semantic match
already present at that address.

The level and file sequence now has reviewed target anchors at `0x1f76b0`
for `TClient_sendLevelWarp_double_double_TString_const`, `0x1f7c88` for
`TClient_sendLevelLinking_TString_const_double_double`, `0x1f8110` for
`TClient_sendEnterLevel_void`, and `0x1f8290` for
`TClient_sendDownloadFile_TString_const_TString_const_TString_const`. The
upload sequence follows at `0x1f8514`, `0x1f86c0`, and `0x1f88e8` for upload
start, save file, and upload end. The image request rows are `0x1f8a94` and
`0x1f943c`, followed by the GANI, weapon, and class script requests at
`0x1f94d8`, `0x1f9724`, and `0x1f98d0`.

The chat and state rows are `0x1f9b1c` for all-chat, `0x1f9d70` for the
player PK-state packet, `0x1f9f14` for carry or throw, `0x1fb194` for player
properties, and `0x1fb340` for NPC properties. The flag pair at `0x1fb4ec`
and `0x1fb6c4` both retain the `client.` guard and their distinct outbound
event paths.

The final action group is anchored at `0x1faad0` for bomb removal, `0x1fad20`
for fire spying, `0x1faed8` for level preload, `0x1fc440` and `0x1fc6e0` for
extra pickup and take, `0x1fc980` for extra removal, `0x1fcbf0` for opening a
chest, `0x1fd0e0` for weapon deletion, `0x1fd280` for NPC deletion, and
`0x1fdbe0` for server warp. Their target signatures preserve the corresponding
string, integer, floating-point, pointer, or no-argument shapes. The target
bodies also retain the common client send slot, coordinate rounding, compact
or long-string branches, and diagnostic format branches where applicable.

The generator checks the source names, target addresses, mangled signature
fragments, required `.gmap`, `.gupd`, or `client.` strings, duplicate targets,
and both input library hashes. The artifact is
`artifacts/spectron_client_outbound_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_outbound_anchors.py`. The rows
were applied to a copy of v7 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v8.i64`. Its database SHA-256 is
`29e9eed59176cdf495705a88e1d193000f59d46eefba5f151e9d213d8ec4f58d`, and the
same hash is recorded in the checkpoint. This is a local protocol translation
aid, not evidence that a current external server accepts these packets.

## Spectron resource resolver anchors

The v9 review moved into the resource-function cluster and added six
high-confidence anchors. The target signatures and pseudocode preserve the
same roles for encoded resource-key validation, wildcard matching, file-list
construction, stream loading, game-file existence, and game-file path lookup.

The first three rows are `TResourceFunctions_validateFileKey_TString_const` at
`0xef5a0`, `TResourceFunctions_getMatchingResourceObjects_TString_const_int_bool`
at `0xef69c`, and `TResourceFunctions_getFilesForPattern_TString_const_int` at
`0xef8d4`. The validator hashes the encoded key, attaches it to the matching
resource alternative, and refreshes the object. The matching helper handles a
direct level lookup or wildcard iteration, includes linked alternatives, and
applies the result limit and optional sort. The file-list helper selects data
or user roots and converts matching resource paths into relative filenames.

The stream and game-file rows are `0xefcd0` for
`TResourceFunctions_getResourceStream_TString_const_bool_bool`, `0xefe58` for
`TResourceFunctions_gamefileexists_TString_const`, and `0xefe78` for
`TResourceFunctions_getGameFile_TString_const_bool`. The stream helper chooses
absolute or level lookup, checks loadability, updates the selected object when
requested, returns its stream, and falls back to a download or empty stream.
The final two helpers preserve the resource-existence predicate and stored
path construction, including the optional download call for a missing file.

The artifact is
`artifacts/spectron_resource_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_resource_anchors.py`. All six names were
applied to a copy of v8 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v9.i64`. The database SHA-256 is
`1e63b822e0d9cd8d9d1ea7f3db5fe03e4b8dbbaf451d22fae6784106c4c34e83`. These
labels are semantic translation aids and do not claim that the original
debug-symbol information survived in the stripped 2.2 build.

## Spectron client script bridge anchors

The v10 review followed the script-call bridge from script-visible actions into
player state and client packet helpers. It added 13 high-confidence labels to
target functions that IDA had left as default `sub_` names.

The first group is the upload, terrain, and action path. `GSFunctionsClient_script_uploadfile`
at `0x15ab64` preserves the allowed-upload list check, script-access filename
lookup, and client upload call. `GSFunctionsClient_script_updateterrain` at
`0x15ac54` retains the active-player buffer refresh wrapper. The trigger helper
at `0x15aca0` keeps action-NPC selection, player coordinate adjustment, the
player-side trigger call, and the client packet call.

The appearance cluster at `0x15b260`, `0x15b2d4`, `0x15b348`, `0x15b3bc`, and
`0x15b430` maps sleeve, skin, shoe, coat, and belt colors. The target indexes
remain 2, 0, 3, 1, and 4, respectively. The weapon-call helper at `0x15b4a4`
preserves weapon index validation, action-NPC state, compact or long argument
conversion, and the selected weapon callback.

The request-text helper at `0x15b958` retains the `graalengine` and `clientrc`
authorization gate and reports the same unauthorized attempt. The map lookup
at `0x15c51c` lowercases map names, scans the map list, and falls back to the
current level. The server-list bridge at `0x15ca50` still emits
`onOpenServerList`. Finally, `0x15d400` preserves the `add`, `delete`, `irc`,
and `lister` command filters, the graalengine guard, and the four-string text
packet dispatch.

The artifact is
`artifacts/spectron_script_bridge_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_bridge_anchors.py`. All 13 names
were applied to a copy of v9 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v10.i64`. The database SHA-256 is
`ef32e71f5dda36f208fe2e61f08f1dbf849e12cc1b223c3d9b2af19e408d6b92`. The
target shape and string checks are recorded in the artifact. These labels are
translation aids for local script behavior and do not establish live service
compatibility.

## 2026-08-26: Spectron client request and window-state anchors

The eleventh Spectron IDA pass followed the readable `TClient` request tail.
The target methods remain in the same order as the 1.8 source cluster, which
made this a useful structural anchor even after application names were
obfuscated. I required the source role, target order, mangled argument shape,
instruction and block counts, and a pseudocode body review to agree before
persisting a label.

The 11 reviewed rows are:

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_sendWeaponImgChange_TString_const` | `0x1f8480` | `0x1fe088` | one string and weapon-image event |
| `TClient_sendRCChat_TString_const` | `0x1f8534` | `0x1fe234` | one string and RC-chat event |
| `TClient_sendRequestText_TString_const_TString_const_TString_const` | `0x1f85e8` | `0x1fe3e0` | three strings and normal request dispatch |
| `TClient_sendRequestFileDeletion_TString_const` | `0x1f88fc` | `0x1fe960` | path parsing and file-deletion dispatch |
| `TClient_sendRequestFolderDeletion_TString_const` | `0x1f89d4` | `0x1feb28` | one string and folder-deletion event |
| `TClient_sendRequestFileRename_TString_const_TString_const` | `0x1f8a88` | `0x1fecd4` | two strings and long-string branch |
| `TClient_sendRequestFilesMove_TString_const_TString_const` | `0x1f8cd0` | `0x1ff020` | two strings and long-string branch |
| `TClient_sendRequestUpdatePackage_TUpdatePackage_bool` | `0x1f8e60` | `0x1ff2b8` | package list, checksums, and block flag |
| `TClient_sendHaveWindow_bool_TString_const` | `0x1f9198` | `0x1ff6c0` | boolean/string `bs` path |
| `TClient_sendPingAnswer_int` | `0x1f92b4` | `0x1ff8c8` | integer clamp and compact encoding |
| `TClient_sendWindowList_TString_const` | `0x1f93e8` | `0x1ffaa0` | one string and window-list event |

The first two methods preserve their distinct image and RC-chat callbacks.
Request text retains the three-string packet. File deletion still extracts the
filename before dispatch, while folder deletion keeps its separate event. The
rename and move methods preserve their bounded string handling and compact or
long packet paths. The update-package method retains the `.gupd` and checksum
logic, and the window methods keep their event-specific branches. The ping
method still clamps large values and uses the compact two-character form.

The artifact is
`artifacts/spectron_client_request_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_request_anchors.py`. All 11 names
were applied to a copy of v10 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v11.i64`. The database SHA-256 is
`6a34445aa580201a046e227b9ec447b73ee37251e7b716b349474e278e3d1daa`. These
are semantic translation labels for the exact hashed Spectron library, not
restored original debug symbols and not proof of current service compatibility.

## 2026-08-26: Spectron client inbound and state-transition anchors

The twelfth Spectron IDA pass moved into the client inbound and state
transition helpers. These are useful complements to the outbound serializer
map because they show how the same client handles script data, file delivery,
map entry, update completion, player state, and GANI data after a packet or
callback arrives.

The eight reviewed rows are:

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_manageDataByScript_uchar_TString_const` | `0x1e7bf0` | `0x1ebf78` | array slots and `onData` event |
| `TClient_uploadFilesToServer_void` | `0x1e9198` | `0x1ed624` | upload queue, packet sequence, and completion |
| `TClient_processServerModifies2` | `0x1ea9f4` | `0x1eedfc` | object-list cleanup and level transition |
| `TClient_enterServerMapTile` | `0x1eac34` | `0x1ef24c` | `.gmap` lookup, clamping, and selected tile |
| `TClient_handleUpdatePackageDownloaded` | `0x1ec044` | `0x1f08ec` | package state and two completion events |
| `TClient_updateGlobalPlayer` | `0x1ed3e8` | `0x1f1d98` | player lists, login/logout, and message merge |
| `TClient_updateGaniFromString` | `0x1f1dd0` | `0x1f65d4` | serialized GANI replacement |
| `TClient_handleGaniUpdate` | `0x1f2a20` | `0x1f7268` | packet slicing and GANI replacement |

The script data target keeps the bool and string array entries before the
event dispatch. The upload target keeps the pending-file loop, the upload
start and save-file requests, removal of completed entries, and the final
callback. The map transition target preserves the active-player fields,
coordinate bounds, `.gmap` resource selection, and level-entry branches. The
server-modification target keeps both object-list cleanup passes and the
choice between applying modifications and entering the selected level.

The package-completion target still marks the package state, emits the object
event, emits the all-packages-complete event when appropriate, and performs
the optional executable-replacer handoff. The global-player target retains
creation and update of player objects, deleted-player recovery, list limits,
mass-message handling, and login or logout event arguments. The two GANI
targets preserve the line-list conversion and animation replacement path,
with the packet handler also retaining its compact index and length parsing.

The artifact is
`artifacts/spectron_client_inbound_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_inbound_anchors.py`. All eight
names were applied to a copy of v11 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v12.i64`. The database SHA-256 is
`3b95170bd3689c176a15503764476a13db7c50e194ae771b7c39d9d33e1badfa`. These
are semantic labels for the exact hashed Spectron library, not restored
original debug symbols and not proof of current service compatibility.

## 2026-08-26: Spectron login, event, and small state-helper anchors

The thirteenth Spectron IDA pass reviewed the compact helpers around login and
connection state. These functions are small, but they sit directly between the
client state setters, event callbacks, and packet handlers that control the
first connection phase.

The eight reviewed rows are:

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGameEnvironment_emit_onFolderLog` | `0x1e96dc` | `0x1edb9c` | transformed one-string folder-log helper |
| `TGameEnvironment_emit_onRCChat` | `0x1e975c` | `0x1edc54` | transformed one-string RC-chat helper |
| `TClient_handleServerLoginSignature` | `0x1e97dc` | `0x1edd0c` | signature storage and login-event path |
| `TClient_setGhostMessage` | `0x1e9840` | `0x1edda8` | direct global string assignment |
| `TClient_setDisconnectReason` | `0x1e9850` | `0x1eddb8` | direct global string assignment |
| `TClient_setServerWarpDestination` | `0x1e9860` | `0x1eddc8` | direct global string assignment |
| `TClient_setLoginAccountName` | `0x1e9870` | `0x1eddd8` | direct global string assignment |
| `TClient_handlePlayerLoginLogout` | `0x1f17b4` | `0x1f3018` | prefix decode and updateGlobalPlayer call |

The target retains the exact four-function setter run after the login helper,
including the shorter final setter. The two event helpers are larger in
Spectron because their string literals are transformed and passed through a
decoder before dispatch. The first one is independently tied to the target
upload-file error path, where the same transformed literal is used for the
folder-log event. The second follows it with the distinct RC-chat literal.

The server-login target stores its argument in a client static and dispatches
the transformed no-argument login event. This matches the source behavior and
the preserved position between the two event helpers and the four string
setters.

The player-login handler shows a deliberate target-side refactor. In 1.8 the
large handler decodes the packet prefix and contains the player update logic.
Spectron places the prefix decode in `0x1f3018`, then calls the separately
translated `v18_TClient_updateGlobalPlayer` function. The anchor therefore
records the shared role and call boundary, not byte identity.

The artifact is
`artifacts/spectron_login_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_login_helper_anchors.py`. All eight names
were applied to a copy of v12 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v13.i64`. The database SHA-256 is
`40fd845df92e2443481d2a3e08299749ba46e3dcde4529769b0a028e65fc1d01`. The
labels are useful for local analysis, but they do not establish live server
compatibility.

## 2026-08-26: Spectron player and download lookup anchors

The next focused pass reviewed three list lookups near the client constructor
and download queue. These were not selected by the broad matcher because the
obfuscated build changes the static and helper names, but the bodies preserve
the same loops and control flow.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_getGlobalPlayerByID_int` | `0x1e7650` | `0x1eb9d8` | active-player list scan and numeric ID comparison |
| `TClient_getDeletedPlayerByID_int` | `0x1e7794` | `0x1ebb1c` | deleted-player list scan and numeric ID comparison |
| `TClient_findDownloadFile_TString_const` | `0x1e8150` | `0x1ec56c` | case-insensitive download-file list scan |

The first two functions scan their respective lists from index zero and return
the matching object or null. The download lookup follows the same pattern and
uses the target's case-insensitive TString comparison helper. All three source
and target functions have six basic blocks with matching instruction counts.

The artifact is
`artifacts/spectron_lookup_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_lookup_helper_anchors.py`. All three names
were applied to a copy of v14 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v15.i64`. The database SHA-256 is
`d2cf2b3cdf701fcd0afc29a0f919b4db15f351f9dc9e4fe8ccb217702c56e40c`.

## 2026-08-26: Spectron connection and SSL helper anchors

The v16 pass focused on the connection object and its SSL-facing helpers. The
source and target bodies line up exactly at the local pseudocode level for
cleanup, configuration propagation, error state, and compact field accessors.

The 18 reviewed rows are:

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGraalConnection_clearEncryptionKeyIn_void` | `0x1fc200` | `0x201b34` | incoming RC4 or AES key cleanup |
| `TGraalConnection_clearEncryptionKeyOut_void` | `0x1fc24c` | `0x201b80` | outgoing RC4 or AES key cleanup |
| `TGraalConnection_clearOutList_void` | `0x1fc298` | `0x201bcc` | clear and delete outgoing strings |
| `TGraalConnection_TGraalConnection__2` | `0x1fc3cc` | `0x201d00` | destructor and delete wrapper |
| `TGraalConnection_setEncryptionParseKey_TString_const` | `0x1fcd50` | `0x202684` | parser-key field assignment |
| `TGraalConnection_printSocketError_void` | `0x1fce4c` | `0x202780` | socket-error byte setter |
| `TGraalConnection_isblocked_void` | `0x1fea58` | `0x2043ac` | shifted outgoing queue limit |
| `TGraalConnection_setEnableSSL_bool` | `0x1fea70` | `0x2043c4` | SSL flag and socket propagation |
| `TGraalConnection_setSSLCipherList_TString_const` | `0x1fea98` | `0x2043ec` | cipher-list field propagation |
| `TGraalConnection_setSSLProtocol_TString_const` | `0x1feae8` | `0x20443c` | protocol field propagation |
| `TGraalConnection_getSSLError_void` | `0x1feb80` | `0x2044d4` | socket error or -1 fallback |
| `TGraalConnection_getByte228` | `0x1fec48` | `0x204598` | byte read at 228 |
| `TGraalConnection_setByte228` | `0x1fec50` | `0x2045a0` | byte write at 228 |
| `TGraalConnection_getDword304` | `0x1fec58` | `0x2045a8` | dword read at 304 |
| `TGraalConnection_getByte240` | `0x1fec60` | `0x2045b0` | byte read at 240 |
| `TGraalConnection_getDouble312` | `0x1fec68` | `0x2045b8` | double read at 312 |
| `TGraalConnection_getDword176` | `0x1fec70` | `0x2045c0` | dword read at 176 |
| `TGraalConnection_getDword244` | `0x1fec78` | `0x2045c8` | dword read at 244 |

The most relevant finding for the SSL hypothesis is that the target keeps the
same separation of concerns as 1.8. `setEnableSSL` changes the connection flag
and forwards it to the socket. The cipher and protocol setters copy their
strings to the live socket. `getSSLError` returns the socket error field or
`-1` when no socket exists. These helpers do not, by themselves, show a new
certificate-verification failure.

The artifact is
`artifacts/spectron_connection_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_connection_helper_anchors.py`. All 18
names were applied to a copy of v15 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v16.i64`. The database SHA-256 is
`bf60436ef5fd788c72b8151b5d7eb60a5a12a0e727932df0db4fb7c315afdf0b`.

## 2026-08-26: Spectron compact client-state helper anchors

The v17 pass reviewed seven compact forwarding and state helpers that were
left as default names after the connection pass.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_callVirtual320` | `0x1e9560` | `0x1eda20` | vtable-320 forwarding |
| `TClient_setServerOptionsRaw` | `0x1e95a0` | `0x1eda60` | server-options assignment |
| `TClient_enableGraal2002ServerMode` | `0x1e95b0` | `0x1eda70` | Graal 2002 mode flag |
| `TClient_setTimeVarRaw` | `0x1e95c4` | `0x1eda84` | time-variable assignment |
| `TClient_setPlayerStateFlag1680` | `0x1e9678` | `0x1edb38` | active-player state byte |
| `TClient_setGhostModeValue` | `0x1e9694` | `0x1edb54` | ghost-mode assignment |
| `TClient_setPlayerStateFlag2328` | `0x1e96a4` | `0x1edb64` | active-player bool state byte |

Each source and target body has the same size, instruction count, and
basic-block count. The target functions are the corresponding compact run
between the preserved state setters and event helpers. The first four are
forwarding or direct static writes. The final three preserve active-player
checks and state-byte behavior.

The artifact is
`artifacts/spectron_client_state_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_state_helper_anchors.py`. All
seven names were applied to a copy of v16 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v17.i64`. The database SHA-256 is
`acb84b3675ece2e5e040ac2eb16b3a15cec4607ecf8b3c5741115074d2954197`.

## 2026-08-26: Spectron client connection-state helper anchors

The v18 pass reviewed five compact helpers that connect client state to the
connection and encrypted-file paths.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_getConnectionString8288` | `0x1e9918` | `0x1ede80` | connection field offset 8288 |
| `TClient_getConnectionString8296` | `0x1e9968` | `0x1eded0` | connection field offset 8296 |
| `TClient_getConnectionString8304` | `0x1e99b8` | `0x1edf20` | connection field offset 8304 |
| `TClient_setEncodedFileKeyAndContinue` | `0x1eafe0` | `0x1ef648` | encoded-key forwarding and continuation |
| `TClient_saveServerLevelEncrypted` | `0x1e9e9c` | `0x1ee404` | guarded encrypted level save |

The first three helpers read the connection pointer from client offset 256,
return an empty TString when it is absent, and copy fields at offsets 8288,
8296, and 8304. Their source and target bodies have identical size,
instruction, block, mnemonic, register, and control-flow hashes. The
encoded-file helper forwards four arguments to the resource key setter before
continuing the download action. The server-level helper keeps the null check
and encrypted-save call.

The artifact is
`artifacts/spectron_connection_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_connection_state_anchors.py`. All five
names were applied to a copy of v17 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v18.i64`. The database SHA-256 is
`c724dfd0fc8bf61ccf0d9b58742bff9a035af022b7a70a2a8f8bd8f73189f7d2`.

## 2026-08-26: Spectron HTTP request helper anchors

The v19 pass reviewed 12 helpers in the request-object region.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THTTPRequest_getStringField200` | `0x1ff04c` | `0x20499c` | request field offset 200 |
| `THTTPRequest_getStringField256` | `0x1ff07c` | `0x2049cc` | request field offset 256 |
| `THTTPRequest_getStringField248` | `0x1ff0ac` | `0x2049fc` | request field offset 248 |
| `THTTPRequest_getStringField280` | `0x1ff0dc` | `0x204a2c` | request field offset 280 |
| `THTTPRequest_getStringField264` | `0x1ff10c` | `0x204a5c` | request field offset 264 |
| `THTTPRequest_getStringField216` | `0x1ff13c` | `0x204a8c` | request field offset 216 |
| `THTTPRequest_getStringField184` | `0x1ff1a0` | `0x204af0` | request field offset 184 |
| `THTTPRequest_getStringField296` | `0x1ff1d0` | `0x204b20` | request field offset 296 |
| `THTTPRequest_getStringField288` | `0x1ff200` | `0x204b50` | request field offset 288 |
| `THTTPRequest_getStringField168` | `0x1ff230` | `0x204b80` | request field offset 168 |
| `THTTPRequest_THTTPRequest__2` | `0x1ffd20` | `0x205668` | deleting destructor |
| `THTTPRequest_sendOutgoing_void` | `0x1ffd6c` | `0x2056b4` | outbound buffer send |

The ten accessor pairs preserve the same direct field offsets and identical
normalized body hashes. The destructor preserves request destruction followed
by `operator delete`. The outbound helper preserves socket error checking,
queued-data sending, and removal of successfully written bytes. The offset-256
row corroborates the earlier medium-confidence semantic match using the
contiguous request-object sequence.

The artifact is
`artifacts/spectron_http_request_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_http_request_anchors.py`. All 12 names
were applied to a copy of v18 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v19.i64`. The database SHA-256 is
`ecd0b6db4a8147fa3771cd02d283b022ddd959cdac17c22301e56b472efeb365`.

## 2026-08-26: Spectron socket-state helper anchors

The v20 pass reviewed five compact socket helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TSocketConnection_hasError_void` | `0x2062b8` | `0x20c404` | socket status error predicate |
| `TSocketConnection_closeForSubProcesses_void` | `0x2062cc` | `0x20c418` | empty subprocess-close hook |
| `TSocketConnection_setNonBlocking_void` | `0x206320` | `0x20c46c` | fcntl nonblocking setup |
| `TSocketConnection_getIPNum_void` | `0x206330` | `0x20c47c` | numeric IP field at offset 8 |
| `TSocketConnection_getIP_void` | `0x2070f4` | `0x20d234` | formatted IP helper |

The source and target bodies have identical size, instruction, block,
mnemonic, register, and control-flow hashes. They preserve the socket status
predicate, empty subprocess hook, `fcntl` setup, and the two address helpers.
The formatted-IP row corroborates the earlier medium-confidence semantic
match using the surrounding socket sequence.

The artifact is
`artifacts/spectron_socket_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_socket_state_anchors.py`. All five names
were applied to a copy of v19 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v20.i64`. The database SHA-256 is
`6d01c2d7fedfef870e19119d6e9bb302ac88012a80072a9cfe135d312d08c96e`.

## 2026-08-26: Spectron changed socket behavior

The changed-size socket functions were compared directly rather than forced
into the exact-match anchor set.

| 1.8 function | Source | Spectron target | 1.8 size | 2.2 size |
| --- | ---: | ---: | ---: | ---: |
| `TSocketConnection_enableSSLOnSocket_void` | `0x206450` | `0x20c59c` | 868 bytes | 792 bytes |
| `TSocketConnection_connectSocket_TString_const_int` | `0x206bd8` | `0x20ccd8` | 564 bytes | 628 bytes |
| `TSocketConnection_read_void` | `0x2074d4` | `0x20d614` | 916 bytes | 928 bytes |

The decompiled SSL setup preserves the verify-buffer load, conditional
verification mode, cipher-list application, optional domain check,
nonblocking TLS setting, and `CyaSSL_connect` call. The connect function
preserves socket creation, hostname resolution, status four and five
transitions, EINTR handling, and delayed SSL setup. The read function
preserves plain, UDP, and CyaSSL receive handling, transient-error treatment,
TLS error recording, and close decisions. The main observed 2.2 changes are
renamed helpers, extra diagnostics, and different code shape.

The artifact is
`artifacts/spectron_socket_behavior_comparison_20260826.json`, generated by
`tools/generate_spectron_socket_behavior_comparison.py`. It records three
changed-size pairs and zero exact-shape matches. This does not prove current
live service compatibility.

## 2026-08-26: Spectron image, folder, and JSON callback anchors

The v30 pass reviewed eight compact helpers that the broad matcher could not
assign safely. The GIF and JPEG stream callbacks are exact normalized matches.
The folder helper and four YAJL callbacks changed size, so their assignments
use caller relationships, class behavior, and the callback table at
`0x39af70`.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TBitmap_GIF_streamRead` | `0x150a30` | `0x153570` | GIF stream forwarding |
| `TBitmap_JPEG_noopFlush` | `0x150ea0` | `0x153cc8` | JFFLUSH callback |
| `TBitmap_JPEG_noopError` | `0x150ea8` | `0x153cd0` | JFERROR callback |
| `TGraalVar_loadFolderRecursive` | `0x213088` | `0x219978` | recursive folder loader |
| `TGraalVar_jsonStringCallback` | `0x22dab4` | `0x237598` | YAJL string callback |
| `TGraalVar_jsonNumberCallback` | `0x22dbbc` | `0x23770c` | YAJL number callback |
| `TGraalVar_jsonStartArrayCallback` | `0x22de60` | `0x237c78` | YAJL start-array callback |
| `TGraalVar_jsonStartMapCallback` | `0x22e12c` | `0x2379bc` | YAJL start-map callback |

The folder helper retains child creation, `filesize` and `isfolder` property
writes, recursive descent, and the 9999-entry guard. The JSON callbacks retain
scalar writes, numeric conversion, context markers, and object or array node
creation. The target's image routines install the three callback targets in
the same libgif and libjpeg roles as the source.

The artifact is
`artifacts/spectron_json_folder_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_json_folder_anchors.py`. All eight names
were applied to a copy of v29 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v30.i64`. The database SHA-256 is
`f8ed0df56c8d17c244ce56751f4ec1c2e4a50d236b5fce5d3e060e46255fdb45`.

The generated animation fatal helper was not assigned in this batch. The
Spectron scanner does not retain the old separate function with its original
`exit(2)` behavior, so labeling the nearby `exit(0)` routine would overstate
the evidence.

## 2026-08-26: Spectron resource-object anchors

The v31 pass reviewed 11 resource functions that were still unmatched after
the broad feature map. This group includes the resource insertion path, the
resource filename comparator, the two link classes, encoded-file keys,
resource-object construction, and the size, alternative, stream, and
loadability methods.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TResourceFunctions_insertResourceObject_TResourceObject` | `0xed260` | `0xee230` | resource insertion and alternative selection |
| `resourceobjects_filenamecompare_void_const_void_const` | `0xef030` | `0xf0244` | extension, filename, and modification-time comparator |
| `TResourceFileLink_TResourceFileLink_TString_const` | `0xef184` | `0xf03ec` | filename normalization and global registration |
| `TResourceFileLink_invokeUpdate_TString_const` | `0xef270` | `0xf04f4` | reverse virtual update walk |
| `TResourceObjectLink_TResourceObjectLink_void` | `0xef428` | `0xf06d8` | pointer-keyed link registration |
| `TEncodedFileKey_TEncodedFileKey_TString_const` | `0xef5a0` | `0xf086c` | key, length sentinel, and active flag |
| `TResourceObject_TResourceObject_TString_const` | `0xef610` | `0xf0904` | base and extended metadata initialization |
| `TResourceObject_getSize_void` | `0xef7ec` | `0xf0b08` | cached size or filesystem fallback |
| `TResourceObject_addAlternative_TResourceObject` | `0xefbc4` | `0xf0f1c` | preference, exchange, and modtime sort |
| `TResourceObject_getStream_void` | `0xefe7c` | `0xf11f0` | cache, zip, `.gani`, and encrypted paths |
| `TResourceObject_canBeLoaded_void` | `0xf03a0` | `0xf1860` | remote download readiness |

The strongest evidence is the repeated class-local sequence. The target
resource insertion helper uses the same hash lookup and alternative decision
as the source. The comparator is passed to the target resource matcher and
retains the source's extension, filename, and modification-time ordering. The
two link constructors still allocate and register their child lists. The
resource object methods retain the same cached-size, alternative-selection,
zip-reading, `.gani` decryption, encoded-resource decryption, and download
state behavior. The target wrappers changed sizes, so the labels are semantic
correspondences rather than exact normalized matches.

All 11 labels were applied to a copy of v30 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v33.i64`. The database SHA-256 is
`69323a7d78797eaa916e13489ba56e3836c6c9c90c1b15ec6cc2589ae828afba`. The
artifact is
`artifacts/spectron_resource_object_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_resource_object_anchors.py`.

The no-argument constructors and destructor families remain review-only.
Several of those bodies are folded or identical across classes, so assigning
them by address alone would make the documentation less reliable.

## 2026-08-26: Spectron GS2 script-machine anchors

The v34 pass reviewed seven functions in the GS2 execution machine. The
target class is obfuscated, but its local order and signatures make this a
useful comparison point for the stripped 2.2 build.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_TScriptMachine` destructor | `0x21886c` | `0x21ff78` | destructor cleanup sequence and D1/D2 signature |
| `TScriptMachine_TScriptMachine_void` | `0x218a3c` | `0x220150` | constructor field initialization |
| `TScriptMachine_setExecutingObject_TGraalVar_TString_const_TScriptMachine` | `0x218b8c` | `0x2202a4` | script-name, executing-object, and parent state |
| `TScriptMachine_resolveObjectMember_TGraalVar_TString_const_TScriptProperty_TGraalVar_bool` | `0x218e98` | `0x2205c4` | alias and property lookup paths |
| `TScriptMachine_assign_void` | `0x21a3b0` | `0x221ef8` | typed assignment dispatch |
| `TScriptMachine_compare_void` | `0x21a6a8` | `0x222218` | value-type comparison dispatch |
| `TScriptMachine_compareFloat_double` | `0x21a8b0` | `0x2224e0` | string conversion and tolerance comparison |

The source destructor is represented by an alternative D2 name in IDA. The
target function carries the matching D1/D2 compiler-generated destructor
family. Both bodies clear the call stack and machine-owned lists, decrement
the live-machine count, and clear string state. The target constructor makes
the same stack, list, and parameter setup. The short executing-object helper
copies the script name, stores the active variable, and records the parent
machine.

The resolver is the strongest behavioral anchor in this group. Both bodies
handle `temp`, `params`, `this`, `thiso`, `player`, `playero`, `level`, `join`,
`leave`, `serverr`, `client`, and `clientr`, then walk object properties,
variables, class and event objects, and fallback state. The assignment helper
keeps string, float, integer, and object writes. The comparison helpers keep
the same string, numeric, and object-backed branches, including the float
tolerance and three-way result. The target bodies are larger where its string
wrappers materialize temporary objects, so these are semantic correspondences
rather than byte-identical matches.

All seven labels were applied to a copy of v33 and reopened with zero
failures in `analysis/spectron_libqplay_translated_v34.i64`. The database
SHA-256 is
`b082b63ff1be3ab1f1d029093b0a7907a62daaea6a136da406e6cb4c15ee2e49`. The
machine-readable evidence is in
`artifacts/spectron_script_machine_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_machine_anchors.py`.

## 2026-08-26: Spectron TScriptSpace event anchors

The v35 pass reviewed eight event and timeout methods that remained unmatched
after the broad map. The target class is the obfuscated `N67CMatrxw` class
identified by the earlier timeout and event-predicate anchors.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_freeScriptErrors_void` | `0x2274d0` | `0x230214` | script-error list cleanup |
| `TScriptSpace_addScriptError_TString_const` | `0x227558` | `0x23029c` | same empty hook and local order |
| `TScriptSpace_catchEvent_TString_const_TString_const_TString_const` | `0x22755c` | `0x2302a0` | universe lookup and catcher registration |
| `TScriptSpace_catchEvent_TGraalVar_TString_const_TString_const` | `0x2277e4` | `0x230570` | object event-space registration |
| `TScriptSpace_leaveClass_TScript` | `0x227ee8` | `0x230cdc` | leave callback and class removal |
| `TScriptSpace_checkLeaveClasses_void` | `0x2280ac` | `0x230eac` | pending class leave loop |
| `TScriptSpace_getEventState_TString_const_TString_const_bool` | `0x22835c` | `0x231180` | normalized event-state lookup |
| `TScriptSpace_setTimeout_double` | `0x228510` | `0x231410` | timeout reset and activation |

The first two rows are exact small-body matches. `freeScriptErrors` releases
the list at offset 112 and writes null back to that field, while
`addScriptError` remains an empty hook with one string argument. The two event
registration methods preserve the object lookup, client-depth rule, lazy
creation of event space, catcher registration, and one-time tracking of
unknown or non-local event objects. The target class has changed string and
hash wrappers, so the registration bodies are larger than the source, but the
operations are still explicit in pseudocode.

The leave methods preserve the iterator over class event objects, the
`onInitFrame` exception, the event leave callback, active-class removal, and
pending-list cleanup. The event-state helper preserves `istimeout` mapping to
`timeout`, lowercasing, `on` prefix removal, current-object fallback, and
optional deletion of the matched state. The timeout setter preserves the
non-positive reset, lookup and destruction of the existing state, universe
pointer update, and positive timer activation. These are semantic anchors
supported by class-local order and decompiled behavior, not restored original
debug symbols.

All eight labels were applied to a copy of v34 and reopened with zero
failures in `analysis/spectron_libqplay_translated_v35.i64`. The database
SHA-256 is
`a019e59e27e5e5b3a3e561d4708cdadb3b2c0e8c747b05b22edff749d2eb4a34`. The
machine-readable evidence is in
`artifacts/spectron_script_space_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_space_anchors.py`.

## 2026-08-26: Spectron GS2 execution anchors

The v36 pass reviewed six execution helpers in `N67CMatrxw`. This group
connects the already anchored script machine and script space to the action
and function dispatch paths that actually run GS2 code.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_executeFunction_TScriptFunction_TGraalVar_bool_TScriptMachine` | `0x22871c` | `0x23168c` | machine acquisition, execution, and return handling |
| `TScriptSpace_executeActionSelfCatch_TString_const_TScriptAction` | `0x228930` | `0x231880` | event-name normalization and self-catch |
| `TScriptSpace_executeActionNamedObject_TScriptAction` | `0x228ce8` | `0x231c3c` | function scans and shared executor |
| `TScriptSpace_executeActionCatch_TGraalVar_TScriptAction` | `0x228eb0` | `0x231e14` | caught-object link argument |
| `TScriptSpace_checkCallerSuspenseWakeUp_TGraalVar_TString_const_double_int` | `0x228f6c` | `0x231f14` | saved-state and event-state wake-up |
| `TScriptSpace_freeActions_void` | `0x22981c` | `0x232944` | action-object cleanup |

The function executor preserves the free-machine slot at universe offset 176,
the executing-object setup, function preparation, argument push, execution
status handling, return-value extraction, machine restoration, and free-list
return. The target's helper names are opaque, but the call sequence matches
the source one operation at a time.

The self-catch helper keeps the `on` prefix handling, the created or
initialized event exclusion list, the direct event-function path, the
multi-function path, and the fallback property lookup. The named-object
helper scans the current script and then joined classes for matching action
and function names. The caught-action helper resolves the catcher, creates a
link variable for the caught object, and invokes the same executor. The
suspended-caller helper preserves both the existing saved-state update and
the object event-state wake-up path, including stack-value copying. Finally,
the action cleanup helper destroys each action and clears its list exactly as
in the source.

All six labels were applied to a copy of v35 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v36.i64`. The database SHA-256 is
`03b2888be2ce9c992a5849126d856d94a7d010f882c095c9b26275f3e65f875f`. The
machine-readable evidence is in
`artifacts/spectron_script_execution_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_execution_anchors.py`.

## 2026-08-26: Spectron top-level GS2 dispatch anchors

The v37 pass reviewed the three large dispatch bodies that remained unmatched
after the smaller execution helpers. They sit in the same `N67CMatrxw` class
sequence and call the previously anchored script machine, event-state, and
action helpers.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_executeScript_TString_const_TString_const_TGraalVar` | `0x22919c` | `0x232160` | event-state execution and free-machine return |
| `TScriptSpace_executeAction_TScriptAction` | `0x2294e8` | `0x232520` | action target selection and routing |
| `TScriptSpace_receiveEvent_TString_const_TString_const_TGraalVar` | `0x229898` | `0x2329c0` | event queue policy and action creation |

The script execution entry preserves the two entry paths: an existing saved
event state or the current script's main function. It borrows the universe
machine, prepares the function or state, supplies NPC comma-text arguments,
executes the machine, handles the suspended and updated-script paths, wakes a
caller when necessary, and returns the machine to the free list.

The action dispatcher preserves target-object lookup, the executing-NPC
player-id update, event-state routing, self-caught actions, caught actions,
named-object actions, whole-script and function-event decisions, fallback
script execution, and class-leave checks. The receive path preserves the
inactive-object check, event-count limit, onAllRCChat exception, overrun error,
onshow and onhide duplicate handling, action construction, priority insertion
for timeout, created, and initialized events, and script activation.

All three labels were applied to a copy of v36 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v37.i64`. The database SHA-256 is
`47366d1d75b2b6cf117a605950d7f7d326b9279338cf56374277d50a555e4cd7`. The
machine-readable evidence is in
`artifacts/spectron_script_dispatch_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_dispatch_anchors.py`.

## 2026-08-26: Spectron GS2 scheduler and cleanup anchors

The v38 pass reviewed six scheduler and event-cleanup methods in the
`N67CMatrxw` class. This fills the gap between the incoming event queue and
the class and object cleanup paths.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_cancelEvents_TString_const` | `0x22a204` | `0x233a68` | scheduled-event deletion and cancel flags |
| `TScriptSpace_checkScheduledEvents_void` | `0x22a354` | `0x233bf0` | timeout, delayed events, and repeats |
| `TScriptSpace_runScript_void` | `0x22a5e0` | `0x233ed8` | class update, action loop, and context restore |
| `TScriptSpace_unlinkEventObject_void` | `0x22ac2c` | `0x234554` | catcher removal and ownership test |
| `TScriptSpace_ignoreEvents_TString_const` | `0x22ada8` | `0x2346f4` | catcher and name-list removal |
| `TScriptSpace_setClasses_TString_const` | `0x22b07c` | `0x234a34` | class replacement and catcher reinstall |

The scheduler comparison shows the same timeout subtraction against universe
time, timeout event insertion, scheduled-event iteration, dead-object unlink,
repeat interval update, and delayed state queueing. The target uses the
already anchored `receiveEvent` helper with the same event and object roles.

The script loop preserves download waiting and the onClassesDownloaded event,
the executing player and NPC assignments, optional execution profiling,
action iteration, error-state termination, action cleanup, and restoration of
the global context. The target's renamed helpers still line up with the
previously anchored `executeAction` and `freeActions` methods.

The unlink and ignore helpers retain global event-object ownership checks,
unknown-object handling, catcher removal, and local tracking-list updates.
The class setter leaves old classes, initializes the empty base script when
needed, joins the comma-separated class list, reinstalls event catchers, and
triggers the class-update action. These target bodies changed size, but their
behavior is visible directly in pseudocode.

All six labels were applied to a copy of v37 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v38.i64`. The database SHA-256 is
`a6981e19c2ac9e3862a21285f2b23eafec6eb21693fa72f3bed922f6544072f7`. The
machine-readable evidence is in
`artifacts/spectron_script_scheduler_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_scheduler_anchors.py`.

## 2026-08-26: Spectron event-object and catcher-list anchors

The v39 pass reviewed six event-object and catcher-list methods below the
already anchored `TScriptSpace` event helpers. The Spectron target uses
`pWihMaQxae` for the event object and `SEPCMa33gw` for the catcher list.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TEventObject_TEventObject__2` | `0x226cac` | `0x22f960` | ABI deleting destructor |
| `TEventObject_TEventObject_TString_const` | `0x226ce8` | `0x22f9a0` | event name and owned catcher storage |
| `TEventObject_addEventCatcher_TString_const_TGraalVar_TString_const` | `0x226f74` | `0x22fc6c` | lookup, lowercase creation, and insertion |
| `TEventCatcherList_TEventCatcherList_TString_const_TString_const` | `0x226df4` | `0x22facc` | list names and entry storage |
| `TEventCatcherList_TEventCatcherList__2` | `0x22a9dc` | `0x234304` | ABI deleting destructor |
| `TEventCatcherList_receiveEvent_TGraalVar` | `0x22af4c` | `0x2348bc` | linked-object callback loop |

The two D0 rows are exact normalized matches. They call their complete
destructors and then `operator delete`, and both retain the 32-byte,
eight-instruction, two-block wrapper shape. The constructors preserve their
class-local state setup. The event object copies its event name and allocates
the catcher storage. The catcher list stores its event and catching-function
names and initializes its entries. The changed target sizes are consistent
with the larger 2.2 wrappers.

The registration method retains the event hash lookup, lowercase key creation,
catcher-list construction, and insertion order. The receive method walks the
catchers, dispatches the supplied variable through each linked event object,
and removes dead entries. The target is larger, but the loop and ownership
decisions remain visible in pseudocode and align with the source class layout.

All six labels were applied to a copy of v38 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v39.i64`. The database SHA-256 is
`2a15e694bf0935c07ef45869388dcff311b61d5cef8e850ddd379e040ff2b016`. The
machine-readable evidence is in
`artifacts/spectron_event_object_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_event_object_anchors.py`.

## 2026-08-26: Spectron GS2 script-action anchors

The v40 pass reviewed the two `TScriptAction` lifecycle methods. The obfuscated
target class is `FOb5fbmyZ8`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptAction_TScriptAction_TString_const_TString_const_TGraalVar` | `0x227164` | `0x22fe78` | prefix normalization, event index, and argument clone |
| `TScriptAction_TScriptAction` | `0x2272e8` | `0x230024` | D2 destructor and ordered cleanup |

The constructor preserves the `player:` prefix branch, event and function
names, event-index lookup, optional variable clone, and status bytes. The
target keeps the 14-block shape and grows from 388 to 428 bytes around the
changed wrappers. IDA's alternative name identifies the second row as the
complete D2 destructor. It releases the cloned variable and clears all three
owned strings in source order.

Both labels were applied to a copy of v39 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v40.i64`. The database SHA-256 is
`6772706f004620089eb4def0d79bdebc77ce821e1340f92e798f7b0c1292d45d`. The
machine-readable evidence is in
`artifacts/spectron_script_action_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_action_anchors.py`.

## 2026-08-26: Spectron GS2 stack-entry conversion anchors

The v41 pass reviewed three `TScriptStackEntry` conversion methods in the
obfuscated `ToQnQaIHFG` class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptStackEntry_switchTypeFloat_TScriptMachine_bool` | `0x2199bc` | `0x22141c` | numeric conversion and property fallback |
| `TScriptStackEntry_switchTypeString_TScriptMachine_bool` | `0x219a54` | `0x2214dc` | float formatting and string read |
| `TScriptStackEntry_switchTypeObject_TScriptMachine_bool` | `0x219b80` | `0x221630` | object read and quoted text special case |

The float method preserves string parsing, the float fast path, property
materialization, missing-source zero, and type-one storage. The string method
preserves the near-zero formatting threshold, property or variable reads,
missing-source clearing, and type-two storage. The object method preserves
property materialization, quoted comma-text handling, variable object reads,
and type-three storage. Their changed sizes are consistent with the larger
2.2 wrappers, while the class-local order and helper calls remain intact.

All three labels were applied to a copy of v40 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v41.i64`. The database SHA-256 is
`b9527ad01e544f2a3e9afdd4defb46bfb625465f2581b86bfda7e7084ed41914`. The
machine-readable evidence is in
`artifacts/spectron_stack_entry_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_stack_entry_anchors.py`.

## 2026-08-26: Spectron GS2 machine-helper anchors

The v42 pass reviewed four small helpers in the obfuscated `mTAogaaEip`
machine class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_restoreExecutionVariables_void` | `0x218bd0` | `0x2202fc` | saved execution field reset |
| `TScriptMachine_charAt_void` | `0x21ca00` | `0x224af0` | input-indexed character result |
| `TScriptMachine_findActionPlayer_void` | `0x21df18` | `0x2261fc` | reverse server-player cast |
| `TScriptMachine_findActionNPC_void` | `0x21dfc0` | `0x2262a4` | reverse server-NPC cast |

The restoration helper is an exact two-instruction match with the expected
machine-field offset change. `charAt` retains input consumption, integer
indexing, bounds checks, and single-character output. The player and NPC
helpers retain reverse action-list scans, their distinct dynamic casts, and
the corresponding global action-context assignments. Both lookup bodies also
retain the exact normalized hashes.

All four labels were applied to a copy of v41 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v42.i64`. The database SHA-256 is
`ade60a5719a41f9769ddd33fd539031cf69dbc31c49feee70bc48557c9e6e46d`. The
machine-readable evidence is in
`artifacts/spectron_machine_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_machine_helper_anchors.py`.

## 2026-08-26: Spectron GS2 array mutation anchors

The v43 pass reviewed three array-writing methods in `TScriptMachine`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_setArrayCell_void` | `0x21c4d8` | `0x224560` | typed cell write and stack unwind |
| `TScriptMachine_setArrayCell2_void` | `0x21c7c0` | `0x224868` | nested index and typed write |
| `TScriptMachine_arrayReplace_void` | `0x21cd88` | `0x224e78` | replacement index and branch policy |

The three methods retain index normalization, property resolution, typed
float/string/object setters, and stack cleanup. The two-dimensional method
also retains nested-array resolution and the quoted string special case.
`arrayReplace` preserves the replacement index behavior and its out-of-range
branch. The target bodies grew around the changed wrappers, while their
setter order and control flow remain recognizable in pseudocode.

All three labels were applied to a copy of v42 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v43.i64`. The database SHA-256 is
`28c062661c587455a8177ffbbd2f3cb9715223db80e3ddee953729e29568f8d2`. The
machine-readable evidence is in
`artifacts/spectron_array_mutation_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_array_mutation_anchors.py`.

## 2026-08-26: Spectron GS2 string-search anchors

The v44 pass reviewed two search methods in the obfuscated `mTAogaaEip`
`TScriptMachine` class. Both targets were absent from the semantic map and
were selected from the corresponding local method sequence.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_indicesOf_void` | `0x21d2a4` | `0x2253b4` | all matching array indices |
| `TScriptMachine_getPositions_void` | `0x21d4b8` | `0x225600` | substring position array |

The `indicesOf` pair shares result-array construction, input-array and search
value resolution, float/string/object comparisons, per-match index appends, and
the same 26-block loop. The source body is 520 bytes and the target is 580
bytes, with the extra size concentrated around the changed string wrappers.
The `getPositions` pair shares source and search string resolution, length
validation, a `memcmp` scan at each candidate offset, and result-array appends.
Those bodies are 276 and 388 bytes respectively, again with changed string
wrappers accounting for the growth.

Both labels were applied to a copy of v43 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v44.i64`. The database SHA-256 is
`a8be3d80ea5f1adb780d714ca960ec88891bd65b2c2d828414a2c096de29b276`. The
machine-readable evidence is in
`artifacts/spectron_string_search_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_string_search_anchors.py`.

## 2026-08-26: Spectron GS2 string-stack helper anchors

The v45 pass reviewed the three string helpers immediately following the
search methods in the obfuscated `mTAogaaEip` machine class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_getNextString_void` | `0x21d698` | `0x225850` | next string stack entry |
| `TScriptMachine_getIndexedString_int` | `0x21d718` | `0x225934` | indexed string stack entry |
| `TScriptMachine_formatString_void` | `0x21d76c` | `0x22599c` | format string stack operation |

`getNextString` preserves stack exhaustion handling, string conversion, the
empty-string fallback, pointer advancement, and count decrement. `getIndexedString`
keeps negative-index rejection, input-count arithmetic, list selection, and
delegation to `getNextString`. `formatString` retains the backward formatter
boundary scan, current-value conversion, formatter parameter object, cleanup
path, and type-two result assignment. Body sizes grow from 128 to 228, 84 to
104, and 320 to 460 bytes as the 2.2 wrappers changed.

All three labels were applied to a copy of v44 and reopened with zero failures
in `analysis/spectron_libqplay_translated_v45.i64`. The database SHA-256 is
`23e333de1f861ee226bd87daaba81c9d9fd1558adc48e278b59bca9d3f912319`. The
machine-readable evidence is in
`artifacts/spectron_string_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_string_helper_anchors.py`.

## 2026-08-26: Spectron GS2 variable-construction anchors

The v46 pass reviewed two variable-construction methods in the obfuscated
`mTAogaaEip` machine class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_makeVar_void` | `0x21db30` | `0x225dec` | script variable construction |
| `TScriptMachine_makeOldScriptVar_TString_const_bool` | `0x21dbc8` | `0x225ea4` | legacy script variable path resolution |

`makeVar` retains the current-entry read, variable/member split, type-four
member result, type-three object result, and temporary-string cleanup. The
legacy helper retains dotted-name scanning, all eight special roots, optional
universe lookup, action-player fallback, resolved-object table lookup, virtual
fallback, and cleanup. Its source and target both have 52 basic blocks, with
the body changing only from 848 to 856 bytes. The shorter helper keeps seven
blocks while growing from 152 to 184 bytes.

Both labels were applied to a copy of v45 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v46.i64`. The database SHA-256 is
`8afd65b7124587981a6757cb8fb5b245860df1647ef87b80384722d67cdc81bb`. The
machine-readable evidence is in
`artifacts/spectron_variable_construction_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_variable_construction_anchors.py`.

## 2026-08-26: Spectron GS2 script diagnostic and object anchors

The v47 pass reviewed the diagnostic and object-creation methods following the
variable-construction helpers in the obfuscated `mTAogaaEip` machine class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_getScriptLineMsg2_TScriptFunction_int` | `0x21e0fc` | `0x2263e0` | script function line diagnostic |
| `TScriptMachine_createObject_void` | `0x21e2e4` | `0x226684` | script object creation and registration |

The diagnostic helper retains line validation, `at line`, `in function`, and
`of` formatting, plus its output cleanup. The object creator retains creator
lookup, construction, special-object filtering, universe registration,
inheritance copying, replacement-reference updates, and the unknown-type error
path. The diagnostic body grows from 444 to 632 bytes with 21 to 24 basic
blocks. The creator grows from 1164 to 1340 bytes with 53 to 61 blocks.

Both labels were applied to a copy of v46 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v47.i64`. The database SHA-256 is
`42edc7d90f88906b11ed4949fbaae28e964c9be32093dbe4cf3e4fd7d17f8f3a`. The
machine-readable evidence is in
`artifacts/spectron_script_object_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_object_anchors.py`.

## 2026-08-26: Spectron GS2 script-state anchors

The v48 pass reviewed the profiling and player-flag methods following the
script diagnostic and object helpers in the obfuscated `mTAogaaEip` class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_addTopCallStackProfileTime_TScript` | `0x21ea64` | `0x226eb4` | top call-stack profile timing |
| `TScriptMachine_setPlayerFlagValue_TString_const_bool` | `0x21f03c` | `0x2274a8` | player flag value update |

The profiling helper retains its gate, timing-field accumulation, call-stack
name join, profiler callback, and cleanup. The player-flag helper retains
`name=value` splitting, boolean coercion, root reset, legacy player-variable
resolution, and no-send writes for zero, one, or arbitrary strings. The first
pair keeps 12 basic blocks while growing from 304 to 332 bytes. The second
grows from 720 to 728 bytes and from 25 to 26 blocks.

Both labels were applied to a copy of v47 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v48.i64`. The database SHA-256 is
`b8042ef8157620ff8e9acd00a875503a5e4e0255ae7ea5cfdae15b04f81c6801`. The
machine-readable evidence is in
`artifacts/spectron_script_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_state_anchors.py`.

## 2026-08-26: Spectron GS2 execution-dispatch anchors

The v49 pass reviewed the large script-call and function-dispatch methods
following the profiling and player-flag helpers in the obfuscated `mTAogaaEip`
class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_callScriptFunction_TGraalVar_TScriptFunction_int` | `0x21f80c` | `0x227c80` | script function call with object context |
| `TScriptMachine_functionCall_TString` | `0x21fd10` | `0x228164` | script and native function call dispatch |

The first helper retains call-stack overrun handling, argument-array creation,
script-space invocation, result capture, stack restoration, and suspended-state
recovery. The second retains callable lookup, direct and object-context paths,
download suspension, native-property calls, error reporting, and stack reset.
Their target sizes are 1252 and 1936 bytes versus 1284 and 1848 in 1.8, with
basic-block counts changing from 38 to 37 and from 79 to 78.

Both labels were applied to a copy of v48 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v49.i64`. The database SHA-256 is
`258a6f0fe2afc8da9eba5b080e326cde15d0abbc8c70a918f098caa44adeda1b`. The
machine-readable evidence is in
`artifacts/spectron_execution_dispatch_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_execution_dispatch_anchors.py`.

## 2026-08-26: Spectron GS2 tokenizer anchor

The v50 pass reviewed `TScriptMachine_tokenizeString_void`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_tokenizeString_void` | `0x220450` | `0x228900` | tokenized string array construction |

Both methods consume the current stack entry, tokenize its source with the
stored delimiter, use a type-three null result for zero tokens, and construct a
string-variable array for non-empty output. Both retain twelve basic blocks,
with body size changing from 404 to 440 bytes as wrappers changed.

The label was applied to a copy of v49 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v50.i64`. The database SHA-256 is
`3588a42c1687c12bf984df19af0c7e4d091df97174c7043785abb9a64c929e9b`. The
machine-readable evidence is in
`artifacts/spectron_tokenizer_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tokenizer_anchors.py`.

## 2026-08-26: Spectron GS2 script executor anchor

The v51 pass reviewed `TScriptMachine_executeScript_void`, the large bytecode
execution loop following the tokenizer method.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_executeScript_void` | `0x2205e4` | `0x228ab8` | script bytecode execution loop |

The source and target decompilations retain the same large opcode switch, the
three exact limit and timeout strings, calls into the reviewed dispatch and
helper methods, stack updates, loop-limit handling, and executor tail. The
source is 15,440 bytes with 892 blocks. The target is 15,688 bytes with 903
blocks. Its additional instructions are consistent with the changed wrappers
and obfuscated helper calls.

The label was applied to a copy of v50 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v51.i64`. The database SHA-256 is
`455a4e0bd55907163525dd3a91b3e7b718bd1b9737d19cbda39fd7c8b0271765`. The
machine-readable evidence is in
`artifacts/spectron_script_executor_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_executor_anchors.py`.

## 2026-08-26: Spectron GS2 script property anchors

The v52 pass reviewed the `TScriptProperty` layer that converts GS2 values to
native property accessors and builds the property and function tables.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptProperty_readString_TGraalVar` | `0x224ac0` | `0x22d168` | typed string conversion |
| `TScriptProperty_writeFloat_TGraalVar_double` | `0x224cc4` | `0x22d390` | typed float conversion and readonly path |
| `TScriptProperty_writeString_TGraalVar_TString_const` | `0x2251b0` | `0x22d8c0` | string parsing and typed writes |
| `TScriptProperty_writeObject_TGraalVar_TGraalVar` | `0x2255f4` | `0x22dd6c` | variable conversion and object forwarding |
| `TScriptProperty_TScriptProperty_TString_const_bool` | `0x225f68` | `0x22e86c` | property construction |
| `TScriptProperty_clone_void` | `0x226008` | `0x22e94c` | metadata copy |
| `TScriptProperty_addProps_TProperties_TPropertyPropDef_int` | `0x2260dc` | `0x22ea1c` | property registration |
| `TScriptProperty_setFunction_TProperties_char_TString_const_void_TString_const_bool` | `0x2264b4` | `0x22ef54` | scope and function metadata |
| `TScriptProperty_addFuncs_TProperties_TPropertyFuncDef_int` | `0x2266a8` | `0x22f148` | function registration |

The typed accessors retain the type-letter dispatch, universe-object branch,
conversion helpers, and read-only diagnostics. The registration methods keep
the encoded and case-insensitive lookup paths, subclass selection, lowercase
fallback, and scope propagation. The source and target structures were
reviewed in IDA before any names were changed. All nine labels reopened with
zero failures in the v52 disposable copy. The machine-readable evidence is in
`artifacts/spectron_script_property_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_property_anchors.py`. The database
SHA-256 is
`b4ae7f8b981ded05bca5a811276aad0f9756ed2662b34d14d77befe7bd56b17d`.

## 2026-08-26: Spectron GS2 script universe anchors

The v53 pass reviewed the `TScriptUniverse` layer that owns global variables,
static objects, class scripts, and zipped script packages.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScriptUniverse_writeString_TString_const` | `0x22b254` | `0x234c1c` | global string and numeric-cache write |
| `TScriptExecutionStats_TScriptExecutionStats_TGraalVar` | `0x22b3ec` | `0x234dd0` | statistics object construction |
| `TScriptUniverse_addStaticObject_TGraalVar` | `0x22b624` | `0x235010` | static-object registration |
| `TScriptUniverse_TScriptUniverse_void` | `0x22b6e8` | `0x2350dc` | universe collections and static variables |
| `TScriptUniverse_getClassAndCreate_TString_const_bool` | `0x22c260` | `0x235c48` | class lookup and creation |
| `TScriptUniverse_addClassScript_TString_const_TString_const` | `0x22cc88` | `0x2366ec` | class stream and load events |
| `TScriptUniverse_compileZippedScripts_TString_const` | `0x22cf78` | `0x236a60` | package verification and archive dispatch |
| `TScriptUniverse_addZippedScripts_TString_const_TSocketConnection` | `0x22cf98` | `0x236a80` | connector setup and script TLS fields |

The variable, statistics, static-object, universe, class lookup, and class
installation methods retain their source state transitions and distinctive
strings. The zip compiler preserves package parsing, RSA and SHA-256 checks,
RC4 decryption, archive limits, and the `.rk`, `.t`, `NPCS/`, and `CLASSES/`
branches. IDA records that compiler as a split function with a short entry
range, so the artifact records its associated instruction counts rather than
pretending that the entry range is the full body. All eight labels reopened
with zero failures in the v53 disposable copy. The machine-readable evidence
is in
`artifacts/spectron_script_universe_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_universe_anchors.py`. The database
SHA-256 is
`a8b0e0611f2148be755691539ffa2cf6607c2ed00caf5ff6fe21f4ba2a1e5c80`.

## 2026-08-26: Spectron static, JSON, and tile anchors

The v54 pass reviewed three methods immediately following the script-universe
cluster: static script-variable construction, recursive `TGraalVar` JSON
serialization, and tile-definition persistence.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TStaticVar_TStaticVar_TString_const` | `0x22d3dc` | `0x236ea0` | global-universe registration |
| `TGraalVar_writeJSONObject_yajl_gen_t_bool` | `0x22e378` | `0x237ec8` | typed recursive YAJL output |
| `TTiles_SaveTileDefinitions_void` | `0x22f32c` | `0x238f48` | tile-definition file serialization |

The static-variable constructor preserves the initialized state, static
properties, list-link updates, global-universe attachment, and count change.
The JSON writer keeps the scalar, array, and object branches, filters the same
special properties, recurses through child values, and emits the same YAJL
types. The tile saver still builds the server-specific `levels/tiledefs` path,
writes the five comma-separated fields for each definition, creates the
directory, and saves the list. All three target functions keep the source
basic-block counts even though rebuilt string and container wrappers change
their byte and instruction counts.

All three labels reopened with zero failures in the v54 disposable copy. The
machine-readable evidence is in
`artifacts/spectron_static_json_tiles_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_static_json_tiles_anchors.py`. The database
SHA-256 is
`01d1833774b599fec7dc4279614dd09e0cf51ccc82ec21beed38c2e532559fec`.

## 2026-08-26: Spectron tile update and draw anchors

The v55 pass reviewed the main `TTiles` update cluster and the tile-panel
screen renderer.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TTiles_UpdateTempTiles_TString_const` | `0x22f6f4` | `0x239330` | temporary-list reconciliation and texture refresh |
| `TTiles_GetLevelTiles_TString_const` | `0x22fb48` | `0x2397a0` | level tileset selection |
| `TTiles_UpdateTiles_void` | `0x22fc98` | `0x239944` | active level and player-buffer update |
| `TTiles_AddTileDefinition_TString_const_TString_const_int_int_int` | `0x22fdb8` | `0x239a80` | definition insertion and replacement |
| `TTiles_isTilesImage_TString_const` | `0x230040` | `0x239d6c` | tile-image membership scan |
| `TTiles_LoadTileDefinitions_void` | `0x230244` | `0x239f8c` | definition-file parsing |
| `TTiles_updateAnimatedTiles_TPlayer_TString_const` | `0x2306fc` | `0x23a598` | visible temporary-tile repaint |
| `TTilesPanel_drawTilesOnScreen_int_int` | `0x231bb4` | `0x23bb2c` | tile-grid rendering |

The temporary-tile method retains the filename and dimension reconciliation,
stale-entry deletion, missing-entry creation, and texture-size refresh. The
level lookup still selects the matching definition and updates the global tile
type. The update wrapper still compares the current tileset, refreshes the
temporary list, and reinitializes the active player's buffer when necessary.

Definition insertion and loading preserve their seven-field record layout,
the levels and tiledefs path, comma-separated file format, and dirty-update
path. The target's insertion guard is a documented behavior change from 9999
to 999999 entries. The animated-tile method keeps the 4096-cell scan and
offscreen repaint call. The screen renderer moves from the original vertex
array backend to the target's newer quad and texture operations, but keeps the
same login guard, Draw_Tiles profiler label, 64-pixel grid, transparent-tile
skip, and black-tile handling.

All eight labels reopened with zero failures in the v55 disposable copy. The
machine-readable evidence is in
`artifacts/spectron_tiles_update_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tiles_update_anchors.py`. The database
SHA-256 is
`b9957326c9871659765825261e9990b9ac3db2d42d632aa180db0fc47fb85417`.

## 2026-08-26: Spectron particle-data anchors

The v56 pass reviewed five `TParticleDataEx` methods covering animation names,
player appearance, template copying, and coded polygons.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TParticleDataEx_getAnimation_void` | `0x232e64` | `0x23cc14` | full gani name and optional parameter |
| `TParticleDataEx_setPlayerLook_bool` | `0x2331a8` | `0x23cf70` | default body, head, shield, sword, and colors |
| `TParticleDataEx_copyFromTemplate_TParticleDataEx` | `0x2337ec` | `0x23d564` | scalar, animation, and appearance copy |
| `TParticleDataEx_setCodedPolygon_TString_const` | `0x233f08` | `0x23dca0` | type field and temporary polygon variable |
| `TParticleDataEx_setTexturedCodedPolygon_TString_const` | `0x233fe0` | `0x23dd7c` | texture field and polygon variable |

The animation getter retains the full gani name plus the trimmed optional
animation parameter. The player-look setter still restores the default body,
head, shield, sword, and six color slots when switching away from player-look
mode. Template copying preserves the same scalar fields, animation, direction,
look flag, appearance strings, and colors. The two polygon setters still parse
the type, normalize it to 2 or 3, remove their header fields, and build a
temporary `TGraalVar` for the polygon values.

All five target methods retain their source basic-block counts. The
machine-readable evidence is in
`artifacts/spectron_particle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_particle_anchors.py`. All five labels
reopened with zero failures in the v56 disposable copy. The database SHA-256
is
`592fc346da450b304540618a4c14f8ab1a0cff048e4efc59acb3a5fb33a147d0`.

## 2026-08-26: Spectron TShowImg serialization anchors

The v57 pass reviewed the three unmatched `TShowImg` serialization and
network-property methods.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TShowImg_readString_void` | `0x2349e0` | `0x23e7d0` | mode-prefixed wire string encoding |
| `TShowImg_writeString_TString_const` | `0x236b8c` | `0x240a14` | mode dispatch and ATTR/PARAM handling |
| `TShowImg_getNetProperty_TServerPlayer_int` | `0x2372d8` | `0x241154` | indexed network-property encoding |

The read path preserves the mode switch and the `@`, `#`, `%`, and `&`
prefixes for text, polygon, textured polygon, and animation values. It also
keeps the image-part, animation-parameter, and five-value color or parameter
branches. The write path dispatches those prefixes back to the corresponding
show methods, handles `ATTR` and `PARAM`, and falls back to image or sprite
handling for numeric and unrecognized values.

The network-property method retains the player-relative coordinate branches,
image-part encoding, rotation, alpha, color, speed, and layer calculations. It
still clamps the numeric fields to the same one-byte representation and emits
the same property indexes. The target adds a small amount of wrapper logic but
stays in the same class-local serialization cluster.

All three labels reopened with zero failures in the v57 disposable copy. The
machine-readable evidence is in
`artifacts/spectron_showimg_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_showimg_anchors.py`. The database SHA-256
is
`4ea4e394195d1d7218b67c4e86c8edd45e68ebd0db4b38f3d948f6ae1f60b79c`.

## 2026-08-26: Spectron particle-emitter anchors

The v58 pass reviewed two unmatched `TParticleEmitter` methods. These are
useful anchors because the target keeps the complete particle list literals
and the same emission state machine even though the 2.2 symbols are
obfuscated.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TParticleEmitter_initStaticVars_void` | `0x23b274` | `0x245114` | three static particle-variable lists |
| `TParticleEmitter_emit_T3DFloatPoint_const_uint_bool` | `0x23b394` | `0x245240` | guarded emission and particle initialization |

The initializer creates the same `once,impulse,range` lifetime list, the full
particle variable list from `x` through `zoom`, and the
`replace,add,multiply` modifier list. The target has the same one-block role
and all three complete literals.

The emission method retains the owner, disabled-state, template, and maximum
count guards. It uses the same `Particles_Emit` profiler label, limits the
per-call count, chooses a random template, obtains or reuses a particle,
copies its template, sets its parent, lifetime, position, angle, and velocity,
then applies offsets, modifiers, optional sound, and final insertion. Both
functions retain their source basic-block counts, one and 44 respectively.

The machine-readable evidence is in
`artifacts/spectron_particle_emitter_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_particle_emitter_anchors.py`. Both labels
reopened with zero failures in the v58 disposable copy. The database SHA-256
is
`0a3ede671e58cb9a2585eb3388aff048d44ddd5588f1fa674ea4e6bc718003be`.

## 2026-08-26: Spectron server-animation anchors

The v59 pass reviewed three unmatched server-animation methods. Their target
implementations retain the same class-local state machines even where the
2.2 build expands the control flow for rebuilt wrappers or direction tables.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TExplosion_animate_void` | `0x23caec` | `0x24699c` | collision, damage, and PK notification |
| `TServerCarry_animate_void` | `0x23d774` | `0x24768c` | movement, obstacles, damage, and bomb handoff |
| `TServerFlying_animate_void` | `0x23eeb0` | `0x248e38` | projectile, collision, and combat state machine |

The explosion method keeps the active-player and level checks, NPC action 13,
distance and protection guards, direction-dependent damage, the `explosion`
label, and the zero-health PK notification. The target expands the direction
table into an explicit switch, but the state transitions and field offsets
remain aligned.

The carry method preserves direction-dependent movement, level-list transfer,
throw-wall and NPC handling, the five `blackstone`, `bush`, `sign`, `stone`,
and `vase` sprite families, bush damage, water leaps, and bomb attachment and
handoff. The flying method preserves dominant-direction selection, four-frame
animation, shield interaction, `arrow` damage, `arrowon.wav`, `bomb.wav`, NPC
action 14, wall checks, and overlap scanning.

The machine-readable evidence is in
`artifacts/spectron_server_animation_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_animation_anchors.py`. All three
labels reopened with zero failures in the v59 disposable copy. The database
SHA-256 is
`a2f9a22dfe43d846c7a354fc79c7fb44e7727d58610bfb39ebbd26b6c133e95f`.

## 2026-08-26: Spectron player lifecycle anchors

The v60 pass reviewed two unmatched `TPlayer` methods that sit on the initial
level and periodic update paths.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_loadStartLevel_bool` | `0x178160` | `0x17c3e8` | reset state and initial level load |
| `TPlayer_timer_void` | `0x179594` | `0x17d8cc` | periodic update and network-state timer |

The start-level method preserves the reset of action, restart, level, freeze,
carrying, emoticon, and board state. It retains the server-privilege decision,
health thresholds, initial animation and spawn link, restart-position update,
and the `Could not find the level` error path in the `levels` log category.

The timer method preserves the repeated encoded-field refresh, action-mode and
counter updates, `stay` emoticon timeout, server-player timer, key and
sitting or sleeping checks, player and level animation, map-link and lava
checks, client triggers, NPC actions, show-image synchronization, board
updates, and movement-buffer path. Both target methods retain the source
27-block and 148-block shapes.

The machine-readable evidence is in
`artifacts/spectron_player_lifecycle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_lifecycle_anchors.py`. Both labels
reopened with zero failures in the v60 disposable copy. The database SHA-256
is
`9254878f5c135452260508068fa54f3ca6821d6cbd506af49dc14fd08bea4ab2`.

## 2026-08-26: Spectron player emoticon anchors

The v61 pass reviewed two unmatched player coordinate getters. They are small
methods, but their preserved vtable calls, literal, field order, and branch
shape make the correspondence unusually clear.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_getEmoticonX_void` | `0x16fc68` | `0x173b30` | X coordinate and `emoticon_z` adjustment |
| `TPlayer_getEmoticonY_void` | `0x16fd24` | `0x173c0c` | Y coordinate, `emoticon_z`, and active-counter adjustment |

The X getter adds the inherited base coordinate to the player X field and adds
2.0 when the optional emoticon object contains `emoticon_z`. The Y getter does
the same for Y, subtracts 5.0 for `emoticon_z`, and retains the separate
positive-counter check that subtracts 1.7. The target shifts the player and
emoticon-object fields for the larger 2.2 class and makes the string-wrapper
conversion explicit, while preserving the source seven-block and ten-block
control-flow shapes.

The machine-readable evidence is in
`artifacts/spectron_player_emoticon_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_emoticon_anchors.py`. Both labels
reopened with zero failures in the v61 disposable copy. The database SHA-256
is
`cfac89e2ddc58e14b0eac9be2eaf052b8cc1373d47036c33ea96b441544ac079`.

## 2026-08-26: Spectron player level-entry anchors

The v62 pass reviewed the two central player level-entry methods that remained
unmatched by the broad semantic matcher.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_enterLevelMain_TString_const_bool` | `0x178558` | `0x17c7f8` | level transition, cleanup, and restart state |
| `TPlayer_enterServerLevel_TString_const_bool` | `0x178a18` | `0x17cd00` | server-level creation and modification handoff |

The main level-entry method preserves client notification, side-level position
calculation, changed-map cleanup, side-level loading, server-player detach,
map-position updates, stale-object cleanup, board and tile updates, render
buffer setup, restart-position resolution, and action-state reset. The target
adds one small branch but keeps the same class-local sequence and nearly the
same 56-block shape.

The server-level method preserves the encoded player-state refresh, health
initialization, level-name swap, server-level creation and loading, client and
NPC level globals, cleanup of the same three object lists, server-modification
dispatch, attached-player reset, and handoff to main level entry. Both methods
retain the source and target 32-block shape for this path.

The machine-readable evidence is in
`artifacts/spectron_player_level_entry_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_level_entry_anchors.py`. Both
labels reopened with zero failures in the v62 disposable copy. The database
SHA-256 is
`888c0ef9c1f5f83a45f30a4429a7e2ea7dd8126e04bdf09d50ec08cdfc0a09b3`.

## 2026-08-26: Spectron player side-level anchors

The v63 pass reviewed four side-level methods used directly by the player
level-entry path.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_setSideLevels_void` | `0x16e3d0` | `0x1720d0` | side-level grid reset and neighbor selection |
| `TPlayer_loadSideLevels_void` | `0x16e634` | `0x172404` | level reuse, cleanup, and preload |
| `TPlayer_getSideLevel_int_int` | `0x16e9e8` | `0x1727e0` | bounded coordinate lookup |
| `TPlayer_SideLevelInDirection_int` | `0x16ea50` | `0x172854` | directional occupancy scan |

The grid setter clears cached names and level pointers, derives neighboring
level names from the current level position, resolves available level objects,
and caches the current level. The target expands the source three-by-three
grid into a seven-by-seven grid, which explains the changed offsets and block
count while preserving the same role.

The loader keeps the old and new side-level sets, removes temporary objects
from levels that are no longer needed, creates missing side levels when a
client exists, marks them as side levels, loads them, and sends preload
packets. The two lookup methods preserve the source bounds and directional
occupancy semantics. The target splits boundary normalization into two small
target-only helpers, so those helpers are intentionally left with their
obfuscated names rather than receiving an invented 1.8 label.

The machine-readable evidence is in
`artifacts/spectron_player_side_level_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_side_level_anchors.py`. All four
labels reopened with zero failures in the v63 disposable copy. The database
SHA-256 is
`9bf7ae63884225e0ef3abab3f9733a1dde9c5c3eae4fdf24b5c83ec41fad076b`.

## 2026-08-26: Spectron player map-position anchors

The v64 pass reviewed two methods that connect the player’s active map state
to level transitions and client level-link notifications.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_updateMapPos_void` | `0x1720a8` | `0x176068` | active-map refresh and `.gmap` fallback |
| `TPlayer_checkMapPos_bool_bool` | `0x173308` | `0x177308` | map-link detection and translated position |

`updateMapPos` preserves the level-list lookup, active-level assignment, map X
and Y refresh, client server-level globals, nearby-NPC recalculation, and the
reset-to-zero fallback when the active level is unavailable. The target keeps
the `.gmap` fallback and the same class-local path with one fewer block.

`checkMapPos` preserves missing-state and bounds rejection, destination-level
lookup, comparison with the player level, world-coordinate translation, and
the choice between caching a pending link and sending a client level-link
packet. The target retains the exact 17-block shape while changing only the
rebuilt wrappers and shifted fields.

The machine-readable evidence is in
`artifacts/spectron_player_map_position_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_map_position_anchors.py`. Both
labels reopened with zero failures in the v64 disposable copy. The database
SHA-256 is
`f53c37fbdbc66d1774c24ac7fcb30d9a68cb4aca569ac8d7cb81aaf81c12510e`.

## 2026-08-26: Spectron player link-traversal anchors

The v65 pass reviewed player animation and link traversal methods that sit
immediately after the map-position helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_animateLevel_void` | `0x16f090` | `0x172e78` | profiler scope and side-level animation |
| `TPlayer_testForMapLinks_void` | `0x16f1b8` | `0x17303c` | nearby link detection and packet send |
| `TPlayer_testForLinks_void` | `0x16f338` | `0x1731a8` | edge and object link state machine |

The animation method keeps the `PlayerTimer_AnimateLevel` profiler scope and
animates every available side level and the active level. The target walks the
expanded seven-by-seven grid, which explains its two additional blocks.

The two link methods preserve attached-player and disallowed-link checks,
side-level selection, direction and boundary handling, level-object scanning,
calculated destination coordinates, and client level-link notification. The
target splits some coordinate arithmetic into the target-only helpers already
described in the side-level section and expands direction handling in the
general link state machine.

The machine-readable evidence is in
`artifacts/spectron_player_link_traversal_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_link_traversal_anchors.py`. All
three labels reopened with zero failures in the v65 disposable copy. The
database SHA-256 is
`0d7f9660341da422888acfc948d0cd6fa2ade6bdbcbbe95d4d5326a39dc7ca44`.

## 2026-08-26: Spectron player weapon-state anchors

The v66 pass reviewed four player weapon and attribute methods from the same
class-local region.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_resetAttributes_void` | `0x1742cc` | `0x1782fc` | full player reset and `letters.png` |
| `TPlayer_deleteSelectedWeapon_void` | `0x1746f0` | `0x178828` | protected weapon check and deletion |
| `TPlayer_setSelectedWeapon_int` | `0x1747b4` | `0x178910` | cyclic selection and name update |
| `TPlayer_getWeapon_TString_const` | `0x175850` | `0x179af8` | weapon-list lookup by name |

The reset method preserves the clearing of level and side-level state, weapon
and carrying reset, cached-trigger cleanup, the thirty GANI parameter reset,
the default `letters.png` asset, nickname refresh, encoded buffers, emoticon
coordinates, and visual defaults. The weapon methods preserve protected-name
handling, client delete notification, cyclic selection, selected-name update,
and lookup by weapon name. Changed fields and wrappers follow the larger 2.2
player object, while the smaller methods retain their source block counts.

The machine-readable evidence is in
`artifacts/spectron_player_weapon_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_weapon_state_anchors.py`. All four
labels reopened with zero failures in the v66 disposable copy. The database
SHA-256 is
`b17096b3ce92774fdfdf90b2a21c52dad8111ad7d09bd2b705fa0d3371ecd25b`.

## 2026-08-26: Spectron player visual setter anchors

The v67 pass reviewed five player draw-state and visual setter methods from
the same class-local region.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_setDrawRect_void` | `0x16df08` | `0x171bf8` | screen layout and aligned draw rectangle |
| `TPlayer_setHead_TString_const` | `0x17ae84` | `0x17f1c8` | head compare, change flag, and inherited setter |
| `TPlayer_setBody_TString_const` | `0x17aec8` | `0x17f238` | body compare, change flag, and inherited setter |
| `TPlayer_setSword_TString_const` | `0x19dce8` | `0x1a295c` | normalized sword image update |
| `TPlayer_setShield_TString_const` | `0x19dd4c` | `0x1a29e4` | normalized shield image update |

The draw-rectangle methods preserve the game-control and main-window origin,
the local-player index and quadrant logic, the aligned tile bounds, and the
same player-count branches. The target adds a small draw-state callback at
the return and moves the player fields, but keeps the fourteen-block shape.
The head and body setters preserve comparison, change-flag, and inherited
GANI updates. The sword and shield setters lower-case their filenames, compare
and update the stored image, and set the corresponding change flag. The target
uses rebuilt string wrappers and shifted fields, while the small setters keep
three target blocks.

The machine-readable evidence is in
`artifacts/spectron_player_visual_setter_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_visual_setter_anchors.py`. All five
labels reopened with zero failures in the v67 disposable copy. The database
SHA-256 is
`b35de4695b4ccc607722b5d049df1b3838f20dcd2e010d9bafda5c47ca105b97`.

## 2026-08-26: Spectron player movement and interaction anchors

The v68 pass reviewed eight player movement, inventory, animation, and hurt
methods from the same class-local region.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_pullStones_void` | `0x197e2c` | `0x19c954` | pulled trigger and client notification |
| `TPlayer_moveStones_void` | `0x1980d0` | `0x19cc50` | pushed trigger and client notification |
| `TPlayer_canJump_void` | `0x198300` | `0x19ced8` | jump tile and wall checks |
| `TPlayer_movementAction_int` | `0x198bb8` | `0x19d7f8` | movement and interaction dispatcher |
| `TPlayer_itemAvailable_int` | `0x19ad78` | `0x19f9a0` | inventory and weapon availability cases |
| `TPlayer_animateJumping_void` | `0x19bbd8` | `0x1a0844` | directional jump animation |
| `TPlayer_loseItem_int` | `0x19c9e0` | `0x1a1650` | item consumption and weapon downgrade |
| `TPlayer_hurtPlayer_double_double_double_TString_const_TServerPlayer` | `0x19dfa4` | `0x1a2c60` | damage, knockback, and hurt event |

The pull and push methods preserve action-level checks, 64 by 64 bounds,
directional coordinates, the `pulled` and `pushed` literals, local trigger
dispatch, and client notifications. The jump check keeps the legacy-server
guard, tile type 21 probe, and wall test. The large movement dispatcher keeps
the same sound literals, movement state, action transitions, and calls into
the reviewed stone, jump, link, animation, and NPC interaction helpers.

The inventory query preserves the same item cases, sword and shield prefixes,
thresholds, and special branches. Item loss keeps the same count decrements,
weapon and shield downgrade paths, replacement PNG names, and selection
updates. Jump animation retains its four direction cases and counter exit.
The hurt method retains invulnerability and ghost-mode guards, hurt animation,
power loss, square-root knockback normalization, and the optional attacker
event argument. Target wrappers and player fields are rebuilt, with small block
count changes in the larger methods.

The machine-readable evidence is in
`artifacts/spectron_player_movement_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_movement_anchors.py`. All eight
labels reopened with zero failures in the v68 disposable copy. The database
SHA-256 is
`5daae0f4a60036947f12748aa7b5ef89312b0fe3ac71aa10477d9bfe84f5bf75`.

## 2026-08-26: Spectron server-player state anchors

The v69 pass reviewed six server-player initialization, level, property,
nickname, and weapon-image methods.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerPlayer_setHead_TString_const` | `0x18b010` | `0x18f8c0` | conditional head-string update |
| `TServerPlayer_initPlayerVars_void` | `0x18ba6c` | `0x190334` | state initialization and default assets |
| `TServerPlayer_playerEnteredLevel_void` | `0x18ccf8` | `0x1915a8` | level and side-level membership |
| `TServerPlayer_setNick_TString_const` | `0x18dea0` | `0x1927a0` | nickname normalization and change events |
| `TServerPlayer_setProperties_TString_const` | `0x18e168` | `0x192ac8` | encoded property parser |
| `TServerPlayer_setWeaponImgs_TString_const` | `0x19004c` | `0x194a54` | encoded weapon-image parser |

The head setter preserves compare-before-assign behavior. Initialization keeps
the same movement, action, health, status, language, and default asset state,
including `English`, `sword1.png`, `shield1.png`, and the default head and
body. Level entry keeps old-list removal, gmap detection, coordinate clamping,
level-cell lookup, and regular-level loading. Nickname handling keeps wrapped
guild text, admin-guild state, and the `onPlayerChanges` propagation path.

The property parser preserves the compact switch cases for nickname, power,
images, GANI state, attachment, coordinates, chat, and status, along with
the image and `setani` literals. The weapon-image parser retains show-image
creation, position, frame, image-part, color, zoom, and mode directives, then
removes stale images. The target shifts fields and rebuilds wrappers, while
the small setters and the larger property paths retain their source block
shapes closely.

The machine-readable evidence is in
`artifacts/spectron_server_player_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_player_state_anchors.py`. All six
labels reopened with zero failures in the v69 disposable copy. The database
SHA-256 is
`3772800d76e7e1cbc252dc7169a4c15c1ff342dc38bbc8cb43904d2739df360e`.

## 2026-08-26: Spectron server-NPC state anchors

The v70 pass reviewed seven server-NPC construction, shape, naming, default-
image, movement, and property methods.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerNPC_script_setShape2` | `0x180f1c` | `0x185484` | shape callback and `shape` variable |
| `TServerNPC_TServerNPC_int` | `0x183cc8` | `0x188340` | constructor and `save` variable |
| `TServerNPC_getLogName_void` | `0x181458` | `0x1859ec` | role-aware log name |
| `TServerNPC_setDefaultImageNames_void` | `0x185fd0` | `0x18a678` | default images and colors |
| `TServerNPC_serverMovedNPC_bool` | `0x186c38` | `0x18b3b0` | movement reset and sound |
| `TServerNPC_setProperties_TString_const` | `0x186d48` | `0x18b4ec` | encoded NPC property parser |
| `TServerNPC_doNPCMove_void` | `0x188260` | `0x18ca28` | NPC move queue and completion |

The shape callback updates width and height, creates or clears the `shape`
script variable, checks the array length, and marks the NPC changed. The source
IDA comment also ties the callback record at `0x37c908` to `setshape2` in the
TServerNPC script-function table installed at `0x183c18`. The target at
`0x185484` was default-named `sub_185484` in the feature export, so this
callback-table evidence is important. The applied v18 label records the role
without pretending that the target retained a debug symbol.

The constructor preserves the server-player base call, NPC vtables, helper
allocation, dimensions, flags, and `save` variable. The log-name method keeps
the GANI, projectile, weapon, head0, and unknown cases and appends level, cell,
and coordinate context. Default-image setup retains water-aware animation,
the four image literals, and the five color defaults. The movement update keeps
the legacy-server guard, action-level check, default gani and water handling,
and optional movement sound.

The large property parser preserves the compact NPC property cases for images,
head and body, weapons, GANI, movement, attachments, map and position, status,
events, and hit detection. The move-queue method keeps the bomy animation
choices, position updates, and `movementfinished` event. Source and target
control-flow counts are identical for the shape, constructor, default-image,
movement-update, and move-queue methods. The log-name, property, and large
parser paths remain close at 62 to 63, 180 to 181, and 91 to 91 blocks.

The machine-readable evidence is in
`artifacts/spectron_server_npc_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_npc_state_anchors.py`. All seven
labels reopened with zero failures in the v70 disposable copy. The database
SHA-256 is
`c384c10b3a0cdd69925df8017a3a870de64aa4942923d59a12bc88c5bbc690b4`.

## 2026-08-26: Spectron NPC accessor anchors

The v71 pass reviewed 17 compact server-NPC property accessors. These were
not part of the earlier semantic map or the earlier NPC-helper checkpoint.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerNPC_getHeartsOrHP` | `0x1807b0` | `0x184d18` | hearts and HP callback getter |
| `TServerNPC_getHurtDX` | `0x1807d0` | `0x184d38` | horizontal hurt field |
| `TServerNPC_setHurtDX` | `0x1807d8` | `0x184d40` | clamped horizontal hurt field |
| `TServerNPC_getHurtDY` | `0x1807fc` | `0x184d64` | vertical hurt field |
| `TServerNPC_setHurtDY` | `0x180804` | `0x184d6c` | clamped vertical hurt field |
| `TServerNPC_getIsBlocking` | `0x180828` | `0x184d90` | inverse blocking byte |
| `TServerNPC_getIsBlockingProjectiles` | `0x18084c` | `0x184db4` | projectile blocking byte |
| `TServerNPC_setIsBlockingProjectiles` | `0x180854` | `0x184dbc` | projectile blocking store |
| `TServerNPC_getLayer` | `0x18085c` | `0x184dc4` | layer normalization |
| `TServerNPC_getSave` | `0x1808b0` | `0x184e18` | save-variable pointer |
| `TServerNPC_getShieldPower` | `0x1808b8` | `0x184e20` | shield-power vtable getter |
| `TServerNPC_setShieldPower` | `0x1808d8` | `0x184e40` | clamped shield-power setter |
| `TServerNPC_getSwordPower` | `0x180900` | `0x184e68` | sword-power vtable getter |
| `TServerNPC_setSwordPower` | `0x180920` | `0x184e88` | clamped sword-power setter |
| `TServerNPC_getX` | `0x180948` | `0x184eb0` | global X coordinate |
| `TServerNPC_getY` | `0x18097c` | `0x184ee4` | global Y coordinate |
| `TServerNPC_getVisible` | `0x1809b0` | `0x184f18` | visibility byte |

The source IDA database gives each callback property its own table record and
comment. The target keeps the same getter and setter ordering in the compact
server-NPC cluster. The hurt setters clamp both axes to -1.0 through 1.0. The
blocking getter returns the inverse of its byte, while the projectile blocking
getter and setter access the byte directly. The layer getter keeps the special
mapping for stored layer values 8 and values below 10.

The save getter shifts the object field from offset 1152 to 1200 bytes. The
shield and sword wrappers shift their vtable coordinates by eight bytes while
preserving the negative-value clamp and integer conversion in the setters. The
coordinate getters still call the inherited local coordinate methods and add
the tile coordinate shifted left by six bits. The visibility getter shifts its
logical byte from offset 1008 to 1032 bytes.

All 17 target functions were default-named in the clean feature export. This is
expected for this stripped 2.2 build. The role labels are supported by the
callback-table records, exact getter and setter adjacency, direct pseudocode,
and compact body shapes. They are not claims that the 2.2 library retained the
original debug symbols.

The machine-readable evidence is in
`artifacts/spectron_npc_accessor_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_npc_accessor_anchors.py`. All 17 labels
reopened with zero failures in the v71 disposable copy. The database SHA-256
is
`307ad12c6bcf4f1aec20e8145daf3b41037a63f5834d84950e7cf399c1859da0`.

## 2026-08-26: Spectron NPC destructor anchors

The v72 pass reviewed the two server-NPC destructor entry points that sit
between the callback helpers and the role-aware log-name method.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerNPC_TServerNPC` | `0x1811ac` | `0x185730` | complete destructor cleanup |
| `TServerNPC_TServerNPC__2` | `0x181438` | `0x1859cc` | deleting-destructor wrapper |

The first source function is a complete destructor even though IDA presents
the readable class-style name. Its alternative name is
`_ZN10TServerNPCD1Ev`. The target retains the corresponding C++ ABI D2 body
and its D1 alternative. Both clear script variables and helper pointers,
remove the NPC from global, universe, local-player, level, and map lists, free
the image buffer, clear strings and resource state, and finish by calling the
server-player destructor. The source and target both have 31 basic blocks.

The second source function is the deleting-destructor wrapper. It calls the
complete destructor and then calls `operator delete`, exactly as the target D0
body does. Both wrappers have two basic blocks and 32 bytes. The target uses
obfuscated class and wrapper names, but the ABI role, class-local adjacency,
and cleanup behavior are unambiguous.

The machine-readable evidence is in
`artifacts/spectron_npc_destructor_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_npc_destructor_anchors.py`. Both labels
reopened with zero failures in the v72 disposable copy. The database SHA-256
is
`24ea9c5816854de6f8e157439e01f6a556009adf432d26bb8ddbcd429bac87d3`.

## 2026-08-26: Spectron server-level property anchors

The v73 pass reviewed eight exact server-level and level-link property pairs.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_set_preloadleveldefaulttile` | `0x19f938` | `0x1a4608` | preload tile static setter |
| `TServerLevel_getHeight` | `0x19f948` | `0x1a4618` | active-layer height |
| `TServerLevel_getNoPKZone` | `0x19f978` | `0x1a4648` | no-PK zone byte |
| `TServerLevel_setNoPKZone` | `0x19f980` | `0x1a4650` | no-PK zone store |
| `TServerLevel_getSparringZone` | `0x19f988` | `0x1a4658` | sparring-zone byte |
| `TServerLevel_getTileLayerCount` | `0x19f990` | `0x1a4660` | layer-list count |
| `TServerLevel_getWidth` | `0x19f99c` | `0x1a466c` | active-layer width |
| `TServerLevelLink_getDestLevel` | `0x19faa8` | `0x1a46a0` | destination-level string |

All eight source and target bodies have identical size, instruction count,
basic-block count, mnemonic hash, register-shape hash, and control-flow shape
hash. The height and width getters select the active layer, convert its tile
dimensions to 64-pixel units, and return 64 when no active layer is present.
The no-PK getter and setter use logical offset 298, while the sparring getter
uses logical offset 297. The layer-count getter follows the layer-list pointer
at logical offset 112.

The preload setter writes the same static script variable. Its paired readable
1.8 getter was not included because the stripped target feature region exposes
the setter at `0x1a4608` but no separate 16-byte getter body at the corresponding
position. Keeping that getter unresolved avoids claiming that a setter is a
getter. The level-link getter initializes the output string wrapper and copies
the destination-level field from logical offset 112; the target only rebuilds
the string wrapper.

All eight target functions were default-named in the clean feature export. The
source property and static-variable table comments, target callback references,
exact body hashes, and class-local order provide the identification. The labels
therefore describe reviewed roles in the stripped target, not retained debug
symbols.

The machine-readable evidence is in
`artifacts/spectron_server_level_property_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_property_anchors.py`. All
eight labels reopened with zero failures in the v73 disposable copy. The
database SHA-256 is
`e38d67d4a9920b462b00c851186a19e93f2f4ed9f9abef957272476402ac52e7`.

## 2026-08-26: Spectron server-level interaction anchors

The v74 pass reviewed five server-level interaction and level-link methods.
The NPC predicate in this neighborhood was deliberately excluded because it
was already labeled in the earlier core-helper checkpoint.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevelLink_getDestY` | `0x19fcdc` | `0x1a49b4` | player-token-aware destination Y |
| `TServerLevelLink_getDestX` | `0x19fd88` | `0x1a4a60` | player-token-aware destination X |
| `TServerLevel_script_removeExplo` | `0x19ff84` | `0x1a4c5c` | indexed explosion removal |
| `TServerLevel_script_removeBomb` | `0x19ffe8` | `0x1a4cc0` | bomb removal and client packet |
| `TServerLevel_script_removeArrow` | `0x1a00ac` | `0x1a4d84` | indexed arrow removal |

The destination X and Y getters preserve the `playerx` and `playery` token
branches, active-player coordinate forwarding, and numeric conversion fallback.
The explosion and arrow helpers reject negative or out-of-range indexes, delete
the indexed object, and invoke its virtual cleanup. The bomb helper also reads
the removed bomb coordinates and sends the remove-bomb packet when a client is
available. Its target keeps those phases but reduces the body from ten blocks
to eight around rebuilt wrappers. The other four pairs have identical exported
body metrics and hashes.

The original callback records identify the level-link properties and the legacy
removeexplo, removebomb, and removearrow script names. Target callback
references and direct pseudocode preserve the same list and coordinate roles.
The NPC predicate at `0x1a4994` is not repeated here because the earlier core
helper artifact already owns that label.

The machine-readable evidence is in
`artifacts/spectron_server_level_interaction_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_interaction_anchors.py`. All
five labels reopened with zero failures in the v74 disposable copy. The
database SHA-256 is
`39cf3f36e09056c034713f8384476d269681315df4ee6b6cbe497cb54720113d`.

## 2026-08-26: Spectron server-level lifecycle helpers

The v75 pass reviewed seven exact server-level lifecycle, script-test, and
animation helper pairs. The NPC-list getter was already labeled in the earlier
core-helper checkpoint and is not repeated here.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_TServerLevel__2` | `0x1a17b8` | `0x1a6468` | deleting-destructor wrapper |
| `TServerLevel_script_tileType` | `0x1a45a8` | `0x1a92c0` | tiletype callback wrapper |
| `TServerLevel_script_testItem` | `0x1a5760` | `0x1aa478` | item collision test wrapper |
| `TServerLevel_script_testExplo` | `0x1a5898` | `0x1aa5b0` | explosion collision test wrapper |
| `TServerLevel_animateCarries_void` | `0x1a6d44` | `0x1aba5c` | carry animation queue |
| `TServerLevel_animateLeaps_void` | `0x1a6dd0` | `0x1abae8` | leap animation queue |
| `TServerLevel_animateFlyingObjects_void` | `0x1a6e5c` | `0x1abb74` | flying-object animation queue |

All seven source and target bodies have identical size, instruction count,
basic-block count, mnemonic hash, register-shape hash, and control-flow shape
hash. The destructor wrapper calls the complete server-level destructor and
then `operator delete`. The three script callbacks forward their coordinate
arguments to the corresponding tile, extra-item, and explosion methods.

The three animation helpers walk their lists in reverse, call the contained
object's animate method, remove completed objects, and invoke virtual cleanup.
They preserve the logical carry, leap, and flying-object list slots 32, 30, and
33. The target class and helper names are obfuscated, but the exact bodies and
class-local sequence make the roles unambiguous. The three script-test targets
were default-named in the clean feature export, so their callback roles are
recorded as evidence rather than inferred from target names.

The machine-readable evidence is in
`artifacts/spectron_server_level_lifecycle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_lifecycle_helpers.py`. All
seven labels reopened with zero failures in the v75 disposable copy. The
database SHA-256 is
`3aaba8fe22c5f8d92c48e58bcaf0290254b28893e405edf600e9525f00eefe07`.

## 2026-08-26: Spectron server-level side and flower helpers

The v76 pass reviewed four server-level helper pairs that sit directly after
the constructor and side-level support methods in the 2.2 class-local layout.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_getSideLevelPos_int_int` | `0x1a92a0` | `0x1ae1d8` | cached side-level position lookup |
| `TServerLevel_getSideLevelInDirection_int` | `0x1a93a0` | `0x1ae3ec` | directional side-level lookup |
| `TServerLevel_calcFlowers_void` | `0x1a9480` | `0x1ae584` | flower calculation hook |
| `TServerLevel_animateFlowers_void` | `0x1a9484` | `0x1ae588` | flower animation hook |

The position lookup accepts a level object and two output pointers, searches
the active player's cached neighboring levels, and writes the matching row
and column. Spectron keeps that role but expands the cached grid from the
1.8 three-by-three arrangement to seven by seven. The directional helper
uses the current level position and input movement vector to select a cached
neighbor, with the same null result for an out-of-range slot. Its target body
is larger because the expanded grid and direction handling are expressed in
the rebuilt 2.2 implementation.

The two flower methods are no-ops in both reviewed libraries. Their four-byte,
one-instruction, one-block bodies have identical normalized hashes, and their
adjacent class-local placement keeps the two hooks distinct.

The machine-readable evidence is in
`artifacts/spectron_server_level_side_helpers_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_side_helpers.py`. All four
labels reopened with zero failures in the v76 disposable copy. The database
SHA-256 is
`0be95bd5c5aa4f7e5a6309e85255f798da63ed62363edf843013584579fe3a3e`.

## 2026-08-26: Spectron server-level construction and storage

The v77 pass reviewed four larger server-level functions whose bodies retain
the 1.8 level lifecycle and persistence state machines.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_TServerLevel_TString_const` | `0x1a854c` | `0x1ad294` | constructor and child arrays |
| `TServerLevel_SaveEncrypted_uint` | `0x1a1f50` | `0x1a6c00` | encrypted level serialization |
| `TServerLevel_LoadEncrypted_void` | `0x1aa198` | `0x1af2a0` | encrypted level deserialization |
| `TServerLevel_invokePlayerEnters_TString_const_int_int_int_int` | `0x1a3ee0` | `0x1a8be0` | NPC and baddie enter dispatch |

The constructor lower-cases and stores the supplied level name, creates the
tile-layer and board children, initializes the level collections, and
registers the same eleven child-array names: arrows, board, bombs, chests,
explos, items, links, projectiles, signs, tilelayers, and tiles. The target
keeps the 38-block shape and all eleven literals while using the obfuscated
2.2 wrappers.

The save and load methods retain the GWEBL001 header, the level identity and
signature checks, the GR-V1.03 and GR-V1.05 board-format branches, the
multi-layer board loop, the link and object sections, and the checksum seed.
The load method also keeps the GR-V1.04 acceptance path. Both target bodies
have the same block count as their source counterparts and retain every
serialized-format literal reviewed in the feature export.

The enter-dispatch method keeps the client and active-level gates, scans NPCs
and baddies, applies the same coordinate-window tests, and invokes the same
virtual callback for matching objects. Its target signature retains the level
string and four integer arguments, with a two-block reduction from wrapper
changes.

The machine-readable evidence is in
`artifacts/spectron_server_level_storage_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_storage_anchors.py`. All
four labels reopened with zero failures in the v77 disposable copy. The
database SHA-256 is
`ff6ad12749bb2114c4b6701e8c304a43b557d2ae2d8367f1b1e2c15ea8bfa666`.

## 2026-08-26: Spectron hidden testnpc callback boundary

The v78 pass found a small gap in the clean target function inventory. The
source `TServerLevel_script_testNPC` callback is at `0x1a4e98`, but the target
code body had no saved IDA function boundary. The bytes from `0x1a9bb0` through
`0x1a9c2c` form a complete 124-byte function immediately between the target
`isOnNPC` and `getOnNPC` methods.

After materializing only that explicit range in a disposable copy, IDA
decompiled a callback with the same arguments and control flow. It checks the
action-player, action-NPC, and universe globals, calls the obfuscated
`zF9VgaBKxR::FQ9UgaXTHQ` is-on-NPC method, and returns the matching NPC list
index. The source and target both have 31 instructions, seven basic blocks,
and identical mnemonic, register-shape, and control-flow hashes.

The machine-readable evidence is in
`artifacts/spectron_hidden_testnpc_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_hidden_testnpc_anchor.py`. The boundary
helper is `tools/ida_materialize_spectron_hidden_functions.py`. The translated
label reopened with zero failures in the v78 disposable copy. The database
SHA-256 is
`07a1209c24090df3908bbb8ec4805cb043d58a7739243a2424f70867e842561c`.

## 2026-08-26: Spectron level and map lookup anchors

The v79 pass reviewed six level and map helpers that connect the server-level
objects to filename lookup, link serialization, and GMAP loading.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `getLevel_TString_const` | `0x1a02e4` | `0x1a4fbc` | normalized level-list lookup |
| `getLevelPos_TString_const_TStringList` | `0x1a03b4` | `0x1a5094` | normalized list index wrapper |
| `TServerLevelLink_getTStringRepresentation_void` | `0x1a08e8` | `0x1a5580` | link coordinate and level serialization |
| `checkForNewMap_TPlayer_TString_const` | `0x1a8404` | `0x1ad124` | player current-map transition |
| `LoadGraalMap_TPlayer_TString_const_bool` | `0x1a8e88` | `0x1add28` | `.gmap` resolution and load path |
| `getMap_TString_const_bool` | `0x1a9148` | `0x1ae07c` | lookup and placeholder creation |

The level lookup target lower-cases the filename, walks the global level list,
compares the same offset-128 level name, and returns the matching object. The
level-position target is a smaller wrapper that validates the same inputs and
forwards to the target string-list index method. Its 48-byte body is 72 bytes
smaller than the 1.8 helper because Spectron performs normalization in its
callers.

The link serializer preserves the field layout and output recipe. It formats
the four coordinate values, removes spaces from the two level fields, changes
comma decimal separators to periods, and prepends the link prefix. It keeps
the source 16-block shape while growing by 24 bytes through the rebuilt string
wrappers.

The map helpers preserve the larger state transitions. `checkForNewMap`
searches the map name and alias list, updates the player's cached map, and
refreshes every loaded level when the map changes. `LoadGraalMap` keeps the
`.gmap` extension rule, 0x198-byte server-level allocation, resource lookup,
global-list insertion, and active-player refresh. `getMap` keeps the fallback
loader and the optional map placeholder path, including the 999-entry limit
and built-in alias insertion.

The target map-transition pointer moved from the 1.8 player offset 216 to the
Spectron offset 219. The loader grew from 704 to 852 bytes, while preserving
the 35-block state machine and the `.gmap` literal. These size changes are
documented version differences, not byte identity claims.

The machine-readable evidence is in
`artifacts/spectron_level_map_lookup_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_level_map_lookup_anchors.py`. All six
labels reopened with zero failures in the v79 disposable copy. The database
SHA-256 is
`6f60bbda2b7e5f2b5f5c3630611938c113932308d57538120ca9857fd405b85b`.

## 2026-08-26: Spectron TGaniObject constructor anchor

The v80 pass reviewed the remaining server-level `TGaniObject` constructor
candidate. The source constructor at `0x15e810` maps to the target constructor
at `0x161a24`, named `_ZN10ieJzgaIFFyC1EP10zF9VgaBKxR` in the stripped library.

The two constructors call the level-object base constructor, install the
animation-object vtable, initialize the same child pointers and scalar state,
create the show-image list and parameter collections, and build the `attr`
variable. Both add the built-in alias and construct 30 numbered animation
parameters. They then create the `colors` variable and add five configured
color variables plus `black`, before initializing scale, color, font,
visibility, sprite, and lookup state.

The target includes extra random-seed and encoded-buffer initialization that
does not exist in the 1.8 body. That accounts for the size and control-flow
change: 1836 bytes and 18 blocks in Spectron versus 1356 bytes and 11 blocks
in 1.8. The shared `attr` and `black` literals and the preserved 31-entry
parameter setup make this a high-confidence semantic anchor, not an exact byte
match.

The machine-readable evidence is in
`artifacts/spectron_gani_constructor_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_gani_constructor_anchor.py`. The label
reopened with zero failures in the v80 disposable copy. The database SHA-256
is
`ec6f4f26293f1025b1e016e0ac5f2ae13ed0f5d3d69d93d5a12be8b02e7993c6`.

## 2026-08-26: Spectron Gani helper anchors

The v81 pass continued through the small helpers surrounding the target
`ieJzgaIFFy` animation class. The source color-variable writer at `0x15dc50`,
`TColorVar_writeString_TString_const`, maps to target `0x160dc0`, whose
obfuscated name is `_ZN10_HTugbItBu10m6pngaXzjoERK10CanTfaz6bZ`.

The color setter is a direct semantic match. Both functions first ask the
Gani color table for a named color, use that index when it is nonnegative, and
fall back to the shared string-to-integer parser for an unknown name. They
then call the color-variable virtual setter at vtable slot 192. The target is
108 bytes and 27 instructions in three blocks, compared with 112 bytes and 28
instructions in three blocks for 1.8.

The source sprite helper at `0x15de20`,
`TGaniObject_getImageForSprite_TGraalAniSprite_bool`, maps to target `0x160f8c`,
`_ZN10ieJzgaIFFy10DYcNfbKw0TEP10JQknDa08eKb`. The pseudocode preserves the
full decision structure. It walks child Gani objects when present, handles
indexed child images, requires the selected image state at offset 128, and
copies the image name at offset 144. Its type 0 through type 9 switch still
selects the sprite name, body fields at offsets 376 through 432, global
sprites and tiles filenames, or a child-list entry. Type 1 also retains the
optional current-object update.

This target is 552 bytes and 137 instructions in 31 blocks, versus 544 bytes,
135 instructions, and 32 blocks in 1.8. The changed layout is consistent with
the target string wrappers and compiler output, so the record makes a semantic
claim rather than an exact byte claim.

The machine-readable evidence is in
`artifacts/spectron_gani_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_helper_anchors.py`. Both labels
reopened with zero failures in the v81 disposable copy. The database SHA-256
is
`bae4704ca2a47e0cbacde2e7c309ae5200e44f0f2c1ea0887dd560518ee2c14e`.

## 2026-08-26: Spectron Gani runtime anchors

The v82 pass extended the Gani mapping into the matrix, parameter, and
animation-start methods. The source `TGaniObject_checkPush2DMatrix_TPlayer` at
`0x15fe4c` maps to target `0x16323c`,
`_ZN10ieJzgaIFFy10oyT6Laxlp5EP10W6NzgawMJy`. Both read the scale and rotation
state, skip the identity case, and push a transformed draw matrix into the
player. Spectron adds a target-side byte and float transform, making the
target 288 bytes and 14 blocks instead of 128 bytes and nine blocks, but the
class-local order and output call are preserved.

The source parameter setter at `0x160260`,
`TGaniObject_setGaniParamOrAttr_bool_bool_int_TString_const`, maps to
`0x1636f0`, `_ZN10ieJzgaIFFy10Q8KcHachlYEbbiRK10C8THgaTQxF`. Both choose the
parameter or attribute list, preserve their different index bases, write the
supplied string through virtual slot 200, update visibility through the same
slot-432 query, and clear the temporary visibility flag. The target keeps the
13-block shape and grows from 228 to 268 bytes.

The companion getter at `0x160344`,
`TGaniObject_getGaniParamOrAttr_bool_int`, maps to `0x1637fc`,
`_ZN10ieJzgaIFFy10b6SzgaMYNyEbi`. It retains the same list selection, bounds
checks, failure result, and virtual value getter at slot 184. Its target body
is 204 bytes in 13 blocks versus 168 bytes in 1.8.

The largest match is the source animation-start routine at `0x160534`,
`TGaniObject_startAnimation_TString_const_TString_const_bool`, to target
`0x163a10`, `_ZN10ieJzgaIFFy10eHoSJa2nncERK10C8THgaTQxFS2_b`. The two bodies
trim and load animation names, maintain the owner relationship, parse bracketed
frame metadata, rebuild comma-separated parameters, create child Gani
objects, rebuild the NPC-backed child when needed, refresh the `playerlook`
child, and invoke the same reload hook when the full Gani name changes. Both
retain the `def`, `playerlook`, and `true` literals. The target is 2880 bytes
and 718 instructions in 126 blocks, compared with 2832 bytes and 706
instructions in 126 blocks for 1.8.

The machine-readable evidence is in
`artifacts/spectron_gani_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_runtime_anchors.py`. All four labels
reopened with zero failures in a serial v82 IDA check. The database SHA-256 is
`2e57b6470fc9dd985cfa3f633ef63cbde493f60f13075da12a8ddfdd263d3fec`.

## 2026-08-26: Spectron Gani serialization and drawing anchors

The v83 pass followed the Gani parameter and draw path. The source
`TGaniParam_writeString_TString_const` at `0x161120` maps to target `0x16462c`,
`_ZN10J0CfgbmrLh10m6pngaXzjoERK10CanTfaz6bZ`. Both update the parameter type,
parse numeric values and image filenames, recognize `.gani` child-animation
specifications, allocate and start child Gani objects, attach them to the
owner list, and create or update child NPC state when needed. The target keeps
the `.gani` literal and the 45-block role, growing from 924 to 948 bytes.

The source `TGaniObject_reloadAnimation_void` at `0x1614bc` maps to target
`0x1649e0`, `_ZN10ieJzgaIFFy10p_Jzga6iGyEv`. Both obtain the full Gani name,
force the main animation reload with the existing parameter string, refresh
the optional NPC-backed child script, send the empty child event, and mark the
object for redraw. The target preserves the 11-block shape and grows from 304
to 356 bytes.

The source `TGaniObject_draw_TPlayer` at `0x162548` maps to target `0x165aa0`,
`_ZN10ieJzgaIFFy10tIIEga1dSCEP10W6NzgawMJy`. Both dispatch to animation drawing
when no body operation is active, retain operation types 0, 1, and 3, and keep
the chat-text, child-sprite, and text-token paths. Both compute world positions
from the same object fields, apply the player matrix for low-index text, check
player bounds, and forward the same style and color state to the drawing
operation. Spectron adds encoded text and image state, producing 1220 bytes and
51 blocks versus 1128 bytes and 47 blocks in 1.8.

The machine-readable evidence is in
`artifacts/spectron_gani_render_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_render_anchors.py`. All three labels
reopened with zero failures in the v83 disposable copy. The database SHA-256
is
`d9655d74b7e8e1c7cbcaed47d8840ee6274d61fb45fb2c2e75c8875a3b6d862c`.

## 2026-08-26: Spectron Gani frame and playback anchors

The v84 pass reviewed the two largest remaining methods in the Gani runtime.
The source `TGaniObject_setFrame_int` at `0x163354` maps to target `0x16690c`,
`_ZN10ieJzgaIFFy8setFrameEi`. Both begin by selecting the actor frame and
querying the same modifier keys: `dx`, `dy`, `layer`, `visible`, `playerlook`,
`dir`, `ani`, and `chat`. When `playerlook` is absent, both continue through
`head`, `body`, `sword`, `shield`, and `horse`, then process `attr`, `param`,
the color fields, `sprite #`, `file`, `text`, `font`, `color`, `zoom`, and the
text-style flags.

The shared control flow is more informative than the changed compiler
details. Both interpolate adjacent `dx` and `dy` modifiers, map the layer
through the parent level, update visibility and direction, apply an animation
override, parse chat text, and update body or equipment state. The `PARAM` and
`ATTR` sprite selectors resolve through the active Gani, while file and text
values feed the corresponding render fields. The target retains all 28
property literals found in the 1.8 feature export. It is 7068 bytes, 1765
instructions, and 128 blocks, compared with 6552 bytes, 1637 instructions,
and 118 blocks in 1.8.

The source `TGaniObject_playAnimation_void` at `0x164cf8` maps to target
`0x1684b0`, `_ZN10ieJzgaIFFy10zE8FfaRT3NEv`. Both update child Gani, NPC-backed,
and object-list entries through the current frame slot, advance the frame and
animation counters, and handle loop, reset, and end-of-animation reload
behavior. Both inspect active-player action entries, resolve `PARAM` and
`ATTR` sound references, load the resource file, compute the sound position,
and call the audio bridge. The target body is 1452 bytes, 363 instructions,
and 62 blocks, compared with 1396 bytes, 349 instructions, and 61 blocks in
1.8.

These are semantic translations, not byte-identity claims. The extra target
wrappers and state fields change the body sizes and local offsets, but the
property inventory, list traversal, counter updates, resource path, and
audio call remain aligned. The machine-readable evidence is in
`artifacts/spectron_gani_frame_playback_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_frame_playback_anchors.py`. Both
labels reopened with zero failures in a serial v84 IDA check. The database
SHA-256 is
`5ea5746f052d6940b6b7facae87de3875e381828847c57d9c03ac782d867984c`.

## 2026-08-26: Spectron Gani lifecycle anchors

The v85 pass reviewed 50 smaller functions that fill in the Gani object and
TGraalAni lifecycle around the larger runtime methods. This pass is useful for
two reasons. It translates the short methods that the broad matcher left
unmatched, and it clarifies several misleading IDA display names. In
particular, the source entries named `TGaniObject_TGaniObject`,
`TGaniParamProperties_TGaniParamProperties`, and
`TGraalAniProperties_TGraalAniProperties` have alternative D1 destructor
names and destructor pseudocode. The v85 labels use the destructor role rather
than repeating the constructor-shaped display name.

The object-side correspondences are:

| 1.8 role | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TGaniObject_clearChatWrapped_void` | `0x16526c` | `0x168a5c` | text-token child release |
| `TGaniObject` D1 destructor | `0x1652ac` | `0x168af8` | visibility, owner, child lists, strings, base teardown |
| `TGaniObject` D0 destructor | `0x1654e0` | `0x168d48` | destructor plus delete |
| `TLevelObject_getlocalx_void` | `0x1656c0` | `0x168ecc` | local x at offset 112 |
| `TLevelObject_getlocaly_void` | `0x1656c8` | `0x168ed4` | local y at offset 120 |
| `TLevelObject_setAttachedTo_TServerPlayer` | `0x1656d0` | `0x168edc` | attached pointer at offset 144 |
| `TGaniObject_onNewAnimation_void` | `0x1656d8` | `0x168ee4` | empty virtual hook |
| `TGaniObject_onGaniAttributeChanged_int` | `0x1656dc` | `0x168ee8` | empty virtual hook |
| `TGaniObject_onGaniStepChanged_void` | `0x1656e0` | `0x168eec` | empty virtual hook |
| `TGaniObject_getdir_void` | `0x1656e4` | `0x168ef0` | direction at offset 260 |
| `TGaniObject_setdir_int` | `0x1656ec` | `0x168ef8` | direction at offset 260 |
| `TGaniObject_onUpdateColors_void` | `0x1656f4` | `0x168f00` | empty virtual hook |
| `TGaniParamProperties` D1 and thunk | `0x1656f8`, `0x165714` | `0x168f04`, `0x168f20` | base destructor and adjusted this |
| `TGaniObjectProperties` D1 and thunk | `0x16571c`, `0x165738` | `0x168f28`, `0x168f44` | base destructor and adjusted this |
| `TGaniParamProperties` D0 and thunk | `0x165740`, `0x165778` | `0x168f4c`, `0x168f84` | delete pair |
| `TGaniObjectProperties` D0 and thunk | `0x165780`, `0x1657b8` | `0x168f8c`, `0x168fc4` | delete pair |
| `TGaniObject_receiveEvent_script_event` | `0x1657c0` | `0x168fcc` | empty prefix and virtual slot 128 |
| `TColorVar` D1 and D0 | `0x165824`, `0x165838` | `0x169030`, `0x169044` | common Graal-variable base teardown |
| `TGaniObject_receiveEvent` base thunk and string wrapper | `0x165868`, `0x16586c` | `0x169074`, `0x169078` | same temporary event and forwarding slot |

The source and target object helpers preserve exact size, instruction, and
block metrics except for the main GaniObject D1 destructor. That destructor
grows from 564 to 592 bytes and from 34 to 38 blocks because Spectron routes
the same cleanup through rebuilt string, list, script, and ShowImg wrappers.
The target pseudocode still performs the same cleanup in the same order. The
property and color-variable rows retain exact wrapper metrics, including the
non-virtual thunks.

The animation-side correspondences fill in the state and resource path:

| 1.8 role | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TGraalAni_get_continuous` and setter | `0x1658c4`, `0x1658cc` | `0x1690d0`, `0x1690d8` | byte offset 201 |
| `TGraalAni_get_loop` and setter | `0x1658d4`, `0x1658dc` | `0x1690e0`, `0x1690e8` | byte offset 200 |
| `TGraalAni_get_movie` and setter | `0x1658e4`, `0x1658ec` | `0x1690f0`, `0x1690f8` | byte offset 172 |
| `TGraalAni_get_singledirection` | `0x1658f4` | `0x169100` | byte offset 202 |
| `TGraalAni_set_setbackto` and getter | `0x165954`, `0x16595c` | `0x169160`, `0x169168` | string at offset 208 |
| `TGraalAni_clear_void` | `0x165a8c` | `0x1692bc` | sprite, step, owner, and script state reset |
| `TGraalAni` D0 destructor | `0x165db8` | `0x16956c` | destructor plus delete |
| `TGraalAni_addOwner_TGaniObject` | `0x1660f4` | `0x1698a8` | owner-list Add |
| `TGraalAni_removeOwner_TGaniObject` | `0x1660fc` | `0x1698b0` | owner-list Remove |
| `TGraalAni_loadScriptEncrypted_void` | `0x1661b0` | `0x169964` | coded filename, `gani::`, CRC, WantGaniScript |
| `TGraalAni_saveScriptEncrypted_TString_const` | `0x166360` | `0x169b6c` | coded stream and local save |
| `TGraalAni_calcGaniType_void` | `0x166444` | `0x169c6c` | `def`, `bomy_walk`, and 31-name loop |
| `TGraalAni_TGraalAni_TString_const` | `0x16653c` | `0x169d84` | lists, `sprites`, `steps`, and clear |
| `TGraalAni_removeGraalAnis_void` | `0x166860` | `0x16a114` | global cache clear |
| `TGraalAni_loadAni_TString_const_bool` | `0x1668a8` | `0x16a15c` | cache, `.gani`, reload, script, rectangle |
| `TGraalAni_initStaticVars_void` | `0x166cbc` | `0x16a5f0` | global hash-list allocation |
| `TGraalAni_initStaticScriptVars_void` | `0x166cec` | `0x16a620` | property registration |
| `TGraalAniProperties` D1 and thunk | `0x166d30`, `0x166d4c` | `0x16a664`, `0x16a680` | base destructor and adjusted this |
| `TGraalAniProperties` D0 and thunk | `0x166d54`, `0x166d8c` | `0x16a688`, `0x16a6c0` | delete pair |

The seven flag accessors are especially useful because they are exact byte
offset matches even though the target names are only `sub_1690D0` through
`sub_169100`. The target `setbackto` pair also preserves the hidden return
object behavior and the 208-byte string field. The larger `clear` method keeps
all 25 source blocks while shrinking from 552 to 428 bytes as target container
wrappers fold some operations together.

The script and resource methods preserve their important boundaries. The
encrypted loader retains the `gani::` class prefix, local-file check, script
universe insertion, CRC path, and WantGaniScript request. The encrypted saver
keeps the four-block coded-stream writer. The type classifier still tests
`def` and `bomy_walk` and walks 31 names. The constructor still creates the
same sprite and step child arrays, while `loadAni` keeps the cache lookup,
`.gani` load, server request, reload, script load, and visible-rectangle
calculation.

The machine-readable evidence is in
`artifacts/spectron_gani_lifecycle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_lifecycle_anchors.py`. All 50
labels reopened with zero failures in a serial v85 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels and
zero failures. Naming the nine target `sub_` accessors reduced the default
sub-function count from 1,697 to 1,688 without changing the 11,679-function
database. The database SHA-256 is
`5ba0fe1662dc09dc2a0ed20cc917184ccbb971b6c1ee09be66459c8f8f9e3ef6`.

## 2026-08-26: Spectron TPlayer core anchors

The v86 pass moved back to the player class and reviewed two larger methods
that the broad matcher left unmatched. They are important because one
serializes the player properties sent over the game protocol and the other
creates the player object and its default state. Both correspondences are
based on direct Hex-Rays comparisons and preserved class-local structure.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_getNetProperty_int` | `0x1712b8` | `0x1751b8` | same property switch, packet encoding, fields, and literals |
| `TPlayer_TPlayer_int` | `0x1748f0` | `0x178a74` | same constructor order, defaults, child variables, and literals |

The source `TPlayer_getNetProperty_int` method maps to target
`_ZN10W6NzgawMJy10fAkcNaaWZ_Ei`. The target keeps the same large switch over
network property IDs. The shared cases cover the account or name field,
numeric getters, body and shield or sword filename encoding, full Gani name
and parameters, head lookup, five Gani colors, action and direction, level
name selection, player coordinates, animation and status values, and the
default space or whitespace properties. The target also preserves the
`head`, three-space, and four-space literals. The source body is 3476 bytes,
867 instructions, and 187 blocks. The target is 3668 bytes, 916
instructions, and 198 blocks. The increase is consistent with the target
string and wrapper implementations, while the switch and field use remain
aligned.

The source `TPlayer_TPlayer_int` method maps to target
`_ZN10W6NzgawMJyC2Ei`, whose alternative name is the C1 constructor. Both
call the server-player base constructor, install the derived vtable,
initialize the repeated property storage and translation state, publish the
player properties object, create the `client` and `clientr` child variables,
initialize account and nickname state, and set the platform, weapon, and
animation defaults. The target retains all seven shared literals: `android`,
`client`, `clientr`, `idle`, `letters.png`, `selectedlistplayers`, and
`weapons`. Both constructors have 46 basic blocks. The source is 3920 bytes
and 973 instructions, while the target is 4208 bytes and 1044 instructions.

These two labels make the player synchronization boundary easier to follow
from construction through property serialization. They do not, by
themselves, prove that the old client can still authenticate or that the
current server accepts the old property protocol. They are code-translation
findings only.

The machine-readable record is
`artifacts/spectron_tplayer_core_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tplayer_core_anchors.py`. Both labels
reopened with zero failures in the serial v86 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures. The v86 database has 11,679 functions and 1,688 default `sub_`
names. Its SHA-256 is
`92dbca0dbff23332208b4f7411576fbad2a46bed14c1e1d998c69618fc141e12`.

## 2026-08-26: Spectron resource and parser anchors

The v87 pass reviewed three unmatched routines that sit on the resource and
package paths. The group covers the generated Gani lexer, the cached-file
path classifier, and the update-package loader. All three were selected from
direct Hex-Rays comparisons with shared literals and close control-flow
metrics.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `lex_load_TGraalAni` | `0x192ec8` | `0x1979cc` | persistent lexer state, `ATTR`, `PARAM`, and parser alphabet |
| `TCachedStream_getDownloadFilename_TString_const` | `0x1fa920` | `0x2000f8` | 53 shared resource path and extension literals |
| `TUpdatePackage_load_void` | `0x209fa4` | `0x210174` | `GRPKG001`, directive parser, and package state reset |

The generated lexer maps to target `_Z10Qe7BkbfIGXP10Kc8uganwOu`. Both
initialize and reuse the persistent input and output buffers, grow the buffer
table when necessary, restore the current cursor, and enter the same lexer
state machine. The target retains the `ATTR` and `PARAM` tokens and the same
parser alphabet string. The source body is 12748 bytes, 3184 instructions,
and 651 blocks. The target is 12768 bytes, 3188 instructions, and 651
blocks. The near-exact size and block counts make the class-local target
routine a direct correspondence.

The cached-file method maps to target
`_ZN10SDrvgadS3u10t0Nyga0GTxERK10C8THgaTQxF`. Both handle URL markers,
escaped names, encrypted `.enc` paths, update packages, sounds, maps, Gani
files, fonts, paths, translations, GUI styles, music, videos, tiles, images,
emoticons, smilies, help files, hats, body, head, sword, and shield files.
The target preserves all 53 source path and extension literals. The source is
3224 bytes, 803 instructions, and 89 blocks. The target is 3392 bytes, 845
instructions, and 95 blocks. The branch order and output path construction
remain aligned despite the expanded target wrappers.

The update-package method maps to target `_ZN10RH6ygazf9x4loadEv`. Both load
from a cached stream or package file, require the `GRPKG001` header, clear
previous lists and flags, then parse the NAME, FLAG, VERSION, PLATFORM,
DESCRIPTION, FILE, SUBPACKAGE, and checksum directives. The target preserves
all 19 source directive literals, including `DESCRIPTIONEND`,
`ISMAINEXECUTABLE`, `PROTECTOVERWRITE`, `USECHECKSUM`, and `QPlay.box`. Both
methods have 63 blocks. The source is 2024 bytes and 505 instructions; the
target is 2012 bytes and 501 instructions.

Together these anchors connect Gani parsing, local resource placement, and
package metadata handling. They do not prove that a remote download or live
server login will succeed, since this pass used only static local evidence.

The machine-readable record is
`artifacts/spectron_resource_parser_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_resource_parser_anchors.py`. All three
labels reopened with zero failures in the serial v87 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v87 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`fd1ec34b138c0cc18d21d32ba88e865725bde77e5acaa72fa10d80de575afa2d`.

## 2026-08-26: Spectron static utility anchors

The v88 pass reviewed five compact utility methods that the broad matcher
left unmatched. They cover engine statistics, profiler output, GUI button
style extraction, ZIP resource scanning, and translation plural-rule parsing.
Each correspondence has distinctive shared literals and a matching control-
flow shape.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TLogActions_getStats_TString_const_TStringList` | `0xf8890` | `0xfaee8` | statistics sections, filters, and report lines |
| `TProfiler_dumpToList_TStringList` | `0xfa2e0` | `0xfc8d8` | profiler headings and timing format |
| `TGUIStyle_getButton_TString_const` | `0x1cdb8c` | `0x1d277c` | 16 shared style-property literals |
| `TFileNameScan_scanZipResource_TResourceObject` | `0xe8bac` | `0xe96d0` | `.uis` and `~!` archive markers |
| `TTranslationFile_addTranslation_TString_const_TString_const_TString_const` | `0xe3c30` | `0xe47f8` | plural-form header and rules |

The statistics method maps to target
`_ZN10SYX_HaZ3zD10EP5AFabwPBERK10C8THgaTQxFP10vuuHgangcF`. Both build the
system, graphics, memory, profiler, and script sections, with the same
filters, time and client-version lines, platform and CPU lines, memory and
rendering counters, and profiler handoff. The target adds an explicit
`GRAALRELOADED-version` line. Both have 34 blocks. The source body is 1844
bytes and 461 instructions; the target is 1800 bytes and 450 instructions.

The profiler method maps to target
`_ZN10esKIvakHfi10_IfAFaEQ6AEP10vuuHgangcF`. It writes the same ordered
profiler tree and measured timing report, including the six source headings,
suffixes, and format strings. Both have 61 blocks. The source is 1488 bytes
and 371 instructions, while the target is 1368 bytes and 341 instructions.

The GUI style method maps to target
`_ZN10iHmzga6Hmy10T__fIaGC4QERK10C8THgaTQxF`. Both extract the named button
style, parse normal, pressed, disabled, and focus images, and copy bitmap,
frame, tile, border, and progress properties. All 16 style literals are
shared, including `Normal,Pressed,Disabled,Focus`. Both have 23 blocks, with
1428 bytes and 354 instructions in 1.8 versus 1460 bytes and 362 instructions
in the target.

The ZIP resource scanner maps to target
`_ZN10CDPvgaY2nv10c7PvgaJsovEP10bNZvga2Awv`. Both filter archive entries,
recognize `.uis`, and use the `~!` marker path when producing the resource
object. Both have 47 blocks. The source is 1388 bytes and 346 instructions;
the target is 1436 bytes and 358 instructions.

The translation method maps to target
`_ZN10Ztjndb0_dS10Q96mdbXD3RERK10C8THgaTQxFS2_S2_`. Both add a translation
entry, recognize `Plural-Forms:`, `nplurals=2;`, and `plural=n>1;`, and update
the same translation structures. Both have 35 blocks, with the target growing
from 856 to 888 bytes and from 214 to 222 instructions.

The machine-readable record is
`artifacts/spectron_static_utility_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_static_utility_anchors.py`. All five
labels reopened with zero failures in the serial v88 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v88 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`0b27f7a9e63f114eb4db2d59dd677c77002c03ab018c6dc75b53eb4d30f18249`.

## 2026-08-26: Spectron font and bitmap anchors

The v89 pass reviewed four unmatched routines in the font and bitmap path.
This is a useful cluster because the routines retain both their class-local
field layout and the messages emitted while resources are prepared. The
assignments came from direct pseudocode comparison, matching literals, and
close function metrics rather than from an address delta.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TFontCharInfo_setData_TFont_uchar_const_int_int_int_int_int_int` | `0x10d038` | `0x10f988` | glyph dimensions, bitmap rows, `Font `, and `#` texture key |
| `TFont_generateFontBitmap_void` | `0x10d4cc` | `0x10fe58` | atlas placement, texture naming, and graphics diagnostics |
| `TFontData_load_void` | `0x110ca0` | `0x113540` | resource stream, FreeType setup, cleanup, and load errors |
| `TBitmapLoader_load_TResourceObject` | `0x115464` | `0x117e4c` | bitmap load, type retry, failure report, and redownload |

The glyph-data method maps to target
`_ZN10DFeOfaFXSU10u6glKaa0vBEP10TZf6gaQ3S_PKhiiiiii`. Both attach the font,
clamp the dimensions, clear an old bitmap or texture, copy the glyph rows,
and retain the same UTF-8 path and texture-key construction. The `Font ` and
`#` references are shared. The source body is 688 bytes and 171 instructions
with 14 blocks; the target is 716 bytes and 178 instructions with 14 blocks.

The font-atlas method maps to target
`_ZN10TZf6gaQ3S_10fl7q4asNqlEv`. Both place glyphs into the atlas, report the
texture name and size, reject an atlas that cannot fit the font, and use the
same graphics logging path. The shared literals include ` in texture of `,
`, size `, `Couldn't fit font `, and `graphics`. The source is 1016 bytes and
252 instructions with 26 blocks; the target is 1052 bytes and 261 instructions
with 26 blocks.

The font-resource method maps to target
`_ZN10fUWH_a_9zm4loadEv`. Both select the system or resource font path, open a
file or memory stream, initialize a FreeType face, clean up the temporary
objects, and report `Failed to load font ` through the `graphics` channel when
loading fails. The target merges two source-side branches, so it has 34
blocks instead of 36. The source is 1032 bytes and 256 instructions; the
target is 840 bytes and 208 instructions.

The bitmap-loader method maps to target
`_ZN10kM00HafgtE4loadEP10bNZvga2Awv`. Both guard the resource load, record the
operation with the profiler, validate the stream, guess and retry the bitmap
type when needed, load the bitmap, report failures, and request a redownload
when the cached object is unusable. The shared diagnostics include `LoadBitmap`,
`Failed to load `, and `graphics`. Both have 25 blocks. The source is 808
bytes and 199 instructions; the target is 932 bytes and 229 instructions.

The machine-readable record is
`artifacts/spectron_font_bitmap_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_font_bitmap_anchors.py`. All four labels
reopened with zero failures in the serial v89 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures. The v89 database has 11,679 functions and 1,688 default `sub_`
names. Its SHA-256 is
`733ada106f4a4cf74ca88ec309d4b0ae617d601767b197c1acbae4caf51ff1d0`.

## 2026-08-26: Spectron MNG animation decoder anchor

The v90 pass followed the font work into the image-animation cluster and
reviewed the large MNG animation-step decoder that the broad matcher left
unmatched. The target routine is easy to distinguish because it follows the
translated `TMNGAnimationStep` constructor and pixel accessor, and it keeps
the same large pixel-pass algorithm as the 1.8 build.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TMNGAnimation_decode_TMNGAnimationStep` | `0x11b7a0` | `0x11e2d0` | pass geometry, channel branches, row copies, and pixel cleanup |

The target symbol is
`_ZN10_5EhmbQbtm10yVYfmb2R2kEP10FZpembCtKj`. Both methods accept the same
animation-step object, call the corresponding pixel accessor, calculate pass
offsets and lengths, handle the same channel and color-mode branches, copy
rows into the output buffer, and finish with the same temporary-buffer
cleanup. The source calls `memcpy`, `TMNGAnimationStep_getPixelBits_void`,
`png_getpasslength_int_int_int_int`, and `png_getpassoffset_int_int_int_int`.
The target calls `memcpy` plus the three corresponding obfuscated helpers.

Both feature records report 16,324 bytes and 4,081 instructions. The source
has 504 basic blocks and the target has 505. The one-block difference is a
small rebuild change, not a reason to reject the direct correspondence. The
machine-readable record is
`artifacts/spectron_mng_animation_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_mng_animation_anchor.py`. The label
reopened with zero failures in the serial v90 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures. The v90 database has 11,679 functions and 1,688 default `sub_`
names. Its SHA-256 is
`ffd09f3d579539492b3ab27f199e3c2212a6a59062242085c5bf7ca4775335b8`.

## 2026-08-26: Spectron script-machine tail anchors

The v91 pass reviewed two adjacent script-machine methods that remained
outside the earlier execution-machine anchor set. Together they prepare the
arguments for a script function and dispatch a native callback. Their method
boundaries line up exactly in both builds, which makes the pair especially
useful for following the interpreter without relying on the obfuscated names.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_prepareFunctionParameters_TString_const_int` | `0x21acac` | `0x222924` | format decoding, stack conversion, array creation, and string packing |
| `TScriptMachine_callCFunction_TGraalVar_TString_const_void_char_char_const_int` | `0x21b0dc` | `0x222dd4` | native callback argument conversion and multi-parameter dispatch |

The parameter-preparation method maps to
`_ZN10mTAogaaEip10F2qFPaZmt4ERK10C8THgaTQxFi`. Both walk the requested format
string, convert stack entries to float, string, object, or array values, store
those values in the machine list, and join trailing string parameters with
commas. The target adds an `e` parameter case and uses the newer string and
stack-entry wrappers. The source is 1,072 bytes, 267 instructions, and 50
blocks; the target is 1,200 bytes, 299 instructions, and 51 blocks.

The native callback method maps to
`_ZN10mTAogaaEip10icnYOaW7ouEP10G0gxgajWBwRK10CanTfaz6bZPvcPKci`. Both decode
the same format characters, fetch values from the machine list, convert
integer and boolean values, read object values, and call the native function
with up to twelve converted parameters. The target adds a guarded static
string workspace and an `e` format branch, so its body is larger. The source
is 2,496 bytes, 618 instructions, and 100 blocks; the target is 3,412 bytes,
847 instructions, and 124 blocks.

In 1.8 the first method ends at `0x21b0dc`, exactly where the callback method
starts. Spectron preserves the same boundary at `0x222dd4`. Both target
methods remain in the `mTAogaaEip` script-machine class and the callback method
ends immediately before the translated suspend-after-call helper. The
machine-readable record is
`artifacts/spectron_script_machine_tail_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_machine_tail_anchors.py`. Both
labels reopened with zero failures in the serial v91 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v91 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`1626932aed2ab1d56d21a788f71ed8587ec3d1041b473978a09ee1cb808f3aec`.

## 2026-08-26: Spectron script stream and profile anchors

The v92 pass reviewed two remaining `TScript` methods in the obfuscated
`zW2NgaU4IK` target class. They are separate from the earlier execution
machine work, but they are useful for understanding how the script package is
loaded and how the built-in profiler reports its results.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScript_setStream_TString_const` | `0x21624c` | `0x21cfb8` | bytecode record walk, `public.` handling, parameter parsing, and function registration |
| `TScript_printFunctionProfiles_TStringList_TString_const` | `0x217168` | `0x21e058` | elapsed-time calculation, percentage formatting, sorting, and nested `Class ` output |

The stream parser maps to
`_ZN10zW2NgaU4IK10pKjZfaKdc3ERK10C8THgaTQxF`. Both methods reset the script,
create a temporary string list, walk the script byte stream, decode class and
function records, recognize the `public.` marker, parse parameter types, add
functions, and call the script-updated hook. The source measures 2,380 bytes,
594 instructions, and 110 blocks. The target measures 2,400 bytes, 599
instructions, and 110 blocks. Both feature records contain 67 calls and the
same `public.` string reference.

The profile printer maps to
`_ZN10zW2NgaU4IK10JkKVfa5Ab0EP10vuuHgangcFRK10C8THgaTQxF`. Both methods check
the output list and profiling state, compute elapsed time, clear stale hash
lists, format and sort function percentages, and then emit nested class and
function profile lines. The source measures 1,092 bytes, 272 instructions,
and 24 blocks with 59 calls and the string references ` %` and `Class `. The
target measures 1,176 bytes, 293 instructions, and 24 blocks with 65 calls. It
retains `Class ` but does not expose a separate `%` string reference. The
target's long-double temporaries and rebuilt C8THgaTQxF, vuuHgangcF, hash, and
iterator wrappers account for the remaining surface differences. Direct
pseudocode comparison shows the same profiler sequence, so the missing
standalone percent reference is recorded as a build or decompiler difference,
not as a rejected match.

The machine-readable record is
`artifacts/spectron_script_stream_profile_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_stream_profile_anchors.py`. Both
labels reopened with zero failures in the serial v92 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v92 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`b6e314fe73ccbd43815c32fe690208460140593230aa99251fdb3b7f977641a1`.

## 2026-08-26: Spectron generated animation-lexer fatal callback

The v93 pass reviewed the one remaining default-style animation lexer helper
from the residual application-role audit. The source helper is called from
the generated `lex_load_TGraalAni` scanner, which was already translated in
the resource-parser pass. The corresponding Spectron scanner at `0x1979cc`
calls the target helper directly.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `ani_lexer_fatalExit` | `0x1925e4` | `0x19af5c` | no-return exit wrapper called by the generated lexer |

The target symbol is `_ZN10QYZugaRKGu10RzQ_IaWQttEv`. Both wrappers measure
16 bytes, 4 instructions, and 1 basic block with one direct `exit` call and no
string references. The source pseudocode is `exit(2)` and the target
pseudocode is `exit(0)`. The changed status is a real target-version behavior
difference, but the callback role is clear from the direct call from the
corresponding generated scanner.

The target helper is not adjacent to the target lexer. Spectron places it
after `loadGaniFromString`, so the direct generated-lexer call relationship is
the decisive evidence. The surrounding source and target lexer records still
match closely: 12,748 versus 12,768 bytes, 3,184 versus 3,188 instructions,
651 blocks in both builds, and the same `ATTR`, `PARAM`, and scanner alphabet
references. The existing lexer anchor is not duplicated in this pass.

The machine-readable record is
`artifacts/spectron_ani_lexer_fatal_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_ani_lexer_fatal_anchor.py`. The label
reopened with zero failures in the serial v93 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures. The v93 database has 11,679 functions and 1,688 default `sub_`
names. Its SHA-256 is
`f48b51d672bd6d7cd57316f09312b9e90d22144ef61ddf473b6cabfb9d66722c`.

## 2026-08-26: Spectron numeric-array string anchors

The v94 pass reviewed eight methods from the double and short instantiations
of Spectron's obfuscated numeric-array template. This is a useful small family
because the source names describe the operation clearly, while the stripped
target preserves the same access pattern, virtual setter slot, and template
pairing.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TNumberArrayVar_double_setArrayCellString_int_TString_const` | `0x18a318` | `0x18eb08` | string-to-number conversion and indexed virtual setter |
| `TNumberArrayVar_double_getArrayCellString_int` | `0x18a440` | `0x18ebac` | indexed getter and numeric string formatting |
| `TNumberArrayVar_double_readString_void` | `0x18a3bc` | `0x18ec04` | array walk with comma-separated output |
| `TNumberArrayVar_double_writeString_TString_const` | `0x18a474` | `0x18eca8` | string-list split and per-index setter |
| `TNumberArrayVar_short_setArrayCellString_int_TString_const` | `0x1abb50` | `0x1afca0` | string-to-number conversion and indexed virtual setter |
| `TNumberArrayVar_short_getArrayCellString_int` | `0x1abd28` | `0x1afe78` | indexed getter and numeric string formatting |
| `TNumberArrayVar_short_readString_void` | `0x1abe00` | `0x1affa0` | array walk with comma-separated output |
| `TNumberArrayVar_short_writeString_TString_const` | `0x1abd5c` | `0x1afed0` | string-list split and per-index setter |

The four double targets use the obfuscated `PfQXva4zXuIdE` template name and
the four short targets use `PfQXva4zXuIsE`. The indexed string setters are
the closest matches in shape: each source and target body is 64 bytes, 16
instructions, and one basic block with two calls. The source uses the known
`strtofloat` helper, while the target uses its rebuilt `nak8fakACb` helper.
In both builds the parsed value is passed to the array's virtual string setter
at the requested index.

The indexed string reads are 52 bytes, 13 instructions, and one block with
two calls in 1.8. Both target versions expand to 88 bytes, 22 instructions,
and one block with four calls. The extra calls are consistent with the target's
explicit `C8THgaTQxF` temporary and string assignment or clear operations.
The double and short target names share the `J89mga585nEi` method suffix,
which mirrors the source pair's shared operation while preserving the element
template in the class name.

The comma-separated `readString` methods are 132 bytes, 33 instructions, and
five blocks with two calls in 1.8. Both targets are 164 bytes, 41 instructions,
and six blocks with four calls. The pseudocode in each build walks the stored
count and data pointer, formats each element, and inserts commas between
elements. The double target uses the numeric formatter and the short target
uses the integer formatter. The target's `VkenganG9n` methods make the rebuilt
temporary string wrapper visible without changing the loop's role.

The string-list writers are 164 bytes, 41 instructions, and three blocks with
six calls in 1.8. Both targets are 208 bytes, 52 instructions, and three blocks
with ten calls. Each method splits the input into a temporary list, iterates
over the list, calls the array's virtual string setter for each index, and
releases the temporary list. The target's `C8THgaTQxF`, `CanTfaz6bZ`, and
`vuuHgangcF` wrapper operations account for the larger body and call count.

The machine-readable record is
`artifacts/spectron_number_array_string_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_number_array_string_anchors.py`. All
eight labels reopened with zero failures in the serial v94 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v94 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`44e98e90efabe2ed93ea5b7c9b53797a12aa4c4147e34891f0403a0d5ec1daae`.

## 2026-08-26: Spectron client-environment clock anchors

The v95 pass reviewed two adjacent methods in the obfuscated
`a7qxJaHqKV` client-environment class. They are useful to the runtime audit
because they control the old client date check and preserve clear libc call
sequences even though the target symbols are stripped.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TClientEnvironment_BuildTime_void` | `0x15d3a8` | `0x1603f4` | time, localtime, date-field setup, and mktime |
| `TClientEnvironment_TimeExpired_void` | `0x15d3ec` | `0x160458` | expiry gates, current time, BuildTime call, and difftime |

`TClientEnvironment_BuildTime_void` is 68 bytes, 17 instructions, and one
block with three calls in 1.8. The target is 100 bytes, 25 instructions, and
one block with the same three calls to `time`, `localtime`, and `mktime`. The
source writes `tm_year=119`, `tm_mon=1`, and `tm_mday=13`, which produces the
fixed 2019-02-13 date. The target writes
`tm_year=otezibkNfe-1900`, `tm_mon=ATGyibuHNd-1`, and `tm_mday=gQsyibySBd`,
so the date is supplied through target globals instead of source literals.

`TClientEnvironment_TimeExpired_void` is 132 bytes, 33 instructions, and
five blocks with three calls in 1.8. The target is 164 bytes, 41 instructions,
and five blocks with the same three logical calls. Both check an enable flag
and a cached not-expired flag, read the current time, call BuildTime, compare
with `difftime`, and clear the cached state when the expiry window has passed.
The source compares against 1,296,000 seconds, or 15 days. Spectron computes
the threshold from `zvCzibh0ze * 24 * 60 * 60`. Its equivalent state globals are
`jfnzibtane` and `G7szibc7re`, and the target directly calls the newly labeled
`LvYNBatwEp` helper.

The target's extra instructions are used for global date and day-count loads,
including the floating-point multiply sequence. They do not change the
surrounding client-environment class order or the expiry control flow. The
machine-readable record is
`artifacts/spectron_client_environment_clock_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_environment_clock_anchors.py`.
Both labels reopened with zero failures in the serial v95 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v95 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`79f62371f6ddbecdb94c923918126b1a9c109e18bcea0771163bb41c0bd8407f`.

## 2026-08-26: Spectron client-variable core anchors

The v96 pass reviewed three remaining methods in the stripped `znLtuaytEf`
client-variable class. Their placement immediately follows the translated
constructor and child-creation methods, and their pseudocode retains the
important send and change-suppression relationships from `TGraalClientVar`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TGraalClientVar_send_void` | `0x166ee8` | `0x16a81c` | dotted child-name construction, zero-value unset, and flag send |
| `TGraalClientVar_writeString_TString_const` | `0x1670c0` | `0x16aa24` | cached string equality, base write, and send on change |
| `TGraalClientVar_setArrayCellString_int_TString_const` | `0x1671b4` | `0x16ab54` | indexed value equality, base setter, and send on change |

The send method is 400 bytes, 100 instructions, and 12 blocks with 18 calls
in 1.8. The target is 448 bytes, 112 instructions, and 12 blocks with 22
calls. Both check that a client exists, honor the do-not-send flag, walk the
parent chain to build a dotted name, read the current value through the same
vtable slot, and choose between sending a flag or unsetting it when the value
is empty or equal to `0`. The target's `C8THgaTQxF` conversions and explicit
temporary cleanup account for the larger body.

The string writer is 100 bytes, 25 instructions, and five blocks with two
calls in 1.8. The target is 96 bytes, 24 instructions, and five blocks with
two calls. Both suppress the write when the variable is type 2 and the new
string equals the cached value. Otherwise they call the base string writer
and then send the changed variable. The target uses `CanTfaz6bZ::Equals` and
the obfuscated base method `G0gxgajWBw::m6pngaXzjo`.

The indexed string writer is 120 bytes, 30 instructions, and three blocks with
five calls in 1.8. The target is 152 bytes, 38 instructions, and three blocks
with seven calls. Both read the current array-cell string through vtable slot
232, compare it to the new value, and call the base setter plus `send` only
when the value changes. The target makes the temporary string conversion
explicit and uses the same target `send` anchor at `0x16a81c`.

The machine-readable record is
`artifacts/spectron_client_var_core_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_var_core_anchors.py`. All three
labels reopened with zero failures in the serial v96 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v96 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`343ea4a80616c6f53b1b7233ad339e44830cd084086bd4bd6204a18bdd5a1af3`.

## 2026-08-26: Spectron TDrawingPanel residual anchors

The v108 pass reviewed six remaining methods in the source `TDrawingPanel`
class. The target methods remain in the obfuscated `V8fxgahcBw` class, with
translated panel initialization, primitive drawing, operation, and image-save
methods providing the surrounding class context.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TDrawingPanel_TDrawingPanel_TString_const` | `0x117bec` | `0x11a64c` | base construction and panel initialization |
| `TDrawingPanel_TDrawingPanel_TString_const_bool` | `0x117c28` | `0x11a6b4` | bool constructor overload |
| `TDrawingPanel_drawImage_Impl_int_int_TString_const` | `0x1191d4` | `0x11bc84` | tiles special case and image forwarding |
| `TDrawingPanel_drawImageRectangle_Impl_int_int_TString_const_int_int_int_int` | `0x1192f0` | `0x11bdd4` | rectangle forwarding and outside fill |
| `TDrawingPanel_filterRectangle_Impl_int_int_int_int_TString_const` | `0x11a48c` | `0x11cf8c` | six filter names and filter dispatch |
| `TDrawingPanel_setDrawPaletteNamed_TString_const_int` | `0x11a6a8` | `0x11d1ac` | color lookup and palette slot storage |

The string and bool constructors are 60/15/2 and 68/17/2 with one direct
base-constructor call each in 1.8. Their target C2 and C1 counterparts are
both 104/26/1 with four calls. The target preserves the `TGraalVar` base,
derived-vtable installation, and panel initialization path. The extra target
calls are explicit string, profile, and panel wrappers.

The image implementation changes from 184/46/4 with four calls to 236/59/4
with six calls. The image-rectangle implementation changes from 252/63/4 with
five calls to 284/71/4 with seven calls. Both retain the `tiles` branch,
texture-size query, forwarding to the six-argument image routine, and temporary
name cleanup. The rectangle variant also retains the outside-rectangle fill.

The filter implementation changes from 536/133/19 with 17 calls to
540/134/19 with 17 calls. Both refresh the panel, lower-case the requested
name, and select among `gray`, `nightgoggle`, `negative`, `updown`,
`blackwhite`, and `lesscolors`. Spectron uses its `EYMwkbFObT` image-filter
class and rebuilt string-list wrappers.

The palette method changes from 204/51/5 with eight calls to 208/52/5 with
eight calls. Both parse the palette string, resolve the named color, select
the requested slot, and clean up the temporary list. The target uses
`Q9LCGaX7dt`, `vuuHgangcF`, and `V8fxgahcBw` wrappers.

The machine-readable record is
`artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_drawing_panel_residual_anchors.py`. All
six labels reopened with zero failures in the serial v108 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v108 database has 1,684
remaining default `sub_` names. Its SHA-256 is
`8350a43be6b31306954e34a17f77d742c8d1702015d671019d2bf2dd6c1bb1e1`.

## 2026-08-27: Spectron TServerPlayer scalar accessor block

The v157 pass translates the contiguous scalar accessor block at the front of
the 1.8 `TServerPlayer` implementation. It contains 37 alternating getters
and setters for health, inventory, combat power, movement flags, and visibility
state. The target block is the corresponding obfuscated `MpGzgariDy` class
block.

| 1.8 function | Source | Spectron target | Source field | Target field |
| --- | ---: | ---: | ---: | ---: |
| `TServerPlayer_getHP_void` | `0x18a1a4` | `0x18e98c` | 680 | 704 |
| `TServerPlayer_setHP_double` | `0x18a1ac` | `0x18e994` | 680 | 704 |
| `TServerPlayer_getMaxHP_void` | `0x18a1b4` | `0x18e99c` | 688 | 712 |
| `TServerPlayer_setMaxHP_int` | `0x18a1bc` | `0x18e9a4` | 688 | 712 |
| `TServerPlayer_getGralats_void` | `0x18a1c4` | `0x18e9ac` | 692 | 716 |
| `TServerPlayer_setGralats_int` | `0x18a1cc` | `0x18e9b4` | 692 | 716 |
| `TServerPlayer_getBombsCount_void` | `0x18a1d4` | `0x18e9bc` | 696 | 720 |
| `TServerPlayer_setBombsCount_int` | `0x18a1dc` | `0x18e9c4` | 696 | 720 |
| `TServerPlayer_getArrows_void` | `0x18a1e4` | `0x18e9cc` | 700 | 724 |
| `TServerPlayer_setArrows_int` | `0x18a1ec` | `0x18e9d4` | 700 | 724 |
| `TServerPlayer_getGlovePower_void` | `0x18a1f4` | `0x18e9dc` | 704 | 728 |
| `TServerPlayer_setGlovePower_int` | `0x18a1fc` | `0x18e9e4` | 704 | 728 |
| `TServerPlayer_getSwordPower_void` | `0x18a204` | `0x18e9ec` | 708 | 732 |
| `TServerPlayer_setSwordPower_int` | `0x18a20c` | `0x18e9f4` | 708 | 732 |
| `TServerPlayer_getShieldPower_void` | `0x18a214` | `0x18e9fc` | 712 | 736 |
| `TServerPlayer_setShieldPower_int` | `0x18a21c` | `0x18ea04` | 712 | 736 |
| `TServerPlayer_getAlignment_void` | `0x18a224` | `0x18ea0c` | 716 | 740 |
| `TServerPlayer_setAlignment_int` | `0x18a22c` | `0x18ea14` | 716 | 740 |
| `TServerPlayer_getMagicPoints_void` | `0x18a234` | `0x18ea1c` | 720 | 744 |
| `TServerPlayer_setMagicPoints_int` | `0x18a23c` | `0x18ea24` | 720 | 744 |
| `TServerPlayer_getCarrySprite_void` | `0x18a244` | `0x18ea2c` | 724 | 748 |
| `TServerPlayer_setCarrySprite_int` | `0x18a24c` | `0x18ea34` | 724 | 748 |
| `TServerPlayer_getWeaponsEnabled_void` | `0x18a254` | `0x18ea3c` | 728 | 752 |
| `TServerPlayer_setWeaponsEnabled_bool` | `0x18a25c` | `0x18ea44` | 728 | 752 |
| `TServerPlayer_getDefaultMovement_void` | `0x18a264` | `0x18ea4c` | 729 | 753 |
| `TServerPlayer_setDefaultMovement_bool` | `0x18a26c` | `0x18ea54` | 729 | 753 |
| `TServerPlayer_getEnabledFeatures_void` | `0x18a274` | `0x18ea5c` | 732 | 756 |
| `TServerPlayer_setEnabledFeatures_int` | `0x18a27c` | `0x18ea64` | 732 | 756 |
| `TServerPlayer_getPaused_void` | `0x18a284` | `0x18ea6c` | 736 | 760 |
| `TServerPlayer_getDead_void` | `0x18a28c` | `0x18ea74` | 737 | 761 |
| `TServerPlayer_setDead_bool` | `0x18a294` | `0x18ea7c` | 737 | 761 |
| `TServerPlayer_getIsHurt_void` | `0x18a29c` | `0x18ea84` | 738 | 762 |
| `TServerPlayer_setIsHurt_bool` | `0x18a2a4` | `0x18ea8c` | 738 | 762 |
| `TServerPlayer_getHidden_void` | `0x18a2ac` | `0x18ea94` | 739 | 763 |
| `TServerPlayer_setHidden_bool` | `0x18a2b4` | `0x18ea9c` | 739 | 763 |
| `TServerPlayer_getSwordHidden_void` | `0x18a2bc` | `0x18eaa4` | 740 | 764 |
| `TServerPlayer_setSwordHidden_bool` | `0x18a2c4` | `0x18eaac` | 740 | 764 |

The two blocks are both contiguous and use the same 8-byte, 2-instruction
function shape throughout. The target address delta is `+0x47e8`, and the
object-field delta is `+24` for every row. The field sequence is especially
useful because it survives the 2.2 object expansion: the target getter and
setter for each property still touch the same logical slot, only at the
expanded offset.

The first target getter decompiles to a double read at field 704, matching the
source health read at 680. The paired health setter writes the same field. The
middle combat and inventory pairs advance through the same four-byte fields,
and the final boolean pairs preserve the byte fields for paused, dead, hurt,
hidden, and sword-hidden state. The next target function after the block is a
different class helper, so the boundary is independently visible in both
builds.

All 37 target symbols already had non-default obfuscated C++ names. The
artifact therefore adds searchable `v18_` aliases without changing the
function count or default `sub_` count. All names reopened successfully, and
the full semantic map check remains at zero failures.

The machine-readable record is
`artifacts/spectron_tserverplayer_accessor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tserverplayer_accessor_anchors.py`. The labels are
persisted in
`analysis/spectron_libqplay_translated_v157.i64`, whose SHA-256 is
`6daaa47e8ee98b08a5e447e86790b3e05f5828fa0cfb0d9e97f99e7b857ca3fc`.

## 2026-08-27: Spectron CyaInt TLS residual anchors, batch two

The v156 pass finishes the CyaInt residual work with 53 more exact-shape
anchors. These rows were not accepted merely because they sat at a convenient
offset. Each source address plus `0xd590` resolves to a target function whose
retained C++ mangled name identifies the same method, and the complete feature
fingerprint is identical in both builds.

| 1.8 function | Source | Spectron target | Role |
| --- | ---: | ---: | --- |
| `CyaInt_CheckRunTimeSettings_void` | `0x2b8bb0` | `0x2c6140` | runtime settings |
| `CyaInt_RsaPrivateDecrypt_uchar_const_uint_uchar_uint_CyaInt_RsaKey` | `0x2bfbf0` | `0x2cd180` | RSA private decrypt |
| `CyaInt_RsaSSL_Verify_uchar_const_uint_uchar_uint_CyaInt_RsaKey` | `0x2bffa4` | `0x2cd534` | RSA signature verify |
| `CyaInt_RsaEncryptSize_CyaInt_RsaKey` | `0x2c0404` | `0x2cd994` | RSA size query |
| `CyaInt_CyaSSL_SetIORecv_CyaInt_CYASSL_CTX_int_CyaInt_CYASSL_char_int_void` | `0x2c386c` | `0x2d0dfc` | receive callback |
| `CyaInt_CyaSSL_SetIOSend_CyaInt_CYASSL_CTX_int_CyaInt_CYASSL_char_int_void` | `0x2c3874` | `0x2d0e04` | send callback |
| `CyaInt_CyaSSL_SetIOReadCtx_CyaInt_CYASSL_void` | `0x2c387c` | `0x2d0e0c` | read context |
| `CyaInt_CyaSSL_SetIOWriteCtx_CyaInt_CYASSL_void` | `0x2c3884` | `0x2d0e14` | write context |
| `CyaInt_CyaSSL_SetIOReadFlags_CyaInt_CYASSL_int` | `0x2c388c` | `0x2d0e1c` | read flags |
| `CyaInt_CyaSSL_SetIOWriteFlags_CyaInt_CYASSL_int` | `0x2c3894` | `0x2d0e24` | write flags |
| `CyaInt_CyaSSL_CTX_free_CyaInt_CYASSL_CTX` | `0x2c395c` | `0x2d0eec` | context free |
| `CyaInt_CyaSSL_free_CyaInt_CYASSL` | `0x2c39cc` | `0x2d0f5c` | TLS object free |
| `CyaInt_CyaSSL_get_fd_CyaInt_CYASSL_const` | `0x2c39fc` | `0x2d0f8c` | file descriptor |
| `CyaInt_CyaSSL_get_using_nonblock_CyaInt_CYASSL` | `0x2c3a14` | `0x2d0fa4` | nonblocking getter |
| `CyaInt_CyaSSL_dtls_CyaInt_CYASSL` | `0x2c3a1c` | `0x2d0fac` | DTLS mode |
| `CyaInt_CyaSSL_dtls_set_peer_CyaInt_CYASSL_void_uint` | `0x2c3a24` | `0x2d0fb4` | DTLS peer setter |
| `CyaInt_CyaSSL_dtls_get_peer_CyaInt_CYASSL_void_uint` | `0x2c3a2c` | `0x2d0fbc` | DTLS peer getter |
| `CyaInt_CyaSSL_GetObjectSize_void` | `0x2c3a34` | `0x2d0fc4` | object size |
| `CyaInt_CyaSSL_send_CyaInt_CYASSL_void_const_int_int` | `0x2c3c34` | `0x2d11c4` | TLS send |
| `CyaInt_CyaSSL_recv_CyaInt_CYASSL_void_int_int` | `0x2c3c64` | `0x2d11f4` | TLS receive |
| `CyaInt_CyaSSL_want_read_CyaInt_CYASSL` | `0x2c3d80` | `0x2d1310` | read wait state |
| `CyaInt_CyaSSL_want_write_CyaInt_CYASSL` | `0x2c3d90` | `0x2d1320` | write wait state |
| `CyaInt_CyaSSL_pending_CyaInt_CYASSL` | `0x2c3f14` | `0x2d14a4` | pending bytes |
| `CyaInt_CyaSSL_CTX_set_group_messages_CyaInt_CYASSL_CTX` | `0x2c3f1c` | `0x2d14ac` | context grouping |
| `CyaInt_CyaSSL_set_group_messages_CyaInt_CYASSL` | `0x2c3f3c` | `0x2d14cc` | connection grouping |
| `CyaInt_CyaSSL_CTX_check_private_key_CyaInt_CYASSL_CTX` | `0x2c5380` | `0x2d2910` | private-key check |
| `CyaInt_CyaSSL_CTX_set_verify_CyaInt_CYASSL_CTX_int_int_int_CyaInt_CYASSL_X509_STORE_CTX` | `0x2c541c` | `0x2d29ac` | context verify mode |
| `CyaInt_CyaSSL_set_verify_CyaInt_CYASSL_int_int_int_CyaInt_CYASSL_X509_STORE_CTX` | `0x2c5458` | `0x2d29e8` | connection verify mode |
| `CyaInt_CyaSSL_load_error_strings_void` | `0x2c54a8` | `0x2d2a38` | error strings |
| `CyaInt_CyaSSL_dtls_get_current_timeout_CyaInt_CYASSL` | `0x2c5578` | `0x2d2b08` | DTLS timeout |
| `CyaInt_CyaSSL_dtls_got_timeout_CyaInt_CYASSL` | `0x2c5580` | `0x2d2b10` | timeout notification |
| `CyaInt_CyaSSLv3_client_method_void` | `0x2c5588` | `0x2d2b18` | SSL 3.0 method |
| `CyaInt_CyaSSL_flush_sessions_CyaInt_CYASSL_CTX_long` | `0x2c5950` | `0x2d2ee0` | session flush |
| `CyaInt_CyaSSL_set_timeout_CyaInt_CYASSL_uint` | `0x2c5954` | `0x2d2ee4` | connection timeout |
| `CyaInt_CyaSSL_CTX_set_timeout_CyaInt_CYASSL_CTX_uint` | `0x2c596c` | `0x2d2efc` | context timeout |
| `CyaInt_CyaSSL_set_compression_CyaInt_CYASSL` | `0x2c5e4c` | `0x2d33dc` | compression setting |
| `CyaInt_CyaSSL_X509_get_issuer_name_CyaInt_CYASSL_X509` | `0x2c61d4` | `0x2d3764` | X.509 issuer |
| `CyaInt_CyaSSL_session_reused_CyaInt_CYASSL` | `0x2c629c` | `0x2d382c` | session reuse |
| `CyaInt_CyaSSL_get_current_cipher_CyaInt_CYASSL` | `0x2c6360` | `0x2d38f0` | current cipher |
| `CyaInt_CyaSSL_get_cipher_CyaInt_CYASSL` | `0x2c64d8` | `0x2d3a68` | cipher name |
| `CyaInt_CyaSSL_X509_free_CyaInt_CYASSL_X509` | `0x2c64f0` | `0x2d3a80` | X.509 free |
| `CyaInt_CyaSSL_X509_get_subjectCN_CyaInt_CYASSL_X509` | `0x2c64f4` | `0x2d3a84` | X.509 subject CN |
| `CyaInt_CyaSSL_CTX_OCSP_set_options_CyaInt_CYASSL_CTX_long` | `0x2c6504` | `0x2d3a94` | OCSP options |
| `CyaInt_CyaSSL_CTX_OCSP_set_override_url_CyaInt_CYASSL_CTX_char_const` | `0x2c650c` | `0x2d3a9c` | OCSP override URL |
| `CyaInt_MakeTLSv1_2_void` | `0x2c706c` | `0x2d45fc` | TLS 1.2 selector |
| `CyaInt_CyaTLSv1_client_method_void` | `0x2c7d44` | `0x2d52d4` | TLS 1.0 method |
| `CyaInt_CyaTLSv1_1_client_method_void` | `0x2c7d7c` | `0x2d530c` | TLS 1.1 method |
| `CyaInt_CyaTLSv1_2_client_method_void` | `0x2c7db4` | `0x2d5344` | TLS 1.2 method |
| `CyaInt_LowResTimer_void` | `0x2c906c` | `0x2d65fc` | low-resolution timer |
| `CyaInt_InitMutex_int` | `0x2ccbc4` | `0x2da154` | mutex initialization |
| `CyaInt_FreeMutex_int` | `0x2cccbc` | `0x2da24c` | mutex release |
| `CyaInt_LockMutex_int` | `0x2cccc4` | `0x2da254` | mutex lock |
| `CyaInt_UnLockMutex_int` | `0x2ccccc` | `0x2da25c` | mutex unlock |

The RSA verifier is a particularly useful checkpoint. Both builds allocate a
copy of the input, call the inline verifier, enforce the caller's output-size
limit, clear the temporary buffer, and free it. The target only replaces the
source PLT-prefixed calls with direct CyaInt method names. The I/O setter pair
stores the callback pointers at the same CyaSSL object fields. The two
verification-mode methods preserve the same flag decoding into offsets 360,
361, 362, and 392. The TLS 1.2 client-method constructor still allocates a
four-byte method object, obtains the protocol selector, and initializes it.

The X.509 issuer accessor is a one-instruction null body in both exports, and
the mutex lock wrapper returns zero in both. Those tiny rows still matter: a
single missing function can make a class-local audit look incomplete, and the
exact target names confirm that they are intentional stubs rather than lost
IDA boundaries.

This second batch is deliberately kept separate from the first 30-row CyaInt
artifact. The generator checks the prior artifact for duplicate source or
target addresses, checks the semantic map for overlap, and records the prior
artifact hash. All 53 rows are new, exact-shape, high-confidence anchors.
The v156 copy reopened all 53 names successfully, and the full semantic map
reopen check remains clean.

The v156 labels are persisted in
`analysis/spectron_libqplay_translated_v156.i64`. The database has 11,693
functions and 1,396 default `sub_` names because every target already had a
non-default C++ symbol. Its SHA-256 is
`addc91603c90f9dff6653fcf9d18dd636731237585549f4461efe7a6f7a6bd91`. The
machine-readable record is
`artifacts/spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_cyaint_tls_residual_v2_anchors.py`.

## 2026-08-27: Spectron CyaInt TLS residual anchors

The v155 pass moves the translation work into the native TLS implementation.
It covers 30 residual `CyaInt` methods that the broad semantic matcher had
left unmatched even though the two builds preserve unusually strong evidence.
The source and target functions have identical size, instruction count,
basic-block count, branch count, call count, mnemonic hash, opcode-shape hash,
register-shape hash, overall shape hash, and string-reference hash. The target
addresses all equal the source addresses plus `0xd590`.

| 1.8 function | Source | Spectron target | Role |
| --- | ---: | ---: | --- |
| `CyaInt_mp_dr_setup_CyaInt_mp_int_uint` | `0x2bb418` | `0x2c89a8` | Montgomery-reduction setup |
| `CyaInt_CyaSSL_set_using_nonblock_CyaInt_CYASSL_int` | `0x2c3a04` | `0x2d0f94` | nonblocking mode |
| `CyaInt_CyaSSL_get_alert_history_CyaInt_CYASSL_CyaInt_CYASSL_ALERT_HISTORY` | `0x2c3d64` | `0x2d12f4` | alert history |
| `CyaInt_CyaSSL_ERR_error_string_n_ulong_char_ulong` | `0x2c3dd8` | `0x2d1368` | error text |
| `CyaInt_CyaSSL_KeepArrays_CyaInt_CYASSL` | `0x2c3de4` | `0x2d1374` | array retention |
| `CyaInt_CyaSSL_CTX_load_verify_locations_CyaInt_CYASSL_CTX_char_const_char_const` | `0x2c520c` | `0x2d279c` | verification path |
| `CyaInt_CyaSSL_CertManagerEnableCRL_CyaInt_CYASSL_CERT_MANAGER_int` | `0x2c5354` | `0x2d28e4` | enable CRL |
| `CyaInt_CyaSSL_CertManagerDisableCRL_CyaInt_CYASSL_CERT_MANAGER` | `0x2c5368` | `0x2d28f8` | disable CRL |
| `CyaInt_CyaSSL_CTX_SetCACb_CyaInt_CYASSL_CTX_void_uchar_int_int` | `0x2c5494` | `0x2d2a24` | CA callback |
| `CyaInt_CyaSSL_get_session_CyaInt_CYASSL` | `0x2c5b78` | `0x2d3108` | session getter |
| `CyaInt_CyaSSL_set_session_CyaInt_CYASSL_CyaInt_CYASSL_SESSION` | `0x2c5c20` | `0x2d31b0` | session setter |
| `CyaInt_CyaSSL_CTX_use_certificate_buffer_CyaInt_CYASSL_CTX_uchar_const_long_int` | `0x2c612c` | `0x2d36bc` | certificate buffer |
| `CyaInt_CyaSSL_CTX_use_PrivateKey_buffer_CyaInt_CYASSL_CTX_uchar_const_long_int` | `0x2c6140` | `0x2d36d0` | private-key buffer |
| `CyaInt_CyaSSL_CTX_use_certificate_chain_buffer_CyaInt_CYASSL_CTX_uchar_const_long` | `0x2c6154` | `0x2d36e4` | certificate chain |
| `CyaInt_CyaSSL_use_certificate_buffer_CyaInt_CYASSL_uchar_const_long_int` | `0x2c616c` | `0x2d36fc` | certificate buffer |
| `CyaInt_CyaSSL_use_PrivateKey_buffer_CyaInt_CYASSL_uchar_const_long_int` | `0x2c6184` | `0x2d3714` | private-key buffer |
| `CyaInt_CyaSSL_use_certificate_chain_buffer_CyaInt_CYASSL_uchar_const_long` | `0x2c619c` | `0x2d372c` | certificate chain |
| `CyaInt_CyaSSL_is_init_finished_CyaInt_CYASSL` | `0x2c61b8` | `0x2d3748` | initialization state |
| `CyaInt_CyaSSL_X509_get_subject_name_CyaInt_CYASSL_X509` | `0x2c61d8` | `0x2d3768` | X.509 subject |
| `CyaInt_CyaSSL_get_peer_certificate_CyaInt_CYASSL` | `0x2c6270` | `0x2d3800` | peer certificate |
| `CyaInt_CyaSSL_get_shutdown_CyaInt_CYASSL_const` | `0x2c6284` | `0x2d3814` | shutdown state |
| `CyaInt_CyaSSL_get_current_cipher_suite_CyaInt_CYASSL` | `0x2c6344` | `0x2d38d4` | cipher suite |
| `CyaInt_MakeTLSv1_void` | `0x2c703c` | `0x2d45cc` | TLS 1.0 selector |
| `CyaInt_MakeTLSv1_1_void` | `0x2c7054` | `0x2d45e4` | TLS 1.1 selector |
| `CyaInt_c32to24_uint_uchar` | `0x2c8c84` | `0x2d6214` | 24-bit encoding |
| `CyaInt_InitSSL_Method_CyaInt_CYASSL_METHOD_CyaInt_ProtocolVersion` | `0x2c8c9c` | `0x2d622c` | SSL method setup |
| `CyaInt_InitCiphers_CyaInt_CYASSL` | `0x2c8d14` | `0x2d62a4` | cipher-state reset |
| `CyaInt_MakeSSLv3_void` | `0x2c9064` | `0x2d65f4` | SSL 3.0 selector |
| `CyaInt_SetErrorString_int_char` | `0x2cbe18` | `0x2d93a8` | error text setter |
| `CyaInt_MakeMasterSecret_CyaInt_CYASSL` | `0x2cdad0` | `0x2db060` | master-secret derivation |

The target names are C++ mangled symbols such as
`_ZN6CyaInt25CyaSSL_set_using_nonblockEPNS_6CYASSLEi`, so they are not blank
stripped entries. The names are obfuscated at the class and method level, but
the `CyaInt` class and method spelling remain visible. That makes this group
particularly useful for separating a certificate problem from a transport or
login problem.

I checked representative pairs directly in Hex-Rays. The nonblocking setter
writes the same CyaSSL state byte at offset 999. The verification-path method
keeps the same null guards before calling `ProcessVerifyPath`, and the
certificate-buffer method calls `ProcessBuffer` with the same arguments. The
protocol selector returns 259 in both builds. `InitCiphers` clears the same
six cipher-state fields. The large `MakeMasterSecret` body preserves the same
TLS key schedule, hash setup, derivation call, and cleanup loops, with the
target simply dropping the source PLT prefixes from its pseudocode names.

This is strong static correspondence, not proof that the old endpoint will
accept the client. In particular, these aliases do not disable certificate
verification. They identify the exact native functions to inspect if a future
controlled test needs to compare trust-store loading, date validation, or
the final certificate result.

The labels are persisted with the `v18_` prefix in
`analysis/spectron_libqplay_translated_v155.i64`. All 30 names reopened
successfully, and the semantic reopen check still reports zero failures across
11,693 functions. Because every target already had a non-default C++ name,
the default `sub_` count remains 1,396. The machine-readable record is
`artifacts/spectron_cyaint_tls_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_cyaint_tls_residual_anchors.py`. The v155 checkpoint
is recorded in
`artifacts/spectron_translation_checkpoint_20260826.json`.

## 2026-08-27: Spectron GSFunctionsClient exact residual anchors, batch four

The v154 pass closes the `GSFunctionsClient` callback-table audit with 11
already-bounded exact-shape rows. They cover the early Adventure helpers,
fullscreen and offline state, application activity, and the two URL bridges.

| 1.8 function | Source table field | Spectron target | Target table field |
| --- | ---: | ---: | ---: |
| `GSFunctionsClient_script_adventure_getwindowlist` | `0x378cd0` | `0x1592c8` | `0x38bce0` |
| `GSFunctionsClient_script_adventure_reconnect` | `0x378eb0` | `0x1592d0` | `0x38bec0` |
| `GSFunctionsClient_script_adventure_setgraalcontrolrecreate` | `0x378f40` | `0x1592e4` | `0x38bf50` |
| `GSFunctionsClient_script_adventure_openexternalpm` | `0x378f70` | `0x1592f4` | `0x38bf80` |
| `GSFunctionsClient_script_adventure_openexternaloptions` | `0x379000` | `0x1592fc` | `0x38c010` |
| `GSFunctionsClient_script_isfullscreenmode` | `0x379030` | `0x159304` | `0x38c040` |
| `GSFunctionsClient_script_adventure_setfullscreen` | `0x379060` | `0x159348` | `0x38c070` |
| `GSFunctionsClient_script_isofflinemode` | `0x379210` | `0x15937c` | `0x38c220` |
| `GSFunctionsClient_get_isapplicationactive` | `0x378488` | `0x159688` | `0x38b498` |
| `GSFunctionsClient_script_openurl` | `0x379cc0` | `0x159adc` | `0x38ccd0` |
| `GSFunctionsClient_script_openurl2` | `0x379cf0` | `0x159b18` | `0x38cd00` |

The target table fields are each the source field plus `0x13010`, and each
contains the target code pointer shown above. That closes the final residual
rows left by the table relocation audit. All 11 pairs match on size,
instruction count, basic blocks, branches, calls, mnemonic shape, opcode
shape, register shape, and overall shape.

The early Adventure rows are compact wrappers around window-list, reconnect,
control-recreate, and external-panel operations. The fullscreen pair retains
the mode read and state update, while the offline and application-activity
rows preserve their direct state checks. `openurl` and `openurl2` retain their
three-block URL dispatch shapes and one call each. The target names were all
default `sub_` labels before this pass.

The labels are recorded with the `v18_` prefix in
`analysis/spectron_libqplay_translated_v154.i64`. All 11 reopened successfully,
and the full semantic reopen check still found zero failures across 11,693
functions. The v154 copy has 1,396 default `sub_` names. The machine-readable
record is
`artifacts/spectron_gsfunctions_client_exact_residual_v4_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v4_anchors.py`.

## 2026-08-27: Spectron GSFunctionsClient boundary residual anchors

The v153 pass handles the 12 client callbacks that the table audit located but
that IDA had not made into separate functions. The target code was inspected
as raw ARM64 rather than guessed from the next address. Each range below was
built from its reachable conditional blocks, local return paths, and tail-call
edges.

| 1.8 function | Source field | Spectron target | Target range | Returns |
| --- | ---: | ---: | --- | --- |
| `GSFunctionsClient_get_focusy` | `0x378518` | `0x1598a0` | `0x1598a0..0x159904` | `0x1598f0`, `0x159900` |
| `GSFunctionsClient_get_isfocused` | `0x378548` | `0x159910` | `0x159910..0x15993c` | `0x159930`, `0x159938` |
| `GSFunctionsClient_get_ghostsnear` | `0x378578` | `0x159948` | `0x159948..0x159968` | `0x15995c`, `0x159964` |
| `GSFunctionsClient_get_iscarrying` | `0x378638` | `0x159a28` | `0x159a28..0x159a48` | `0x159a3c`, `0x159a44` |
| `GSFunctionsClient_get_screenpixelscale` | `0x3789f8` | `0x159bd8` | `0x159bd8..0x159be0` | `0x159bdc` |
| `GSFunctionsClient_get_mousey` | `0x378908` | `0x15a2a8` | `0x15a2a8..0x15a2c4` | `0x15a2c0` |
| `GSFunctionsClient_get_mousex` | `0x3788d8` | `0x15a428` | `0x15a428..0x15a444` | `0x15a440` |
| `GSFunctionsClient_script_worldy` | `0x37a4d0` | `0x15aa58` | `0x15aa58..0x15aae8` | `0x15aae4` |
| `GSFunctionsClient_script_worldx` | `0x37a4a0` | `0x15aaf0` | `0x15aaf0..0x15ab40` | `0x15ab3c` |
| `GSFunctionsClient_script_adventure_uploadfile` | `0x37a470` | `0x15ab48` | `0x15ab48..0x15ab64` | `0x15ab60` |
| `GSFunctionsClient_script_screenx` | `0x379ed0` | `0x15b8d0` | `0x15b8d0..0x15b950` | `0x15b928`, `0x15b944` |
| `GSFunctionsClient_script_freezeplayer` | `0x379690` | `0x15d340` | `0x15d340..0x15d3f4` | `0x15d3b4` |

The table evidence is independent of the code walk. The target fields are the
source fields plus `0x13010`, and their qwords point to the target starts.
Adjacent table entries identify the neighboring callback records, but they do
not determine the code end by themselves. That distinction is important for
`screenx`, where the next table callback is at a lower code address, and for
the world-coordinate helpers, whose table order differs from code order.

The raw bodies also explain the recovered roles. `focusy` combines a player
field with a row offset after a floating-point comparison. `isfocused`,
`ghostsnear`, and `iscarrying` return guarded client-state bytes. The pixel
scale callback is a two-instruction constant return. The mouse callbacks either
tail-call the obfuscated coordinate helper or return zero. `worldx` and
`worldy` retain the source tile rounding and level-coordinate conversion, and
the upload callback guards an external file-dispatch helper. `screenx` saves a
small coordinate pair, calls the target coordinate routine, and has separate
positive and negative conversion returns. `freezeplayer` retains its global
guard, range clamp, player update, and shared cleanup path.

The 12 ranges contain 17 explicit raw `RET` instructions in total. No target
function was assigned a default `sub_` name before this pass, so materializing
the boundaries increased the IDA function count from 11,681 to 11,693 without
changing the default-name count after renaming. All 12 labels and all 12
function ends reopened successfully. The full semantic reopen check still
found zero failures. The labels are recorded with the `v18_` prefix in
`analysis/spectron_libqplay_translated_v153.i64`.

The machine-readable record is
`artifacts/spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_boundary_residual_anchors.py`.
The persisted database hash and reopen counts are retained in
`artifacts/spectron_translation_checkpoint_20260826.json`.

## 2026-08-27: Spectron GSFunctionsClient exact residual anchors, batch three

The v152 pass closes the last nine residual client callbacks whose target code
already had a separate IDA function record. The remaining client rows are
being held for boundary work because their table pointers land inside larger
target functions.

| 1.8 function | Source table field | Spectron target | Target table field |
| --- | ---: | ---: | ---: |
| `GSFunctionsClient_script_adventure_geteditnickname` | `0x378d00` | `0x15cb88` | `0x38bd10` |
| `GSFunctionsClient_get_levelorgx` | `0x3786c8` | `0x15cd4c` | `0x38b6d8` |
| `GSFunctionsClient_get_levelorgy` | `0x3786f8` | `0x15cdac` | `0x38b708` |
| `GSFunctionsClient_get_screenheight` | `0x3789c8` | `0x15cee0` | `0x38b9d8` |
| `GSFunctionsClient_get_screenwidth` | `0x378998` | `0x15cf14` | `0x38b9a8` |
| `GSFunctionsClient_get_rightmousebutton` | `0x378878` | `0x15cf48` | `0x38b888` |
| `GSFunctionsClient_get_leftmousebutton` | `0x3787b8` | `0x15cf90` | `0x38b7c8` |
| `GSFunctionsClient_script_savelog` | `0x379e40` | `0x15cfd8` | `0x38ce50` |
| `GSFunctionsClient_script_sendrpgmessage` | `0x379f60` | `0x15da2c` | `0x38cf70` |

The table fields again form an explicit correspondence. For every row, the
target field is the source field plus `0x13010`, and its qword value is the
target address shown above. This ties the two small groups of screen and
mouse accessors to their client-table records instead of relying on a loose
code address delta.

All nine target functions retain the exact normalized shape of their source
counterparts. The level-origin accessors preserve their six-block coordinate
calculation, the screen dimensions remain six-block field reads, and the two
mouse-button accessors retain their five-block state queries. `savelog` and
`sendrpgmessage` both preserve the one-call `echo` bridge and its five-block
shape. The target names were all default `sub_` labels before this pass.

The labels are recorded with the `v18_` prefix in
`analysis/spectron_libqplay_translated_v152.i64`. All nine reopened
successfully, and the full semantic reopen check still found zero failures
across 11,681 functions. The v152 copy has 1,407 default `sub_` names. The
machine-readable record is
`artifacts/spectron_gsfunctions_client_exact_residual_v3_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v3_anchors.py`.

## 2026-08-27: Spectron GSFunctionsClient exact residual anchors, batch two

The v151 pass continues the client-side GSFunctions table audit with another
20 rows. These callbacks were already distinct IDA functions, so the pass only
renamed them and did not change function boundaries.

| 1.8 function | Source table field | Spectron target | Target table field |
| --- | ---: | ---: | ---: |
| `GSFunctionsClient_script_setshootparams` | `0x37a200` | `0x159e58` | `0x38d210` |
| `GSFunctionsClient_get_statusimage` | `0x378b18` | `0x159e94` | `0x38bb28` |
| `GSFunctionsClient_get_spritesimage` | `0x378ae8` | `0x159ecc` | `0x38baf8` |
| `GSFunctionsClient_script_adventure_getinstallationpath` | `0x378d60` | `0x159f04` | `0x38bd70` |
| `GSFunctionsClient_set_selectedweapon` | `0x378ac0` | `0x159f38` | `0x38bad0` |
| `GSFunctionsClient_set_selectedsword` | `0x378a90` | `0x159f9c` | `0x38baa0` |
| `GSFunctionsClient_get_rightmousebuttonglobal` | `0x378848` | `0x15a478` | `0x38b858` |
| `GSFunctionsClient_get_leftmousebuttonglobal` | `0x378788` | `0x15a498` | `0x38b798` |
| `GSFunctionsClient_script_adventure_geteditaccountnames` | `0x378d30` | `0x15a570` | `0x38bd40` |
| `GSFunctionsClient_script_setsword` | `0x37a290` | `0x15b208` | `0x38d2a0` |
| `GSFunctionsClient_script_setshield` | `0x37a140` | `0x15b65c` | `0x38d150` |
| `GSFunctionsClient_script_sendtorc` | `0x379f30` | `0x15b828` | `0x38cf40` |
| `GSFunctionsClient_script_opengraalurl` | `0x379d20` | `0x15bb2c` | `0x38cd30` |
| `GSFunctionsClient_script_keyname2` | `0x379a80` | `0x15be30` | `0x38ca90` |
| `GSFunctionsClient_script_keyname` | `0x379a50` | `0x15be50` | `0x38ca60` |
| `GSFunctionsClient_script_freefileresources` | `0x379660` | `0x15c4f8` | `0x38c670` |
| `GSFunctionsClient_script_adventure_requestfilesmove` | `0x3791e0` | `0x15c830` | `0x38c1f0` |
| `GSFunctionsClient_script_adventure_requestfilerename` | `0x3791b0` | `0x15c854` | `0x38c1c0` |
| `GSFunctionsClient_script_adventure_requestfolderdeletion` | `0x379180` | `0x15c878` | `0x38c190` |
| `GSFunctionsClient_script_adventure_requestfiledeletion` | `0x379150` | `0x15c894` | `0x38c160` |

The table check again supplies the primary cross-build link. For example, the
source `setshootparams` pointer at `0x37a200` becomes the target field at
`0x38b210`, and that field contains `0x159e58`. The same relationship holds
for the other 19 rows, including the two table records that are not adjacent
to the main source cluster. This matters because a single broad text address
delta would not explain those records.

The code comparison is independent of that data evidence. The target keeps
the exact normalized shapes for the 20 rows, from the 20-byte shooting
parameter wrapper and 56-byte image getters through the 100-byte selected
weapon setters and the 36-byte Adventure file requests. The key-name and
URL helpers preserve their small dispatch shapes, while `setsword` and
`setshield` retain their larger player-state wrappers. The file cleanup and
Adventure operations remain distinct callbacks in both table layouts.

The labels are recorded with the `v18_` prefix in
`analysis/spectron_libqplay_translated_v151.i64`. All 20 reopened successfully,
and the full semantic reopen check still found zero failures across 11,681
functions. The v151 copy has 1,416 default `sub_` names. The machine-readable
record is
`artifacts/spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v2_anchors.py`.

## 2026-08-27: Spectron GSFunctionsClient exact residual anchors

The v150 pass translated the first sizeable residual block in the client-side
GSFunctions table. This block is a particularly clean cross-build anchor
because the 1.8 callback pointer fields and the Spectron fields preserve their
relative layout even though the target function names are default `sub_` names.

| 1.8 function | Source table field | Spectron target | Target table field |
| --- | ---: | ---: | ---: |
| `GSFunctionsClient_get_allfeatures` | `0x3782a8` | `0x1593bc` | `0x38b2b8` |
| `GSFunctionsClient_get_allrenderobjecttypes` | `0x3782d8` | `0x1593c4` | `0x38b2e8` |
| `GSFunctionsClient_get_allstats` | `0x378308` | `0x1593cc` | `0x38b318` |
| `GSFunctionsClient_get_carriesnpc` | `0x378368` | `0x15940c` | `0x38b378` |
| `GSFunctionsClient_get_graalversion` | `0x3785a8` | `0x159968` | `0x38b5b8` |
| `GSFunctionsClient_get_isopengl` | `0x3785d8` | `0x159978` | `0x38b5e8` |
| `GSFunctionsClient_get_gravity` | `0x378608` | `0x159980` | `0x38b618` |
| `GSFunctionsClient_set_gravity` | `0x378610` | `0x159990` | `0x38b620` |
| `GSFunctionsClient_get_isonmap` | `0x378698` | `0x159a70` | `0x38b6a8` |
| `GSFunctionsClient_get_middlemousebuttonglobal` | `0x3787e8` | `0x159a98` | `0x38b7f8` |
| `GSFunctionsClient_get_mousewheeldelta` | `0x3788a8` | `0x159aa8` | `0x38b8b8` |
| `GSFunctionsClient_get_scriptedcontrols` | `0x378a28` | `0x159be0` | `0x38ba38` |
| `GSFunctionsClient_get_scriptedplayerlist` | `0x378a58` | `0x159bf0` | `0x38ba68` |
| `GSFunctionsClient_get_selectedsword` | `0x378a88` | `0x159bf8` | `0x38ba98` |
| `GSFunctionsClient_get_selectedweapon` | `0x378ab8` | `0x159c18` | `0x38bac8` |
| `GSFunctionsClient_get_weapons` | `0x378bd8` | `0x159d68` | `0x38bbe8` |
| `GSFunctionsClient_get_weaponsenabled` | `0x378c08` | `0x159d88` | `0x38bc18` |
| `GSFunctionsClient_set_weaponsenabled` | `0x378c10` | `0x159dcc` | `0x38bc20` |
| `GSFunctionsClient_set_statusimage` | `0x378b20` | `0x159e30` | `0x38bb30` |
| `GSFunctionsClient_set_spritesimage` | `0x378af0` | `0x159e44` | `0x38bb00` |

The target table fields are exactly `+0x13010` from their source fields, and
each target field contains the target code pointer shown above. This is the
primary correspondence. It is stronger than copying a broad address delta,
because the fields belong to the same named callback records and their
contents were checked directly in both IDA databases.

The code shapes provide an independent check. The four tiny collection or
state getters are eight-byte, one-instruction wrappers. The gravity and mouse
accessors are short field reads or writes. The map, weapon, and image rows
retain their source control-flow shape exactly, including the larger
`get_isonmap`, weapon-enable, and image setter bodies. All 20 pairs match on
the nine exported normalized metrics. Every target was already a separate IDA
function, so this pass did not create a speculative function boundary.

The labels are recorded with the `v18_` prefix in
`analysis/spectron_libqplay_translated_v150.i64`. All 20 reopened successfully,
and the full semantic reopen check still found zero failures across 11,681
functions. The v150 copy has 1,436 default `sub_` names. The machine-readable
record is
`artifacts/spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_anchors.py`.
The persisted database hash and the pointer-field evidence are retained in
`artifacts/spectron_translation_checkpoint_20260826.json`.

## 2026-08-27: Spectron GSFunctions randomstring residual anchor

The v149 pass translated the remaining `randomstring` callback from the
GSFunctions static script table. The source code pointer at `0x3872c0` is
immediately after the source `strequals` entry. Spectron preserves that same
relationship: its `randomstring` pointer is at `0x39a3e0`, after the target
`strequals` entry at `0x210f58`, and the body begins at `0x2130c4`.

| 1.8 function | Source | Spectron target | Target | Result |
| --- | ---: | --- | ---: | --- |
| `GSFunctionsInitstaticscriptvars_script_randomstring` | `0x20cd34` | `sub_2130C4` | `0x2130c4` | high-confidence table order, layout change |

Both bodies remove a trailing comma when present, build a temporary string
list, choose one entry with `rand` modulo the list count, append it to the
result, and destroy the temporary list. The target uses `C8THgaTQxF` and
`vuuHgangcF` wrappers for the same operations. It grows from 260 to 264 bytes
and from 65 to 66 instructions, while retaining 9 basic blocks, 17 branches,
12 calls, and one return.

The machine-readable evidence is in
`artifacts/spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gsfunctions_randomstring_residual_anchors.py`.
The label reopened successfully in the v149 IDA check. The full translation
reopen check also passed with 3,641 high-confidence map labels and zero
failures across 11,681 functions. The v149 database has 1,456 remaining
default `sub_` names. Its SHA-256 is
`12de3cc80150cba753609346f881cec872df68966f47634befff579dcf9590b1`.

## 2026-08-27: Spectron GSFunctions callback-table residual anchors

The v147 pass reviewed the remaining callback rows in the GSFunctions static
script table. This was a useful case for table-order translation because the
target C++ names are stripped or obfuscated, while already translated rows
still mark the same sequence. The target table preserves the source order
through the callback block.

| 1.8 function | Source | Spectron target | Target | Result |
| --- | ---: | --- | ---: | --- |
| `GSFunctionsInitstaticscriptvars_script_getstringkeys` | `0x20afd8` | `sub_2111D8` | `0x2111d8` | table order, layout change |
| `GSFunctionsInitstaticscriptvars_script_callnpc` | `0x20b268` | `sub_211908` | `0x211908` | table order, layout change |
| `GSFunctionsInitstaticscriptvars_script_getmapx` | `0x20b404` | `sub_211580` | `0x211580` | table order, layout change |
| `GSFunctionsInitstaticscriptvars_script_getmapy` | `0x20b460` | `sub_2114B0` | `0x2114b0` | table order, layout change |
| `GSFunctionsInitstaticscriptvars_script_getimgwidth` | `0x20b4f8` | `sub_211610` | `0x211610` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_getimgheight` | `0x20b53c` | `sub_211654` | `0x211654` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_clearemptyglobalvars` | `0x20b7d8` | `sub_2118F0` | `0x2118f0` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_arcsin` | `0x20b7f0` | `sub_211AD4` | `0x211ad4` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_arccos` | `0x20b818` | `sub_211AFC` | `0x211afc` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_aindexof` | `0x20b840` | `sub_211B24` | `0x211b24` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_echo` | `0x20b858` | `sub_211B3C` | `0x211b3c` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_trace` | `0x20bc48` | `sub_211F2C` | `0x211f2c` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_findpathinarray` | `0x20bf6c` | `sub_21224C` | `0x21224c` | table order, layout change |

The most important boundary correction is `getstringkeys`. The target script
table stores its code pointer at `0x39a290`, and the body begins at
`0x2111d8`. The main return is at `0x2113ac`; the later cleanup branches run
through `0x211420`, and the next callback begins at `0x211424`. That gives a
reviewed function range of `0x2111d8..0x211424`. IDA initially treated this
code as unbounded data because the stripped target had no function record for
the pointer.

The behavior also agrees with the source role. The target derives a prefix
from the requested name, walks the active script-variable hash, filters
visible matching entries, sorts the names, and returns a script string-list
variable. The target grows from 516 to 588 bytes as the 2.2 wrappers make
string and list operations explicit.

`callnpc` remains guarded by the action-NPC pointer, a non-negative index,
the universe list bounds, and the NPC script-name extraction path before it
invokes the selected NPC. It grows from 412 to 460 bytes and keeps 13 basic
blocks, but the target has additional string and variable-wrapper calls.
`getmapx` and `getmapy` preserve the level-position lookup and coordinate
conversion roles while growing from 92 to 144 bytes and from 140 to 196
bytes. `findpathinarray` keeps its profiler-scoped path-array construction
and `ScriptFunction_findPathInArray` marker, while growing from 2,348 to
2,524 bytes and from 99 to 116 basic blocks.

The eight smaller rows have identical size, instruction count, basic-block
count, branch count, call count, mnemonic hash, opcode shape, register shape,
and overall shape. They are `getimgwidth`, `getimgheight`,
`clearemptyglobalvars`, `arcsin`, `arccos`, `aindexof`, `echo`, and `trace`.
The complete machine-readable evidence is in
`artifacts/spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gsfunctions_callback_residual_anchors.py`.
All 13 labels reopened with zero failures in the v148 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,681 functions. The v148 database has 1,457
remaining default `sub_` names. Its SHA-256 is
`ea1cd81d0d6639959b0ddbf70d2f66ec20883fdd49e879ec077e61d8199a2b8d`.

## 2026-08-27: Spectron GSFunctions math and string residual anchors

The v146 pass reviewed six callbacks from the GSFunctions static script table.
Five were ordinary target boundaries. The `radtodeg` target was present as a
table pointer into code but had not been materialized as an IDA function, so
the pass also persisted its independently proven 24-byte boundary.

| 1.8 function | Source | Spectron target | Target | Match |
| --- | ---: | --- | ---: | --- |
| `GSFunctionsInitstaticscriptvars_script_degtorad` | `0x20abc8` | `sub_210DC8` | `0x210dc8` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_radtodeg` | `0x20abf0` | `sub_210DF0` | `0x210df0` | exact normalized shape |
| `sub_20ADBC` | `0x20adbc` | `sub_210FBC` | `0x210fbc` | exact normalized shape |
| `jump_TString_compareIgnoreCase_TString_const` | `0x20adcc` | `j_._ZNK10C8THgaTQxF10nVCrgaSlRrERKS_` | `0x210fcc` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_uppercase` | `0x20add0` | `sub_210FD0` | `0x210fd0` | exact normalized shape |
| `GSFunctionsInitstaticscriptvars_script_lowercase` | `0x20adf0` | `sub_210FF0` | `0x210ff0` | exact normalized shape |

The math callbacks retain the source formulas. `degtorad` multiplies by pi
and divides by 180, while `radtodeg` multiplies by 180 and divides by pi.
Spectron's script table points to `0x210dc8` and `0x210df0` respectively.
The latter range ends at the `RET` at `0x210e04`; the bytes after it are a
literal pool, so the saved function range is `0x210df0..0x210e08`.

The shared clearer releases the static `TString` used by the
`findpathinarray` implementation. The compare-ignore-case jump forwards to
the target string comparison method. The uppercase and lowercase wrappers
forward to the matching target string methods.

All six pairs have identical size, instruction count, basic-block count,
branch count, call count, mnemonic hash, opcode shape, register shape, and
overall shape. Five target rows were default names before the batch, including
the newly materialized `radtodeg` function. The comparison jump already had a
non-default target name.

The machine-readable record is
`artifacts/spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_math_string_residual_anchors.py`. All
six labels reopened with zero failures in the serial v146 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,680 functions. The v146 database has 1,469
remaining default `sub_` names. Its SHA-256 is
`a868b16b549a8e70c40d5ded8f487228674d3295f9d41fe35c3bc03449b05556`.

## 2026-08-27: Spectron TUpdatePackageProperties residual anchors

The v145 pass closed the five-row package-properties lifecycle family. It
contains the uninstall jump thunk, a complete destructor, its non-virtual
thunk, a deleting destructor, and the deleting-destructor thunk.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `jump_TUpdatePackage_uninstall_void` | `0x20aab8` | `j_._ZN10RH6ygazf9x10TrDxob8NUfEv` | `0x210cb4` | exact normalized shape |
| `TUpdatePackageProperties_TUpdatePackageProperties` | `0x20aabc` | `_ZN20RH6ygazf9xPropertiesD2Ev` | `0x210cb8` | exact normalized shape |
| `non_virtual_thunk_to_TUpdatePackageProperties_TUpdatePackageProperties` | `0x20aad8` | `_ZThn16_N20RH6ygazf9xPropertiesD1Ev` | `0x210cd4` | exact normalized shape |
| `TUpdatePackageProperties_TUpdatePackageProperties__2` | `0x20aae0` | `_ZN20RH6ygazf9xPropertiesD0Ev` | `0x210cdc` | exact normalized shape |
| `non_virtual_thunk_to_TUpdatePackageProperties_TUpdatePackageProperties__2` | `0x20ab18` | `_ZThn16_N20RH6ygazf9xPropertiesD0Ev` | `0x210d14` | exact normalized shape |

The source constructor-like labels have alternative names ending in `D2` and
`D0`, so they are destructor variants rather than ordinary constructors. The
complete form restores its two vtable fields and calls the `TProperties` base
cleanup. The deleting form does the same and then calls `operator delete`.
Each non-virtual thunk adjusts the object pointer by 16 bytes before
forwarding to its corresponding destructor.

The uninstall row is a one-instruction jump wrapper in both builds. Every
pair has identical size, instruction count, basic-block count, branch count,
call count, mnemonic hash, opcode shape, and overall shape. All target names
were already non-default, so the v145 database default-name count is
unchanged.

The machine-readable record is
`artifacts/spectron_update_package_properties_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_properties_residual_anchors.py`. All
five labels reopened with zero failures in the serial v145 IDA check. The
full translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v145 database remains
at 1,473 default `sub_` names. Its SHA-256 is
`3b26ba1e6a150a8aebef18c46372843615523a76a813af5eba231c924a459f59`.

## 2026-08-27: Spectron update-package event and lookup residual anchors

The v144 pass reviewed six remaining package-state helpers. They are split
between the package event wrappers, the downloading and privileged package
lookups, and the script-facing force flags.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `updatePackageFailed_TString_const` | `0x209260` | `_Z10PPxXSam4HQRK10C8THgaTQxF` | `0x20f3f8` | expanded event wrapper |
| `getContainingUpdatePackage_TString_const` | `0x209310` | `_Z10e3y_Sao6eTRK10C8THgaTQxF` | `0x20f4e4` | exact normalized shape |
| `getContainingPrivilegedPackage_TString_const` | `0x209414` | `_Z10k1gxobOWBfRK10C8THgaTQxF` | `0x20f5e8` | exact normalized shape |
| `TUpdatePackage_updateNoForce` | `0x20993c` | `sub_20FB10` | `0x20fb10` | exact normalized shape |
| `TUpdatePackage_updateForce` | `0x209944` | `sub_20FB18` | `0x20fb18` | exact normalized shape |
| `updatePackageDownloaded_TString_const` | `0x20a798` | `_Z10by20SakLuURK10C8THgaTQxF` | `0x210958` | expanded event wrapper |

Both event helpers check for an active `.gupd` download. If the client is not
currently downloading that file type, they notify the game environment with
`onPackagesDownloaded`. The downloaded form first resolves and loads the
selected update package. Spectron keeps the same behavior, although its
temporary strings and event calls use obfuscated wrappers and add a few
instructions.

The two containment helpers lowercase the requested filename, walk the
downloading or privileged package list, inspect each package's file list, and
compare normalized paths. Their source and target bodies have identical
260-byte, 65-instruction, 8-block, 12-branch, 8-call normalized metrics,
including the nested loop and temporary-string cleanup.

The force wrappers pass false and true to the common package update method.
They were the only default target names in this batch, so applying the labels
reduces the database default-name count by two. The remaining four targets
already had obfuscated non-default names.

The machine-readable record is
`artifacts/spectron_update_package_wrapper_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_wrapper_residual_anchors.py`. All six
labels reopened with zero failures in the serial v144 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v144 database has 1,473
remaining default `sub_` names. Its SHA-256 is
`fecbafa39ffeca37580a23828e71b4a0d3be317029bd896548d02d7ae61799f6`.

## 2026-08-27: Spectron TUpdatePackage deleting-destructor residual anchor

The v143 audit found one remaining row in the update-package lifecycle
sequence. The source function at `0x208eb4` has a constructor-like IDA label,
but its body forwards to the package constructor entry and then calls
`operator delete`, so it is the deleting destructor variant. It maps cleanly
to Spectron's `_ZN10RH6ygazf9xD0Ev` at `0x20f04c`.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `TUpdatePackage_TUpdatePackage__2` | `0x208eb4` | `_ZN10RH6ygazf9xD0Ev` | `0x20f04c` | exact normalized shape |

Both bodies are 32 bytes with 8 instructions, 2 basic blocks, 2 branches,
and 1 call. Their mnemonic, opcode, and overall shape hashes also match.
The complete constructor or destructor at source `0x208dc8` and target
`0x20ef60` was already in the canonical semantic map, so this one-row pass
closes the adjacent deleting form without duplicating the existing anchor.
The target already had a non-default obfuscated name. The new `v18_` alias
keeps the source database label while the evidence records its destructor
role.

The machine-readable record is
`artifacts/spectron_update_package_destructor_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_destructor_residual_anchors.py`. The
label reopened with zero failures in the serial v143 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v143 database remains at
1,475 default `sub_` names. Its SHA-256 is
`0ff80f9687ea4115fd861d8319f1c1ee6fb9b3292d830659af242a6c01ce0e15`.

## 2026-08-27: Spectron TClient and TUpdatePackage accessor residual anchors

The v142 pass translated the dense accessor run from the base-package helper
through the update-package description getter. This is a useful block because
the source and Spectron functions remain in the same order and every pair has
the same normalized instruction shape.

| 1.8 function | Source | Spectron target | Target | Role |
| --- | ---: | --- | ---: | --- |
| `TClient_getBasePackage` | `0x208a70` | `sub_20EC08` | `0x20ec08` | base-package pointer |
| `TClient_getDownloadingPackageCount` | `0x208a80` | `sub_20EC18` | `0x20ec18` | download-list count |
| `TUpdatePackage_getDownloadComplete` | `0x208a94` | `sub_20EC2C` | `0x20ec2c` | completion byte |
| `TUpdatePackage_getDownloadBytesField228` | `0x208a9c` | `sub_20EC34` | `0x20ec34` | downloaded bytes |
| `TUpdatePackage_getFileCount` | `0x208aa4` | `sub_20EC3C` | `0x20ec3c` | file-list count |
| `TUpdatePackage_getDwordField236` | `0x208ab0` | `sub_20EC48` | `0x20ec48` | dword at +236 |
| `TUpdatePackage_getDwordField232` | `0x208ab8` | `sub_20EC50` | `0x20ec50` | dword at +232 |
| `TUpdatePackage_getByteField249` | `0x208ac0` | `sub_20EC58` | `0x20ec58` | byte at +249 |
| `TUpdatePackage_getDoubleField216` | `0x208ac8` | `sub_20EC60` | `0x20ec60` | double at +216 |
| `TUpdatePackage_getQwordField128` | `0x208ad0` | `sub_20EC68` | `0x20ec68` | qword at +128 |
| `TUpdatePackage_getProtectOverwrite` | `0x208ad8` | `sub_20EC70` | `0x20ec70` | `PROTECTOVERWRITE` flag |
| `TUpdatePackage_getTotalBytesField224` | `0x208ae0` | `sub_20EC78` | `0x20ec78` | total bytes |
| `TUpdatePackage_getUseChecksum` | `0x208ae8` | `sub_20EC80` | `0x20ec80` | `USECHECKSUM` flag |
| `TUpdatePackage_getVersion` | `0x208af0` | `sub_20EC88` | `0x20ec88` | `VERSION` value |
| `TUpdatePackage_getPlatform` | `0x208af8` | `sub_20EC90` | `0x20ec90` | platform string |
| `TUpdatePackage_getName` | `0x208b28` | `sub_20ECC0` | `0x20ecc0` | package name |
| `TUpdatePackage_getMode` | `0x208b58` | `sub_20ECF0` | `0x20ecf0` | package mode |
| `TUpdatePackage_getStringField240` | `0x208b88` | `sub_20ED20` | `0x20ed20` | string at +240 |
| `TUpdatePackage_getFilename` | `0x208bb8` | `sub_20ED50` | `0x20ed50` | package filename |
| `TUpdatePackage_getDescription` | `0x208be8` | `sub_20ED80` | `0x20ed80` | description string |

The first fourteen functions are direct scalar or pointer reads. The source
and target pseudocode show the same offsets, including the nested file-list
count at package offset +200. The last six functions initialize an output
`TString` and assign the corresponding embedded string field. Spectron uses
`C8THgaTQxF::operator=` where the source database exposes the original
`TString` assignment helper.

All twenty targets were default `sub_` names, and every pair has identical
size, instruction count, basic-block count, branch count, call count,
mnemonic hash, opcode shape, and overall shape. The conservative names that
end in `Field` intentionally record an offset rather than inventing a member
name that was not recovered from the 1.8 binary.

The machine-readable record is
`artifacts/spectron_update_package_accessor_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_update_package_accessor_residual_anchors.py`. All
twenty labels reopened with zero failures in the serial v142 IDA check. The
full translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v142 database has
1,475 remaining default `sub_` names. Its SHA-256 is
`b8596d19b6c12d71c5ed331474d78bc9e274192a88566bcbe5f46dcbee4b9a66`.

## 2026-08-27: Spectron client-thread residual anchors

The v141 pass reviewed seven remaining client-thread helpers around the
socket mutex and package queues. The source and target bodies match exactly
after normalized ARM64 comparison, and their decompilations preserve the
same synchronization and cleanup behavior.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `lockClientSocket_void` | `0x208344` | `_Z10E3UikbICwHv` | `0x20e4e0` | exact normalized shape |
| `unlockClientSocket_void` | `0x208350` | `_Z10Tqmikbou3Gv` | `0x20e4ec` | exact normalized shape |
| `readIncomingData_void` | `0x20835c` | `_Z10LK7hkb_7RGv` | `0x20e4f8` | exact normalized shape |
| `clearIncomingPackages_void` | `0x208478` | `_Z10d5ahkbYW3Fv` | `0x20e614` | exact normalized shape |
| `clearOutgoingPackages_void` | `0x20858c` | `_Z10A0fhkbd57Fv` | `0x20e728` | exact normalized shape |
| `disableClientThread_void` | `0x2087a0` | `_Z10wlXykbJx0Uv` | `0x20e93c` | exact normalized shape |
| `sendOutgoingPackages_void` | `0x2088f8` | `_Z10aC0C_aG7qiv` | `0x20ea94` | exact normalized shape |

The lock and unlock wrappers use the same client-socket mutex role. The
incoming reader locks it, calls the connection's read method, and releases
it. The outgoing wrapper follows the same pattern around the connection send
method.

The two clear helpers are especially useful because they retain the full
package lifetime behavior. Each locks its queue mutex, walks the stored
package pointers, clears the embedded string, deletes each package, clears
the list, and finally unlocks. Spectron expresses the list through
`vy1JgaKVkH` and the string cleanup through `C8THgaTQxF`, but the loop shape
and cleanup order are unchanged.

`disableClientThread` returns the running flag and only calls the destroy
helper when it is set. This is the same guard visible in the source. All
seven target functions already had non-default obfuscated names, so the pass
adds readable `v18_` aliases without changing the default-name count.

The machine-readable record is
`artifacts/spectron_client_thread_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_client_thread_residual_anchors.py`. All seven labels
reopened with zero failures in the serial v141 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v141 database remains at
1,495 default `sub_` names. Its SHA-256 is
`88c9abdbc6997eac4ee321d695df1170f17cc394b2ee0906370e2f5e726cb6b7`.

## 2026-08-27: Spectron TPlayerList residual anchors

The v140 pass reviewed the three uncovered `TPlayerList` support rows just
before the client-socket helpers. The source and target sequences are still
aligned by local role and structure, even though the target class and helper
names are obfuscated.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `TPlayerList_setStaffGuilds_TString_const` | `0x2081e4` | `_ZN10y3t2LaCUH110UpiB7az6Z_ERK10C8THgaTQxF` | `0x20e380` | exact normalized shape |
| `TPlayerList_initStaticVars_void` | `0x208310` | `_Z10LG6O2aDeCZv` | `0x20e4ac` | allocation layout change |
| `TPlayerList_initStaticScriptVars_void` | `0x208340` | `_Z10ZdoB2ay_3Nv` | `0x20e4dc` | exact normalized shape |

The staff-guild setter calls the target `vuuHgangcF` comma-text helper against
the obfuscated `y3t2LaCUH1` global, which is the same operation represented by
the source `TStringList` setter. The source static initializer allocates
0x18 bytes, constructs a `TStringList`, and publishes the global. Spectron
keeps that sequence but allocates 0x20 bytes for its target list object. This
is why the initializer is recorded as a layout change despite matching size,
instruction, block, branch, and call counts. The static-script initializer is
an empty function in both builds.

All three target functions already had non-default obfuscated names, so this
pass adds readable `v18_` aliases without replacing an unnamed `sub_` entry.
The next target address, `0x20e4e0`, is the separate client-socket lock helper
and is held as the boundary for the next batch.

The machine-readable record is
`artifacts/spectron_player_list_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_player_list_residual_anchors.py`. All three labels
reopened with zero failures in the serial v140 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v140 database remains at
1,495 default `sub_` names. Its SHA-256 is
`45a774f4240b145c575dd7ff2e92d8b15d1bec215e64c98386d81519b039729b`.

## 2026-08-27: Spectron URL-cache support residual anchors

The v139 pass reviewed the remaining URL-cache support rows around
`TURLCache::addURL` and the cache-entry type. Five functions were still
absent from the combined semantic and manual anchor records.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `TURLCache_addURL_TString_const_TString_const` | `0x207d24` | `_ZN10uK2SHaPVVw10btKSHa7HFwERK10C8THgaTQxFS2_` | `0x20de90` | expanded wrapper layout |
| `TURLCache_initStaticVars_void` | `0x207ebc` | `_Z10IMaXHaJGoAv` | `0x20e054` | exact normalized shape |
| `TURLCache_load_void` | `0x207eec` | `_ZN10uK2SHaPVVw4loadEv` | `0x20e084` | expanded wrapper layout |
| `TURLCache_TURLCacheEntry_TURLCacheEntry` | `0x20815c` | `_ZN10uK2SHaPVVw10S5XSHaIaRwD2Ev` | `0x20e2f8` | exact normalized shape |
| `TURLCache_TURLCacheEntry_TURLCacheEntry__2` | `0x20819c` | `_ZN10uK2SHaPVVw10S5XSHaIaRwD0Ev` | `0x20e338` | exact normalized shape |

`addURL` still rejects `.code` files, hashes the URL, looks up the existing
entry, allocates a 0x18-byte entry when absent, stores the local path, and
calls `scheduleSave`. Its source metrics are 272/68/10/18/11 for bytes,
instructions, blocks, branches, and calls. The target is 316/79/10/20/13,
with explicit `C8THgaTQxF`, `CanTfaz6bZ`, `KKhLga4xoI`, `J7zOgaf09K`, and
`uK2SHaPVVw` wrappers.

The URL-cache initializer is an exact 48-byte, 12-instruction, one-block
match that allocates and publishes the 0x28-byte hash list. `load` keeps the
base-folder path construction, `URLCACHE.txt` filename, line loading, two
field split, and valid-entry call to `addURL`. Its metrics change from
288/72/6/16/15 to 292/73/6/16/15 because of target wrapper details.

The two cache-entry rows are destructor variants despite the constructor-like
IDA labels. The complete destructor clears both embedded string fields and
restores both vtable layers. The deleting destructor performs the same work
and calls `operator delete`. Both target `S5XSHaIaRw` rows have exact
normalized metrics.

The machine-readable record is
`artifacts/spectron_url_cache_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_url_cache_residual_anchors.py`. All five labels
reopened with zero failures in the serial v139 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v139 database remains at
1,495 default `sub_` names. Its SHA-256 is
`ffa33dac8790bd45cfabeaae38201f09954a9cb298ceb747ed3f82b76155c08a`.

## 2026-08-27: Spectron socket-cache support residual anchors

The v138 pass reviewed the support block after `GetOwnIP`. Five rows were
still absent from the combined semantic and manual anchor records: the two
`TSocketConnection` static initializers, `IsHostAndPortInList`, and the
complete and deleting `TCachedHostAddress` destructors.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `TSocketConnection_initStaticVars_void` | `0x207968` | `_Z10OYaS2aPQb1v` | `0x20dab4` | combined global setup |
| `TSocketConnection_initStaticScriptVars_void` | `0x207998` | `_Z10TO_L1aAs_5v` | `0x20db00` | property-table layout change |
| `IsHostAndPortInList_TString_const_TString_const_int` | `0x2079ac` | `_Z10mNHZ0adswrRK10C8THgaTQxFS1_i` | `0x20db14` | wrapper layout change |
| `TCachedHostAddress_TCachedHostAddress` | `0x207c54` | `_ZN10reub2aL2gsD1Ev` | `0x20ddc0` | exact normalized shape |
| `TCachedHostAddress_TCachedHostAddress__2` | `0x207c68` | `_ZN10reub2aL2gsD0Ev` | `0x20ddd4` | exact normalized shape |

The source static initializer allocates the cached-host hash list. The target
initializer does that and also constructs a second target global object, so
its body grows from 48 to 76 bytes, 12 to 19 instructions, and 2 to 4 calls.
The script initializer keeps the property-registration role, but the source
passes a two-entry table while the target passes a four-entry table. Its
metrics remain 20/5/2/1/0, but the immediate data and target call differ, so
it is recorded as a layout change.

`IsHostAndPortInList` retains the wildcard fast path, comma-list parsing,
host-pattern matching, single-port comparison, and inclusive range check. It
changes from 680/170/20/49/37 to 684/171/20/49/37 for bytes, instructions,
blocks, branches, and calls. The target exposes the same logic through
`C8THgaTQxF`, `vuuHgangcF`, and comparison wrappers.

The two `TCachedHostAddress` rows are the complete and deleting destructors.
Both restore the vtable and clear the embedded `TString`; the deleting form
also calls `operator delete`. Their 20-byte and 48-byte bodies match exactly,
including all normalized metrics.

The machine-readable record is
`artifacts/spectron_socket_cache_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_socket_cache_residual_anchors.py`. All five labels
reopened with zero failures in the serial v138 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The target names were already
non-default, so the v138 database remains at 1,495 default `sub_` names. Its
SHA-256 is
`73a990ab8d29c9dd83e5542eb0130bfdb7ff80bc9e7b5f0eb3f9495354c7cfc8`.

## 2026-08-27: Spectron TSocketProperties destructor residual anchors

The v137 pass closed the four-function `TSocketProperties` destructor family
that follows `TSocket::runScript`: the complete destructor, its non-virtual
thunk, the deleting destructor, and its non-virtual thunk.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `TSocketProperties_TSocketProperties` | `0x205e94` | `_ZN20XJLBgarMnAPropertiesD1Ev` | `0x20bfa0` | exact normalized shape |
| `non_virtual_thunk_to_TSocketProperties_TSocketProperties` | `0x205eb0` | `_ZThn16_N20XJLBgarMnAPropertiesD1Ev` | `0x20bfbc` | exact normalized shape |
| `TSocketProperties_TSocketProperties__2` | `0x205eb8` | `_ZN20XJLBgarMnAPropertiesD0Ev` | `0x20bfc4` | exact normalized shape |
| `non_virtual_thunk_to_TSocketProperties_TSocketProperties__2` | `0x205ef0` | `_ZThn16_N20XJLBgarMnAPropertiesD0Ev` | `0x20bffc` | exact normalized shape |

The source complete destructor writes the two `TSocketProperties` vtable
fields and calls the `TProperties` base cleanup. The target D1 destructor
performs the same role with the `XJLBgarMnAProperties` vtable fields and its
`c76BgaJBGA` base cleanup. The deleting D0 pair adds `operator delete` in
both builds. Each non-virtual thunk adjusts the object pointer by 16 bytes
before forwarding to its corresponding destructor.

Every pair has the same size, instruction count, block count, branch count,
call count, mnemonic hash, opcode shape, register shape, and overall shape.
The target names were already non-default, so this pass adds four readable
`v18_` aliases without changing the 1,495 default `sub_` count.

The machine-readable record is
`artifacts/spectron_tsocket_properties_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_properties_residual_anchors.py`. All four
labels reopened with zero failures in the serial v137 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v137 database SHA-256 is
`594158817ff9bcecdd2e16896ad7216f6f470bc711809709f225178e604a1dc7`.

## 2026-08-27: Spectron TSocket host and logging residual anchors

The v136 pass reviewed the next helper region after the lifecycle block. It
adds three labels: the cached IPv4 writer, the SSL logging callback helper,
and the host resolver. The nearby plain send and receive helpers were already
present in the semantic map as `v18_TSocket_sendPlain` and
`v18_TSocket_recvPlain`, so they remain documented boundaries.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `TSocket_cacheHostAddress` | `0x205ef8` | `sub_20C020` | `0x20c020` | expanded cache wrapper |
| `TSocket_logSocketMessage` | `0x205fcc` | `sub_20C018` | `0x20c018` | reduced SSL callback thunk |
| `resolveHost_TString_const` | `0x206108` | `_Z10dsmb2ajvasRK10C8THgaTQxF` | `0x20c20c` | expanded resolver wrapper |

`cacheHostAddress` keeps the source behavior of converting the host text with
`inet_addr`, looking up a case-insensitive entry in the cached-host list,
creating the 32-byte cache object when needed, storing the address, marking it
valid, and recording the current time. Its source metrics are 212/53/6/12/7
for bytes, instructions, blocks, branches, and calls. The target is
244/61/6/14/9 because its `C8THgaTQxF`, `CanTfaz6bZ`, `KKhLga4xoI`,
`J7zOgaf09K`, and `zYRMgaG0IJ` wrapper calls are explicit.

`logSocketMessage` is the one factoring change in this group. The source
method builds a temporary `TString` and sends it through `TLog_echo`. The
target passes the 8-byte `sub_20C018` helper directly to
`CyaSSL_SetLoggingCb`; that helper tail-forwards the callback message into
`qjQMgaXCHJ::cWQMgaD8HJ`. This is why the target body is only 8 bytes, with
2 instructions, 2 blocks, 1 branch, and no ordinary call instruction, while
the source is 68/17/1/4/3. The mapping is based on the callback reference and
the target logger call, not on raw body size.

`resolveHost` keeps the source validation, cached-object lookup, one-hour
timestamp check, `gethostbyname` fallback, address storage, and timestamp
refresh. It changes from 300/75/15/18/8 to 344/86/15/20/10 as the target
wrapper operations become explicit. The target cache writer begins at
`0x20c020`, while the resolver begins at `0x20c20c`. The target-only helper at
`0x20c008` clears a separate global string container and is retained as an
explicit boundary before the SSL callback helper.

The machine-readable record is
`artifacts/spectron_tsocket_host_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_host_residual_anchors.py`. All three labels
reopened with zero failures in the serial v136 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. Two of the target functions had
default names before this pass, leaving 1,495 default `sub_` names. The v136
database SHA-256 is
`fbd9c0aaacb910343fda7807264cb8c66c25a9f8b9f8f394950e620479678723`.

## 2026-08-27: Spectron TSocket lifecycle residual anchors

The v135 pass reviewed the ordered `TSocket` lifecycle block after the receive
methods. Four rows were still absent from the semantic map:
`preDestroy`, `checkAllowBind`, `bind`, and `runScript`. The nearby
`checkScriptActive` row was also reviewed, but it was already present as
`v18_TSocket_checkScriptActive_void`, so it remains an explicit existing
boundary instead of being recorded twice.

| 1.8 function | Source | Spectron target symbol | Target | Match |
| --- | ---: | --- | ---: | --- |
| `TSocket_preDestroy_void` | `0x205780` | `_ZN10XJLBgarMnA10PWkBgafe1zEv` | `0x20b78c` | exact normalized shape |
| `TSocket_checkAllowBind_int` | `0x2057a0` | `_ZN10XJLBgarMnA10MXSAgaXQDzEi` | `0x20b7ac` | expanded wrapper layout |
| `TSocket_bind_int_bool` | `0x205948` | `_ZN10XJLBgarMnA4bindEib` | `0x20b958` | expanded wrapper layout |
| `TSocket_runScript_void` | `0x205bdc` | `_ZN10XJLBgarMnA10_xWAgaiSGzEv` | `0x20bc1c` | expanded wrapper layout |

`preDestroy` is a compact 32-byte, 8-instruction, 2-block cleanup method
with two branches and one call in both builds. `checkAllowBind` changes from
424/106/16/24/17 for bytes, instructions, blocks, branches, and calls to
428/107/16/24/17. Its target still compares the configured allowed-port field
with the wildcard, parses the configured list and ranges, and returns whether
the current port is allowed. The target string list retains `*`.

`bind` changes from 588/146/13/41/31 to 636/158/13/45/35. The target first
checks the allowed-port policy, stores the requested port, recreates the live
connection object, and calls its bind method. When SSL is enabled, it copies
the certificate, cipher, and protocol state into the connection before
starting it. The final branches preserve the `onBind` success path and the
`onBindFailed` or logged rejection path. The target has an encoded string
reference in place of one of the readable source event values.

`runScript` changes from 696/173/23/45/31 to 900/223/23/60/46. Its state
machine still handles the connect transition, accepted clients, and close
transition. It accepts new connections, adds them to the `clients` collection,
dispatches the corresponding script events, calls the base socket
`runScript`, and performs the close transition afterward. The target retains
`clients` and `onClose` in the clean string export and constructs other event
values through encoded wrappers.

The source and target offsets are not one uniform delta because target wrapper
growth shifts later methods. The reviewed rows use `+0x600c` for `preDestroy`
and `checkAllowBind`, `+0x6010` for `bind`, and `+0x6040` for `runScript`.
The source jump thunk at `0x205b94` and target thunk at `0x20bbd4` remain an
explicit boundary. The following `TSocketProperties` block, beginning at the
target destructor region near `0x20bfa0`, was not folded into this pass.

The machine-readable record is
`artifacts/spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_lifecycle_residual_anchors.py`. All four
labels reopened with zero failures in the serial v135 IDA check. The full
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. Because the target functions
already had non-default names, the v135 database still has 1,497 default
`sub_` names. Its SHA-256 is
`66f9607ed18bcd93ebbee727c3f42299fd05c7c17fa5659746afd52bd9e3598f`.

## 2026-08-27: Spectron TSocket receive residual anchors

The v134 pass reviewed the two larger receive-side `TSocket` methods.
`TSocket_checkDataPackages_void` at `0x205328` maps to
`_ZN10XJLBgarMnA10xS6AgaBoQzEv` at `0x20b1f8`. `TSocket_read_void` at
`0x2054c4` maps to `_ZN10XJLBgarMnA4readEv` at `0x20b3f0`. The first target
body grows by 92 bytes, which shifts the second target row from a simple
`+0x5ed0` alignment to `+0x5f2c`.

| 1.8 function | Source | Spectron target symbol | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_checkDataPackages_void` | `0x205328` | `_ZN10XJLBgarMnA10xS6AgaBoQzEv` | `0x20b1f8` | queued package splitting and event |
| `TSocket_read_void` | `0x2054c4` | `_ZN10XJLBgarMnA4readEv` | `0x20b3f0` | connection read and data events |

`checkDataPackages` keeps the source queue fields at offsets 200 and 216,
searches for the same delimiter, splits each package, builds an array
argument, and dispatches `onReceiveDataPackage`. Spectron makes the
`C8THgaTQxF`, `CanTfaz6bZ`, `D6TlgajP1m`, and `G0gxgajWBw` wrappers explicit.
The source body is 376 bytes, 94 instructions, 14 blocks, 24 branches, and
15 calls. The target is 468 bytes, 117 instructions, 14 blocks, 30 branches,
and 21 calls.

`read` keeps the live connection pointer at offset 176, the connection error
check, the native read call, and the state transition from 4 to 5. It still
branches on the UDP flag at connection offset 8344. The UDP path builds the
same array fields and dispatches `onReceiveUDPData`; the ordinary path
appends to the receive string, dispatches `onReceiveData`, then calls
`checkDataPackages`. The source body is 548/137/15/38/29 and the target is
772/193/16/56/47. The extra target instructions are encoded event-string and
temporary-value wrappers, not a changed receive-state decision tree.

The source string references are `onReceiveDataPackage`, `onConnect`,
`onReceiveUDPData`, and `onReceiveData`. Spectron constructs encoded target
events through `C8THgaTQxF` and `KKhLga4xoI`, so the clean target feature
export has no plain string references for these methods. Both target names
were already non-default, leaving the v134 database at 1,497 default `sub_`
names.

The machine-readable record is
`artifacts/spectron_tsocket_receive_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_receive_residual_anchors.py`. Both labels
reopened with zero failures in the serial v134 IDA check. The full semantic
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v134.i64`.
The v134 database SHA-256 is
`0fa7676435cea1bdbdb334e9926d99dbb4437ccc4ff4c04d81c4531399b62971`.

## 2026-08-27: Spectron TSocket SSL residual anchors

The v133 pass reviewed four residual `TSocket` methods in the SSL and
outgoing-buffer sequence. The source rows at `0x205120`, `0x20514c`,
`0x2051a0`, and `0x205240` map to `0x20aff0`, `0x20b01c`, `0x20b070`, and
`0x20b110` in target class `XJLBgarMnA`, using a fixed `+0x5ed0` delta.

| 1.8 function | Source | Spectron target symbol | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_setEnableSSL_bool` | `0x205120` | `_ZN10XJLBgarMnA10Sf9Aga1oSzEb` | `0x20aff0` | SSL state and live connection update |
| `TSocket_setSSLCipherList_TString_const` | `0x20514c` | `_ZN10XJLBgarMnA10ze1AgaTELzERK10C8THgaTQxF` | `0x20b01c` | cipher field propagation |
| `TSocket_setSSLProtocol_TString_const` | `0x2051a0` | `_ZN10XJLBgarMnA10S12AgafaNzERK10C8THgaTQxF` | `0x20b070` | protocol field propagation |
| `TSocket_send_TString_const` | `0x205240` | `_ZN10XJLBgarMnA4sendERK10C8THgaTQxF` | `0x20b110` | outgoing string append |

All four pairs have exact size, instruction, block, branch, call,
mnemonic, opcode-shape, register-shape, and overall-shape matches. The SSL
enable method compares and stores byte 140, then updates the live connection
at object offset 176 when present. The cipher-list and protocol methods keep
the source socket fields at offsets 144 and 152 and propagate them to live
connection fields at offsets 8248 and 8256. The send method appends to the
outgoing string at offset 168. Spectron's `u3cBgayBVz` and `C8THgaTQxF`
helpers replace the source helper names without changing the control flow.

The already translated target rows at `0x20b0c4` for
`setSSLVerifyCert`, `0x20b11c` for `sendUDP`, and `0x20b1b8` for `close`
confirm the surrounding ordered block. The four target names were already
non-default obfuscated symbols, so the v133 database retains 1,497 default
`sub_` names.

The machine-readable record is
`artifacts/spectron_tsocket_ssl_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_ssl_residual_anchors.py`. The four labels
reopened with zero failures in the serial v133 IDA check. The full semantic
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v133.i64`.
The v133 database SHA-256 is
`d3d0be59f3cee7f3b10ab9f3da04910a4f6e4a7cdacdefa4996e4cb1a594afcd`.

## 2026-08-27: Spectron TSocket accessor and factory residual anchors

The v132 pass reviewed 19 residual `TSocket` methods. Seventeen field
accessors occupy the source sequence from `0x204630` through `0x2047e8` and
the matching Spectron sequence from `0x20a508` through `0x20a6c0`. The
`sendOutgoing` method at `0x204894` and the socket factory at `0x204a70` stay
in the same class-local block. Every row uses the fixed `+0x5ed8` delta in
the obfuscated `XJLBgarMnA` class.

| 1.8 function | Source | Spectron target symbol | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_getByte140` | `0x204630` | `sub_20A508` | `0x20a508` | byte accessor |
| `TSocket_getListCountField168` | `0x204638` | `sub_20A510` | `0x20a510` | list-count accessor |
| `TSocket_getField208` | `0x204650` | `sub_20A528` | `0x20a528` | field accessor |
| `TSocket_getDword192` | `0x204658` | `sub_20A530` | `0x20a530` | dword accessor |
| `TSocket_setStringField232` | `0x204660` | `sub_20A538` | `0x20a538` | string-field setter |
| `TSocket_setStringField224` | `0x204668` | `sub_20A540` | `0x20a540` | string-field setter |
| `TSocket_setStringField200` | `0x204670` | `sub_20A548` | `0x20a548` | string-field setter |
| `TSocket_setAllowedPortsBind` | `0x204678` | `sub_20A550` | `0x20a550` | allowed-port global setter |
| `TSocket_setAllowedSocketsConnect` | `0x204688` | `sub_20A560` | `0x20a560` | allowed-socket global setter |
| `TSocket_getStringField216` | `0x204698` | `sub_20A570` | `0x20a570` | string-field getter |
| `TSocket_getStringField232` | `0x2046c8` | `sub_20A5A0` | `0x20a5a0` | string-field getter |
| `TSocket_getStringField224` | `0x2046f8` | `sub_20A5D0` | `0x20a5d0` | string-field getter |
| `TSocket_getStringField200` | `0x204728` | `sub_20A600` | `0x20a600` | string-field getter |
| `TSocket_getStringField184` | `0x204758` | `sub_20A630` | `0x20a630` | string-field getter |
| `TSocket_getStringField144` | `0x204788` | `sub_20A660` | `0x20a660` | string-field getter |
| `TSocket_getStringField152` | `0x2047b8` | `sub_20A690` | `0x20a690` | string-field getter |
| `TSocket_getStringField160` | `0x2047e8` | `sub_20A6C0` | `0x20a6c0` | string-field getter |
| `TSocket_sendOutgoing_void` | `0x204894` | `_ZN10XJLBgarMnA10da7AgaaEQzEv` | `0x20a76c` | buffered send and prefix removal |
| `TSocket_create_TString_const` | `0x204a70` | `_Z20XJLBgarMnAE7Bm2aaHDBRK10C8THgaTQxF` | `0x20a948` | socket allocator and constructor |

The 17 accessor rows preserve the source field roles and all normalized
metrics except `setAllowedPortsBind`. That setter changes from the source
global `data_TSocket_allowedportsbind` assignment to the target
`XJLBgarMnA::gwjBgaP1_z` assignment through the `C8THgaTQxF` wrapper. It
remains a high-confidence layout-change anchor because the field and wrapper
roles are direct in the pseudocode. The other 16 accessor pairs have exact
size, instruction, block, branch, call, mnemonic, opcode-shape,
register-shape, and overall-shape matches. None of the 19 rows has string
references.

`sendOutgoing` keeps the connection-present and no-error guards, sends a
positive-length buffer from the same object fields, and removes the number of
bytes accepted by the connection. The target uses the obfuscated
`u3cBgayBVz` connection and `C8THgaTQxF` string helpers, but its body remains
an exact normalized match at 124 bytes, 31 instructions, 8 blocks, 7
branches, and 2 calls. The factory is also an exact match at 48/12/1/3/2.
It allocates `0xf0` bytes, calls the `XJLBgarMnA` parameterized constructor,
and returns the socket. The source factory's reference from
`TSocket_initStaticScriptVars_void` corresponds to the translated target
factory's reference from `v18_TSocket_initStaticScriptVars_void`.

The machine-readable record is
`artifacts/spectron_tsocket_accessor_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_tsocket_accessor_residual_anchors.py`. The 19
labels reopened with zero failures in the serial v132 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The target had 17 default
names before this batch, so the v132 database has 1,497 remaining default
`sub_` names. The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v132.i64`.
Its SHA-256 is
`56d799699ce321c4e212fb2e9c9ca0e7d8fed8a349da89dc733972d8f4e8bef9`.

## 2026-08-27: Spectron GuiControl factory residual anchor

The v131 pass resolved the remaining `GuiControl_create_TString_const`
factory ambiguity. The source wrapper at `0x1b4974` allocates `0x1c8` bytes,
calls the parameterized constructor, and returns the object. The matching
Spectron factory is `0x1b9040`, named
`_Z20w9XxgaJdbxE7Bm2aaHDBRK10C8THgaTQxF` in the clean export.

| 1.8 function | Source | Spectron target symbol | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `GuiControl_create_TString_const` | `0x1b4974` | `_Z20w9XxgaJdbxE7Bm2aaHDBRK10C8THgaTQxF` | `0x1b9040` | class-specific allocator and C2 call |

Both wrappers are 48 bytes, 12 instructions, one basic block, three branches,
and two calls. They also share the same mnemonic hash, opcode shape, register
shape, and overall shape hash, with no string references. The source calls
`operator new` and the parameterized constructor. The target calls the same
allocator and the `w9XxgaJdbx` C2 constructor at `0x1b8f68`.

The generic semantic search initially produced 26 factory-shaped candidates.
The target class name, exact normalized shape, `0x1c8` allocation size, and
the factory reference from the already translated
`v18_guiControl_initStaticScriptVars_void` caller identify `0x1b9040` as the
correct target. This resolves the ambiguity without relying on address order
alone. The target already had an obfuscated non-default name, so the default
`sub_` count remains 1,514.

The machine-readable record is
`artifacts/spectron_guicontrol_create_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_create_residual_anchors.py`. The label
reopened with zero failures in the serial v131 IDA check. The full semantic
translation reopen check also passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The label is in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v131.i64`.
The v131 database SHA-256 is
`0a9e38bcc80186b86ed83b5f6c92cad4101f8a2d7746e7379b2a192a02e8b603`.

## 2026-08-27: Spectron GuiControl initialization residual anchors

The v130 pass reviewed two residual `GuiControl` initialization methods. The
source `initObject` at `0x1b4680` and parameterized constructor at `0x1b48c8`
map to `0x1b8cfc` and `0x1b8f68` in the obfuscated `w9XxgaJdbx` class.
`GuiControl_create_TString_const` at `0x1b4974` remains outside this batch
because its existing target search has 26 candidates.

| 1.8 function | Source | Spectron target symbol | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `GuiControl_initObject_void` | `0x1b4680` | `_ZN10w9XxgaJdbx10j9gLgaw2nIEv` | `0x1b8cfc` | full field and child-list initialization |
| `GuiControl_GuiControl_TString_const` | `0x1b48c8` | `_ZN10w9XxgaJdbxC2ERK10C8THgaTQxF` | `0x1b8f68` | parameterized C2 construction |

`initObject` preserves the complete field initialization sequence, including
the controls registry string, child-list allocation, vtable slot 72 lookup,
and final array-update call. The source body is 584 bytes, 145 instructions,
4 basic blocks, 12 branches, and 8 calls. The target body is 620 bytes, 154
instructions, 4 basic blocks, 14 branches, and 10 calls. The target's extra
instructions are the explicit `CanTfaz6bZ` string assignment and cleanup and
the `G0gxgajWBw::tpNgMa2aKd` update wrapper. Both sides reference `controls`,
and both retain the same static initialization guard and cleanup boundary.

The parameterized constructor preserves the `TGraalVar` base construction,
region construction at object offset 176, the same field clearing, and the
call into `initObject`. Its source metrics are 172 bytes, 43 instructions,
2 basic blocks, 3 branches, and 2 calls. The target C2 body is 216 bytes, 54
instructions, 1 basic block, 6 branches, and 5 calls. The target constructs an
explicit temporary `CanTfaz6bZ`, calls the obfuscated base constructor, clears
the temporary, and then performs the same derived-object setup.

The default constructor at source `0x1b49a4` is already translated to target
`0x1b9070`, the target C1 constructor, with identical normalized metrics.
That existing pair confirms the class-local construction sequence and makes
the C2 signature at `0x1b8f68` the correct counterpart for the source
constructor that accepts a `TString` argument. Both new target names were
already non-default obfuscated names, so the default `sub_` count remains
1,514.

The machine-readable record is
`artifacts/spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_initialization_residual_anchors.py`.
Both labels reopened with zero failures in the serial v130 IDA check. The
full semantic translation reopen check also passed with 3,641 high-confidence
map labels and zero failures across 11,679 functions. The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v130.i64`.
The v130 database SHA-256 is
`1113a2703e11e58c61ff69510de89d938801ca3c405ca03c7a0fab3faa5b574d`.

## 2026-08-27: Spectron GuiControl event-dispatch residual anchors

The v129 pass reviewed eight remaining `GuiControl` event-dispatch methods.
They occupy the source sequence from `0x1b3984` through `0x1b3e40` and the
ordered Spectron sequence from `0x1b7eb8` through `0x1b84bc` inside the
obfuscated `w9XxgaJdbx` class. Four already translated rows remain useful
alignment anchors inside the enclosing sequence: `setY` at `0x1b3bf0`,
`setX` at `0x1b3c34`, `onAcceleratorKeyEvent` at `0x1b3c78`, and `getStyle` at
`0x1b3d14`. The corresponding target rows are `0x1b826c`, `0x1b82b0`,
`0x1b82f4`, and `0x1b8390`.

| 1.8 function | Source | Spectron target symbol | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `GuiControl_onBecomeFirstResponder_void` | `0x1b3984` | `_ZN10w9XxgaJdbx10xV7Kwa7ggaEv` | `0x1b7eb8` | event-string dispatch |
| `GuiControl_onDialogPush_void` | `0x1b39d0` | `_ZN10w9XxgaJdbx10fK5BgaArFAEv` | `0x1b7f3c` | event-string dispatch |
| `GuiControl_onDialogPop_void` | `0x1b3a1c` | `_ZN10w9XxgaJdbx10qgnIBawbXkEv` | `0x1b7fc0` | event-string dispatch |
| `GuiControl_onAdd_void` | `0x1b3a68` | `_ZN10w9XxgaJdbx10VSoCgaTxVAEv` | `0x1b8044` | event plus parent refresh |
| `GuiControl_notifyVisible_bool` | `0x1b3ad4` | `_ZN10w9XxgaJdbx10kpGWHa_hZzEb` | `0x1b80e8` | event plus child propagation |
| `GuiControl_onAction_void` | `0x1b3b9c` | `_ZN10w9XxgaJdbx10_pyQMazzPHEv` | `0x1b81e0` | action-state dispatch |
| `GuiControl_onMouseWheelUp_GuiEvent_const` | `0x1b3dd8` | `_ZN10w9XxgaJdbx10bvLrxaOzYKERK10cXoLgatBuI` | `0x1b8454` | exact wheel hook |
| `GuiControl_onMouseWheelDown_GuiEvent_const` | `0x1b3e40` | `_ZN10w9XxgaJdbx10TwTrxark4KERK10cXoLgatBuI` | `0x1b84bc` | exact wheel hook |

The first three source bodies are each 76 bytes, 18 instructions, one basic
block, four branches, and three calls. Their target bodies are each 132
bytes, 32 instructions, one basic block, eight branches, and seven calls.
`onAdd` grows from 108/26/3/6/4 to 164/40/3/10/8, where the values are size,
instructions, blocks, branches, and calls. `notifyVisible` grows from
200/48/9/10/5 to 248/60/9/14/9. `onAction` grows from 84/21/3/5/3 to
140/34/3/9/7. The two mouse-wheel methods are exact normalized-shape
matches at 104/26/6/7/1 on both sides.

The pseudocode supports the names beyond address order. The source
first-responder, dialog-push, and dialog-pop methods stream their readable
event names into a temporary string, invoke the `TGraalVar` event path, and
clear the temporary. Spectron keeps the same sequence through its encoded
`C8THgaTQxF`, `KKhLga4xoI`, and `G0gxgajWBw` wrappers. `onAdd` still invokes
the event and then refreshes the parent through the same parent slot and
virtual slot 480. `notifyVisible` still chooses the show or hide event and
propagates the state to active children through virtual slot 344. `onAction`
still checks the control-state byte at offset 277 before dispatching.

The source string references are `onBecomeFirstResponder`, `onDialogPush`,
`onDialogPop`, `onAdd`, `onHide` or `onShow`, and `onAction`. Spectron exposes
the encoded target string `33cSO` in `onAdd` and `22F>NF` in
`notifyVisible`, while the other four target bodies do not retain a plain
string reference. These differences are expected wrapper evidence, not a
behavior mismatch. Both mouse-wheel methods retain the same byte 276 state
check, byte 278 parent-window branch, and virtual slot 664 call.

The target-only one-instruction thunk at `0x1b7c6c` remains outside this
event block and outside the translated rows. It is kept as a separate
boundary before the already mapped `resizeChildren` method. All eight
Spectron targets already had obfuscated non-default names in the clean
export, so this batch leaves the default `sub_` count at 1,514.

The machine-readable record is
`artifacts/spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_event_dispatch_residual_anchors.py`.
The eight labels reopened with zero failures in the serial v129 IDA check.
The full semantic translation reopen check also passed with 3,641
high-confidence map labels and zero failures across 11,679 functions. The
labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v129.i64`.
The v129 database SHA-256 is
`f2f0e0e125d868a43ed9aba2caf46025bd65df9254669fc6aa3caeef0771c0bf`.

## 2026-08-27: Spectron GuiControl style and bounds residual anchors

The v128 pass reviewed 12 residual `GuiControl` style, geometry, profile, and
color methods. The first three rows use the source-to-target `+0x4500` delta.
Spectron's `getStyle` implementation grows by 0x34 bytes, so the remaining
rows align at `+0x4534` through target `0x1b7b64`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `GuiControl_setHint` | `0x1b30f8` | `0x1b75f8` | hint string assignment |
| `GuiControl_getHint` | `0x1b3100` | `0x1b7600` | hint string return |
| `GuiControl_getStyle` | `0x1b3130` | `0x1b7630` | style and level-resource fallback |
| `GuiControl_getMinExtent` | `0x1b33cc` | `0x1b7900` | point-string conversion |
| `GuiControl_getClientExtent` | `0x1b33f0` | `0x1b7924` | point-string conversion |
| `GuiControl_getPosition` | `0x1b3414` | `0x1b7948` | point-string conversion |
| `GuiControl_getExtent` | `0x1b3438` | `0x1b796c` | point-string conversion |
| `GuiControl_getRotationCenter` | `0x1b345c` | `0x1b7990` | two-field point conversion |
| `GuiControl_setProfile` | `0x1b3494` | `0x1b79c8` | profile dynamic cast and dispatch |
| `GuiControl_script_addControl` | `0x1b3518` | `0x1b7a4c` | script add-control wrapper |
| `GuiControl_getColor` | `0x1b3558` | `0x1b7a8c` | packed color reconstruction |
| `GuiControl_getBounds` | `0x1b3630` | `0x1b7b64` | rectangle-string conversion |

The first two wrappers preserve the same `TString` field at object offset
424. `getStyle` still obtains the active profile through the same vtable slot
808, returns a nonempty profile style, falls back to the level-resource
filename, and finally returns the same default style string. Spectron makes
temporary string and resource wrappers explicit, changing the source body
from 256 bytes, 64 instructions, 11 blocks, 16 branches, and 8 calls to 308
bytes, 77 instructions, 11 blocks, 20 branches, and 12 calls.

The other 11 pairs are exact normalized-shape matches. The point and rectangle
getters call the same conversion roles. `setProfile` keeps the dynamic cast
and vtable dispatch at byte offset 792. `getColor` reconstructs the same four
packed color bytes from the float fields before calling the target color
string wrapper. All 12 target rows were generic `sub_` functions in the clean
export, and none has string references. The v128 application therefore
reduced the default count from 1,526 to 1,514.

The target-only thunk at `0x1b7c6c` remains an explicit boundary before the
next already mapped `resizeChildren` method. It is not assigned to a source
row from this artifact.

The machine-readable record is
`artifacts/spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_style_bounds_residual_anchors.py`. The 12
labels reopened with zero failures in the serial v128 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v128 database has
1,514 remaining default `sub_` names. Its SHA-256 is
`d48e2c7f17fb26f72f4619589b6612cffdd862570476f3e3efa77b3b5c67d6b4`.

## 2026-08-27: Spectron GuiControl event and sizing residual anchors

The v127 pass reviewed eight remaining named methods from the next
`GuiControl` sequence. The source interval is `0x1b2b78` through `0x1b306c`.
The corresponding Spectron interval is `0x1b7078` through `0x1b74ec`, using
the same fixed `+0x4500` delta. Six methods inside the enclosing interval were
already in the semantic map, and the unnamed source row at `0x1b2fdc` was
left out because it has no readable 1.8 symbol.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `GuiControl_onChildResized_GuiControl` | `0x1b2b78` | `0x1b7078` | empty child-resize hook |
| `GuiControl_onInputEvent_InputEvent_const` | `0x1b2e90` | `0x1b7390` | default input-event return |
| `GuiControl_onMouseMove_GuiEvent_const` | `0x1b2ec0` | `0x1b73c0` | empty mouse-move hook |
| `GuiControl_onKeyRepeat_GuiEvent_const` | `0x1b2ec4` | `0x1b73c4` | vtable forwarding at slot 760 |
| `GuiControl_getScrollLineSizes_uint_uint` | `0x1b2f48` | `0x1b7448` | paired scroll-line fields |
| `GuiControl_getVertSizing` | `0x1b2f5c` | `0x1b745c` | vertical sizing string lookup |
| `GuiControl_getHorizSizing` | `0x1b2f9c` | `0x1b749c` | horizontal sizing string lookup |
| `GuiControl_setVertSizing` | `0x1b2fec` | `0x1b74ec` | vertical sizing index setter |

The event methods retain their original behavior. The child-resized and
mouse-move hooks are empty, while the input-event default returns zero. The
key-repeat wrapper dispatches through vtable byte offset 760. The scroll-line
helper writes the two output values from the same object fields at offsets
324 and 328. The vertical and horizontal sizing getters scan the same static
string tables and stream the selected name into a temporary `TString`.
The vertical setter compares against the same string table and stores the
selected index at offset 404. The horizontal setter is already in the
semantic map at `0x1b306c` and is retained as the next sequence boundary.

All eight reviewed pairs have matching size, instruction count, basic-block
count, branch count, call count, mnemonic hash, opcode shape, register shape,
and overall shape hash. Neither side has string references. Three target rows
were generic `sub_` functions in the clean export. The v126 database already
contained the `getScrollLineSizes` alias from the earlier manual lineage, so
the v127 application wrote seven new names and reduced the default count from
1,529 to 1,526.

The source `sub_1B2FDC` and target `sub_1B74DC` rows remain an explicit
unnamed gap. The target-only-looking helper at `0x1b7078` is therefore now
resolved to `GuiControl_onChildResized_GuiControl`, rather than being folded
into the preceding property block. This preserves both the v125 property
boundary and the v127 event-block evidence.

The machine-readable record is
`artifacts/spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_event_sizing_residual_anchors.py`. The
eight labels reopened with zero failures in the serial v127 IDA check. The
full semantic translation reopen check also passed with 3,641 high-confidence
map labels and zero failures across 11,679 functions. The v127 database has
1,526 remaining default `sub_` names. Its SHA-256 is
`a8b9293373fc4424b5a6de148a3822fd2819e21888703d1062aea3117bb1d1c5`.

## 2026-08-27: Spectron GuiControl virtual and base-hook residual anchors

The v126 pass reviewed the 13 remaining `GuiControl` methods in the small
base and virtual-hook sequence immediately before the bitmap-control property
classes. The source range is `0x1ac750` through `0x1ac81c`. Spectron keeps the
same ordered range at `0x1b0910` through `0x1b09dc`, a fixed `+0x41c0` delta,
inside the obfuscated `w9XxgaJdbx` class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `GuiControl_requiredCacheSize_void` | `0x1ac750` | `0x1b0910` | cache-size output wrapper |
| `GuiControl_setMinExtent_TPoint_const` | `0x1ac76c` | `0x1b092c` | minimum extent setter |
| `GuiControl_getCursorType_GuiEvent_const` | `0x1ac778` | `0x1b0938` | cursor-type lookup |
| `GuiControl_getRoot_void` | `0x1ac780` | `0x1b0940` | parent root dispatch |
| `GuiControl_getExternalWindow_void` | `0x1ac7b0` | `0x1b0970` | parent window dispatch |
| `GuiControl_updateClientBounds_void` | `0x1ac7e0` | `0x1b09a0` | client-bound refresh |
| `GuiControl_onPreRender_void` | `0x1ac7fc` | `0x1b09bc` | empty pre-render hook |
| `GuiControl_onRightMouseDown_GuiEvent_const` | `0x1ac800` | `0x1b09c0` | empty right-button hook |
| `GuiControl_onRightMouseUp_GuiEvent_const` | `0x1ac804` | `0x1b09c4` | empty right-button hook |
| `GuiControl_onRightMouseDragged_GuiEvent_const` | `0x1ac808` | `0x1b09c8` | empty right-button hook |
| `GuiControl_setScriptAccessRestricted_bool` | `0x1ac80c` | `0x1b09cc` | script-access byte setter |
| `GuiControl_forceClipping_void` | `0x1ac814` | `0x1b09d4` | empty clipping hook |
| `GuiControl_showContextMenus_void` | `0x1ac81c` | `0x1b09dc` | empty context-menu hook |

The pseudocode confirms more than just the address arithmetic. Both cache
wrappers return the same 64-bit field through the output pointer. The root and
external-window wrappers follow the same parent pointer at object slot 14 and
dispatch through vtable byte offsets 416 and 432. The script-access setter
writes the same byte at offset 204. The pre-render, right-mouse, clipping,
and context-menu hooks remain null-returning stubs in both versions.

All 13 pairs have matching size, instruction count, basic-block count, branch
count, call count, mnemonic hash, opcode shape, register shape, and overall
shape hash. Neither side has string references. The target rows already have
obfuscated method names, so this pass adds readable `v18_` aliases without
changing the default `sub_` count. The adjacent target destructor family
begins at `0x1b09e4`, which is kept as a separate class boundary.

The machine-readable record is
`artifacts/spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_virtual_residual_anchors.py`. The 13
labels reopened with zero failures in the serial v126 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v126 database has
1,529 remaining default `sub_` names. Its SHA-256 is
`aed7e8fe3fd07cfe33c1ea0cc13df6742dec3e9a120e06873729203d9c4404a4`.

## 2026-08-27: Spectron GuiControl property residual anchors

The v125 pass reviewed 61 residual `GuiControl` property and script-wrapper
rows. They are one compact source sequence covering the generated control
properties that were not already included in the semantic map. Spectron keeps
the same sequence at a fixed `+0x4500` delta in its obfuscated `w9XxgaJdbx`
class.

| Source sequence | Spectron sequence | Coverage |
| --- | --- | --- |
| `0x1b2748` through `0x1b28e4` | `0x1b6c48` through `0x1b6de4` | drop handling, activity, color, clipping, focus, flicker, and height accessors |
| `0x1b2934` through `0x1b2a14` | `0x1b6e34` through `0x1b6f14` | hint, mouse-lock, mode, color, resize, rotation, and scroll-line properties |
| `0x1b29fc` through `0x1b2ab4` | `0x1b6efc` through `0x1b6fb4` | topmost, hint visibility, profile ownership, visibility, width, position, and parent accessors |
| `0x1b2af4` through `0x1b2b14` | `0x1b6ff4` through `0x1b7014` | `showtop` and `showalwaysontop` script wrappers |

The ranges above describe the enclosing source and target order. Seven source
rows inside the interval were already covered by the semantic map and were
not duplicated: `setClientHeight`, `setClientWidth`, `setHeight`,
`getIsInAnimation`, `setWidth`, `script_resize`, and `compare_y`. The
machine-readable artifact contains the other 61 rows in their original
order.

The representative bodies confirm the property roles directly. The
`AcceptDropFiles` getter reads the byte at object offset 340 in both builds.
The `AreaClickPriority` setter clamps its input to the inclusive range 0
through 2 and stores the result at offset 332. The height setter keeps the
same positive-size fallback and virtual resize callback, including the
rectangle fields at offsets 344, 352, and 356. The `ScrollLineX` setter
clamps negative values to zero and writes offset 324. The `UseOwnProfile`
setter dispatches through the same vtable slot at byte offset 800, and the
`showtop` wrapper dispatches through the same slot at byte offset 360.

Every one of the 61 reviewed pairs has matching size, instruction count,
basic-block count, branch count, call count, mnemonic hash, opcode shape,
register shape, and overall shape hash. Neither side has string references.
All 61 target rows were generic `sub_` functions in the clean feature export.
The v124 database already contained one of the proposed names from an older
manual anchor set, so the v125 application wrote 60 new names and verified
all 61 expected names after reopening. The default target count therefore
drops from 1,589 to 1,529.

The target-only one-instruction helper at `0x1b7078` remains outside the
translated interval. It has no source row in this block and is intentionally
left unlabeled. This keeps the fixed-delta result from absorbing a target
method that may belong to a later virtual or helper section.

The machine-readable record is
`artifacts/spectron_guicontrol_property_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_property_residual_anchors.py`. The 61
labels reopened with zero failures in the serial v125 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v125 database has
1,529 remaining default `sub_` names. Its SHA-256 is
`0b55e73e765827d37e37e7403c2f0779229a178f3deb78314e86da17d770a75b`.

## 2026-08-27: Spectron GuiControlProfile destructor anchors

The v124 pass reviewed the six remaining destructor-family rows around the
profile implementation. Four rows cover the `GuiControlProfileProperties`
complete and deleting destructors plus their non-virtual thunks. The final
two rows cover the complete and deleting `GuiControlProfile` destructors.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `GuiControlProfileProperties_GuiControlProfileProperties` | `0x112914` | `0x1151c8` | properties complete destructor |
| `non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties` | `0x112930` | `0x1151e4` | properties D1 thunk |
| `GuiControlProfileProperties_GuiControlProfileProperties__2` | `0x112938` | `0x1151ec` | properties deleting destructor |
| `non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties__2` | `0x112970` | `0x115224` | properties D0 thunk |
| `GuiControlProfile_GuiControlProfile` | `0x112978` | `0x11522c` | profile complete destructor |
| `GuiControlProfile_GuiControlProfile__2` | `0x112a00` | `0x1152bc` | profile deleting destructor |

IDA presents the source destructor entries at `0x112914` through `0x112a90`
with constructor-style names because of the historical symbol spelling. The
alternative names identify the first four as D2 or D0 forms. Spectron makes
the corresponding D1 and D0 forms explicit in its `XoqxgaMPJwProperties`
and `XoqxgaMPJw` classes.

The four properties rows are exact normalized-shape matches. Both target
thunks subtract 16 from `this`, just like the source thunks. The target
complete destructor installs both vtable pointers and calls the obfuscated
`c76BgaJBGA` base destructor. The deleting form performs the same cleanup
and then calls `operator delete`.

The main profile destructor pair is a documented 2.2 layout change. The
source D2 form is 136 bytes with ten direct calls, while the target D1 form is
144 bytes with eleven direct calls. The source D0 form is 144 bytes with
eleven direct calls, while the target D0 form is 152 bytes with twelve direct
calls. In both cases the target adds two instructions and one cleanup call.
The cleanup order remains recognizable: the string fields are cleared, the
two resource-file-user subobjects are destroyed, and the `TGraalVar` base is
destroyed. Spectron uses its `C8THgaTQxF`, `CanTfaz6bZ`, `EXZ0IaPJru`, and
`G0gxgajWBw` wrappers for those same roles.

The machine-readable record is
`artifacts/spectron_gui_control_profile_destructor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gui_control_profile_destructor_anchors.py`. All six
labels reopened with zero failures in the serial v124 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v124 database keeps
1,589 remaining default `sub_` names because all six target destructor rows
already had non-default names. Its SHA-256 is
`0db16cc6d06a77627a4b57048764aabb24f3a7b0c50cd9013b8b0a45c5bf0608`.

## 2026-08-27: Spectron GuiControlProfile accessor anchors

The v123 pass translated 89 residual `GuiControlProfile` accessors. This is
the largest compact property block reviewed so far. It covers the generated
boolean and integer properties, alignment and point fields, font-style
strings, color setters and getters, background inset, the resource-file
notification hook, and the profile font-color conversion helper.

The source block begins at `0x111248` and ends with the font-color helper at
`0x111cfc` (which ends at `0x111d8c`). The target sequence begins at
`0x113a28` and ends at `0x11457c`,
inside the obfuscated `XoqxgaMPJw` profile implementation. Most target rows
were still generic `sub_` names, so the class-local sequence was essential.

| Source sequence | Target sequence | Coverage |
| --- | --- | --- |
| `0x111248` through `0x111370` | `0x113a28` through `0x113b50` | 38 scalar property getters and setters |
| `0x111378` | `0x113b58` | alignment getter |
| `0x1113b8` through `0x111484` | `0x113ba8` through `0x113c74` | text, shadow, and box point wrappers |
| `0x1114a8` through `0x111658` | `0x113c98` through `0x113e48` | font-style setters and string getters |
| `0x111688` through `0x11189c` | `0x113e78` through `0x11408c` | color setters through shadow color |
| `0x111974` | `0x114164` | font-color setter |
| `0x1119e0` through `0x111b48` | `0x1141f4` through `0x11435c` | eleven color getters |
| `0x111b90` | `0x114380` | shadow-color getter |
| `0x111c54` through `0x111c78` | `0x114444` through `0x114468` | background inset and alignment setter |
| `0x111cf8` through `0x111cfc` | `0x1144e8` through `0x1144ec` | resource notification and font-color helper |

The first part of the block is a direct ordered match. Each source getter or
setter has the same two-instruction body shape in the target, with the target
field offsets adjusted for its profile layout. The alignment and point
wrappers preserve their source string conversion calls. The font-style
getters preserve the temporary string return convention.

The color methods also keep their source behavior. A representative setter
parses a packed color, scales each byte by 1/255, and stores four floats in
the corresponding profile slot. The target uses `Q9LCGaX7dt` for the color
parser. The representative getter reverses the float conversion and calls
`wC1CGa7Yrt` to build the returned color string. The field slots match the
source role sequence, including the target's shifted profile layout.

There are three deliberate coverage gaps in this alignment. Spectron has a
target-only 16-byte method at `0x113b98` after the alignment getter. The source
`GuiControlProfile_set_gradientcolor` row at `0x111908` is followed by target
data at `0x1140f4`, not a distinct IDA function. The source
`GuiControlProfile_get_bordercolor` row at `0x111b6c` has no distinct target
function before the target shadow-color getter at `0x114380`. These rows are
not silently assigned to the nearest same-shaped method. The separate target
data slots at `0x1140f4` and `0x1141cc` are retained as data references in the
IDA database.

Every one of the 89 reviewed pairs has matching size, instruction count,
basic-block count, branch count, call count, mnemonic hash, opcode shape,
register shape, and overall shape hash. None has string references, and none
was already in the semantic map. One target helper at `0x1144e8` already had
an obfuscated `XoqxgaMPJw` name; the other 88 target rows were generic names.
The saved database therefore drops the remaining default count from 1,677
to 1,589.

The machine-readable record is
`artifacts/spectron_gui_control_profile_accessor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gui_control_profile_accessor_anchors.py`. All 89
labels reopened with zero failures in the serial v123 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v123 database has
1,589 remaining default `sub_` names. Its SHA-256 is
`50300d39030edb45142902407ff7651d7a436bb237fe54fe9d1aa59c8f3d7b8f`.

## 2026-08-27: Spectron font options, font data, window properties, and screen-panel lifecycle anchors

The v122 pass reviewed 16 short methods that were still outside the semantic
map. They fill four small gaps around the resource and rendering classes:
the `TScreenPanelOpenGL` native predicate and destructor pair, six
`TFontOptions` property accessors, three `TFontData` methods, and the
`TWindowProperties` destructor pair with its two adjusted-this thunks.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScreenPanelOpenGL_isNative_void` | `0x10cbc4` | `0x10f514` | native predicate |
| `TScreenPanelOpenGL_TScreenPanelOpenGL` | `0x10cbcc` | `0x10f51c` | complete destructor |
| `TScreenPanelOpenGL_TScreenPanelOpenGL__2` | `0x10cbe0` | `0x10f530` | deleting destructor |
| `TFontOptions_get_pref__graal__defaultfontsize` | `0x10f6d4` | `0x111f70` | default-size getter |
| `TFontOptions_set_pref__graal__defaultfontsize` | `0x10f6e4` | `0x111f80` | default-size setter |
| `TFontOptions_get_enableutf8` | `0x10f6f4` | `0x111f90` | UTF-8 flag getter |
| `TFontOptions_set_pref__graal__defaultfontname` | `0x10f704` | `0x111fa0` | default-name setter |
| `TFontOptions_get_pref__graal__utf8fontfile` | `0x10f718` | `0x111fb4` | UTF-8 font-file getter |
| `TFontOptions_get_pref__graal__defaultfontname` | `0x10f750` | `0x111fec` | default-name getter |
| `TFontData_TFontData__2` | `0x110ad8` | `0x113354` | deleting destructor |
| `TFontData_findFontData_TString_const` | `0x110af8` | `0x113374` | filename hash lookup |
| `TFontData_initStaticVars_void` | `0x111218` | `0x1139f8` | hash-list initializer |
| `TWindowProperties_TWindowProperties` | `0x108280` | `0x10abd4` | base destructor |
| `non_virtual_thunk_to_TWindowProperties_TWindowProperties` | `0x10829c` | `0x10abf0` | adjusted-this thunk |
| `TWindowProperties_TWindowProperties__2` | `0x1082a4` | `0x10abf8` | deleting destructor |
| `non_virtual_thunk_to_TWindowProperties_TWindowProperties__2` | `0x1082dc` | `0x10ac30` | adjusted-this deleting thunk |

The first three rows complete the small `SU3JfaCUmR` screen-panel lifecycle
block. The native predicate returns one in both versions. The source
destructor pair installs the screen-panel vtable and calls the
`TPanelInterface` destructor. Spectron does the same work through its
obfuscated `oMhmIajzmW` base class, and the deleting form also calls
`operator delete`.

The six `TFontOptions` rows are particularly useful because the target
functions were still named `sub_111F70` through `sub_111FEC`. The source
pseudocode identifies the exact properties rather than just a generic field
access. The target getters and setters read or write the corresponding
`KcKRganuPN` globals for default font size, the UTF-8 switch, the default
font string, and the UTF-8 font-file string. The two string getters still
construct a return `TString` and assign the stored value through the target
string wrapper.

The `TFontData` deleting destructor calls its complete destructor and then
releases the object in both builds. The filename lookup lowercases the input,
computes a hash, queries the font-data hash list, and clears its temporary
string. The static initializer still allocates 0x28 bytes, constructs a
`THashList`, publishes it as the static font-data registry, and returns its
address. Spectron uses the `fUWH_a_9zm` class and its obfuscated hash-list
methods for the same sequence.

The four window-properties rows are a destructor family, not a second normal
constructor. IDA labels the source D2 and D0 forms with constructor-style
names because of the old symbol spelling. The two source thunks subtract 16
from the incoming `this` pointer before entering the destructor. Spectron
keeps the same `LJyzga9PwyProperties` D2 and D0 entries and the same
16-byte adjusted-this thunk layout.

Every source and target pair has matching size, instruction count,
basic-block count, branch count, call count, mnemonic hash, opcode shape,
register shape, and overall shape hash. None of the rows has string
references, and none was already in the semantic map. Six target rows were
default IDA names, so this pass reduces the remaining default count from
1,683 to 1,677.

The machine-readable record is
`artifacts/spectron_font_options_font_data_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_font_options_font_data_residual_anchors.py`. All 16
labels reopened with zero failures in the serial v122 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v122 database has
1,677 remaining default `sub_` names. Its SHA-256 is
`6163a6d7dcb2b510ec8664f72e40965ee31b56bc8d177a2c2ed1f969664a5c85`.

## 2026-08-27: Spectron font and font-manager residual anchors

The v121 pass reviewed nine remaining font-related methods. They cover the
`TFont` deleting destructor, texture bind, ascent, and descent methods, the
`TFontCharInfo` deleting destructor, and the `TFontManager` cache and text
metric helpers.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TFont_TFont__2` | `0x10ce3c` | `0x10f780` | `TZf6gaQ3S_` deleting destructor |
| `TFontCharInfo_TFontCharInfo__2` | `0x10d018` | `0x10f968` | `DFeOfaFXSU` deleting destructor |
| `TFont_bindTexture_void` | `0x10d998` | `0x110364` | texture lookup and bind |
| `TFont_getTextAscend_int` | `0x10da0c` | `0x1103d8` | scaled ascent and timestamp |
| `TFont_getTextDescend_int` | `0x10da64` | `0x110430` | scaled descent and timestamp |
| `TFontManager_freeResources_void` | `0x10e374` | `0x110d44` | font-cache clear |
| `TFontManager_getTextHeight_TString_const_int_TString_const` | `0x10f438` | `0x111cfc` | lookup, renderability, height |
| `TFontManager_getTextAscent_TString_const_int_TString_const` | `0x10f4a4` | `0x111d68` | lookup, renderability, ascent |
| `TFontManager_getTextDescent_TString_const_int_TString_const` | `0x10f510` | `0x111dd4` | lookup, renderability, descent |

The target keeps the `TZf6gaQ3S_` font sequence around its D0 destructor,
texture binding, and text metrics. The bind method reads the same texture
pointer and forwards mode `1` to the target texture object. The ascent and
descent methods retain the same high-precision timestamp update, zero-font-
size fallback, and scaled metric fields. The target time global is renamed,
but the formula and field selection are unchanged.

The `DFeOfaFXSU` target is the matching font-character-info class. Its D0
wrapper calls the corresponding destructor and then releases the object. The
three `Kv6ugas5Mu` manager methods preserve the font-cache clear operation and
the lookup, `canRender`, and metric-dispatch sequence. The target methods call
the corresponding `TZf6gaQ3S_` helpers for height, ascent, and descent.

Every row has matching size, instruction count, basic-block count, branch
count, call count, mnemonic hash, opcode shape, register shape, and overall
shape hash. No target row was a default name and none was already in the
semantic map. The source and target class-local sequences provide the role
evidence for the short wrappers that would otherwise have many generic shape
matches.

The machine-readable record is
`artifacts/spectron_font_manager_font_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_font_manager_font_residual_anchors.py`. All nine
labels reopened with zero failures in the serial v121 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v121 database has
1,683 remaining default `sub_` names. Its SHA-256 is
`b331d230f59f5229f98c69747b501e7015a4a979fb50bf2e7d3f40ab48021fae`.

## 2026-08-27: Spectron screen-panel and GLES-window residual anchors

The v120 pass translated the remaining screen-panel polygon-font stub and six
residual `TWindowGLES` methods. The target keeps these rows in the
`SU3JfaCUmR` and `StGQIaOlWk` classes, immediately after the renderer and
window methods already mapped in earlier passes.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TScreenPanelOpenGL_drawPolygonFont_TFont_int_int_char_const_int_int_TFontOptions_const` | `0x10c5e4` | `0x10ef34` | empty polygon-font hook |
| `TWindowGLES_flipOffscreen_void` | `0x10cc10` | `0x10f560` | empty offscreen-flip hook |
| `TWindowGLES_setSizeImpl_bool` | `0x10cc14` | `0x10f564` | empty resize hook |
| `TWindowGLES_TWindowGLES` | `0x10cc18` | `0x10f568` | complete destructor |
| `TWindowGLES_TWindowGLES__2` | `0x10cc2c` | `0x10f57c` | deleting destructor |
| `TWindowGLES_createPixelBuffer_TString_const_int_int_int` | `0x10cc4c` | `0x10f59c` | OpenGL pixel-buffer factory |
| `TWindowGLES_isNative_void` | `0x10cd70` | `0x10f6c0` | true native-mode result |

The polygon-font stub is a four-byte return in both versions and sits between
the target's large texture-font method and its already translated text method.
The `TWindowGLES` rows are one local class block. The first two are empty in
both builds. IDA identifies the source constructor-style names at
`0x10cc18` and `0x10cc2c` as the complete and deleting destructor forms; the
target names make this explicit as D1 and D0 methods. Both destructor bodies
install the target vtable, invoke the base window destructor, and the deleting
form releases the object.

The pixel-buffer factory allocates 0x78 bytes in the source and 0x80 bytes in
the target, then forwards the window, resource name, dimensions, and format
arguments to the corresponding window-backed pixel-buffer constructor. The
size change is consistent with the target `uzN1fatj75` layout already seen in
the renderer pass. The native-mode method returns true in both builds.

All seven source and target pairs have matching size, instruction count,
basic-block count, branch count, call count, mnemonic hash, opcode shape,
register shape, and overall shape hash. No target row was a default name and
none was already in the semantic map. The target `TWindowGLES` class is
therefore a high-confidence role translation even though its original C++
symbols are obfuscated.

The machine-readable record is
`artifacts/spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_screen_panel_window_gles_residual_anchors.py`. All
seven labels reopened with zero failures in the serial v120 IDA check. The
full semantic translation reopen check also passed with 3,641 high-confidence
map labels and zero failures across 11,679 functions. The v120 database has
1,683 remaining default `sub_` names. Its SHA-256 is
`c110ed3f38aad8b12296aa81cc6d780c2911d608fba5b895e0eaee7a2f48d955`.

## 2026-08-27: Spectron screen-panel renderer residual anchors

The v119 pass filled ten residual methods in the concrete renderer sequence
that follows the pixel-buffer allocation helpers. The source starts with the
`TPixelBufferOpenGL` texture predicate and then enters the
`TScreenPanelOpenGL` matrix and shader methods. Spectron keeps that sequence
in the obfuscated `uzN1fatj75` and `SU3JfaCUmR` classes.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TPixelBufferOpenGL_hasTexture_void` | `0x109c34` | `0x10c584` | texture-handle predicate |
| `TScreenPanelOpenGL_getProjMatrix_void` | `0x109c44` | `0x10c594` | projection-matrix copy |
| `TScreenPanelOpenGL_getModelMatrix_void` | `0x109c70` | `0x10c5c0` | model-matrix copy |
| `TScreenPanelOpenGL_setProjMatrix_MatrixF_const` | `0x109c9c` | `0x10c5ec` | projection-matrix store and valid flag |
| `TScreenPanelOpenGL_setModelMatrix_MatrixF_const` | `0x109ccc` | `0x10c61c` | model-matrix store and valid flag |
| `TScreenPanelOpenGL_drawTriangleStripPanel_TDrawingPanelPort_float_int_float_float_bool` | `0x109d2c` | `0x10c67c` | empty triangle-strip hook |
| `TScreenPanelOpenGL_canUseShader_void` | `0x109d40` | `0x10c690` | false shader-capability result |
| `TScreenPanelOpenGL_setShader_TOpenGLShaderProgram` | `0x109d48` | `0x10c698` | empty shader setter |
| `TScreenPanelOpenGL_clearShader_void` | `0x109d4c` | `0x10c69c` | empty shader clearer |
| `TScreenPanelOpenGL_setAlphaReference_float` | `0x109d64` | `0x10c6b4` | `glAlphaFunc` wrapper |

The texture predicate reads the source texture handle at object offset 116
and the target handle at offset 120. This is the same boolean test with one
four-byte layout shift. The projection getter copies the same eight-word
matrix from source offset 40 and target offset 56. The model getter does the
same from source offset 104 and target offset 120. The setters copy all eight
words back to those regions and set the corresponding validity byte. Their
source flags are at offsets 36 and 37; the target flags are at 53 and 54.
These changes fit the target class layout and are stronger evidence than a
body-size comparison alone.

The triangle-strip method is empty in both versions. The shader-capability
method returns false, while the shader setter and clearer are empty. The
alpha-reference method forwards the threshold to `glAlphaFunc(516, value)`
in both builds. The nearby `clearStates` and `setBlendColor` methods are not
part of this batch because their target rows already carry labels from the
earlier renderer anchors. The address gaps at those two source positions are
therefore intentional.

All ten source and target pairs have matching size, instruction count,
basic-block count, branch count, call count, mnemonic hash, opcode shape,
register shape, and overall shape hash. None of the target rows had a default
name, and none was already in the semantic map. This is a manual context
anchor batch, so the semantic map's high-confidence count remains 3,641 even
though the persisted IDA copy now contains ten additional readable aliases.

The machine-readable record is
`artifacts/spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_screen_panel_renderer_residual_anchors.py`. All ten
labels reopened with zero failures in the serial v119 IDA check. The full
semantic translation reopen check also passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v119 database has
1,683 remaining default `sub_` names. Its SHA-256 is
`d57ae1011d866d392898e057f6a1cc309955755a8c5175a5ca07c66644fdaa27`.

## 2026-08-27: Spectron dummy-panel residual anchors

The v118 pass completed the next contiguous renderer-side cluster. It covers
three residual `TPanelInterface` hooks followed by the portable `TDummyPanel`
virtual table and its two destructor forms. The target class names are
obfuscated, but the local sequence is unusually strong and every pair has the
same normalized function shape.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TPanelInterface_addModificationClipped_float_float_float_float` | `0x103b40` | `0x1061a8` | empty clipped-modification hook |
| `TPanelInterface_addModification_float_float_float_float` | `0x103b44` | `0x1061ac` | empty modification hook |
| `TPanelInterface_drawArrays_int_int_int` | `0x103b48` | `0x1061b0` | empty array-draw hook |
| `TDummyPanel_drawImage_TString_const_float_float_float_float_int_int_int_int` | `0x103b4c` | `0x1061b4` | empty image hook |
| `TDummyPanel_drawLine_float_float_float_float_float` | `0x103b50` | `0x1061b8` | empty line hook |
| `TDummyPanel_fillRectangle_float_float_float_float_bool` | `0x103b54` | `0x1061bc` | empty rectangle hook |
| `TDummyPanel_drawDrawingPanel_TDrawingPanelPort_float_float_float_float_int_int_int_int` | `0x103b58` | `0x1061c0` | empty nested-panel hook |
| `TDummyPanel_drawTriangleStripPanel_TDrawingPanelPort_float_int_float_float_bool` | `0x103b5c` | `0x1061c4` | empty triangle-strip hook |
| `TDummyPanel_drawText_TFontOptions_const_TPoint_const_char_const_int` | `0x103b60` | `0x1061c8` | empty text hook |
| `TDummyPanel_createDrawingPanel_int_int_int_int` | `0x103b64` | `0x1061cc` | zero-return panel factory |
| `TDummyPanel_setTransformedClippingRectangle_float_float_float_float` | `0x103b6c` | `0x1061d4` | empty clipping setter |
| `TDummyPanel_getTransformedClippingRectangle_void` | `0x103b70` | `0x1061d8` | zeroed clipping rectangle |
| `TDummyPanel_TDummyPanel` | `0x103b8c` | `0x1061f4` | complete destructor |
| `TDummyPanel_TDummyPanel__2` | `0x103ba0` | `0x106208` | deleting destructor |

The three `TPanelInterface` rows at `0x103b40` through `0x103b48` are empty
methods in the source and in the target `oMhmIajzmW` class. They sit directly
before the target's already translated nontrivial panel methods at
`0x106244`, which keeps the residual hooks in the correct class context.

The next eleven rows form the `TDummyPanel` block. Target class
`HtZ2_aJk7E` preserves the source order from the image, line, and rectangle
hooks through the drawing-panel and text hooks, the null panel factory, the
transformed-clipping pair, and the lifecycle methods. The target pseudocode
confirms that the drawing methods are no-ops, the factory returns zero, and
the rectangle getter writes four zero values.

The source and target constructors are represented by the same D1 and D0
destructor shapes that IDA showed in the source. The complete form installs
the target vtable and invokes the `oMhmIajzmW` base destructor. The deleting
form does the same and then releases the object. This class-local destructor
evidence is stronger than treating the two short bodies as generic delete
wrappers.

Every row has matching size, instruction count, basic-block count, branch
count, call count, mnemonic hash, opcode shape, register shape, and overall
shape hash. No target address was already in the semantic map, and no default
target name was involved in this batch.

The machine-readable record is
`artifacts/spectron_dummy_panel_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_dummy_panel_residual_anchors.py`. All 14
labels reopened with zero failures in the serial v118 IDA check. The full
semantic translation reopen check still passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v118 database has 1,683
remaining default `sub_` names. Its SHA-256 is
`de9c45f75c839c7cbbe802544129f2021e29f1aec02f0543d374df89a777fbbf`.

## 2026-08-27: Spectron panel virtual and renderer residual anchors

The v117 pass reviewed the remaining compact panel-interface virtual methods
around the already translated drawing-panel code, three panel-port tail hooks,
and the graphic-operation texture flush loop. This group is useful because it
joins small methods that are ambiguous by body shape alone to larger class
clusters whose order and behavior are clear.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TPanelInterface_isNative_void` | `0xfe308` | `0x100970` | zero-return base predicate |
| `TPanelInterface_drawTextureStretched_TPixelBuffer_float_float_float_float_int_int_int_int` | `0xfe310` | `0x100978` | empty texture-stretch hook |
| `TPanelInterface_setArrays_int_int_float_const_float_const_float_const_float_const_void_const` | `0xfe314` | `0x10097c` | empty array setup hook |
| `TPanelInterface_drawElements_int_int_int_void_const` | `0xfe318` | `0x100984` | empty indexed-draw hook |
| `TPanelInterface_requestState_int_int` | `0xfe31c` | `0x100988` | empty state request hook |
| `TPanelInterface_clearStates_void` | `0xfe320` | `0x10098c` | empty state clear hook |
| `TPanelInterface_setBlendMode_int` | `0xfe324` | `0x100990` | empty blend-mode hook |
| `TPanelInterface_setBlendColor_ColorF_const` | `0xfe328` | `0x100994` | empty blend-color hook |
| `TPanelInterface_setAlphaReference_float` | `0xfe32c` | `0x100998` | empty alpha-reference hook |
| `TPanelInterface_canUseShader_void` | `0xfe330` | `0x10099c` | zero-return shader predicate |
| `TPanelInterface_setShader_TOpenGLShaderProgram` | `0xfe338` | `0x1009a4` | empty shader-selection hook |
| `TPanelInterface_clearShader_void` | `0xfe33c` | `0x1009a8` | empty shader-clear hook |
| `TPanelInterface_reloadDefaultShaders_void` | `0xfe340` | `0x1009ac` | empty shader-reload hook |
| `TPanelInterface_freeResources_void` | `0xfe344` | `0x1009b0` | empty resource-release hook |
| `TPanelInterface_getProjMatrix_void` | `0xfe348` | `0x1009b4` | identity projection matrix |
| `TPanelInterface_getModelMatrix_void` | `0xfe398` | `0x100a04` | identity model matrix |
| `TPanelInterface_setProjMatrix_MatrixF_const` | `0xfe3e8` | `0x100a54` | empty projection setter |
| `TPanelInterface_setModelMatrix_MatrixF_const` | `0xfe3ec` | `0x100a58` | empty model setter |
| `TDrawingPanelPort_flushTexture_void` | `0xfe3f0` | `0x100a5c` | empty inherited flush hook |
| `TPanelInterface_captureScreen_int_int_int_int_uchar_int_int` | `0x102760` | `0x104dc8` | zero-return capture hook |
| `TDrawingPanelPort_setPixels_uchar_int_int` | `0x102768` | `0x104dd0` | empty pixel setter hook |
| `TDrawingPanelPort_getPixels_void` | `0x10276c` | `0x104dd4` | zero-return pixel getter |
| `TGraphicOperation_flushTextures_void` | `0x1030a4` | `0x10570c` | drawing-panel flush loop |

The first 18 rows form a contiguous source `TPanelInterface` block. The
target `oMhmIajzmW` block has the same method order and matching signatures,
but it also contains one four-byte method at `0x100980`, between the source
`setArrays` and `drawElements` positions. Its mangled signature adds two
integer arguments to the array-style hook, so it is recorded as a target-only
2.2 method rather than being forced into a source role. The alignment skips
that one target method and then resumes exactly at `drawElements`.

This is more than a position-only match. Every reviewed source and target pair
has the same size, instruction count, basic-block count, branch count, call
count, mnemonic hash, opcode shape, register shape, and overall shape hash.
The source identity matrix getters and zero-return predicates have matching
target pseudocode. The other base methods are empty in both builds, which is
consistent with their role as a portable interface rather than an OpenGL
implementation.

The source `TDrawingPanelPort_flushTexture_void` follows the base block. The
target `OYYKfaPU7R` method at `0x100a5c` occupies the same inherited slot and
is immediately followed by the previously translated panel-port methods. The
later source tail contains a screen-capture hook followed by the pixel setter
and getter. Spectron keeps that same local trio at `0x104dc8` through
`0x104dd4`, split between the `oMhmIajzmW` base and `OYYKfaPU7R` derived
classes. All three bodies are exact shape matches.

The larger renderer row is the most useful operational result. The source
`TGraphicOperation_flushTextures_void` walks
`data_TGraphicOperation_drawingpanels`, obtains each panel through
`TList::operator[]`, and calls the panel vtable at byte offset 320. The target
`s40xgamwex::C2xOKaWf8Z` at `0x10570c` performs the same loop against
`s40xgamwex::NYGMKaOLzY`, uses `vy1JgaKVkH::operator[]`, and dispatches the
same flush responsibility at byte offset 328. The eight-byte difference is a
target class-layout change, not a different operation. This ties the readable
flush label to the renderer's drawing-panel lifecycle and gives us a concrete
place to inspect if texture updates fail during a real device run.

The machine-readable record is
`artifacts/spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_panel_virtual_renderer_residual_anchors.py`. All 23
labels reopened with zero failures in the serial v117 IDA check. The full
semantic translation reopen check still passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v117 database has 1,683
remaining default `sub_` names. Its SHA-256 is
`82f78696b705112585e04e2b3c522b88bed026d9d281bc4fdc9a7fff085ad5c4`.

## 2026-08-27: Spectron animation and palette residual anchors

The v116 pass reviewed four residual image-animation and palette methods.
The two base hooks belong to the target `n_rGfa49jO` class. The deleting
destructors belong to the target `_5EhmbQbtm` MNG class and `NLT0HaSwmE`
palette class.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TImageAnimation_makeNextBitmap_void` | `0x120610` | `0x123148` | base zero-return hook |
| `TImageAnimation_parsePicture_void` | `0x120618` | `0x123150` | base zero-return hook |
| `TMNGAnimation_TMNGAnimation__2` | `0x11f9b8` | `0x1224f0` | MNG deleting destructor |
| `TPalette_TPalette__2` | `0x12066c` | `0x1231a4` | palette deleting destructor |

The two image-animation hooks are exact 8/2/1 zero-return bodies in both
builds. Their target methods sit in the already identified `n_rGfa49jO`
class beside the reviewed constructor, stream factory, and destructor pair.
The target class therefore preserves the abstract base hooks while the
derived `_5EhmbQbtm` methods retain the actual MNG decode and frame logic.

The MNG and palette deleting destructors are exact 32/8/2 shapes with one
destructor call in both versions. The target wrappers call their matching D2
or D1 destructor and then `operator delete`, just as the source wrappers call
the corresponding destructor thunk and delete the object. The target
`_5EhmbQbtmD0Ev` and `NLT0HaSwmED0Ev` names make the class identity explicit.

The machine-readable record is
`artifacts/spectron_animation_palette_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_animation_palette_residual_anchors.py`.
All four labels reopened with zero failures in the serial v116 IDA check. The
full translation reopen check passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v116 database has 1,683
remaining default `sub_` names. Its SHA-256 is
`e0befd5c98459fd191889bfe921fb9c2e1caa7d372a8e0feceed8ce2ffe69e77`.

## 2026-08-27: Spectron pixel-buffer and bitmap lifecycle correction

The v115 pass corrected a medium-confidence collision in the automatic
semantic report and reviewed four destructor rows. The earlier shape-only
candidate had paired the source `TPixelBuffer` destructor with the target
`Fcx_gaoydV` bitmap destructor because both bodies were 48 bytes long. The
active translated IDA database had not applied that medium-confidence row.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TPixelBuffer_TPixelBuffer` | `0x104e5c` | `0x1074e4` | `uSjUgask_P` D1 destructor and pixel cleanup |
| `TPixelBuffer_TPixelBuffer__2` | `0x104e8c` | `0x107514` | `uSjUgask_P` deleting destructor |
| `TBitmap_TBitmap` | `0x112e24` | `0x1156f4` | `Fcx_gaoydV` D1 destructor and image cleanup |
| `TBitmap_TBitmap__2` | `0x112e54` | `0x115724` | `Fcx_gaoydV` deleting destructor |

The source pseudocode identifies the first and third rows as D1 destructors.
Each calls its class-specific cleanup method and clears the class string. The
second and fourth rows are deleting wrappers that call the matching D1 form
and then `operator delete`. Target cleanup callees confirm the class split:
`uSjUgask_P::pSeYgan7hT` releases pixel storage, while
`Fcx_gaoydV::MJw7Bag9WG` releases bitmap image state.

The correction keeps the original automatic report unchanged for reproducible
comparison, but supersedes its one medium-confidence collision in the
translated database. This matters because the target address `0x1156f4` is a
real bitmap destructor, not a pixel-buffer destructor. The corrected rows have
exact 48/12/2 and 32/8/2 metrics in both source and target pairs, with the
class-specific cleanup call providing the semantic distinction that a shape
hash alone missed.

The machine-readable record is
`artifacts/spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826.json`,
generated by `tools/generate_spectron_pixelbuffer_bitmap_lifecycle_anchors.py`.
All four labels reopened with zero failures in the serial v115 IDA check. The
full translation reopen check still passed with 3,641 high-confidence map
labels and zero failures across 11,679 functions. The v115 database has 1,683
remaining default `sub_` names. Its SHA-256 is
`a0272f3a6d1a8acd0e700e6924b99a2faa93f87151f47581385cbe6bdadb932e`.

## 2026-08-27: Spectron TPixelBuffer residual anchors

The v114 pass reviewed ten small methods in the target `uSjUgask_P` pixel
buffer class. The class-local sequence is anchored by the already translated
pixel setter, window-backed constructor, pitch getter, pixel destructor,
compatible-bitmap helper, kept-bitmap helper, and pixel allocator.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TPixelBuffer_setPixelsNoDestroy_uchar_int_int` | `0x104c90` | `0x107318` | pixel pointer and dimension stores |
| `TPixelBuffer_setPalette_TPalette_const` | `0x104ca8` | `0x107330` | palette pointer store |
| `TPixelBuffer_unsetPixels_void` | `0x104eac` | `0x107534` | pixel and palette clearing |
| `TPixelBuffer_setFormat_int` | `0x104eb8` | `0x107540` | format field store |
| `TPixelBuffer_getPixels_void` | `0x105084` | `0x10770c` | lazy allocation and pointer return |
| `TPixelBuffer_hasTexture_void` | `0x1050a4` | `0x10772c` | base texture predicate |
| `TPixelBuffer_createTexture_void` | `0x1050ac` | `0x107734` | base texture create hook |
| `TPixelBuffer_updateTexture_void` | `0x1050b0` | `0x107738` | base texture update hook |
| `TPixelBuffer_updateTexture_int_int_int_int` | `0x1050b4` | `0x10773c` | rectangle update dispatch |
| `TPixelBuffer_bindTexture_int` | `0x1050d4` | `0x10775c` | base texture bind hook |

The first four target bodies preserve the source field operations. The
offsets change because Spectron's pixel-buffer layout has additional fields,
but the target still stores the incoming pixel pointer and dimensions,
stores the palette pointer, clears the pixel and palette pointers, and stores
the format value. The source and target metrics are exact for all four
methods.

The source and target `getPixels` methods both call their class's pixel
allocation helper before returning the pixel pointer. The base
`hasTexture` method returns zero in both versions. The create, no-argument
update, and bind hooks are empty in both base classes. The four-argument
update overload keeps the same one-call indirect vtable dispatch, with an
exact 32/8/1 shape in both builds.

The target methods sit in the same `uSjUgask_P` local order as the translated
window constructor, pitch, destruction, compatible-bitmap, kept-bitmap, and
allocation methods. This class-local evidence is important for the three
empty hooks, whose bodies alone would not distinguish their roles. The
target's overloaded `dplYgaNCnT` names also preserve the no-argument and
four-argument pairing visible in the source method order.

The machine-readable record is
`artifacts/spectron_pixelbuffer_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_pixelbuffer_residual_anchors.py`. All
ten labels reopened with zero failures in the serial v114 IDA check. The full
translation reopen check passed with 3,641 high-confidence map labels and
zero failures across 11,679 functions. The v114 database has 1,683 remaining
default `sub_` names. Its SHA-256 is
`62362bfe045dfa107edc90dc3ca501baec50eaf6477b949f9e74be888c6fd725`.

## 2026-08-27: Spectron sound-runtime anchors

The v113 pass reviewed three residual methods in the target audio classes.
The main dispatcher is a method of `IUKzgam4Gy`, the note helper is a nearby
sound-manager function, and Java playback belongs to `QPh5pbnC3y`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TSounds_play_impl_TString_const_bool_bool_double_double` | `0xe135c` | `0xe1f34` | extension, cache, and playback state machine |
| `TSounds_script_setSoundPitchByNote` | `0xe2858` | `0xe3440` | note table, octave parsing, and pitch ratio |
| `TSoundEffectJava_play_void` | `0xe31d0` | `0xe3dc0` | Java playback, timing, and channel calculation |

The main dispatcher changes from 1,312/328/72 with 42 calls to
1,328/332/72 with 44 calls. Both lower-case and classify the extension,
select the relevant volume global, initialize the sound subsystem, check the
player capabilities, resolve absolute paths or downloads, consult the cached
effect list, stop or restart music when needed, create or reuse an effect,
and update its playing, loop, volume, and pan state. The target replaces the
source `TString`, `TFiles`, and `TSounds` wrappers with its
`C8THgaTQxF`, `wiULgacZUI`, `uq9xgaUxlx`, and `IUKzgam4Gy` equivalents.

The note helper changes from 548/135/21 with 26 calls to 556/137/21 with 26
calls. It still initializes the same twelve-note list, splits each note into
a two-character name and an octave, converts the octave into semitone space,
and calls `powf(2, delta / 12)` before passing the ratio to the sound manager.
The target function was still named `sub_E3440` in the stripped database, so
this row also records a safe recovery of a default name.

The Java playback method changes from 720/178/20 with 12 calls to 676/168/19
with 9 calls. Both enforce a short playback interval, resolve
`startSound([BII)V`, remove the configured base folder from the resource path,
obtain and release the Java byte array, calculate channel or volume values,
and update the playing flag and high-precision timestamp. The source has a
literal `steps` special case that is not present in the target string set or
body, so that is recorded as a 2.2 behavior difference rather than silently
called equivalent.

The source `TSoundEffect` constructor at `0xe0dc0` was checked during the same
pass but is intentionally excluded. The target sound manager clearly returns
the `J7zOgaf09K` effect class, yet the corresponding stripped constructor was
not isolated with enough evidence to justify a rename. Keeping that row out
maintains the archive's distinction between a useful hypothesis and a
reviewed correspondence.

The machine-readable record is
`artifacts/spectron_sound_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_sound_runtime_anchors.py`. All three
labels reopened with zero failures in the serial v113 IDA check. The full
translation reopen check passed with 3,641 high-confidence map labels and
zero failures across 11,679 functions. Renaming the default target note
helper reduces the remaining default `sub_` count from 1,684 to 1,683. The
v113 database SHA-256 is
`b8d25d41ea73f217003a7e39799ce9f124f2452c12f4df694b22c3caf4c70b37`.

## 2026-08-27: Spectron TWindow residual anchors

The v112 pass reviewed two small methods in the target `LJyzga9Pwy` window
class. They sit beside the previously translated input and window lifecycle
methods.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TWindow_onCloseQuery_void` | `0x1066e8` | `0x1090b4` | main-window shutdown preparation |
| `TWindow_createPixelBuffer_TString_const_int_int_int` | `0x1068a0` | `0x109048` | allocation and window-backed construction |

The close-query method changes from 72/18/3 with one direct call to 88/22/3
with one call. Both compare the current object with the main-window global,
call shutdown preparation for that window, and set the application-close
state. Spectron additionally writes a second value, `2`, into its shutdown
state global. That is recorded as a target-version state difference.

The pixel-buffer factory is an exact 100/25/1 and two-call shape in both
versions. Both allocate 0x78 bytes and pass the window, name, width, height,
and format or flags to the window-backed pixel-buffer constructor. The target
uses the `uSjUgask_P` wrapper while preserving the source factory role.

The machine-readable record is
`artifacts/spectron_window_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_window_residual_anchors.py`. Both labels
reopened with zero failures in the serial v112 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v112 database has 1,684 remaining
default `sub_` names. Its SHA-256 is
`d8c782e2040a57c3bae8e406c90e0d94d7bc32fef82b203a33621fcd0a6c9209`.

## 2026-08-27: Spectron GIF decoder anchor

The v111 pass reviewed the changed `TBitmap` GIF decoder. The target remains
in the `Fcx_gaoydV` bitmap implementation class and is called by the v110
extension dispatcher.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TBitmap_readGIF_TStream` | `0x150a38` | `0x153578` | GIF parsing and animation-step construction |

The decoder changes from 1,096/274/50 with 27 direct calls to 1,840/457/66
with 67 calls. Both open the GIF stream, walk image and extension records,
decode Graphic Control Extensions, build RGBA palettes, allocate animation
steps, copy indexed rows, insert each step into the bitmap list, close the
file, and initialize the first bitmap from the first animation step.

The target preserves the source transparency index and delay extraction,
palette byte ordering, row-order state machine, allocation failure cleanup,
and final bitmap setup. It adds a boolean retry or diagnostic mode, maps GIF
errors through `GifErrorString`, logs numbered failure cases, and logs a
successful animation-step count. Those additions explain the larger target
body and are recorded as target-version behavior, not as a different decoder
role.

The machine-readable record is
`artifacts/spectron_gif_decoder_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_gif_decoder_anchor.py`. The label
reopened with zero failures in the serial v111 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v111 database has 1,684 remaining
default `sub_` names. Its SHA-256 is
`aa225a0d07cbd7f7ab3e015762c3d9ab14e4c6c46b6154b0bf11ef6852d3d64c`.

## 2026-08-27: Spectron panel and bitmap-loader anchors

The v110 pass reviewed four methods spanning panel construction and bitmap
resource loading. The target panel implementation is in `oMhmIajzmW`, the
bitmap implementation is in `Fcx_gaoydV`, and the resource loader is in
`kM00HafgtE`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TPanelInterface_TPanelInterface_TWindow_TString_const` | `0x103fcc` | `0x106634` | window pointer, base construction, and vtable |
| `TBitmap_loadBitmap_TStream_TString_const` | `0x114be8` | `0x1174b8` | extension dispatch to image decoders |
| `TBitmapLoader_forceRedownload_TResourceObject` | `0x114f80` | `0x1178e8` | remove, ignore, and fresh download sequence |
| `TBitmapLoader_findImageFile_TString_const` | `0x114fbc` | `0x117988` | level resource lookup and extension fallback |

The panel constructor changes from 64/16/1 with one direct call to 96/24/1
with three calls. Both construct the named panel object, store the owning
window pointer, and install the panel vtable. The target makes its temporary
`C8THgaTQxF` to `CanTfaz6bZ` conversion explicit before constructing the
`J7zOgaf09K` base object.

The bitmap decoder dispatcher changes from 352/88/19 with eight calls to
504/125/15 with 20 calls. Both choose the same decoder for `.png` and `.mng`,
`.bmp` and `.dib`, `.gif`, `.jpg` and `.jpeg`, and `.tga`. Spectron adds a
`PROBLEM reading gif=` diagnostic and retries the GIF reader with a second
mode when the first read fails. That retry is a target-version behavior
difference, while the extension routing itself remains aligned.

The force-redownload helper changes from 60/15/4 with two calls to 160/40/4
with nine calls. Both remove the requested file from the client, ignore the
current download, and start a fresh download. The target's larger body makes
the temporary string copies and the `w6qzgacqqy` and `uq9xgaUxlx` wrappers
visible.

The image lookup helper changes from 364/90/19 with 15 calls to 392/97/19
with 17 calls. Both reject a missing or zero name, try the level resource
directly, probe each configured image extension when needed, request a
download when no resource is found, reject resources that cannot load, and
refresh stale resource data. The target preserves the same branch order with
`f6WHgaQkAF`, `wiULgacZUI`, `bNZvga2Awv`, and `uq9xgaUxlx` wrappers.

The machine-readable record is
`artifacts/spectron_panel_bitmap_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_panel_bitmap_anchors.py`. All four labels
reopened with zero failures in the serial v110 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v110 database has 1,684 remaining
default `sub_` names. Its SHA-256 is
`1a10cd6b7c5a586ecdd8c6f475c753dbbdc9ac5d21b74e3590758212fe8a2129`.

## 2026-08-27: Spectron HTML color and image-animation anchors

The v109 pass reviewed four compact methods that sit at the boundary between
the renderer's color helpers and its image-animation support. The target
places the color registry in the obfuscated `nDIHgaJ9nF` class and the image
animation in `n_rGfa49jO`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `THTMLColors_initHTMLColorList_void` | `0x11b1f0` | `0x11dcf8` | two-container color registry construction |
| `TImageAnimation_TImageAnimation_void` | `0x11b508` | `0x11e030` | palette, list, and field initialization |
| `TImageAnimation_TImageAnimation` | `0x11f898` | `0x1223c8` | complete destructor and buffer cleanup |
| `TImageAnimation_TImageAnimation__2` | `0x11f8dc` | `0x122414` | deleting-destructor delegation |

The HTML initializer changes from 272/67/3 with nine direct calls to
304/76/3 with 11 calls. Both set the one-time initialization flag, allocate a
hash list and a string list, iterate over the built-in color table, create a
color object for each entry, and insert it into both containers. Spectron
uses the `C8THgaTQxF` string wrapper, converts through `CanTfaz6bZ`, and
constructs `J7zOgaf09K` objects before adding them to `KKhLga4xoI` and
`vy1JgaKVkH`. The additional calls document the wrapper boundary rather than
a change in the registry's purpose.

The image-animation constructor changes from 140/35/1 with three direct calls
to 148/37/1 with three calls. It still installs the vtable, constructs two
palette objects, initializes the animation flags and dimensions, allocates
the small bitmap or frame list, and clears the optional pointers. The target
stores these fields at shifted offsets because its `NLT0HaSwmE` palette and
string-list helpers have different layouts.

The complete destructor changes from 68/17/4 with two calls to 76/19/4 with
three calls. Both release the optional bitmap buffer, restore the vtable,
destroy the two palettes, and clear the backing string. The deleting
destructor is an exact 32/8/2 and one-call shape on both sides, routing through
the complete destructor before freeing the object.

The machine-readable record is
`artifacts/spectron_image_html_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_image_html_anchors.py`. All four labels
reopened with zero failures in the serial v109 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v109 database has 1,684 remaining
default `sub_` names. Its SHA-256 is
`50b930130628290213ede4905c578676ca3996280c40ac8d9bb8527e44d5695d`.

## 2026-08-26: Spectron TWindow input anchors

The v107 pass reviewed two remaining methods in the source `TWindow` input
path. The target methods remain in the obfuscated `LJyzga9Pwy` class beside
the already translated focus, pointer, wheel, and window-state helpers.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TWindow_invokeMouseEvent_int_int_int_int_double_double_int` | `0x107334` | `0x109bac` | canvas routing and cursor-relative coordinates |
| `TWindow_onKeyEvent_int_int_TString_const_int_bool_bool` | `0x107728` | `0x109f64` | special keys, control bindings, and control events |

The mouse dispatcher is 548/137/24 with nine direct calls in 1.8 and
488/122/23 with eight calls in Spectron, measured as bytes, instructions,
basic blocks, and direct calls. Both look up the canvas, translate event types
2 through 5 into the same mouse codes, translate buttons 1 through 3, adjust
coordinates through the canvas cursor position when required, dispatch the
event, and fall back to the input object when the canvas does not consume it.
The target's corresponding helpers are `LJyzga9Pwy::ggIZgagRwU`,
`SsrLga3IwI::i2GxgaCPXw`, and the target canvas or input dispatch wrappers.

The key dispatcher is 516/129/22 with nine direct calls in the source and
792/195/23 with 30 calls in the target. Both normalize special keys 16, 17,
and 18, select modifier and press-state values, dispatch the event to the
canvas, check control bindings for the main window, and invoke
`onControlKeyDown` or `onControlKeyUp` for scan code 4. Spectron adds an
`onKeyEvent` diagnostic log and explicit temporary event-name construction.
The larger target body records wrapper and logging changes, not a different
key-state transition.

The machine-readable record is
`artifacts/spectron_window_input_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_window_input_anchors.py`. Both labels
reopened with zero failures in the serial v107 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v107 database has 1,684 remaining
default `sub_` names. Its SHA-256 is
`53c6c656d4f44bf6b74977e9a6441658bf0bd502f1013d387b078098caac3dee`.

## 2026-08-26: Spectron font and resource anchors

The v106 pass reviewed six remaining methods from the source font and
resource support classes. The target functions remain in the local clusters
for the obfuscated `TZf6gaQ3S_` font, `Kv6ugas5Mu` font manager,
`KcKRganuPN` font options, and `fUWH_a_9zm` font data.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TFont_TFont_TString_const` | `0x10d348` | `0x10fcb4` | 256 glyph records and cache defaults |
| `TFont_makeFontTexture_void` | `0x10d8c4` | `0x110274` | bitmap-to-texture upload path |
| `TFontManager_findFontFile_TString_const_TString_const` | `0x10e998` | `0x111368` | system and resource font search |
| `TFontManager_initStaticVars_void` | `0x10f660` | `0x111f24` | font and missing-font registries |
| `TFontOptions_script_addutf8fontrange` | `0x10f81c` | `0x1120b8` | validated UTF-8 range insertion |
| `TFontData_TFontData_TString_const` | `0x110c00` | `0x11347c` | normalized name and data-list setup |

The TFont constructor is 156/39/3 with two direct calls in 1.8 and
188/47/3 with four calls in Spectron, measured as bytes, instructions, and
basic blocks. Both call the hash-list base, initialize the same 256 embedded
glyph records, install the derived vtable, and reset the texture, bitmap, and
font-state fields. Spectron exposes an intermediate `C8THgaTQxF` to
`CanTfaz6bZ` conversion around the rebuilt string wrapper.

The texture builder is 212/52/3 with eight calls in 1.8 and 240/59/3 with ten
calls in Spectron. Both call the font bitmap generator, return early when it
fails, build the `Font ` texture name, create the texture, set the same three
texture flags, upload the bitmap, and store the current high-precision time.
The target calls `TZf6gaQ3S_::fl7q4asNql` and the already translated
`_WevgakbUu::vDdFEaX4hP` texture helper.

The font-file resolver is 828/207/15 with 52 calls in the source and 560/140/10
with 34 calls in the target. The changed size is not treated as a failed
match because the pseudocode retains the meaningful sequence: derive the base
name and style addition, try `.ttf`, try the `it.ttf` alternative when the
style calls for it, check the system-font directory, and ask the resource
manager for the remaining candidates. It returns an empty string after the
same failure cases. The target wrappers are `R9Hyfb3LOH`, `F_uyfbmHDH`, and
`f6WHgaQkAF::r3WHgaBiAF`.

The font-manager initializer is a deliberate target-version difference. The
source is 116/29/1 with six calls. It allocates and publishes the system-font
path string, the 0x28-byte font hash list, and the 0x18-byte missing-font
list. The target `_Z10vVWN2a5aDYv` is 76/19/1 with four calls. It publishes
the matching `KKhLga4xoI` hash list and `vuuHgangcF` string list, but the
`/system/fonts/` literal is not initialized in that function. The evidence
therefore maps the static role while preserving the difference in startup
ownership.

The UTF-8 range helper is 232/58/6 with nine calls in 1.8 and 200/50/4 with
eight calls in Spectron. Both validate the range, normalize the path, allocate
a record containing the font name and two bounds, and append it to the global
range list. The target was still named `sub_1120B8` and is now labeled with
the reviewed role. The font-data constructor is 160/40/1 with five calls in
the source and 196/49/1 with seven calls in the target. Both lower-case or
normalize the lookup name, construct the hash-list base, store the original
name, clear the resource fields, and allocate a 0x18-byte data list.

The machine-readable record is
`artifacts/spectron_font_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_font_runtime_anchors.py`. All six labels
reopened with zero failures in the serial v106 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v106 database has 1,684 remaining
default `sub_` names. Its SHA-256 is
`f4089384f3663f387e9838fa1b4f6ad4932b003b163940ddd1a78e0047729c52`.

## 2026-08-26: Spectron TColorManager anchors

The v105 pass reviewed five remaining methods in the source `TColorManager`
class. The target methods are in the obfuscated `X7ZxganTcx` class and sit
around the already translated color lookup and push methods. This local
ordering is useful evidence because it keeps the target stack-state helpers
with the same neighboring color operations. The target's matrix-list global
is `X7ZxganTcx::UuAMgaMjuJ`.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TColorManager_isActivated_void` | `0xfdacc` | `0x100134` | list exists and contains at least one transform |
| `TColorManager_getTop_void` | `0xfdaf4` | `0x10015c` | guarded final-entry lookup |
| `TColorManager_clear_void` | `0xfdb40` | `0x1001a8` | delete all transforms and clear the list |
| `TColorManager_pop_void` | `0xfdf2c` | `0x100594` | remove and delete the final transform |
| `TColorManager_initStaticVars_void` | `0xfdf94` | `0xffafc` | allocate and publish the matrix list |

The source and target feature metrics are exact for all five rows. The
activation test is 40/10/3 with zero direct calls in both builds. It reads the
same global list, checks for null, and checks that the count is greater than
zero. The top accessor is 76/19/4 with one direct call in each build. It keeps
the same guards and returns the final list entry. The source calls
`plt_TList_operator_index_int`; the target calls
`._ZNK10vy1JgaKVkHixEi`.

The clear method is 116/29/7 with two direct calls in both builds. Both loop
over the transform list, delete each transform, and clear the list. The target
uses `._ZNK10vy1JgaKVkHixEi` and `._ZdlPv` for the indexed read and deletion.
The pop method is 104/26/5 with two direct calls in both builds. Both guard an
empty list, remove the last item, and delete it. The target uses
`._ZN10vy1JgaKVkH6DeleteEi` and `._ZNK10vy1JgaKVkHixEi`.

The static initializer is 68/17/1 with one direct allocation call in both
builds. It allocates an 0x18-byte list, initializes its fields, installs the
list vtable, and publishes the global. The target function is
`_Z10HnexgaAIzwv` and calls `._Znwm`. These rows retain the target wrapper and
global names as evidence, while the proposed `v18_` labels continue to mean
reviewed 1.8 roles rather than recovered original symbols.

The machine-readable record is
`artifacts/spectron_color_manager_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_color_manager_anchors.py`. All five
labels reopened with zero failures in the serial v105 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v105 database has 1,685
remaining default `sub_` names. Its SHA-256 is
`705878c4d7ceaf711e1a93e80bc6bed3449d0af9d28ac3c38c7f5f4ca69dc36c`.

## 2026-08-26: Spectron TBitmapArrayHolder anchors

The v104 pass reviewed five remaining methods in the source
`TBitmapArrayHolder` class. The target methods remain in the obfuscated
`r1dvgaPpTu` class, with already translated rectangle clear, constructor,
rectangle accessor, and file-update methods surrounding the group.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TBitmapArrayHolder_TBitmapArrayHolder_TString_const` | `0xfd524` | `0xffb40` | hash-list base construction and null rect list |
| `TBitmapArrayHolder_TBitmapArrayHolder__2` | `0xfd600` | `0xffc44` | deleting destructor |
| `TBitmapArrayHolder_calcRects_void` | `0xfd620` | `0xffc64` | color-run rectangle discovery |
| `TBitmapArrayHolder_getBitmapArrayRects_TString_const` | `0xfd9d4` | `0x100034` | normalized lookup and lazy holder creation |
| `TBitmapArrayHolder_initStaticVars_void` | `0xfda9c` | `0x100104` | bitmap-array registry initialization |

The string constructor grows from 48/12/1 with one direct call to 88/22/1
with three calls, measured as bytes, instructions, basic blocks, and direct
calls. Both call the hash-list-object base constructor, initialize the
rectangle list to null, and install the derived vtable. The target makes a
temporary `CanTfaz6bZ` conversion and cleanup explicit.

The deleting destructor is an exact 32/8/2 wrapper with one call. It invokes
the complete holder destructor and then `operator delete`; the target uses the
D0 ABI spelling and an obfuscated D2 helper.

The rectangle calculator changes from 804/201/38 with 11 calls to 832/208/38
with 13 calls. Both obtain the Graal bitmap, test the top-left color, clear
the previous rectangle list, scan horizontal and vertical color runs, and
append four-field rectangles for each discovered region. The target keeps the
same nested loop bounds and color comparisons. Its extra calls are explicit
typed string conversion, target bitmap lookup, and target list operations.

The rectangle lookup changes from 200/50/7 with nine calls to 208/52/7 with
eight calls. Both normalize the requested graphics filename, skip an empty
normalized name, calculate the hash, look up the holder in the global
registry, lazily allocate and register a holder when missing, return its
rectangle list, and clear the temporary name. The target uses
`C8THgaTQxF`, `KKhLga4xoI`, and `vuuHgangcF` wrappers.

Static initialization is an exact 48/12/1 body with two calls. Both allocate a
0x28-byte hash list, construct it, and publish the bitmap-array registry. The
target function names the list class `KKhLga4xoI` and the initializer was not
a default `sub_` name.

The machine-readable record is
`artifacts/spectron_bitmap_array_holder_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_bitmap_array_holder_anchors.py`. All
five labels reopened with zero failures in the serial v104 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v104 database has 1,685
remaining default `sub_` names. Its SHA-256 is
`a2f163408c9fb6e29863efd888d98597ae87cdb514335fdc27647e4b9f5f0fe1`.

## 2026-08-26: Spectron TDrawTexture anchors

The v103 pass reviewed four remaining methods in the source `TDrawTexture`
class. The target methods remain in the obfuscated `NVxhJah9mI` class, where
the already translated load, constructor, delete, destructor, repeat, and
draw methods surround this group. The static initializer sits beside the
target's early class initialization functions and publishes the same list
role.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TDrawTexture_initializeTexturesList` | `0xe0770` | `0xe0754` | 0x18-byte texture-list allocation and publish |
| `TDrawTexture_freeResources_void` | `0x108d1c` | `0x10b66c` | indexed list traversal and per-entry delete |
| `TDrawTexture_reloadTextures_void` | `0x108d7c` | `0x10b6cc` | indexed list traversal and per-entry load |
| `TDrawTexture_bindTexture_void` | `0x108e60` | `0x10b7b0` | OpenGL texture bind wrapper |

The static initializer is an exact 68/17/1 body with one direct allocation
call. Both allocate an 0x18-byte list, clear its count and storage fields,
install the list vtable, and store the result in the class texture-list
global. Spectron's target was the default `sub_E0754` name before this pass,
and its global is named `NVxhJah9mI::w_AhJajKpI` by the decompiler.

The cleanup and reload methods are both exact 96/24/3 bodies with two direct
calls. Cleanup walks the published list by index and calls the deleting
texture helper on every entry. Reload walks the same list and calls the load
helper. The target replaces the source `TList` and texture names with
`vy1JgaKVkH` and `NVxhJah9mI`, while retaining the loop bounds and indexed
access.

The bind helper is an exact 12/3/2 body with no direct calls in the feature
export. Both invoke `glBindTexture` with target 3553 and the texture ID stored
at the same object offset. Only the obfuscated target method name changes.

The machine-readable record is
`artifacts/spectron_draw_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_draw_texture_anchors.py`. All four labels
reopened with zero failures in the serial v103 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v103 database has 1,685 remaining
default `sub_` names. Its SHA-256 is
`bb0cb110ad0926c183bccc00d71d084ba5f5220945f56d70950d0f7bb300808e`.

## 2026-08-26: Spectron TDrawingPanelTexture anchors

The v102 pass reviewed five remaining methods in the source
`TDrawingPanelTexture` class. The target methods remain together in the
obfuscated `BP3Kfa2PcS` class, immediately after its panel texture property
helpers. This local order provides a useful class-level check in addition to
the matching destructor, constructor, and dimension logic.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TDrawingPanelTexture_TDrawingPanelTexture` | `0x1082e8` | `0x10ac38` | complete destructor and base cleanup |
| `TDrawingPanelTexture_TDrawingPanelTexture__2` | `0x10832c` | `0x10ac7c` | deleting destructor and object release |
| `TDrawingPanelTexture_TDrawingPanelTexture_TWindow_int_int_int_int` | `0x1084d0` | `0x10ae20` | panel-port construction and null texture |
| `TDrawingPanelTexture_getTextureWidth_void` | `0x108500` | `0x10ae50` | virtual update and width field |
| `TDrawingPanelTexture_getTextureHeight_void` | `0x108540` | `0x10ae90` | virtual update and height field |

The complete destructor is an exact 68/17/4 body with one call on both
builds, measured as bytes, instructions, basic blocks, and direct calls. Both
replace the vtable, release the texture object when present, clear the stored
texture pointer, and call the `TDrawingPanelPort` base destructor. The source
uses the alternative D2 spelling, while the target exports D1 with D2 as its
alternative name.

The deleting destructor is also exact at 32/8/2 with one call. It invokes the
complete destructor and then `operator delete`. The target exports the D0 ABI
variant, matching the source `__2` helper after demangled name normalization.

The window-backed constructor is exact at 48/12/1 with one call. Both call the
panel-port constructor with the window and four integer dimensions, clear the
texture handle, and install the derived vtable. The target exposes a C1
constructor spelling and uses the obfuscated `OYYKfaPU7R` base class.

The width and height accessors each retain the exact 64/16/3 shape and one
call. Both invoke the virtual texture update method first, read the stored
texture object, and return its width or height field, or zero when no texture
has been created. The target uses a different vtable slot and obfuscated
method names, but the field offsets and branch structure are unchanged.

The machine-readable record is
`artifacts/spectron_drawing_panel_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_drawing_panel_texture_anchors.py`. All
five labels reopened with zero failures in the serial v102 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures across 11,679 functions. The v102 database has 1,686
remaining default `sub_` names. Its SHA-256 is
`387015ee8aa3b32836bec8914d471f111ea310780a9da2dd2d5349fcde98f650`.

## 2026-08-26: Spectron TTexture anchors

The v101 pass reviewed ten remaining methods in the source `TTexture` class.
The target methods sit in the obfuscated `_WevgakbUu` class, directly between
the already translated bitmap helpers and the target `TDrawTexture` class.
That local order, together with matching control flow and field offsets, makes
this a stronger correspondence than a size-only match.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TTexture_getWidth_void` | `0x10540c` | `0x107a94` | lazy bitmap width accessor |
| `TTexture_getHeight_void` | `0x105474` | `0x107afc` | lazy bitmap height accessor |
| `TTexture_createTexture_void` | `0x10566c` | `0x107cf4` | GPU allocation and upload decision |
| `TTexture_getTextureWidth_void` | `0x105794` | `0x107e34` | loaded GPU width field |
| `TTexture_getTextureHeight_void` | `0x1057cc` | `0x107e6c` | loaded GPU height field |
| `TTexture_TTexture__2` | `0x1058e0` | `0x107f80` | deleting destructor |
| `TTexture_TTexture_TWindow_TString_const` | `0x105ad0` | `0x108170` | window-backed object initialization |
| `TTexture_getGraalBitmap_TString_const_bool_bool` | `0x105d5c` | `0x1084cc` | Graal lookup, reload flags, and texture load |
| `TTexture_freeResources_void` | `0x105e54` | `0x108644` | global image registry cleanup |
| `TTexture_initStaticVars_void` | `0x1065e4` | `0x108dd4` | image and animation registry creation |

The width and height accessors are exact in their exported feature shape at
104/26/8 with one call on both builds, measured as bytes, instructions, basic
blocks, and direct calls. Both first inspect the loaded bitmap, return its
dimension or one for a zero dimension, honor the stored fallback dimension
when the object is marked loaded, and invoke the virtual load path before the
final zero result when no bitmap is available.

The GPU allocator changes from 152/38/10 with one recorded direct call to
176/44/10 with four calls. Both require a window and bitmap, allocate the
underlying GPU texture only once, and choose whether to update immediately
based on the bitmap animation state and the object's reload flag. Spectron
makes the temporary string conversion and cleanup explicit before calling the
obfuscated update method. The two GPU dimension accessors retain their exact
56/14/3 shape and call the target lazy texture loader before reading the width
or height field.

The deleting destructor is an exact 32/8/2 wrapper in both builds. The source
calls the base `TTexture` destructor and then deletes the object. Spectron
spells the same ABI role as the target `_ZN10_WevgakbUuD0Ev` function, which
calls its D1 destructor and `operator delete`.

The window-backed constructor changes from 252/63/1 with five calls to
280/70/1 with seven calls. Both derive the texture name, initialize the base
hash-list object, store the window and name, reset bitmap and GPU state, set
the same lazy-load and animation flags, and initialize the timing fields. The
target uses explicit `C8THgaTQxF` and `CanTfaz6bZ` temporaries and exposes the
C1 constructor spelling. Its target constructor also initializes the renamed
`J7zOgaf09K` base object, which is the target's hash-list object type.

The Graal bitmap accessor is an exact 128/32/9 function with three calls on
both builds. It looks up the named Graal texture, rejects a missing texture or
the guarded unloaded case, sets the reload flags when requested, invokes the
virtual load method, and returns the bitmap or texture pointer through the
same vtable slot. The target body at `0x1084cc` calls the typed helper
`0x108418`; the target region also contains an additional typed overload at
`0x10854c` with no separate 1.8 counterpart. The anchor points to the body
that preserves the source three-argument behavior.

The global cleanup helper is an exact 20/5/2 body with no direct calls in the
feature export. It clears the target image hash list using the same static
registry role. Static initialization is also an exact 76/19/1 body with four
calls. Both builds allocate and construct the image hash list and the allowed
animation string list, then publish those two globals. The target names the
corresponding classes `KKhLga4xoI` and `vuuHgangcF`.

The machine-readable record is
`artifacts/spectron_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_texture_anchors.py`. All ten labels
reopened with zero failures in the serial v101 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. The v101 database has 1,686 remaining
default `sub_` names. Its SHA-256 is
`8944246d7b9b491cecbeec2298383defe1d624a6643d654fdc28894885c15913`.

## 2026-08-26: Spectron TOptions anchors

The v100 pass reviewed seven remaining methods in the source `TOptions` class.
The target methods remain in the obfuscated `K7FLgag3II` class, and their
order matches the surrounding translated filename, load, save, password-load,
and nickname methods. This gives a strong local ordering check in addition to
the body shape and call-role evidence.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TOptions_set_pref__video__externalguistyle` | `0x16a4f0` | `0x16df48` | style guard and `onExternalStyleChanges` event |
| `TOptions_set_pref__video__defaultguistyle` | `0x16a5a8` | `0x16e03c` | style guard and `onDefaultStyleChanges` event |
| `TOptions_getGraalNickName_void` | `0x16b8ec` | `0x16f3bc` | decoded slot 0 getter |
| `TOptions_getGraalAccountName_void` | `0x16bc24` | `0x16f720` | decoded slot 1 getter |
| `TOptions_setGraalAccountName_TString_const` | `0x16bcd8` | `0x16f800` | account filtering, recent list, and registry write |
| `TOptions_getGraalPassWord_void` | `0x16be70` | `0x16f9e0` | decoded slot 2 getter |
| `TOptions_runOptionsTimer_void` | `0x16bf24` | `0x16fac0` | three stored-value refreshes |

The two GUI-style setters have the same source shape at 184/46/7 with five
direct calls and the same target shape at 244/60/7 with nine direct calls,
measured as bytes, instructions, basic blocks, and calls. Both compare the
new style against the corresponding global, assign only when it changed,
check for a live universe, build the appropriate event name, invoke the event
with the style value, and clear the temporary string. The target style
functions were still named `sub_16DF48` and `sub_16E03C` before this pass, so
the anchor records their default-name status. Their event literals are visible
in the pseudocode review even though they are not present as standalone target
feature string references.

The nickname getter changes from 64/16/3 with one direct call to 108/27/3 with
three calls. The account and password getters change from 68/17/3 with one
call to 112/28/3 with three calls. All three preserve the null-global return,
copy the options hash-list state, and decode slots 0, 1, and 2 respectively.
The additional target calls are explicit `C8THgaTQxF` temporary construction,
assignment, and cleanup around the obfuscated decode helper.

The account-name setter changes from 408/101/10 with 20 calls to 480/119/10
with 24 calls. Both versions call the simple setter, update the active-player
field, lowercase the name, return early for guest, `guest_`, or cookie values,
remove the previous entry from the recent-account list, insert the new entry
at index zero, trim the list to five entries, serialize it, and persist it in
the registry. The target uses explicit `C8THgaTQxF` and `CanTfaz6bZ` wrappers
and stores the list under `accountname_new` instead of the source literal
`accountname`. That literal change is a target-version difference, not a
translation error.

The options timer changes from 132/33/3 with seven calls to 156/39/3 with
nine calls. It still refreshes the three stored values at the options object
offsets used by the nickname, account, and password getters, making each value
unique before assignment. The target exposes the conversion helper explicitly.

The machine-readable record is
`artifacts/spectron_options_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_options_anchors.py`. All seven labels
reopened with zero failures in the serial v100 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures across 11,679 functions. Two default `sub_` labels were renamed, so
the v100 database contains 1,686 remaining default `sub_` names. Its SHA-256
is
`3b438b39ec6f02fe7a8059c1abe8172338b0d1cee936522ce9e23611f4f94b5d`.

## 2026-08-26: Spectron hash-list and hash-string anchors

The v99 pass reviewed nine methods from the source `THashList` and
`THashStrings` families. The target implementations are the obfuscated
`KKhLga4xoI` and `yL3_IaDMFt` classes. Their surrounding constructors,
iterators, add/remove methods, and file helpers were already translated, which
makes the local ordering useful evidence for this pass.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `THashList_getObject_uint_TString_const` | `0xea674` | `0xeb260` | bucket chain and string equality |
| `THashList_getObjectIgnoreCase_uint_TString_const` | `0xea700` | `0xeb3a0` | bucket chain and ASCII-folded comparison |
| `THashList_getObjectEncoded_uint_TString_const` | `0xea7fc` | `0xeb50c` | encoded character comparison |
| `THashStrings_getObject_TString_const` | `0xeade4` | `0xeba30` | hash lookup and key equality |
| `THashStrings_setValue_TString_const_TString_const` | `0xeb358` | `0xebfcc` | add, replace, or remove value |
| `THashList_Assign_THashList_bool_bool` | `0xebaa4` | `0xec840` | clear, iterate, and copy objects |
| `THashList_getListSorted_void` | `0xebba8` | `0xec90c` | ordered iterator insertion |
| `THashStrings_listStrings_void` | `0xebea0` | `0xecc58` | name/value list construction |
| `THashStrings_GetCommaText2_void` | `0xebff0` | `0xecde8` | comma joining and double-quote escaping |

The three lookup methods stay in the target `KKhLga4xoI` class. The
case-sensitive string lookup changes from 140/35/9 with one call to 180/45/9
with three calls, measured as bytes, instructions, blocks, and direct calls.
The target makes a temporary `C8THgaTQxF` copy and comparison explicit. The
case-insensitive method changes from 252/63/24 with no direct calls to
364/91/31 with three calls. Both compare the bucket hash first and then fold
ASCII letters before returning the matching object. The encoded method changes
from 284/71/24 with no direct calls to 320/80/25 with two calls. Its target
pseudocode retains the source's per-character transform and case fold, using
the target string's indexed accessor.

`THashStrings_getObject_TString_const` maps to
`_ZN10yL3_IaDMFt10TBCvgay5cvERK10C8THgaTQxF`. It changes from 136/34/7 with
two calls to 176/44/7 with four calls. Both calculate the bucket from the key,
walk the chained entries, compare keys, and return the matching hash-string
object. The target's extra calls are its temporary string assignment, clear,
and obfuscated hash helper.

`THashStrings_setValue_TString_const_TString_const` maps to
`_ZN10yL3_IaDMFt10juVsfa5YWCERK10C8THgaTQxFS2_`. It changes from 280/70/11
with seven calls to 308/77/11 with nine calls. Both insert a new object when a
missing key has a nonempty value, suppress an unchanged write, replace an
existing value when needed, and remove the object when the new value is empty.
The target compares a temporary copy of the current value and uses the
obfuscated `NYF9TaOVKR` object methods for construction, update, and removal.

`THashList_Assign_THashList_bool_bool` maps to
`_ZN10KKhLga4xoI6AssignEPS_b`. The source is 160/40/6 with nine calls, while
the target is 104/26/4 with six calls. Both clear the destination, walk the
source iterator, add each object, and destroy the iterator. The source has two
boolean controls and chooses between normal and encoded insertion. Spectron's
target signature has one boolean and retains only the normal add path. This is
a real target-version behavior and interface difference, so the anchor records
it instead of presenting the routines as byte-identical.

`THashList_getListSorted_void` maps to
`_ZN10KKhLga4xoI10AotaUajlqSEv`. It changes from 260/65/9 with ten calls to
324/81/9 with fourteen calls. Both allocate a result list, iterate the hash
objects, compare each name with the existing sorted entries, and use either
append or indexed insertion to keep the list ordered. The target's temporary
string conversions account for the extra calls.

`THashStrings_listStrings_void` maps to
`_ZN10yL3_IaDMFt10SpbdUardIUEv`. It changes from 272/68/7 with 14 calls to
336/84/7 with 18 calls. Both create a `TStringList`, iterate all hash strings,
append `name=value` for nonempty values, and append a bare name for empty
values. The target contains the same branches through `C8THgaTQxF` and
`vuuHgangcF` operations, but its feature export does not list the standalone
equals literal that appears in the source record.

`THashStrings_GetCommaText2_void` maps to
`_ZN10yL3_IaDMFt10glvHgatZcFEv`. It changes from 360/90/9 with 17 calls to
440/110/9 with 23 calls. Both join entries with commas, build `name=value`
for nonempty values, quote and escape each entry, and quote bare names for
empty values. The target uses `Z1ceJasAzF` for the same double-quote escaping
role. Its standalone equals literal is visible in pseudocode but not as a
separate feature string reference.

The machine-readable record is
`artifacts/spectron_hash_family_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_hash_family_anchors.py`. All nine labels
reopened with zero failures in the serial v99 IDA check. The full translation
reopen check still passed with 3,641 high-confidence map labels and zero
failures. The v99 database has 11,679 functions and 1,688 default `sub_`
names. Its SHA-256 is
`0760c6fb90cd51a7f575eb46bedcb07f8d72eb6885055b48f2305aedd7ef276b`.

## 2026-08-26: Spectron extended TStringList anchors

The v98 pass reviewed seven more methods from the source `TStringList`
implementation. The target class remains `vuuHgangcF`, and the target methods
follow the v97 comma parser and serializer anchors in the same local method
sequence.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TStringList_Assign_TStringList` | `0xf5e50` | `0xf76c8` | full list copy, capacity, allocation, and indexed reads |
| `TStringList_AddList_TStringList_int_int` | `0xf5ef8` | `0xf7790` | bounded range append and destination placement |
| `TStringList_getValue_TString_const` | `0xf5ff8` | `0xf7904` | equals-key lookup and substring return |
| `TStringList_setValue_TString_const_TString_const` | `0xf60dc` | `0xf79f0` | add, replace, or delete empty value |
| `TStringList_toString_void` | `0xf6408` | `0xf7d40` | newline-separated buffer serialization |
| `TStringList_SaveToFile_TString_const_uint` | `0xf6580` | `0xf7ef4` | file mode, fwrite loop, and error logging |
| `TStringList_Tokenize_TString_const_TString_const` | `0xf6950` | `0xf82f8` | delimiter-aware quoted tokenizer |

The assignment target is
`_ZN10vuuHgangcF6AssignEPS_`. It grows from 168/42/8 with four direct calls
to 200/50/9 with six calls, measured as bytes, instructions, blocks, and
calls. Both clear the destination, reserve the source count, allocate one
entry per source value, copy each value through the indexed accessor, and set
the destination count. The target's explicit `CanTfaz6bZ` copy and cleanup
operations account for the additional surface.

The range append target is
`_ZN10vuuHgangcF10TF9BgaVKIAEPS_ii`. It changes from 216/54/8 with three calls
to 244/61/8 with five calls. Both clamp the start index, cap the end index to
the source count, reserve the combined destination size, and append allocated
copies at the destination tail. The target uses the obfuscated `operator[]`,
capacity, allocation, and string-copy roles identified in the adjacent list
family.

The key/value lookup and setter map to
`_ZNK10vuuHgangcF10iVjofaNm4yERK10C8THgaTQxF` and
`_ZN10vuuHgangcF10juVsfa5YWCERK10C8THgaTQxFS2_`. The lookup changes from
228/57/9 with six calls to 236/59/10 with eight calls. Both append `=`, scan
the list with a starts-with test, and return the substring after the key. The
setter changes from 372/93/12 with 15 calls to 408/102/12 with 17 calls. Both
replace an existing value, append a missing nonempty value, and delete an
existing key when the replacement is empty. The target feature export does
not expose the standalone `=` literal as a string reference, but the
pseudocode still shows the same key construction.

The newline serializer target is
`_ZNK10vuuHgangcF10bwoY2aKeq6Ev`. It changes from 376/94/17 with three calls
to 436/109/19 with six calls. Both calculate the required buffer size, copy
each value, append one newline per entry, and handle empty strings. Spectron
makes the temporary value conversion and buffer setup visible through
`CanTfaz6bZ::gwFWfaPxY0` and `C8THgaTQxF::PHFwgaxH5v`.

The file-output target is
`_ZNK10vuuHgangcF10IA7WHax_lAERK10C8THgaTQxFj`. It changes from 472/116/16
with 16 calls to 524/129/18 with 18 calls. Both select append or write mode,
write every list entry followed by a newline, close the file, and report
non-log open failures with the same message fragments. The target's
`wiULgacZUI::Rr3vga6vAv` and `qjQMgaXCHJ::cWQMgaD8HJ` methods occupy the
source file-extension and logging roles.

The tokenizer target is
`_ZN10vuuHgangcF10q316gaulx0ERK10C8THgaTQxFS2_`. It changes from 1020/253/49
with 37 calls to 972/241/49 with 33 calls. Both initialize delimiter tables,
scan quoted and unquoted fields, recognize backslash escapes, trim extracted
tokens, preserve trailing empty fields, and add them to the list. The target
uses the same `C8THgaTQxF` parser operations and its `_xFPgaiz4LEv` trim role.
The source feature record exposes both `\\"'` and `\\n:,` tables, while the
target exposes only `\\n:,` as a string reference because its quote table is
represented as byte data.

The machine-readable record is
`artifacts/spectron_tstringlist_extended_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tstringlist_extended_anchors.py`. All
seven labels reopened with zero failures in the serial v98 IDA check. The
full translation reopen check still passed with 3,641 high-confidence map
labels and zero failures. The v98 database has 11,679 functions and 1,688
default `sub_` names. Its SHA-256 is
`1819af30ea8729c14088b398f0994c6b35af92054b433a13c14a238ad5b4b76c`.

## 2026-08-26: Spectron TStringList comma-text anchors

The v97 pass reviewed four remaining methods from the source `TStringList`
family. The target class is the obfuscated `vuuHgangcF`, and the functions sit
in the same local method sequence as the already translated list constructor,
capacity, add, clear, load, save, and sort methods.

| 1.8 function | Source | Spectron target | Evidence |
| --- | ---: | ---: | --- |
| `TStringList_SetCommaText2_TString_const` | `0xf5938` | `0xf71a8` | comma parser, quoted fields, escaped quotes, and length guards |
| `TStringList_TStringList_TString_const` | `0xf5c18` | `0xf744c` | list initialization followed by comma parsing |
| `TStringList_GetCommaText_void` | `0xf5c4c` | `0xf7484` | single-quote escaping, comma insertion, and overflow fallback |
| `TStringList_GetCommaText2_void` | `0xf5d4c` | `0xf75a8` | double-quote escaping and comma insertion |

The comma parser maps to
`_ZN10vuuHgangcF10gzgLgalynIERK10C8THgaTQxF`. Its source body is 736 bytes,
182 instructions, and 35 blocks with 23 direct calls. The target is 676 bytes,
168 instructions, and 35 blocks with 19 calls. Both clear the existing list,
split unquoted fields on commas, preserve trailing empty fields, scan quoted
fields, handle backslash escapes, and use the same 60000 and 65000 length
limits. The source exposes the `\\"'` quote-character table as a string
reference. The target keeps the table in a byte data label instead, so its
feature record has no separate string reference for it.

The string constructor maps to
`_ZN10vuuHgangcFC2ERK10C8THgaTQxFb`. The source is 52 bytes, 13 instructions,
and two blocks. The target is 56 bytes, 14 instructions, and two blocks. Both
initialize the list storage and count before entering the comma parser. The
target has an additional `char` constructor argument and stores it at the
object's byte field. That is a real target-side interface difference, not a
reason to reject the role correspondence.

The single-quote serializer maps to
`_ZNK10vuuHgangcF10LzrhKaQOhyEv`. It grows from 256/64/12 with seven calls to
292/73/12 with nine calls, measured as bytes, instructions, blocks, and direct
calls. Both iterate the list, escape each item, insert commas, stop at the
same output-length limits, and replace an oversized result with the same empty
fallback. Spectron makes the temporary string copy and assignment visible
through `C8THgaTQxF` methods, while `R3jeJaVuFF` is the obfuscated counterpart
of the source `escaped39_TString_const` helper.

The double-quote serializer maps to
`_ZNK10vuuHgangcF10glvHgatZcFEv`. It grows from 172/43/6 with four calls to
200/50/6 with six calls. Both apply the double-quote escaping helper and join
items with commas. The target helper `Z1ceJasAzF` occupies the role of the
source `escaped34_TString_const` routine. The extra target calls are wrapper
operations, not a changed list traversal.

The machine-readable record is
`artifacts/spectron_tstringlist_comma_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tstringlist_comma_anchors.py`. All four
labels reopened with zero failures in the serial v97 IDA check. The full
translation reopen check still passed with 3,641 high-confidence map labels
and zero failures. The v97 database has 11,679 functions and 1,688 default
`sub_` names. Its SHA-256 is
`e7287802d3f8f7d967fd12259a45ff3c5635d78005648c0d86d698917c767c0a`.

## 2026-08-26: Spectron render and GUI helper anchors

The v29 pass reviewed 20 compact texture, OpenGL, drawing-panel, GUI-control,
markup, and scrolling helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TTexture_getBitmap_void` | `0x105110` | `0x107798` | bitmap and timestamp |
| `TDrawTexture_draw_float_float` | `0x1091e8` | `0x10bb38` | draw dimensions |
| `TScreenPanelOpenGL_clearStates_void` | `0x109d30` | `0x10c680` | three state clears |
| `TScreenPanelOpenGL_setBlendColor_ColorF_const` | `0x109d50` | `0x10c6a0` | four-color load |
| `GuiControlProfile_getTextWidth_char_const_int` | `0x11274c` | `0x115000` | font-manager forwarding |
| `TDrawingPanel_set_enablecache` | `0x117e94` | `0x11a944` | cache flag and clear |
| `TDrawingPanel_clearAll_void` | `0x118164` | `0x11ac14` | rectangle clear path |
| `TPanelOperation_DrawText_execute_void` | `0x1195d8` | `0x11c0dc` | text operation fields |
| `TPanelOperation_DrawImage_TPanelOperation_DrawImage` | `0x11ab6c` | `0x11d674` | embedded resource cleanup |
| `GuiControl_updateClientBounds_void` | `0x1ac7e0` | `0x1b09a0` | client rectangle update |
| `GuiCanvas_script_cursoroff` | `0x1afe18` | `0x1b4008` | cursor false wrapper |
| `GuiCanvas_script_cursoron` | `0x1afe34` | `0x1b4024` | cursor true wrapper |
| `GuiControl_setAreaClickPriority` | `0x1b2770` | `0x1b6c70` | bounded priority |
| `GuiControl_getScrollLineSizes_uint_uint` | `0x1b2f48` | `0x1b7448` | scroll dimensions |
| `GuiControl_buildUpdateRegion_void` | `0x1b6478` | `0x1bab44` | pending-region extraction |
| `GuiMLTextCtrl_script_getselectedposition` | `0x1bc75c` | `0x1c0088` | selection position |
| `GuiMLTextCtrl_clearSelection_void` | `0x1bdc50` | `0x1c15ec` | selection reset |
| `GuiMLTextCtrl_getFlowExtent_void` | `0x1bea5c` | `0x1c2448` | nested flow extent |
| `GuiScrollCtrl_set_wheelscrolllines` | `0x1bffec` | `0x1c4a58` | positive wheel count |
| `GuiScrollCtrl_scrollDelta_int_int` | `0x1c199c` | `0x1c6478` | relative scroll forwarding |

IDA pseudocode confirms the preserved timestamp update, draw dimensions, state
clears, four-component color call, profile offsets, cache invalidation,
rectangle clearing, panel-operation fields, client-bound copy, cursor
booleans, priority bounds, scroll fields, selection state, flow extent, and
relative scroll calculation. Every source and target body has identical size,
instruction, block, mnemonic, register, and control-flow hashes.

The artifact is
`artifacts/spectron_render_gui_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_render_gui_anchors.py`. All 20 names
were applied to a copy of v28 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v29.i64`. The database SHA-256 is
`2a1af1958e3bc50445a0057c57cbf537ce2a8e8f5c5dd0e28796813d406d944d`.

## 2026-08-26: Spectron core, world, and script helper anchors

The v28 pass reviewed 30 compact helpers that the broad semantic matcher left
out because they were short or had shape-equivalent lookalikes. IDA pseudocode,
field offsets, neighboring class context, and exact normalized function hashes
were used for the final assignments.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TLevelObject_getOrderPoint_void` | `0x16a180` | `0x16dbd8` | zeroed order point |
| `TLevelObject_setlocalx_double_bool` | `0x16a19c` | `0x16dbf4` | local-x field at 112 |
| `TLevelObject_setlocaly_double_bool` | `0x16a1b8` | `0x16dc10` | local-y field at 120 |
| `TLevelObject_setz_double` | `0x16a1d4` | `0x16dc2c` | depth field at 128 |
| `TLevelObject_getVisibleRectangle_void` | `0x16a1e8` | `0x16dc40` | zeroed visible rectangle |
| `TNumberArrayVar_double_setArrayCellFloat_int_double` | `0x18a2fc` | `0x18eaec` | bounded numeric cell write |
| `TServerLevel_isOnNPCPredicate` | `0x19fcbc` | `0x1a4994` | NPC predicate callback |
| `TServerLevel_getNPCList_void` | `0x1a193c` | `0x1a65ec` | NPC-list fallback |
| `TGUIScriptLoader_runFailedsafeConnectorIfNoClient` | `0x1eba10` | `0x1f02b8` | no-client fallback |
| `TSocket_checkAllowConnect_TString_const_int` | `0x204d94` | `0x20ac64` | host and port allow-list |
| `TUpdatePackage_script_getupdatepackage` | `0x20a888` | `0x210a84` | update-package lookup |
| `TGraalVar_script_isinclass` | `0x20d578` | `0x2139a4` | script-space class query |
| `TGraalVar_clearVars_void` | `0x20d6e4` | `0x213b8c` | variable-container clear |
| `TGraalVar_needEvent_script_event` | `0x20edc4` | `0x215290` | script-space event query |
| `TGraalVar_getShowTimer_void` | `0x20ee40` | `0x21530c` | show-timer byte |
| `TGraalVar_getScriptLogMissingFunctions_void` | `0x20eeac` | `0x215378` | logging byte |
| `TGraalVar_getMaxLoopLimit_void` | `0x20eee0` | `0x2153ac` | loop limit and default |
| `TScriptCom_TScriptCom_uchar` | `0x2147f8` | `0x21b3ac` | command record constructor |
| `TScriptCom_TScriptCom_uchar_double` | `0x21480c` | `0x21b3c0` | timed command constructor |
| `TScript_getClassFilename_TString_const` | `0x216b98` | `0x21d918` | empty filename result |
| `TScriptStackEntry_switchTypeProperty_TScriptMachine_bool` | `0x219cac` | `0x221788` | property type switch |
| `TGraalPlayersArrayVar_getArrayCellObject_int` | `0x22d2b8` | `0x236d7c` | action-NPC special index |
| `TStaticVar_markAsNonGarbage_bool` | `0x22d31c` | `0x236de0` | subvariable marking |
| `TTempTile_TTempTile_void` | `0x22f314` | `0x238f30` | temporary tile initialization |
| `TTilesBlock_isTransparent_void` | `0x230b48` | `0x23aac0` | transparent sentinel |
| `TTilesBlock_isBlack_void` | `0x230c08` | `0x23ab80` | black sentinel |
| `TParticleModifier_script_addmod` | `0x23899c` | `0x24283c` | double-to-float wrapper |
| `TExplosion_getDir` | `0x23c86c` | `0x24671c` | direction-table lookup |
| `TServerBomb_setPower` | `0x23ce88` | `0x246da0` | power range one through three |
| `Java_com_quattroplay_GraalClassic_Natives_onReloadTextures` | `0x244758` | `0x2518a4` | texture reload flag |

The strongest GS2 evidence is the preserved script-space field layout and
wrapper signatures. The level-object pair is resolved by the differing local
field offsets inside one target class cluster. The two tile predicates, the
numeric array setter, the NPC-list fallback, the socket policy wrapper, and
the update lookup all retain their literal field operations or argument
forwarding. The remaining callback and constructor labels are supported by
their matching signatures, target class context, and exact normalized hashes.

Every source and target body has identical size, instruction, block, mnemonic,
register, and control-flow hashes. The artifact is
`artifacts/spectron_core_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_core_helper_anchors.py`. All 30 names
were applied to a copy of v27 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v28.i64`. The database SHA-256 is
`fd2c58ef97d63f6d4cfa55ae0e0d4bbf3e57872ab5e0e079f6e777bfbb7b35e4`.

## 2026-08-26: Spectron GS2 script-runtime helper anchors

The v27 pass reviewed 12 compact GS2-facing script-runtime helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGraalVar_getArraySize_void` | `0x20d28c` | `0x21364c` | array size or zero |
| `TGraalVar_setPaused_bool` | `0x20d8b4` | `0x213d5c` | pause and action clearing |
| `TGraalVar_script_scheduleevent` | `0x20eae0` | `0x214fb4` | schedule-event wrapper |
| `TGraalVar_getTimeout_void` | `0x20edd8` | `0x2152a4` | script-space timeout |
| `TGraalVar_script_settimer` | `0x20ee38` | `0x215304` | timer wrapper |
| `TGraalVar_setScriptLogMissingFunctions_bool` | `0x20eec8` | `0x215394` | missing-function logging |
| `TGraalVar_setArrayWasUpdated_void` | `0x20f878` | `0x215e40` | linked-array update clearing |
| `TScript_copyAccessRights_TGraalVar` | `0x214e8c` | `0x21ba9c` | access-right byte copy |
| `TScriptSpace_getTimeout_void` | `0x227b94` | `0x230988` | timeout field |
| `TScriptSpace_needWholeScriptEvent_script_event` | `0x227eb8` | `0x230cac` | whole-script event mask |
| `TScriptSpace_needFunctionEvent_script_event` | `0x227ed0` | `0x230cc4` | function event mask |
| `TScriptUniverse_clearVars_void` | `0x22b600` | `0x234fec` | non-protected variable cleanup |

IDA pseudocode confirms the preserved array and script-space fields, pause
cleanup, timer and schedule wrappers, logging byte, linked-array traversal,
access-right copy, event masks, and conditional universe cleanup. Every source
and target body has identical size, instruction, block, mnemonic, register,
and control-flow hashes.

The artifact is
`artifacts/spectron_script_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_runtime_anchors.py`. All 12 names
were applied to a copy of v26 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v27.i64`. The database SHA-256 is
`4c50294949544e27105f6ee457153dc6d06c5c83e25ce8e539ad64e4ca8d14dd`.

## 2026-08-26: Spectron visual helper anchors

The v26 pass reviewed 11 compact animation, particle, and show-image helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGaniObject_getChildVisibilityInverted` | `0x15d4f8` | `0x160588` | child visibility inversion |
| `TGaniObject_setByteField500Clamped` | `0x15d624` | `0x1606f4` | bounded animation byte |
| `TGaniObject_setz_double` | `0x15d78c` | `0x16085c` | depth and changed flag |
| `TGUIAnimation_get_alpha` | `0x1c96f0` | `0x1ce270` | alpha property with default |
| `TGUIAnimation_get_rotation` | `0x1c9758` | `0x1ce2d8` | rotation property with default |
| `TParticleDataEx_getPartHeightInTiles_void` | `0x232b50` | `0x23c900` | pixel-to-tile height |
| `TParticleDataEx_getPartWidthInTiles_void` | `0x232bd8` | `0x23c988` | pixel-to-tile width |
| `TParticleDataEx_getPlayerLook_void` | `0x233190` | `0x23cf58` | particle player look |
| `TShowImg_set_mode` | `0x2341e0` | `0x23df38` | bounded show-image mode |
| `TShowImg_setImageType_int` | `0x235548` | `0x23f3d0` | image type and visibility |
| `TParticleEmitter_setNrofParticles_int` | `0x239950` | `0x2437f0` | bounded particle count |

IDA pseudocode confirms the preserved field operations, defaults, bounds,
conversions, and update call. Every source and target body has identical
size, instruction, block, mnemonic, register, and control-flow hashes.

The artifact is
`artifacts/spectron_visual_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_visual_helper_anchors.py`. All 11 names
were applied to a copy of v25 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v26.i64`. The database SHA-256 is
`03ce132e9b5953523e6b01c13a1e4e4fa2a540b752127ef87e240a17e403d04d`.

## 2026-08-26: Spectron input and window bridge anchors

The v25 pass reviewed eight compact input and window helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TInput_getKeyState_int` | `0x168fdc` | `0x16c9dc` | key-state table read |
| `TInput_graalkeypressed_int_bool` | `0x169158` | `0x16cbac` | bounded key-state write |
| `TWindow_setCursorPosition_int_int` | `0x1066c8` | `0x108eb8` | cursor coordinate stores |
| `TWindow_getScreenWidth_void` | `0x106d30` | `0x109530` | mode-selected width |
| `TWindow_getScreenHeight_void` | `0x106d4c` | `0x10954c` | mode-selected height |
| `TWindow_getCanvasControl_void` | `0x107154` | `0x109954` | canvas lookup |
| `TWindow_init_void` | `0x107f58` | `0x10a8a8` | drawing-panel initialization |
| `TWindow_getPreferredPosition_void` | `0x1081f4` | `0x10ab44` | zeroed position result |

IDA pseudocode confirms the preserved table, field, mask, lookup, and
initialization behavior. Every source and target body has identical size,
instruction, block, mnemonic, register, and control-flow hashes.

The artifact is
`artifacts/spectron_input_window_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_input_window_anchors.py`. All eight
names were applied to a copy of v24 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v25.i64`. The database SHA-256 is
`a309f9556b21ea43585455a08f5ec0a3291aa60e44d34b475f02672e4341c476`.

## 2026-08-26: Spectron TPlayer helper anchors

The v24 pass reviewed five compact `TPlayer` helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_setAttachedTo_TServerPlayer` | `0x16c760` | `0x170318` | attachment pointer and change flag |
| `TPlayer_sendChanges_void` | `0x1731f0` | `0x1771f0` | client-gated property update |
| `TPlayer_setFreezeCounter_int` | `0x1764a8` | `0x17a778` | counter and negative reset |
| `TPlayer_drawSpriteAbsolute_int_int_int` | `0x17bcb8` | `0x180060` | zero-offset absolute wrapper |
| `TPlayer_drawSprite_int_float_float` | `0x17bd88` | `0x180130` | zero-offset sprite wrapper |

IDA pseudocode confirms the same local behavior and forwarding calls. Every
source and target body has identical size, instruction, block, mnemonic,
register, and control-flow hashes.

The artifact is
`artifacts/spectron_player_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_helper_anchors.py`. All five
names were applied to a copy of v23 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v24.i64`. The database SHA-256 is
`126b3d9ffb27b26e91ccd2f0dfd0d1f48c2f03dd45cf0c1ee4e731b2f9cdec9f`.

## 2026-08-26: Spectron THTMLAtom helper anchors

The v23 pass reviewed five compact `THTMLAtom` helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THTMLAtom_THTMLAtom_THTMLPage` | `0x1cf240` | `0x1d3e94` | constructor and clear call |
| `THTMLAtom_setTextInBuffer_uint_int` | `0x1cf274` | `0x1d3ec8` | buffer start and length stores |
| `THTMLAtom_setLengthInBuffer_int` | `0x1cf280` | `0x1d3ed4` | buffer length store |
| `THTMLAtom_getLengthInBuffer_void` | `0x1cf290` | `0x1d3ee4` | buffer length read |
| `THTMLAtom_getEndInBuffer_void` | `0x1cf298` | `0x1d3eec` | start plus length |

IDA pseudocode confirms the same field layout and local behavior. The five
functions remain contiguous in both builds, and every source and target body
has identical size, instruction, block, mnemonic, register, and control-flow
hashes.

The artifact is
`artifacts/spectron_html_atom_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_html_atom_anchors.py`. All five names
were applied to a copy of v22 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v23.i64`. The database SHA-256 is
`ee5ce543cb188e0b16b8479b2d19dd76c7ac0e636852d8446a022ce1a5e8da33`.

## 2026-08-26: Spectron TServerNPC helper anchors

The v22 pass reviewed 15 compact `TServerNPC` helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerNPC_setIsBlocking` | `0x180834` | `0x184d9c` | blocking-state fields |
| `TServerNPC_script_blockAgain` | `0x1809b8` | `0x184f20` | block-again mode |
| `TServerNPC_script_blockAgainLocal` | `0x1809cc` | `0x184f34` | local block-again mode |
| `TServerNPC_script_dontBlock` | `0x180a1c` | `0x184f84` | dont-block mode |
| `TServerNPC_script_dontBlockLocal` | `0x180a30` | `0x184f98` | local dont-block mode |
| `TServerNPC_script_drawAsLight` | `0x180a40` | `0x184fa8` | draw mode eight |
| `TServerNPC_script_drawOverPlayer` | `0x180a4c` | `0x184fb4` | draw mode one |
| `TServerNPC_script_drawUnderPlayer` | `0x180a58` | `0x184fc0` | draw mode negative one |
| `TServerNPC_getLevelVisible_void` | `0x180ac0` | `0x185028` | visibility override |
| `TServerNPC_script_setBow` | `0x180adc` | `0x185044` | mode-gated bow assignment |
| `TServerNPC_getPeltWithBlackStone` | `0x180c1c` | `0x185184` | pelt comparison |
| `TServerNPC_getPeltWithStone` | `0x180c30` | `0x185198` | pelt comparison |
| `TServerNPC_getPeltWithVase` | `0x180c44` | `0x1851ac` | pelt comparison |
| `TServerNPC_getPeltWithSign` | `0x180c58` | `0x1851c0` | pelt comparison |
| `TServerNPC_getPeltWithBush` | `0x180c6c` | `0x1851d4` | pelt comparison |

IDA pseudocode confirms the same blocking and local-state stores, draw-mode
values, visibility override rule, mode-gated bow assignment, and pelt
comparisons. The source callback records decode to the named script methods
and property getters. Every source and target body has identical size,
instruction, block, mnemonic, register, and control-flow hashes.

The artifact is
`artifacts/spectron_npc_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_npc_helper_anchors.py`. All 15 names
were applied to a copy of v21 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v22.i64`. The database SHA-256 is
`5632ecb9a4fef83373c2a21b6a8ca96708e05252a6acedba802cc321e47a0bc0`.

## 2026-08-26: Spectron HTTP request-state helper anchors

The v21 pass reviewed four compact request-state helpers.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THTTPRequest_getRequestCount` | `0x1fec80` | `0x2045d0` | request-count global |
| `THTTPRequest_getLastRequestTime` | `0x1fec90` | `0x2045e0` | last-request-time global |
| `THTTPRequest_getLastWebDownloadTime` | `0x1feca0` | `0x2045f0` | last-download-time global |
| `THTTPRequest_isDownloadingFile_TString_const` | `0x201bec` | `0x2073dc` | download lookup predicate |

The first three helpers return the same request-count or timestamp globals.
The fourth calls the request download-file lookup and returns whether a
result exists. Each source and target body has identical size, instruction,
block, mnemonic, register, and control-flow hashes.

The artifact is
`artifacts/spectron_http_request_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_http_request_state_anchors.py`. All
four names were applied to a copy of v20 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v21.i64`. The database SHA-256 is
`ab2c0ebb20066e28896a6774aa7da1eaa857f55f21c81d427165add8705c9dc6`.

## 2026-08-26: Spectron client encryption-in tail-thunk

The next focused check covered the 28-byte client encryption-in wrapper that
the main semantic matcher intentionally leaves out because its minimum
function size is 32 bytes. The source function at `0x1e96c0` loads the global
client object, checks for null, and forwards its string argument to the
connection parser.

The Spectron block at `0x1edb80` has the same seven-instruction AArch64 shape
and ends at `0x1edb9c`, immediately before the reviewed folder-log helper. It
was already present in the target IDA function list under the mangled name
`_Z10YvswSaABVtRK10C8THgaTQxF`, so the final operation was an ordinary
`v18_` rename. The raw target bytes are recorded in the artifact as a guard
against an address or boundary drift.

The artifact is
`artifacts/spectron_parse_wrapper_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_parse_wrapper_anchor.py`. The label was
applied to a copy of v13 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v14.i64`. The database SHA-256 is
`417ee107e499d6729ddefad89108a2b105bff1b8120734c3c8e1b7ba1e1967c7`.

An earlier working note described this block as missing an IDA boundary. That
was corrected after checking the feature export directly. The initial query
had requested only raw evidence and had not asked the evidence dumper for the
function record. The public artifact now records the corrected status.
