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

The two helper projects were checked out
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

The saved IDA database was later brought to the same state as the public
translation plan. The active base database was copied, the callback and
script-table boundaries were applied, and the reviewed application, CyaSSL,
and bundled-library aliases were added. The final copy has 11,297 functions,
11,297 named function heads, and 421 remaining default `sub_` entries. The
read-only verifier checked 1,249 reviewed names at their expected addresses
with zero failures. The copy hash and pass breakdown are in
`artifacts/ida_translation_verification_20260830.json`.

## Android lifecycle and the first network checkpoint

The original Java activity does not call the native engine from
`onCreate`. It stores `ApplicationInfo.sourceDir` and `dataDir`, registers the
activity as the native event listener, sets the GL thread activity pointer,
and requests the permissions declared by the package. `onStart` creates the
`GLView`, constructs `QPlayRenderer`, starts `GLThread`, and queues the first
foreground event.

The important detail is inside `GLThread.needToWait`. Its render loop does not
call `Renderer.drawFrame` until the activity is resumed, the window has focus,
the surface exists, the EGL context is not marked lost, and the thread is not
done. While waiting it sleeps for 100 milliseconds. The first call to
`QPlayRenderer.loadLibrary`, and therefore the first call to
`Natives.QPlayMain`, happens only after that gate opens.

There is also a Java-side permission gate. `PermissionsAllGranted` sets the
field `Natives.downloaded` to true. `QPlayRenderer.loadLibrary` returns
without loading `qplay` while that field is false. On API 23 and later,
`AskPermissions` filters the package's declared Android dangerous permissions,
checks them, and requests missing entries. The field name is misleading: in
this path it is the switch that permits native startup, not a proof that a
native download just completed.

The renderer passes the locale language, APK source directory, application
data directory, first external-files directory, display values, and the full
launch URI to the ARM64 JNI wrapper. `QPlayMain` stores the external path as
`sdcardpath`, uses the application data directory as the native base data
folder after adding a separator, and falls back to the historical package
directory pattern when the value is empty. It then loads the engine, selects
the translation language, loads the GUI unless offline, and forwards a
nonempty launch URI to `TServerList` through `onStartedWithURL`.

The Java bridge ignores the integer returned by `QPlayMain` and sets
`Natives.loaded` true immediately afterward. Every later frame calls
`Natives.QPlayLoop`, which advances timers and the network scheduler before
choosing the loading or game draw path. This gives a useful troubleshooting
split:

* no native library load means the focus, surface, permission, or GL-thread
  gate has not opened;
* a loaded library with no connector request points to engine initialization,
  launch-URI handling, or the native server-list state machine;
* a connector request that fails before a response reaches CyaSSL or the HTTP
  parser belongs to the independent connector trust and transport review.

The smali also exposes two old lifecycle quirks. One local string in
`QPlayRenderer.loadLibrary` is initialized to an empty value and checked with
the message `internalstorage string is empty`, while a separate local holds
the external-files directory passed to native code. This is a stale diagnostic
and path-marshalling defect, but the local replay still supplied an external
cache directory and reached the resource path. More seriously,
`Natives.onAppPause` sets the native close flag when there is no client or the
loading state is at most 2, and `QPlayLoop` exits when that flag is observed.
An interruption during early startup can therefore look like a failed login.

The focused evidence is in
`artifacts/original_android_lifecycle_review_20260830.json`. The native
functions are exported directly from the active ARM64 IDA database by
`tools/ida_export_original_android_lifecycle_review.py`; the Java observations
were checked against the original DEX smali kept outside the public repository.

## Android custom-scheme launch path

The Android manifest registers `graalclassic` and `graalclassicplus` as
browsable schemes for `QPlayActivity`. This is a real external entrypoint
because the activity has intent filters and no explicit `exported` attribute.
The Java renderer does not parse the incoming URI. It checks that the current
intent has a scheme and data, converts the data URI to a string, and passes the
full value to `QPlayMain`.

The native wrapper calls `TServerList_setProtocolString` for a nonempty URI and
then invokes the script event `onStartedWithURL` with the original string. The
parser strips only `graal://` and `graal3://`. For those forms it splits a
slash-delimited connection and parameter value. For an accepted Android URI
such as `graalclassic://host/path`, the parser sees the internal `://` marker
before it has removed anything. It stores the full value in
`serverstartparams` and leaves `serverstartconnect` empty. Those two globals
are exposed through script getters and setters.

This gives two useful conclusions. First, a deep link can open the app without
starting the intended server because the Java and native scheme grammars do
not agree. Second, the exported activity forwards unvalidated launch data into
script code. If the core startup scripts use that data to make a connection,
an external caller could influence the destination. The core consumer was not
fully recovered and no external intent was sent, so the latter remains a
conditional capability rather than a proven SSRF or code-execution issue.

The focused IDA export is in
`artifacts/original_intent_launch_review_20260830.json`. It includes the URI
parser and the script-field accessors without publishing the missing core
script or any live destination.

## Script-triggered Android URL handling

The native script table contains `openurl`, `openurl2`, `opengraalurl`, and
`canopenurl`. The focused export is
`artifacts/original_external_url_review_20260830.json`, generated by
`tools/ida_export_original_external_url_review.py`; the original Java behavior
was checked in the private DEX smali.

Both `openurl` callbacks dispatch through the main window virtual method at
slot 472. `TWindow_openURL_TString_const_bool` forwards the string to
`openAndroidURL_TString_const`, which calls the Java static `openURL([B)V`
method. In `QPlayActivity.getIntentForURL`, exact legacy game strings map to
explicit `ACTION_RUN` components. Any other string is parsed as a URI and
wrapped in `ACTION_VIEW`. `QPlayActivity.openURL` first checks
`queryIntentActivities` and then starts the resolved activity when a handler
exists.

This makes the generic external URL callback materially different from the
native HTTP request API and from the incoming deep-link path. An activated
script can request a browser or another URI handler without a visible scheme
or host allowlist. `JNI_canOpenURL` and the Java `canOpenURL` method expose a
Boolean installed-handler query through the same mapping.

`opengraalurl` follows a separate path. When both `activeplayer` and the game
client exist, `TAdventure_openSecureURL` stores the supplied page, derives a
short-lived page value, and sends a `setcookie` message through the game
connection. When that state is absent, it calls the main window URL bridge
directly. The server-mediated path is therefore a useful control, but its
fallback still inherits the generic external-navigation behavior.

The static findings are medium severity for an already activated script and
low severity for handler-presence probing. No script was executed, no intent
was launched, and no external application was contacted. A safe repair should
allowlist schemes and hosts before `startActivity`, preserve explicit routing
for legacy game components, and keep `canopenurl` outside untrusted script
reach.

## Credential and local-option storage

The credential pass follows the native option object rather than assuming
that the Java activity owns login state. The compact export is
`artifacts/original_credential_storage_review_20260830.json`, generated by
`tools/ida_export_original_credential_storage_review.py`.

`TOptions_loadPasswords` reads `nickname` and `accountname` from a flat native
registry below `cache/registry`. The account list is decoded into memory, and
the normal account setter keeps at most five ordinary names. Guest,
guest-prefixed, and cookie names are not added to that history. The reviewed
password setter updates a third in-memory option slot but does not write the
registry. The loader only fills that slot through the default guest fallback.

The `THashList_encodesimple` pair is not a password hash. It transforms every
byte using the string length and arithmetic, while the inverse routine is
called by the option getters. There is no random salt, secret key, or
integrity check in these functions. A reader with the client binary can
reverse values stored in the registry. The script table also exposes
`TClient_getGraalPassword` as `getpassword`, so an activated script can read
the current process-held value. The `dontsavepasswords` preference changes a
global byte but the reviewed setter does not erase the live password.

This is a privacy and trust-boundary finding, not evidence that the original
server was sending a password to an attacker. It explains why package
signature verification matters beyond code loading, and it gives a concrete
repair direction: keep credentials out of scripts, use platform-backed secret
storage, and make account-history retention explicit.

## Embedded script capability review

The next pass mapped the native callbacks registered by the script tables. The
compact export is `artifacts/original_script_capability_review_20260830.json`,
generated by `tools/ida_export_original_script_capability_review.py`. It
focuses on capabilities that cross a security boundary: local files, uploads,
HTTP requests, protocol controls, and dynamic class loading.

The file API has two different designs. `fileexists`, `filesize`, and
`deletefile` resolve names through `TFileScripting_getScriptAccessFilename`,
and `decompressfile` checks both its source and write folder. In contrast,
`adventure_getfilecontent` at `0xfbda4` sends its filename directly to
`TStream_LoadFromFile`, while `adventure_setfilecontent` at `0xfbbc8` sends its
filename directly to `TStream_SaveToFile`. The generic writer uses normal file
modes and deletes the target for an empty overwrite stream. The visible
callbacks therefore do not share one canonical-root policy.

Uploads repeat the pattern. The normal `uploadfile` callback checks the
one-shot allowed-upload list or uses the script access helper. The
`adventure_uploadfile` callback at `0x157d20` calls `TClient_uploadFile`
directly. The queue limits a reported file to 20,000,000 bytes and sends it in
small chunks, but that is a size limit, not a filename policy.

The script HTTP factories accept HTTP and HTTPS URLs and create requests for
the supplied host and port. The reviewed wrapper does not show a host
allowlist. The narrower game-file factory rejects the connector pseudo-file
and blocked extensions, so it should not be generalized to the ordinary HTTP
API. The same script table exposes raw protocol send, encryption setup, game
connection, and password callbacks. This is why the signed package check is a
security boundary rather than only a content-integrity feature.

Dynamic class loading is not an unrestricted raw stream installation in the
reviewed path. The class count is capped at 9,999, duplicate requests are
tracked, encrypted class scripts are requested when absent, and class
installation compares the class privilege against the current server
privilege. The remaining concern is capability concentration: an untrusted
activated script would inherit powerful native operations even when those
individual controls behave as designed. No script was executed and no server
was contacted during this pass.

## Facebook session and Graph callbacks

The Android script table contains a separate Facebook feature family. The
focused export is `artifacts/original_facebook_bridge_review_20260830.json`,
generated by `tools/ida_export_original_facebook_bridge_review.py`. It covers
the table owner at `0x245f40`, the JNI session and Graph callbacks, and the
native `requestnewfacebookgraph2` resource conversion path. The table registers
44 Android functions, with 13 relevant Facebook entries including availability,
login, logout, state, token, permission, Graph, permission-request, share, and
WebDialog callbacks.

The most important boundary is `getnewfacebooktoken`. The native callback at
`0x240380` calls Java `getNewFacebookToken()[B`, and the activity returns the
active Facebook session access token whenever that session is open. The
matching permissions callback at `0x24025c` returns the session permissions as
escaped comma text. Both values are copied into native strings and are
therefore available to the script runtime when the corresponding table entries
are invoked.

The session state mapping is explicit: `CREATED` is 0,
`CREATED_TOKEN_LOADED` is 1, `OPENING` is 2, `OPENED` is `0x201`,
`OPENED_TOKEN_UPDATED` is `0x202`, `CLOSED_LOGIN_FAILED` is `0x101`, and
`CLOSED` is `0x102`. Login parses requested permissions, builds a Facebook
`OpenRequest`, and calls `openForRead`. A status callback reports the mapped
state through `onNewFaceBookState`. Permission requests require an already
open session, choose read or publish permission APIs from the Boolean argument,
and report whether every requested permission was granted through
`onNewFaceBookRights`.

Graph requests are asynchronous. The Java activity requires an open session,
maps only exact `POST` and `DELETE` method strings specially, and treats all
other method strings as `GET`. The bundled SDK uses the `v2.1` Graph API
version by default and constructs HTTPS URLs from the default Facebook domain.
It adds `sdk=android`, `format=json`, and the active access token when the
request did not supply one. The callback returns the requested path and the
inner Graph JSON object when present. It does not append the exception text
when a response has no Graph object, which is a diagnostic weakness for a
repair.

`requestnewfacebookgraph2` is more than a parameter convenience wrapper. The
native function recognizes `image:` and `file:` values, resolves the suffix
with `TResourceFunctions_getGameFile`, loads the resource stream, Base64
encodes it, and replaces the parameter before calling Java. Java decodes image
values into `Bitmap` objects and file values into byte arrays in the request
Bundle. This creates a clear data path from game-readable resources to an
authenticated Facebook upload, although the review did not show that it can
read an arbitrary raw filesystem path.

The security conclusion is conditional but concrete. An activated script can
read the current bearer token and can use the open session for Graph operations
within the granted permission set. It can also prompt for additional read or
publish permissions and upload eligible game resources. The SDK's HTTPS
transport protects the network leg from ordinary passive interception, but it
does not make token exposure to script code safe. No Facebook login, script
execution, token capture, or external request was performed during this pass.

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

## Native connection lifecycle

The native connector does not directly become the game socket. Packet 178
delivers a comma-separated server-warp destination. `TServerList_handleServerWarp`
at `0x204488` clears the global destination and invokes
`StartScript_Connector.onServerWarp` with the host, server name, and port. The
script-side handoff eventually reaches `TClient_connectToGameServer` at
`0x1e7058`.

The game connect function calls `TGraalConnection_connectToServer` only when
the address is nonempty and the port is positive. It accepts a socket that has
not recorded an error, hashes address plus port into `serveripstr`, starts the
client thread, and returns success. Its failure message is generic, so the
socket state is more useful than the message when diagnosing a real device.

The focused native export is
`artifacts/game_connection_flow_review_20260830.json`. It covers
`TServerList_login`, `TServerList_handleServerWarp`,
`TClient_connectToGameServer`, the three socket state helpers,
`TSocketConnection_enableSSLOnSocket`, `TClient_networkThreadMain`, and
`TServerList_handleClient`.

The socket is IPv4 TCP and nonblocking. `connectSocket` uses status 4 for
`EINPROGRESS` and status 5 for a completed connection. The status-4 path uses
a zero-timeout write `select` followed by `getsockopt(SO_ERROR)`. Status 5
triggers the CyaSSL setup when the per-socket SSL flag is set. The server-list
loop treats a connection still in status 4 after five seconds as failed. This
gives three independent checkpoints for a future device trace: socket and
resolver setup, delayed connect completion, and TLS handshake.

The game TLS fields are configured through the script callback at `0x1eb964`.
The callback decrypts its certificate argument with the DES key `NakFpz15`,
stores the protocol, cipher list, and verify buffer, and applies the SSL enable
flag. `TGraalConnection_connectToServer` then copies those fields to the new
socket before connecting. The recovered source was checked with
`tools/audit_classic_ssl_mode.py`: the Classic branch sets `usessl=false`, the
NewGraal `setSSLParameters` call is guarded by that flag, and the final value
remains false. The same expired Eurocenter Games certificate is therefore
real but dormant in stock Classic. It remains relevant to legacy branches or
modified scripts. The active connector HTTPS request is the path that directly
consumes the expired GraalWeb bundle.

The client network thread reads incoming data, processes and sends outgoing
packages, and sleeps for one millisecond while the incoming queue stays below
1,000 entries. The server-list loop handles reconnect callbacks, starts the
loading state after socket status 5, checks stalled downloads, and disconnects
after a status-4 timeout or status-2 failure. A device log that records these
states will distinguish transport failure from a later NewGraal parser issue.

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

The follow-up IDA export is
`artifacts/original_script_package_review_20260830.json`. It confirms that the
RSA check happens before the encrypted ZIP is opened and before
`StartScript_Connector` can be activated. The ZIP parser caps the number of
entries at 10,000 and rejects an individual reported size above 1 GiB, but it
does not show an aggregate decompressed-size budget. It also dispatches
recognized ZIP names to script objects rather than directly writing arbitrary
entry paths. The report redacts embedded crypto literals while retaining the
structural decompilation and hashes of the redacted values.

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
tests. It also exposes `--omit-content-length` for the EOF case. The earlier
capitalized-header failure was confounded by another response or timing
difference that has not been reproduced, so it should not be treated as
evidence of a header-case rule.

## Native HTTP redirect review

The next pass followed the response state machine instead of assuming that a
successful connector request stays on its original URL. The compact export is
`artifacts/original_http_redirect_review_20260830.json`, generated by
`tools/ida_export_original_http_redirect_review.py`.

At `0x2025a0`, `THTTPRequest_runScript_void` recognizes status 300 through
303, 305, and 307 as redirect-like. It tokenizes the stored `Location` field,
parses the first token with `THTTPRequest_extractHTTPHostPortFile` at
`0x200d44`, copies the returned host, port, path, and SSL flag into the
request, and calls `THTTPRequest_sendRequest` again. The retry counter is
incremented and accepted while it is at most ten. The counter prevents an
unbounded redirect loop, but it does not establish trust in the replacement
destination.

The absolute URL parser accepts both HTTP schemes, default ports, explicit
numeric ports, and a path beginning at the first slash. No host allowlist,
canonical comparison, or redirect-specific certificate policy appears in the
reviewed function. `THTTPRequest_sendRequest` uses the new host and port in
the Host header and socket connection, and selects native SSL from the copied
scheme flag. An HTTPS request can therefore follow an `http://` location over
cleartext. The connector marker is a separate request field, so an HTTPS
follow-up can still enter the connector trust helper, but that helper does not
restrict the destination host.

The same request machinery is reachable from the game-file helper and the
ordinary script URL factory. The latter was already a broad HTTP capability;
the redirect pass shows that a response can change its destination after the
request has been created. These are confirmed static findings with medium
severity for network confidentiality and destination control. They are not a
live-service result: no redirect was sent, no current server behavior was
claimed, and no remote code execution path was demonstrated.

The repair direction is a request-class policy applied before reconnecting.
Connector and update requests should use an explicit approved host and port,
or reject redirects altogether. HTTPS should be preserved unless a deliberate
and validated downgrade is required. The retry count should remain as a loop
guard, but it cannot substitute for those checks.

## Native HTTP response framing review

The redirect pass exposed a second question for startup compatibility: what
does the old client consider a complete HTTP response? The compact export is
`artifacts/original_http_framing_review_20260830.json`, generated by
`tools/ida_export_original_http_framing_review.py`.

`TSocketConnection_read_void` at `0x2077a0` reads up to 8,192 bytes from
`recv`, `recvfrom`, or `CyaSSL_read` on each call. It repeats TLS reads when
data remains available. `THTTPRequest_read_void` at `0x200a70` appends those
chunks to its response stream without a general total limit. That 8,192-byte
value is therefore an I/O buffer size, not a body cap.

`TStream_readLine_void` at `0xf0ce0` scans from the current offset to LF or
the current end of the stream and strips a preceding CR from the copied line.
There is no line-length bound. `THTTPRequest_preParseData_void` at `0x201d68`
accepts a status line whose first token starts with `HTTP`, parses the next
token as an integer, and recognizes the legacy server, last-modified,
location, content-language, content-type, content-length, keep-alive, and
modtime fields. It lowercases the complete line before matching names, but it
does not inspect `Transfer-Encoding`. A later Content-Length line overwrites
an earlier value.

The client does not contain a chunk decoder in the reviewed body path. A
positive Content-Length is used once the accumulated bytes reach that value.
When the length is absent or nonpositive, the response state machine waits for
the socket to close before taking its close-delimited completion path. The
local no-length responder half-closed its write side and completed. A declared
web-download limit protects selected transfers after header parsing, but it
does not cap header growth or every unknown-length response.

This gives a medium availability finding for missing response limits and a
medium compatibility finding for unsupported chunked transfer coding, plus a
lower-severity framing ambiguity for lenient status and duplicate-length
handling. No malformed response was fuzzed and no live server was contacted.
The repair direction is to bound headers and bodies before append, reject
unsupported transfer codings, and require strict, non-overflowing framing
metadata.

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

## Game login and framing review

The next pass followed the bytes between the first game connection and the
`onServerLogin` event. The compact export is
`artifacts/original_game_login_review_20260830.json`. It covers the NewGraal
header setup, the type-252 encryption setup path, RSA unwrap, both directional
cipher states, sequence checks, socket reads, dispatch, and the type-54 login
handler.

The native code configures the framing string as `EILLLT`. The parser waits for
the three-byte length field to be present, optionally removes the two legacy
compression forms, verifies the sequence value, and then dispatches the
packet. The special encryption-setup handler runs immediately instead of
entering the network-thread queue. Packet 54 is mapped to handler index 10.
Its handler subtracts the text offset from the first body byte, stores the
result as `serversignature`, and invokes `onServerLogin`.

The setup path is important for the original connection failure question. It
optionally DES-decrypts the input, then uses a helper that decodes a private
RSA key supplied by the client-side trust material and calls private-key
decrypt. The resulting mode selects RC4 or AES. RC4 state is continuous
across frames; AES holds back incomplete 16-byte blocks. This is a
cryptographic envelope, not proof of server identity. The recovered Classic
branch leaves game-socket TLS disabled, and the setup path does not call the
separate package RSA signature verifier.

The same review found an availability boundary. Reads use an 8192-byte
temporary buffer, but the accumulated protocol string has no visible smaller
limit than the 24-bit frame-length field. A peer can therefore advertise a
large incomplete frame and keep the parser waiting. This remains a static,
local-harness test target, not a live-service result. Fixed key-like literals
were redacted from the public export.

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
the load, while a `FILE` entry adds a file to the package's file list after
platform and path-policy checks. The focused security export now includes the
parser, package path builder, resource lookup, and file-download gate alongside
the update completion and uninstall callers.

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

## Original APK security pass

The first offline security pass is now limited to the original 1.8 APK. The
machine-readable reports are `artifacts/original_apk_security_audit_20260830.json`
and `artifacts/original_security_callsite_review_20260830.json`. The APK audit
does not install the package or contact a host. It records the manifest, DEX
string indicators, packaged ELF metadata, signing metadata, and hashes of the
private input files.

The most important native result is an update boundary. The download-complete
handler at `0x1ec044` can call the executable replacer at `0x196fe0` after all
package downloads complete and a replacement flag is set. The replacer changes
the configured executable mode to `0775`, forks, and calls `execvp` on the
configured path. The reviewed function does not perform a package signature
check itself, so the next step is to trace the package verification and path
provenance before making any repair that enables this branch.

The generic file helper at `0xe6dfc` calls `unlink`. Package uninstall routes
file names through a resource resolver before reaching it. The script-facing
delete path also resolves a policy-controlled filename, checks existence, and
updates the resource object. The policy tables block executable and other
high-risk extensions and restrict folder prefixes, but a complete traversal
review still needs separator, escape, symlink, and archive-entry tests.

The identification path reads `eth0`, stores the six-byte MAC address, and
computes a network ID from an MD5 digest. Other system-ID modes include
hard-disk, OS, and Android ID values. The cookie loader reads
`cache/creationtime.dat` or `files/creationtime.dat` below the native data
folder. These are privacy and account-correlation surfaces rather than proof of
code execution.

The APK also has an effectively exported custom-scheme activity, separate
JavaScript-enabled WebView surfaces, an expired `admin.fabzat.com` certificate
resource, legacy CyaSSL cipher identifiers, and an embedded connector trust
bundle whose earliest recovered certificate expired on 2023-07-29. The Java
smali review shows that the game WebView and the bundled Bolts JSON metadata
bridge are different paths. All four packaged native libraries report
non-executable stacks, GNU RELRO, and `BIND_NOW`. These facts are documented in
`docs/SECURITY.md` with confidence limits so compatibility failures are not
presented as confirmed vulnerabilities.

The parser-hardening pass adds
`artifacts/original_level_parser_review_20260830.json`. It confirms that the
outer `.code` length uses a signed 32-bit check before allocation, that
allocation failures are not handled, and that fixed field reads do not always
check their short-read count. The normal board path is bounded to 4096 cells
with a fixed 13-bit callsite and 8192-byte tile buffers. The line-oriented
readers are less defensive: signs and links have no total record budget, the
shared line reader has no per-line limit, and key-code replacement repeatedly
rebuilds sign text. NPC and chest object creation is disabled in the stock
encrypted-level loader, so those branches remain context-dependent rather than
normal-path findings. The report records these as availability or parser
robustness risks and leaves remote reachability for a disposable local harness
and a complete cache/download trace.

The follow-up cache-flow export is
`artifacts/original_download_cache_flow_review_20260830.json`. It connects
wire packet 102 and the large-file 68, 84, 102, 69 sequence to
`TClient_processFileChunk`, `TCachedStream_saveAndUpdate`, and the resource
resolver. The client appends received data to a dynamic cached stream while
recording, but not visibly enforcing, the declared offset and big-file size.
Recognized extensions are mapped into application-owned directories and final
components are escaped, yet the reviewed save path still uses string prefixes
and `stat` without visible canonical-root or no-follow creation. This makes
server-supplied resource exhaustion a real trust-boundary concern after a
connection is accepted, while symlink traversal remains an untested local
question rather than a confirmed vulnerability.

The focused update-package path export is
`artifacts/original_update_package_path_review_20260830.json`. It separates the
two manifest cases that had previously been easy to conflate. `SUBPACKAGE`
names are reduced to a basename before package lookup, so a literal traversal
string does not reach the package filename builder. `FILE` directories are
retained after the `AllowedFoldername` check, which rejects ordinary dot-dot
components but does not provide canonical containment. The package-aware cache
mapper adds the native base user folder to the stored path, so the static pass
does not prove a root escape from an absolute-looking directory. Symlink
following, uncrossed canonical roots, and non-atomic file writes remain the
important local checks. The package parser also has no visible total budget for
records, descriptions, or nested packages, so the strongest current finding is
context-dependent availability risk rather than confirmed arbitrary file write.

The companion integrity export is
`artifacts/original_update_integrity_review_20260830.json`. It resolves an
important distinction in the update protocol. `TResourceObject_getChecksum`
and the package request builder calculate CRC32 values for conditional requests
and encode them into five-character fields. The response path does not visibly
compare received bytes against those values. Packet 102 appends data to a
cached stream, and both ordinary and large-file completion call the cache save
path without a visible CRC, RSA signature, keyed MAC, offset-order, or declared
size check. The scheduler's ten-entry queue limit is not a byte-size limit.
This is a static response-integrity and availability concern after a trusted
connection is established, not proof that an unauthenticated server can reach
the write in stock operation.

## Image resource and decoder review

The next pass followed the same packet-102 resource path into the image loader.
The compact export is
`artifacts/original_image_parser_review_20260830.json`, generated by
`tools/ida_export_original_image_parser_review.py`. It covers the resource
entrypoint, extension dispatch, shared bitmap allocation, PNG/MNG chunk and
frame handling, GIF frames, and the JPEG, BMP, and TGA boundaries.

The important result is a missing common resource budget. PNG and GIF dimensions
feed 32-bit allocation arithmetic, while PNG IDAT chunks grow an accumulated
buffer and GIF frames are retained in an animation list. The reviewed wrappers
do not visibly cap dimensions, total decoded pixels, compressed bytes, frame
count, or cumulative texture bytes before allocation. JPEG uses the bundled
decoder's error path but still reaches the shared bitmap allocator without a
separate application pixel limit. The BMP and TGA readers were included to
document the dispatch boundary, not to claim that they were fuzzed.

This is a static finding. No malformed image corpus was run and no live server
was contacted. The useful next experiment is a bounded local harness that
checks dimension multiplication, oversized IDAT data, many GIF frames, and
decoder error cleanup without writing the test corpus into the repository.

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

One negative control is worth preserving. A test build routed packet 59
directly to the apparent x86_64 parser block at `0x2096f0`, bypassing the
directly to the apparent x86_64 parser block. That build did not reproduce the
working exchange. It changed the first connection to ordinary packet 23
requests and stopped before the normal second-connection sequence. The direct
jump is therefore rejected as a repair. The working responder uses packet 102
for a complete file response and can also emit the native 68, 84, 102, 69
large-file sequence.

The public game responder accepts `--frame-after-client` and
`--frame-after-map`. The first is useful for event-driven packet experiments.
The second was used here to send packet 49 only after the GMAP response, which
made the successful replay deterministic without a wall-clock delay.
