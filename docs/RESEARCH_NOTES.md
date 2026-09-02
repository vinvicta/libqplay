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
and bundled-library aliases were added. The exact source-role pass then
matched 141 FreeType functions, 153 IJG libjpeg 6b functions, one zlib
function, and one static giflib role. The current copy has 11,296 functions,
11,296 named function heads, and no remaining default `sub_` entries. The 124
functions that lacked preserved source names now carry stable descriptive
labels. The read-only verifier returned zero failures after the source-role
and residual-label passes. The copy hash and pass breakdown are in
`artifacts/ida_translation_verification_20260902.json`.

The final scope check keeps that count honest. None of the 124 residual labels
is in the `0x240000` through `0x246fff` Android bridge range. None of the
1,779 unique callback addresses in the script-table inventory currently has a
residual label, including the callbacks added during the Facebook, billing,
partner, and device/media reviews. The remaining 23 labeled entries in the
broader `0x1e0000` through `0x246fff` application-core range are short
static-state or cleanup wrappers. No residual function has a direct call edge
to the selected socket, file, process, or update imports. The IDA-generated
check is preserved in
`artifacts/ida_active_translation_scope_check_20260902.json`.

## FreeType source matching

The former default-name queue was not treated as an invitation to invent
every routine by proximity. A local shallow checkout of the official
FreeType 2.3.6 tree was compared with the active ARM64 pseudocode. The
checkout is pinned to commit
`6174e17cf7cb3eef826d95c96757dbb0feea7bdb` and the source files and line
anchors are listed in
`artifacts/ida_freetype_source_matches_20260901.json`.

The comparison matched 141 functions exactly enough to apply the upstream
names. The set spans the SFNT face and table loaders, the smooth rasterizer,
the TrueType interpreter and glyph loader, and the Latin, Latin2, CJK, and
dummy autofit classes. The strongest interpreter cluster includes
`Compute_Funcs`, the projection and movement callbacks, the instruction
handlers, fixed-point rounding helpers, and the glyph-loading callbacks.

The source comparison also resolved the two diagnostic helpers that had been
left address-based in the earlier residual review. `0x256060` is now
`tt_name_entry_ascii_from_utf16`, and `0x2563d0` is now
`tt_name_entry_ascii_from_other`. The callback assignments, driver class
slots, source declarations, and matching decompiler bodies supplied checks
beyond a superficial name similarity.

This FreeType follow-up reduced the default-name count from 394 to 274 and
removed the FreeType residual bucket entirely. The same review identified
`tt_get_cmap_info` at `0x254b98` from the FreeType cmap service dispatch, and
`default_bzfree`, `default_bzalloc`, and `handle_compress` at `0x273350`,
`0x273360`, and `0x27336c` from the bzip2 stream initialization and compression
state machine. Those counts are historical checkpoints. The current residual
queue is documented below.

## IJG, zlib, and GIF source-role pass

The old profile grouped a large address interval as JPEG because the bundled
IJG routines occupy that part of the text segment. A source-body comparison
resolved 153 functions to IJG libjpeg 6b. The local archive is
`jpegsrc.v6b.tar.gz`, released 27-Mar-1998, with SHA-256
`75c3ec241e9996504fe02a9ed4d12f16b74ade713972f3db9e65ce95cd27e35d`.
The marker-reader corrections were important: `0xe0454` parses Adobe APP14,
`0x28d2ec` is `skip_variable`, and `0x28db3c` is `next_marker`.

The function at `0x28a2f4` was initially placed in that same address bucket.
Its literal, length, and distance Huffman decode loop and its zlib diagnostic
strings match `inflate_fast` from zlib 1.2.5. It is now named
`zlib_inflate_fast`.

The function at `0x2acb20` is the static GIF LZW line decompressor. The
preserved `DGifGetLine` and `DGifGetPixel` symbols both reference it. Its
prefix table, suffix table, stack, clear code, EOF code, variable-width code
reader, dictionary links, and output loop agree with the giflib
`DGifDecompressLine` role. It is now named
`giflib_DGifDecompressLine`; the exact giflib release remains unestablished.

One more correction was at `0x2ac400`. The preserved `jpeg_fdct_float` symbol
ends at `0x2ac3fc` and `jpeg_fdct_ifast` starts at `0x2ac440`. The bytes in
between are alignment and floating-point constants referenced by the DCT code,
not a separate function. Removing that false IDA boundary reduced the final
function inventory by one and left 124 genuine residual functions. They now
carry descriptive labels recorded in
`artifacts/ida_descriptive_residual_labels_20260902.json`.
The current source-role artifacts are
`artifacts/ida_libjpeg_source_matches_20260902.json`,
`artifacts/ida_zlib_source_matches_20260902.json`, and
`artifacts/ida_giflib_source_matches_20260902.json`.

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

## Google Play billing bridge

The next Android feature pass followed the two billing entries in the
`main_android` script table. The compact native and DEX export is
`artifacts/original_billing_bridge_review_20260830.json`, generated by
`tools/ida_export_original_billing_bridge_review.py`. The native side has
`JNI_initGooglePlay` at `0x24090c`, `JNI_buyGooglePlayItem` at `0x240eb8`, and
the reverse JNI callbacks `Java_com_quattroplay_GraalClassic_Natives_onGooglePlayInitialized`
and `Java_com_quattroplay_GraalClassic_Natives_onGooglePlayPurchase`. The
feature marker `TGameEnvironment_script_getGooglePlay` returns the literal
`googleplay` used by the version helpers.

The table registers `initgoogleplay` and `buygoogleplayitem`. The setup method
constructs `IabHelper` with the embedded RSA public key, enables debug logging
under the tag `unixmad`, and calls `startSetup`. The helper looks specifically
for the old `com.android.vending` service action and checks in-app billing v3
support. The initial Java Boolean is optimistic: it is true when the helper is
already present, true after the asynchronous setup is started, and still true
when the outer method catches an exception. The GL-thread
`onGooglePlayInitialized` event carries the later success or failure Boolean.
This is a plausible compatibility problem on devices that no longer expose
the legacy binder service, although it is separate from the native connector
TLS failure.

The purchase method has the same split between immediate and eventual state.
The native wrapper converts two native strings into Java byte arrays. The
activity passes them as the SKU and developer payload to
`IabHelper.launchPurchaseFlow`, which calls the billing service
`getBuyIntent` method. There is no local product-ID allowlist in this path.
The method returns true before the store UI completes, so scripts must wait
for the later purchase event. An arbitrary SKU does not produce a free item:
the store still controls product availability and signs the result.

`IabHelper` verifies the purchase JSON and signature through `Security.verifyPurchase`
before it reports a successful IAB result. It uses the embedded RSA key and
`SHA1withRSA`, and it repeats the check when rebuilding inventory. The result
handling has a less obvious boundary. A failed signature check still sends the
parsed `Purchase` object to the activity listener, paired with a failure
`IabResult`. `QPlayActivity$21` maps the result to `failed`, and the activity
then schedules a GL-thread event containing status, SKU, original purchase
JSON, and signature. The native callback at `0x2457d4` converts all four Java
strings and invokes the script event `onGooglePlayPurchase` with an `ssss`
signature. Verification therefore gates the success label, but not exposure
of the purchase fields to script code.

Successful purchases, and matching owned inventory entries, are automatically
consumed when the SKU contains `gralatspack`, `coinspack`, or `vippack`, or
starts with `android.test`. The filter is intentionally name-based rather
than a fixed product catalog. A collision with a future SKU could consume an
item unexpectedly. The consume callback reuses the same event with
`consumesuccess` or `consumefailed`; there is no separate inventory event.

The resulting security finding is conditional. A compromised activated script
can trigger arbitrary store prompts and can receive raw transaction fields,
including fields from a failed verification path. The static review did not
run a billing flow, bind to Google Play, collect a purchase, or test entitlement
logic. The public artifact contains no public-key literal, purchase data,
order identifier, or signature.

## Legacy partner compatibility bridges

The next pass followed every TapJoy, Distimo, Fabzat, and TrialPay callback in
the Android script table. The compact export is
`artifacts/original_partner_bridge_review_20260830.json`, generated by
`tools/ida_export_original_partner_bridge_review.py`. It includes 23 native
functions, the 22 partner-related table entries, and the private DEX behavior
of `com.quattroplay.GraalClassic.Natives`.

The first useful correction is that the table does not imply an active SDK.
`isTapJoyEnabled`, `isTrialpaySupported`, and `isFabzatSupported` are Java
methods that return false. The Java TapJoy connection method also returns
false. Distimo, TrialPay, and Fabzat methods return immediately. The native
wrappers still perform their normal JNI marshalling, so IDA shows complete
looking calls to Java, but the target methods terminate at the first line.

Two native TapJoy setters at `0x2401f4` and `0x240204` retain their incoming
strings in global `TString` objects. The later connection wrapper reads those
globals and passes them to the false-returning Java method. This means a script
can cause configuration text to be allocated and held in memory, but the
original APK does not send it to a functioning TapJoy service. The strings
should still be treated as sensitive if a future diagnostic patch reactivates
the provider.

Fabzat has five additional table entries for logo, share URL, font, and texture
settings. Their native callbacks are `nullsub_8` through `nullsub_12` at
`0x2401e0` through `0x2401f0`, each only returning. The separate Fabzat store
and resource-path wrappers call Java no-op methods. This is why the embedded
Fabzat certificate should remain a legacy inventory fact rather than being
used as a proposed connector trust anchor.

The DEX also carries OnePF/OpenIAB, Amazon, and other vendor billing classes.
The active Android table contains no Amazon or Mobiroo entries, and the
corresponding Natives helper methods are no-ops. Native Amazon and Mobiroo
callback symbols are not present in the script callback inventory. Their
presence is useful historical context but does not establish a reachable
alternate billing flow.

The practical result is a smaller compatibility target. These partner paths
cannot explain the native connector's failure to connect, and re-enabling one
would require more than restoring a missing symbol. It would require a current
SDK, a new service contract, and a separate review of credentials, user
consent, and network destinations. No partner service, UI, or offerwall was
opened during this pass.

## Android device, display, input, and media bridges

The next callback pass followed the Android script entries for
`getandroidosversion`, `getandroiddevicemodel`, `setvideoplayerrectangle`, and
`forceclosevirtualkeyboard`. The compact export is
`artifacts/original_android_device_media_review_20260830.json`, generated by
`tools/ida_export_original_android_device_media_review.py`. It contains 11
native functions and the relevant DEX behavior, with no device-collected
values and no media opened.

The two build-information callbacks are straightforward. The Java
`getAndroidOSVersion` method returns `Build.VERSION.RELEASE`. The device-model
method returns `Build.MANUFACTURER`, one space, and `Build.MODEL`. Both use the
platform default charset when turning the Java string into a byte array. The
native wrappers copy only lengths from 1 through 1024 bytes and release the
array. These values are not unique identifiers by themselves, but an activated
script can combine them with the existing network, URL, HTTP, or Facebook
surfaces to build a broader environment profile. The callbacks do not transmit
anything on their own.

`QPlayMain` captures four display values before the first native frame:
`densityDpi`, `xdpi`, `ydpi`, and `scaledDensity`. The newly translated
`MainAndroid_script_androidgetdisplayattributes` callback serializes them in
that order as comma-separated text. The active IDA database now labels the
backing values `android_density_dpi`, `android_xdpi`, `android_ydpi`, and
`android_scaled_density`. This is useful when comparing a screenshot or a
layout bug across devices, but it is not part of the connector handshake.

The video path is more incomplete than its native names suggest.
`JNI_setVideoPlayerRectangle` stores four integers in named global state and
tries to resolve `setVideoPlayerRectangle(IIII)V` on the Java class passed to
`QPlayMain`. There is no matching static declaration in the reviewed
`Natives.smali`. `QPlayLoop` only draws a quad when the native video helper says
that a player is open and the cached width and height are positive. The
EventListener route does not establish that state because
`QPlayActivity.openVideoPlayer` and `stopVideoPlayer` both return immediately.
The exported native update callback also has no declaration in the reviewed
DEX class. This is a dead or incomplete media bridge, not a reason for the
connector to fail.

The keyboard path is live at the activity boundary. Native code remembers the
current `GuiTextEditCtrl`, and `JNI_closeVirtualKeyboard` calls the Java
listener only when that control exists. `QPlayActivity.closeVirtualKeyboard`
returns if the EditText is hidden. Otherwise it snapshots the text, schedules a
GL-thread `onTextEntered(true, text)` event only when the caller requested final
text and `Natives.loaded` is true, then posts a UI-thread task that hides the
IME and marks the EditText gone. A renderer startup or lifecycle interruption
can therefore lose a final text callback without saying anything about network
reachability.

The practical repair order is to keep environment callbacks minimal and
documented, make final text delivery resilient to lifecycle changes, and either
remove the video entries or implement their Java side as an explicit feature.
No live service, media provider, or external application was contacted during
this pass.

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

The body passes the public-key check recovered from this APK when the native
wolfSSL raw-digest signature format is reproduced. An earlier generic ASN.1
`DigestInfo` verifier reported a mismatch because it used the wrong format.
The first local test therefore used a narrowly scoped RSA branch bypass before
the native format was identified. The saved fixture does not need that bypass,
and the bypass is not a safe release repair.

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
package-verification diagnostic. Keeping those diagnostics separate makes it
clear which changes are needed to study the client and which bytes are
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

## Cache filename and write follow-up

The next cache pass followed the filename from a completed HTTP request into
the file writer and resource refresh. The focused machine-readable record is
`artifacts/cache_filename_policy_review_20260902.json`, generated by
`tools/generate_cache_filename_policy_review.py`.

`TCachedStream_getDownloadFilename_TString_const` at `0x1fa920` sends URL-like
names to `baseuserfolder/webfiles`. `TFiles_escapedFilename_TString_const` at
`0xe7a50` preserves only underscore, ASCII letters, and digits. Every other
byte is represented by a percent sign and a zero-padded decimal byte value of
at least three digits. A slash or dot therefore does not remain a path
separator or a literal dot in this URL-derived route.

Ordinary relative names take the extension and resource-category path through
the same mapper. `TCachedStream_resolveFilename_void` at `0x1fb5b8` first
accepts an existing local path in selected base directories and otherwise
requests a mapped download filename. `TFiles_hasAbsolutePath_TString_const`
at `0xe8208` recognizes the configured URL marker, a leading slash, a colon,
or either configured path separator. These are lexical checks. The writer does
not show a `realpath` or no-follow open operation.

The most useful startup lead is in the persistence step. `TCachedStream_save`
at `0x1fa6e8` creates parent directories and calls
`TStream_SaveToFile_TString_const_uint` at `0xf0aa8`. The latter opens the
destination in replace mode for ordinary saves, calls `fwrite`, ignores its
return value, and closes the file. `TCachedStream_saveAndUpdate` then refreshes
the resource object, so a short write can leave a partial file at the expected
name while the in-memory resource graph treats the download as present. The
packet-102 completion path at `0x200010` reaches this sequence. This is a
conditional cache-integrity and startup-availability problem, not a reproduced
remote exploit.

The same pass checked `URLCACHE.txt`. `TURLCache_load_void` at `0x207eec`
loads every line into a string list and processes entries with at least two
comma-separated fields. `TURLCache_checkSave_bool_bool` at `0x20800c` writes
all entries back to `baseuserfolder/URLCACHE.txt`. There is no visible entry
count, byte budget, or integrity tag. The URL cache is keyed by a normalized
filename and deliberately skips `.code` insertion, which limits its direct
effect on level-code provenance. A malformed or very large local cache remains
a local availability and provenance concern.

The repair target is to check the exact write count, discard failed downloads,
write through a same-directory temporary file followed by an atomic rename, and
apply canonical-root and no-follow policy to ordinary cache paths. URLCACHE
should have explicit byte and entry limits and should reset safely when a
record is malformed. No storage-full, symlink, or interrupted-write runtime
test was performed.

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

The certificate-directory helper was traced as a separate CyaSSL API. Its
bounded 256-byte path construction still uses `stat`, which follows symbolic
links, but IDA shows only the CyaSSL certificate-directory wrapper reaching it.
The stock connector uses the embedded trust buffer through
`CyaInt_CyaSSL_CTX_load_verify_buffer` instead. The symlink concern therefore
remains relevant to an external caller of the dormant API, not to the active
connector path established in this client.

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

The same audit records a loader-level compatibility lead. Each packaged ABI
declares `libstdc++.so` as a needed library, but no copy is present in the APK.
The ARM64 `LOAD` alignment is `0x10000`; the armeabi, x86, and x86_64 files use
`0x1000`. The x86_64 diagnostic replay loaded its variant, so the missing
runtime dependency is not proven to be the startup failure. A real ARM64
device logcat should be used to check the dynamic-linker result before
changing the connector. The finding is `APK-012` in
`artifacts/original_apk_security_audit_20260830.json`.

The focused libc call-site pass also closed the last explicitly open formatter
question. Residual function `0x292b34` is the bundled libjpeg
`format_message` callback, not an application formatter. Its `sprintf` call
does omit a destination length, but the 124-entry table has only three `%s`
messages and all three refer to temporary files. The build's backing-store
helper reports `JERR_NO_BACKING_STORE` instead of creating one, while the
bitmap reader reaches the callback with numeric JPEG diagnostics. No
`msg_parm.s` write was found in the bundled JPEG path. The report now records
this as an unsafe source pattern with no demonstrated reachable string-format
overflow for this APK, while noting that a different backing-store
implementation would change the conclusion.

The native init/fini pass then followed the dynamic-section arrays through
IDA. There are 20 fixed init callbacks and 10 fini callbacks. Most are small
static-state routines: they initialize resource link lists, the texture list,
cached image dimensions, GUI defaults, client restart strings, input state,
and Android video globals. Two init callbacks allocate small hash or texture
objects. The exporter found no direct edge from the callback set into the
selected socket, resolver, file, or process boundary names. This makes the
constructor phase a useful loader checkpoint without treating it as a hidden
network path. The full output is in
`artifacts/original_native_init_review_20260830.json`.

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

## Native import and socket capability inventory

The next pass widened the native boundary check from the selected libc calls to
every undefined symbol in the original ARM64 ELF. The compact report is
`artifacts/original_aarch64_import_callsite_inventory_20260830.json`, generated
by `tools/audit_aarch64_import_calls.py`. It maps `.rela.plt` entries to their
AArch64 PLT stubs, scans `.text` for direct `BL` calls and unconditional `B`
tail transfers, and uses the checked-in function inventory to label each
containing function. It found 167 undefined symbols, 165 imports with direct
transfers, 3,186 transfer sites, and 301 tail calls. No network service was
contacted.

The wider scan clarified the native socket surface. The `TSocketProperties`
table registers `bind`, `connect`, `send`, and `sendudp`. The bind entry at
`0x3864f0` points through `jump_TSocket_bind_int_bool` at `0x205b94`; the UDP
entry points through `jump_TSocket_sendUDP_TString_const_TString_const_int` at
`0x2052e4`. The underlying `TSocketConnection_bindSocket_int_bool` at
`0x2068b4` creates and configures a socket, then reaches libc `bind` at
`0x206940` and `listen` at `0x2069f0`. The separate
`TSocketConnection_acceptSocket_void` function calls `accept` at `0x206e60`.

The constructor at `0xe0ab4` starts with null values for the allowed outbound
socket and allowed bind-port strings. Script callbacks at `0x204688` and
`0x204678` replace those values. The exact matching rules are still a runtime
question, but the static relationship is enough to classify the capability as
conditional: an activated script may be able to create a local listener if it
can supply permissive policy values and reach the bind operation. The stock
connector path uses the separate nonblocking TCP connect flow and is not shown
to start a listener.

The same class has a UDP data branch. `sendto` is called at `0x2071f0` and
`recvfrom` at `0x207730`; the receive path records the sender address and port
before appending the bytes. This establishes a native datagram capability, not
a live destination or proof that the stock script invokes it. The signed
connector script package remains a significant reachability gate for these
script-facing entries.

The scan also corrected a completeness assumption in the earlier libc report.
`TFiles_deleteFile_TString_const` reaches `unlink` through two unconditional
tail branches at `0xe6e08` and `0xe6e18`. A search limited to `BL` would have
reported that import as unused. The report now records the transfer kind for
each site and explicitly excludes conditional branches, `BLR`, function
pointers, vtables, and data-table dispatch. Those omissions mean the result is
an import boundary inventory, not a complete call graph.

## Remaining Android JNI callback review

The remaining Java-to-native boundary was exported from the active ARM64 IDB
into `artifacts/original_android_callback_review_20260830.json` by
`tools/ida_export_original_android_callback_review.py`. The pass covers the
surface-size, touch, key, text, accelerator, texture-reload, lifecycle,
script-registration, purchase, legacy-provider, video, and generic event
callbacks that were not included in the earlier focused Android reviews. It
records the decompiler text, effective native callers, and manually reviewed
behavior for each callback. No callback was executed and no service was
contacted.

The DEX counterpart is
`artifacts/original_dex_native_surface_review_20260830.json`, generated by
`tools/audit_dex_native_surface.py`. The original `Natives` class contains 18
public static native methods. Fourteen have 21 direct `invoke-*` callsites in
the DEX. The four exported methods with no direct DEX caller are
`onAddScriptFunction`, `onRegisterEvent`, `onVideoFinished`, and
`onVideoLoaded`. This is a useful reachability distinction, but it is not a
complete Java call graph because the small scanner does not resolve
reflection, method handles, native function pointers, or native-to-Java
callbacks.

The most useful startup lead is the relationship between `onAppPause` and
`QPlayLoop`. The native render callback is the process heartbeat: it throttles
frames, drains queued touch input, resets or rebuilds graphics state, runs
timers, and draws the loading or game path. The pause callback sets
`closeapplication` when the client is absent or `loadingstate` is at most two.
The next render callback sees that flag and calls `exit(0)`. An Android
compatibility prompt, permission transition, or early focus pause can therefore
end the process before the connector has made progress. This explains why a
silent launch failure must be checked against lifecycle logs before assuming
certificate pinning is the cause.

`onInvokeEvent` converts a Java event name and comma-delimited argument string
into a native script event. The special `onDeviceBackButton` path closes the
application when no active script catcher exists. Background entry and exit
are also forwarded to the script universe, with background entry additionally
calling `prepareEnterBackground` on the `-Games` object when present.

The registration callbacks are worth keeping separate from ordinary Android
IPC. `onRegisterEvent` lowercases a Java name, removes a leading `on`, and
adds it to the global event table. `onAddScriptFunction` builds an `Fs` script
property backed by `JNI_onScriptFunctionCall`. No direct DEX caller was found
for either callback, and no length limit is visible in the wrapper bodies.
That combination makes them ABI surface and review targets, but not a proven
active vulnerability in the stock APK. Their callers should remain within the
signed script and native registration boundary.

The input callbacks use fixed native state with a pointer-index check from zero
through four. Key events require an active native window and enabled hardware
keyboard handling. Text, Google Play, legacy-provider, and video callbacks
marshal Java values into native events, while the earlier billing, partner,
and device/media passes provide the reachability context for those paths. This
callback pass established no new native copy overflow. The next runtime check,
when a controlled device is available, is to capture activity pause, surface,
permission, and first-render timestamps beside the connector log.

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

The focused GIF pass also found that `DGifSlurp` retains every nonempty
extension block until it reaches the next image or trailer. Calls at
`0x2ae77c`, `0x2ae7a0`, and `0x2ae914` reach `GifAddExtensionBlock`, which
grows the extension array at `0x2af03c` and allocates each payload at
`0x2af074`. Each sub-block is capped at 255 bytes by its length byte, but no
aggregate extension count or byte budget was visible. This is recorded as
`GIF-004`, a static memory-pressure concern, in
`artifacts/gif_decoder_security_review_20260902.json`.

The same API grows its `SavedImages` array for each image descriptor. The
`reallocarray(existing, ImageCount + 1, 56)` site is `0x2ada90`, the count
increment is `0x2adafc`, and the `DGifSlurp` record loop begins at `0x2ae72c`
and runs until a trailer. There is no application frame-count limit in the
reviewed path. This is recorded as `GIF-005`, a static frame-metadata and
cumulative-resource concern, in the same machine-readable review.

The direct `TBitmap_readGIF_TStream` wrapper exposes a sharper arithmetic
candidate. It allocates the temporary source buffer from a 32-bit
height-times-width product at `0x150b88`, then allocates the destination from
a 32-bit width-times-height-times-8 product at `0x150c9c`, `0x150ca0`, and
`0x150cb8`. The row-copy loop at `0x150d40` through `0x150d50` writes one
decoded row at a time. Width `16385` and height `32768` produce a
`536903680`-byte source and copy length but a `32768`-byte wrapped destination.
This is recorded as `GIF-006`, a conditional static heap-overflow candidate;
no malformed GIF fuzzing or crash reproduction has been performed.

The PNG/MNG pass now has its own focused artifact,
`artifacts/png_decoder_security_review_20260902.json`, generated by
`tools/generate_png_decoder_security_review.py`. The entry path at
`0x11b4a8` through `0x11b4d4` allocates the decoded output from a width,
height, and pixel-bit product evaluated in 32-bit W registers. The PNG parser
at `0x1203a0` through `0x1203d4` allocates the filtered scanline buffer from a
second 32-bit expression. The decoder's size check at `0x11b878` through
`0x11b894` compares the stored raw length with that wrapped expression, then
the row loop at `0x11c58c` advances through the parsed height. The 8-bit RGBA
format path reaches the generic per-row `memcpy` at `0x11d410`.

The report's witness uses width `65536`, height `65537`, bit depth `8`, and
color type `6`. The output expression requests `262144` bytes after its
32-bit wrap even though the mathematical RGBA output is `17180131328` bytes.
The filtered input expression requests `327681` bytes after wrapping even
though the mathematical scanline stream is `17180196865` bytes. A zlib stream
with the wrapped output length could satisfy the visible check. This is
`PNG-001`, a conditional static overflow candidate. It has not been fuzzed or
reproduced in a runtime harness, so the artifact does not claim a crash or a
code-execution primitive.

The next image pass covered the native BMP and TGA readers. The focused
machine-readable record is
`artifacts/bmp_tga_decoder_security_review_20260902.json`, generated by
`tools/generate_bmp_tga_decoder_security_review.py`.

`TBitmap_readMSBmp_TStream` reads the BMP file and DIB headers without checking
the return value of each header read. In the 4 and 8-bit BI_RGB cases it uses
`biClrUsed` as a byte count after the `0x11611c` left shift and passes the
result to `TStream_read_void_int` at `0x11612c`. The destination is the
1,024-byte local `v79` array. A `biClrUsed` value of 257 is enough to request
1,028 bytes, so `BMP-001` is a concrete conditional stack-buffer boundary.
The usual zero count is replaced with 256 and exactly fills the local array.

The BMP reader also calls the shared allocator with format 2, which the
`TBitmap_updateBytesPerPixel_void` routine maps to three bytes per pixel. The
allocator's `0x11415c` product is a 32-bit value. The reader's non-4-bit path
then uses `width * 3` as the row read length at `0x116070`. The witness width
`1048576`, height `1366`, and source depth 24 produce a wrapped bitmap
capacity of `2097152` bytes but a first-row request of `3145728` bytes. This
is `BMP-002`, a conditional static heap-overflow candidate if the stream has
the row available. The `biSizeImage` field does not provide a visible limit.

The TGA pass found the same unchecked 32-bit size pattern in a smaller header
field range. `tga_load` at `0x1515cc` accepts image type 2 and 32-bit pixels,
multiplies width and height at `0x1516a4`, computes the four-byte allocation at
`0x151810`, and writes decoded pixels at the direct-path stores near
`0x151ca4`. Width and height of `32768` produce a nonzero pixel count but a
zero-byte decoded allocation. `TBitmap_readTGA_TStream` then allocates its
destination at `0x152168` and copies rows at `0x1521bc`. This is `TGA-001`, a
conditional memory-safety candidate. These BMP and TGA results are static
arithmetic and disassembly observations only. No malformed-image harness or
runtime crash reproduction has been performed.

The JPEG wrapper was then checked against the same shared bitmap allocator.
The focused record is `artifacts/jpeg_decoder_security_review_20260902.json`,
generated by `tools/generate_jpeg_decoder_security_review.py`. The wrapper
calls `jpeg_start_decompress`, passes output width and height to
`TBitmap_allocateBitmap_uint_uint_bool_TBitmap_BitmapFormat` at `0x1510c4`,
and calculates the decoder scanline length as output components times output
width at `0x1510dc`. Each scanline is written through the pointer formed at
`0x151120`, then the 32-bit row offset is advanced at `0x151134`.

The source dimensions `65535` by `21846` fit the JPEG 16-bit dimension fields.
For an RGB output, the mathematical bitmap size is `4295032830` bytes, but
the 32-bit shared allocation wraps to `65534` bytes and the first scanline
needs `196605` bytes. This is `JPEG-001`, a conditional static heap-overflow
candidate. The wrapper relies on the bundled IJG error path for malformed
syntax and does not add a decoded-pixel budget. No malformed JPEG was fuzzed
and no runtime crash reproduction has been performed.

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
normal packet-102 file path. That build did not reproduce the working
exchange. It changed the first connection to ordinary packet 23 requests and
stopped before the normal second-connection sequence. The direct jump is
therefore rejected as a repair. The working responder uses packet 102 for a
complete file response and can also emit the native 68, 84, 102, 69
large-file sequence.

A second negative control returned a 49-byte package containing only the
`GRPKG001` header and three metadata fields. The client accepted the packet
sequence, then crashed in the x86_64 diagnostic build at
`TScriptSpace::receiveEvent` while creating the script space. The stack passed
through `invokeCreatedEvent`, `TScriptSpace`, `TGraalVar::createScriptSpace`,
and `TClient::processIncomingPackages`. This establishes that the native
script setup path assumes required package records are present. It is a local
synthetic-fixture result, not a live-server exploit claim. The compact private
hash record is `artifacts/synthetic_basepackage_crash_20260902.json`.

The follow-up controls narrowed the trigger. Static analysis maps the native
large-file path to packet 68 for the filename, packet 84 for the declared size,
packet 102 for chunks, and packet 69 for completion. A valid private
152-byte `basepackage.gupd` sent as 68, 84, and 102 without packet 69 left the
x86_64 diagnostic process alive. Delaying packet 69 by two seconds reproduced
the same `TScriptSpace::receiveEvent` null fault. Repeating the large-file
sequence with `probe.bin` instead of a package name produced the same trace,
which separates the generic completion callback from package-specific
metadata parsing. Returning the complete package through one ordinary packet
102 also stayed alive during the bounded replay. The full control matrix,
capture hashes, and static addresses are in
`artifacts/update_package_transfer_review_20260902.json`; the narrative is in
`docs/UPDATE_PACKAGES.md`.

The filename check was then isolated. The responder used `basepackage.gupd`
for packets 68, 84, and 102, but sent `mismatch.bin` in packet 69. Offline
decoding of the private outgoing capture confirmed that packet-69 body. The
x86_64 diagnostic process again entered `TScriptSpace::receiveEvent`, but the
fault was `SIGSEGV` with `SEGV_ACCERR` at a nonzero address and instruction
offset `+43`, rather than the null-address `+38` seen in the matching-name
controls. This is a useful correction to the earlier shorthand: the common
fact is the script-space call chain, not one fixed null dereference. The result
supports a completion-state instability lead, but does not establish that the
mismatch alone corrupted a pointer or that the path is remotely reachable.

The same static pass tightened the security interpretation. Packet 84 at
`0x1ef48c` accepts any five available bytes and combines them with 32-bit
shifts into `bigfilesize`; no visible range or overflow check precedes the
store. Packet 69 at `0x1eb294` clears `bigfilename` only when the equality test
matches, but its equal and unequal paths both continue into cached-file lookup.
That is a state-confusion and arithmetic-validation lead, not a proven memory
corruption or arbitrary file write. The declared-size field's direct impact
was not established, and the mismatch replay does not prove a memory-safety
impact beyond the observed diagnostic crash.

The public game responder accepts `--frame-after-client` and
`--frame-after-map`. The first is useful for event-driven packet experiments.
The second was used here to send packet 49 only after the GMAP response, which
made the successful replay deterministic without a wall-clock delay.

## Bundled dependency provenance pass

The next security pass checked which old third-party implementations are
actually inside the ARM64 library and which native paths reach them. The
focused export is
`artifacts/original_dependency_provenance_20260830.json`, generated by
`tools/ida_export_original_dependency_provenance.py`. It records 12
decompiled functions, nine manually anchored callsites, and three conservative
dependency findings. The pass was read-only, contacted no server, and did not
fuzz a decoder.

The binary gives exact version evidence for three components. `zlibVersion` at
`0x289b50` returns `1.2.5`; `BZ2_bzlibVersion` at `0x2751ac` returns
`1.0.4, 20-Dec-2006`; and `FT_Init_FreeType` at `0x253f1c` writes the library
version fields `2`, `3`, and `6`. The embedded JPEG body matches IJG libjpeg
6b, released 27-Mar-1998, across 153 source-role entries. The GIF analysis
establishes the giflib API and static decompressor role, but not a unique
giflib release.

`readelf -d` shows no `libz.so`, `libbz2.so`, or `libfreetype.so` dependency.
Those implementations are statically embedded in `libqplay.so`. That means a
modern Android system cannot patch the decoder by replacing a host shared
library. The legacy protocol parser at `0x1fc598` selects zlib for modes 3 and
4 and bzip2 for modes 5 and 6. The NewGraal parser at `0x1fe31c` selects the
same wrappers for selectors 1 and 2.

The resource paths are broader than the protocol parser. The PNG/MNG parser
uses zlib `inflate` and `uncompress`, and the ZIP reader uses `inflate` for
deflated entries. `TFontData_load_void` at `0x110ca0` calls
`FT_New_Face` for filesystem fonts and `FT_New_Memory_Face` for resource
streams. A missing relative font can enter the file-download and resource
lookup path before that call.

The automatic decompression wrapper uses a shared output buffer. It starts at
at least 64 KiB and retries through 4 MiB, while the lower-level buffer helper
rounds requested sizes to powers of two without its own cap. This is a useful
per-call limit, but it does not replace the separate packet, stream, or total
resource budgets. The resulting DEP-001 through DEP-003 findings are phrased
as dependency exposure and resource-policy gaps. They are not claims that a
particular CVE is exploitable in this exact build because vendor backports were
not diffed and no fuzzing was performed.

The focused compression follow-up made that buffer policy more concrete. Its
machine-readable record is
`artifacts/compression_buffer_security_review_20260902.json`, generated by
`tools/generate_compression_buffer_security_review.py`. The helper at
`0xe4dd4` doubles a W32 capacity while the signed request remains greater than
the signed capacity. With request `0x40000001`, the state reaches
`0x80000000`, wraps to zero, and repeats. The matching compressor expression
is `input_length + 1024` at `0xe4f14` and `0xe51b8`; an input length of
`1073740801` supplies the witness. This is `COMP-001`, a static conditional
availability stall. It is not shown reachable through one normal NewGraal
frame because that protocol's length field is three bytes.

The same pass found a process-wide high-water effect. Automatic zlib and
bzip2 decompression starts from the larger of the shared capacity and 64 KiB,
then retries only while the next capacity is at most 4 MiB. Compression does
not share that ceiling when it initially requests `input_length + 1024`. An
input length of `4194305` requests `4195329`, which rounds the shared capacity
to 8 MiB. A later automatic decompression starts from that 8 MiB value. This
is `COMP-002`, a memory-policy inconsistency rather than a direct memory
overwrite. The helper also records its new capacity before `realloc`, and no
clear or shrink routine was found in the reviewed data references.

The protocol parser uses the same wrappers for NewGraal selectors 1 and 2 and
legacy modes 3 through 6. `TSocketConnection_read_void` reads at most 8192
bytes per call, but `TGraalConnection_read_void` appends the chunks without a
visible aggregate cap. This ties the shared-buffer review to the existing
framing review without treating a chunk size as a maximum frame or decoded
resource size.

## ZIP-backed resource follow-up

The next pass followed the bundled minizip implementation beyond the signed
connector package. Its machine-readable record is
`artifacts/zip_resource_security_review_20260902.json`, generated by
`tools/generate_zip_resource_security_review.py`. The ordinary resource scanner
at `0xe8bac` clamps the global entry count to 10,000 and skips a member whose
reported uncompressed size exceeds 1 GiB. Accepted members become resource
objects, and `TResourceObject_getStream_void` at `0xefe7c` sizes a native
stream from the member metadata before reading it. The script callback
`decompressfile` at `0xfca80` can use a wildcard to save every loaded child.
There is no aggregate decoded-byte or total output budget. This is `ZIP-001`,
a conditional availability and resource-policy gap.

The read boundary has a smaller integrity issue. The stream loader calls
`unzReadCurrentFile` at `0xeff90` and tests only the sign bit of the return
value. It does not compare a non-negative short count with the declared member
size. The stream resize at `0xeff74` clears new bytes through
`TString_setSize_int_bool`, so a short stored-member read can leave zero padding
inside a stream that still reports the declared logical size. This is `ZIP-002`,
a parser robustness gap that needs a bounded malformed-archive harness.

Finally, `unzOpenCurrentFile3` at `0x24b6fc` allocates a 0x120-byte state and a
0x4000-byte work buffer. If `inflateInit2_` at `0x24b844` returns an error, the
function returns at `0x24ba80` before assigning the state to the parent handle.
The normal `unzCloseCurrentFile` path at `0x24b620` cannot clean those temporary
allocations. This is `ZIP-003`, a conditional resource leak under decoder or
allocation failure. No malformed ZIP or allocation-failure reproduction was
performed.

The upstream [zlib 1.2.x ChangeLog](https://raw.githubusercontent.com/madler/zlib/v1.2.12/ChangeLog)
records later inflate validation work. The [bzip2 historical source archive](https://www.sourceware.org/pub/bzip2/)
contains the old 1.0.4 source package for a future source comparison. The
highest-value follow-up is a bounded local harness for protocol compression,
PNG or ZIP data, and font parsing.

## Connector fallback state-machine pass

The next connector review followed the failure branch instead of treating an
empty HTTP capture as the end of the investigation. The machine-readable
record is `artifacts/connector_fallback_review_20260902.json`, generated by
`tools/generate_connector_fallback_review.py`. The generator is offline and
can optionally hash-check the private original ARM64 library before producing
the report.

`TServerList_login_void` at `0x204420` starts mode 1. The normal negative
failure transition in `TServerList_enterNextConnectorMode_int` at `0x203df4`
keeps two attempts per mode: HTTPS `con.png`, HTTPS `con.gs`, then HTTP
`conf.gs`, with the `con2` host as the second attempt in each mode. Mode 4
shows the generic connector failure.

The important branch is in `THTTPRequest_saveDownloadedData_void` at
`0x200010`. The request object has a connector marker at offset 229. On a
failed connector request, the function reads the socket's CyaSSL error field at
byte offset 8312. The CyaSSL read and write paths store that field in
`TSocketConnection_read_void` at `0x2074d4` and
`TSocketConnection_sendData_void_const_int` at `0x207118`. If the field is
nonzero while the current connector mode is 1 or 2, the completion path calls
`enterNextConnectorMode_int` with explicit mode 3. This bypasses the second
HTTPS host and the alternate HTTPS file, then tries
`http://con.quattroplay.com/conf.gs`.

Plain socket failures do not populate that CyaSSL field and follow the normal
two-attempt transition. The distinction matters for the current startup
problem: an expired certificate can cause the first TLS connection to emit no
HTTP GET, then the fallback can make a plain request that was not included in
the earlier TLS-only control. The existing local control therefore proves the
pre-HTTP TLS failure but not the later mode-3 request. No live endpoint was
contacted, and the current service's support for `conf.gs` remains unknown.

The diagnostic port patcher now supports separate ARM64 defaults for the
diagnostic TLS port and the mode-3 HTTP port. On x86_64 the compiler folded the
two defaults into one expression with a fixed 363-port difference. A compatible
repair should use a current authorized chain, preserve peer and hostname
verification, and make any HTTPS-to-HTTP fallback an explicit policy decision.

## Runtime two-port fallback control

The static fallback branch was exercised on 2026-09-02 with a private x86_64
package built from the stock 1.8 APK. The package changed only the connector
HTTPS default to `18443`, the folded x86_64 fallback expression to `18080`,
hostname resolution to `127.0.0.1`, and the outgoing game RC4 key to the fixed
value used by the local responder. The native RSA result branch and
certificate verification remained enabled. The APK and native hashes are in
`artifacts/connector_fallback_runtime_control_20260902.json`.

An expired test certificate was served on `127.0.0.1:18443`. The client
reached the listener, aborted the TLS exchange before sending an HTTP request,
and then opened the separate cleartext listener on `127.0.0.1:18080`. That
listener recorded exactly one request with the original request shape, but the
path was `/conf.gs`, which is the mode-3 fallback endpoint. The body returned
was the archived 16,446-byte `/con.png` package because no current `conf.gs`
body was available locally.

The app stayed at the native `Connecting to the login server...` checkpoint
and did not connect to the synthetic game responder. A repeat with title-case
headers and `Connection: close` produced the same result. This closes the
question of whether the native TLS error branch can reach mode 3 at runtime,
but leaves the next boundary deliberately open: the archived `/con.png` body
may not be the response format expected from `conf.gs`, and the local trace
does not distinguish that case from a later script activation problem. No live
host was contacted.

## Runtime mode-3 role control

The next local control used a role-correct package rather than reusing the
archived `con.png` body. The supplied Moreno.kahn workbench, pinned at commit
`e1f49b5ce6fa46b41354d9a81f75994f91d3ff16`, defines separate output slots in
`src/contool.cpp`: `StartScript_Fail` for the `conf.gs` role and
`StartScript_Connector` for the `con.png` role. Its packing code also matches
the native envelope observed in the APK: a big-endian length-prefixed raw
RSA-SSL signature, an outer RC4-encrypted ZIP, a wrapped 16-byte script key in
`.rk`, a 20-byte `.t` entry, and RC4-encrypted compiled script entries.

A private 959-byte package containing only `.rk`, `.t`, and
`NPCS/StartScript_Fail` was generated from that format. The x86_64 diagnostic
library was paired with the matching public test key. No RSA-result bypass and
no certificate-verification skip was used. The expired TLS responder then
forced the same plain `/conf.gs` transition as the earlier two-port control.

This time the native log emitted `MODE3_FAIL_SCRIPT_REACHED` from the test
script's `onCreated` event. That is a complete local proof of HTTP body
acceptance, native signature verification, ZIP unpacking, script installation,
and failure-script execution. It also explains the earlier stalled replay:
the archived `con.png` package contained the connector role, so it was the
wrong semantic fixture for `conf.gs`. The failure role is not expected to open
a game socket. The current service's package, key, and connector script remain
unverified. The compact record is
`artifacts/connector_mode3_fail_script_runtime_control_20260902.json`.

## Native signed-package negative controls

The actual x86_64 package path was then exercised with a small targeted
negative-control suite. Each mutated body was re-signed with the private test
key, so the cases tested ZIP and dispatch behavior after the native outer RSA
gate rather than relying on a signature bypass. The emulator used the same
expired local certificate to enter mode 3 and a loopback HTTP responder.

The invalid-signature case, a package with the complete 22-byte EOCD removed,
an out-of-range `.rk` local-header offset, and an oversized script entry were
all rejected. They emitted the ordinary networking-problem message and did
not produce a filtered crash indicator. A one-byte-short version of the ZIP
was different: the client still activated `StartScript_Fail` and emitted
`MODE3_FAIL_SCRIPT_REACHED`. This likely reflects lenient handling of the
otherwise empty end-record tail. It is a format-integrity and parser
robustness concern, not a demonstrated memory-safety exploit.

The result supports two repair requirements: validate the complete ZIP end
record before trusting its offsets, and compare each non-negative decompressor
read with the declared member size before exposing the stream to script or
resource code. The six-case record is
`artifacts/connector_package_negative_controls_20260902.json`. It is a
bounded x86_64 control, not exhaustive fuzzing, and no live endpoint was
contacted.

## Delayed socket-to-TLS gate

The next static pass checked the state transition that precedes certificate
verification. `TSocketConnection_connectSocket` at `0x206bd8` creates an IPv4
TCP socket, makes it nonblocking, and begins `connect`. A pending connection
is status 4. `TSocketConnection_checkConnecting` at `0x206a48` polls the write
set with a zero-timeout `select`, then calls `getsockopt(SOL_SOCKET, SO_ERROR)`.
A zero error changes the state to 5. A nonzero error closes the socket and
enters the failure state.

`TSocketConnection_setStatus` at `0x2067b4` starts
`TSocketConnection_enableSSLOnSocket` only when the state reaches 5 and SSL is
enabled. The TLS function at `0x206450` returns early unless the descriptor
exists and the TCP state is 5. It then loads the trust buffer, selects a
legacy CyaSSL method, configures I/O and verification, checks the hostname,
and calls `CyaSSL_connect`. The request builder at `0x1ffde8` can set the SSL
flag before the TCP socket is ready, so that early call is expected to be a
no-op and the later status transition is significant.

This adds an ordering constraint to runtime diagnosis. Seeing a TCP attempt
without a TLS ClientHello does not by itself prove certificate rejection. The
render and timer loop may not have completed the status-4 poll, or the poll
may have reported a socket error first. The static map is preserved in
`artifacts/connector_socket_state_review_20260902.json`. No network endpoint or
native library was executed for this pass.

## Cross-ABI parity pass

Because a physical ARM64 run is not currently available, the four native
variants packaged in the original APK were compared without executing them.
The machine-readable report is
`artifacts/cross_abi_compatibility_review_20260902.json`, generated by
`tools/generate_cross_abi_compatibility_review.py`.

All four variants contain the connector host and path markers, CyaSSL and TLS
markers, and the same 12,820-byte encoded connector trust text. The encoded
text has SHA-256
`c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0` in each
file. Each variant also declares `libGLESv1_CM.so`, `libc.so`, `liblog.so`,
`libm.so`, and `libstdc++.so`, and each reports `BIND_NOW`, GNU RELRO, and a
non-executable GNU stack.

The ABI-specific differences remain important. ARM64 is ELF64 AArch64 with
`0x10000` `LOAD` alignment. armeabi and x86 are ELF32, x86_64 is ELF64, and
the other three use `0x1000` alignment. The ARM64 to x86_64 comparison shares
6,486 defined dynamic symbol names, while armeabi shares 6,349 and x86 shares
6,346. The differences are enough to make raw address transfer unsafe, even
though the shared trust bytes make the certificate-expiry lead cross-build.

The report also includes 34 exact shared address anchors for the two JNI entry
points, connector selection and HTTP completion, socket and protocol setup,
game connection, and selected CyaSSL operations. They are useful for locating
the same 1.8 behavior in a different ABI build. They are not a substitute for
function matching in the stripped 2.2 library.

This pass strengthens the diagnosis without overstating it. The stale trust
material and connector fallback are not likely isolated to ARM64, but a missing
legacy C++ runtime or an alignment-sensitive loader error still needs ARM64
logcat or a physical device. No live endpoint was contacted.

## 1.8 to 2.2 CyaSSL anchor pass

The installed 2.2 package gives us a more useful bridge than its stripped label
first suggested. The two ARM64 libraries retain the same 253 exact `CyaInt`
dynamic function names, and all 253 exported sizes match. The 2.2 addresses
move by `0xd590` for 240 functions and by `0xd588` for 13 certificate-parser
functions. Eighty-four corresponding function bodies are byte-identical,
including `CyaSSL_set_verify` and `CyaSSL_CTX_load_verify_buffer`.

The package-wide security inventory is now preserved in
`artifacts/comparison_apk_security_audit_20260902.json`, generated by
`tools/audit_comparison_apk.py`. It confirms the manifest, DEX, ZIP, signing,
and ELF surface and records the companion hook-library markers without
installing or executing either native object.

The result is strong enough to carry static CyaSSL labels into the 2.2 IDA
database after checking callers and data references. It is not a general
application address translation. `CyaSSL_check_domain_name` and
`CyaSSL_connect` have changed bytes despite the same names and sizes, and the
2.2 render loop grows from 696 to 1,560 bytes. The JNI startup entrypoint keeps
its 1,092-byte size at a separate `0xcdec` delta. The exact hashes, addresses,
and limits are in
`artifacts/cross_version_cyassl_anchor_review_20260902.json`.

## 1.8 to 2.2 retained-function overlap

The CyaSSL pass was intentionally widened after the first bridge proved that
the installed 2.2 file still carries useful dynamic names. The complete
defined `FUNC` sets contain 5,709 unique names in 1.8 and 5,782 in 2.2, with
835 exact names in common after symbol-version suffix normalization. There are
4,874 names unique to 1.8 and 4,947 unique to 2.2.

The common set is structurally useful but not uniform. Eight hundred thirty
shared names keep the same exported size, and 279 are byte-for-byte equal at
their corresponding file locations. The largest address clusters are
`0xd470` for 447 names, `0xd590` for 262, `0xd588` for 47, and `0xd584` for
27. The remaining names have smaller or isolated shifts, including several
independent JNI groups.

The compact family totals are CyaSSL 253, FreeType or TrueType 252, JPEG-like
exports 92, YAJL 47, crypto-like helpers 40, zlib 33, JNI 27, GIF 26, bzip2
17, and other retained names 48. These are name-based triage buckets. They
are useful for choosing the next IDA range to inspect, but they do not replace
function-level validation.

The repeatable measurement is in
`artifacts/cross_version_symbol_overlap_20260902.json`, generated by
`tools/generate_cross_version_symbol_overlap.py`. It records private input
hashes, section mapping, exact overlap counts, delta clusters, selected
anchors, and byte-equality results. It does not copy either native file into
the repository or contact a network service. The safe translation workflow is
to find the exact 2.2 name first, verify its size and bytes, then check its
callers and data references before applying an IDA name or patch.

The next step made that workflow searchable rather than implicit. The
metadata-only `artifacts/cross_version_translation_candidates_20260902.json`
contains all 835 exact-name rows, including both symbol values, per-function
size equality, the measured address delta, and raw-byte equality. Its generator
can read `lib/arm64-v8a/libqplay.so` directly from the private 2.2 APK. This
does not make a global delta safe and does not claim that the unverified
package represents stock 2.2 behavior.
