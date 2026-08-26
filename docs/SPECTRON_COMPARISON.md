# Spectron comparison

This note records what the supplied `spectron_client_1.0.2.apk` tells us
about the old client. It is a comparison artifact, not a claim that the
modded build is a drop-in replacement or that it has been proven playable.

## Inputs

The modded APK has SHA-256
`5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c`.
The original ARM64 library has SHA-256
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8`.
The modded ARM64 library has SHA-256
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The two helper repositories were inspected at these commits:

* [GScript.Go-HexaParser](https://github.com/MorenoLand/GScript.Go-HexaParser),
  `ad9bd3657feece825b5f5a888f5db34ffe37afb9`.
* [Moreno.kahn](https://github.com/MorenoLand/Moreno.kahn),
  `5e3a05fc8fbcf3c3f72b3c263238b2ed275fc66d`.

## Package differences

| Property | Original | Spectron |
| --- | --- | --- |
| Package | `com.quattroplay.GraalClassic` | `com.quattroplay.GraalClassiC` |
| Version | `6158` / `1.8` | `6612` / `2.2` |
| Target SDK | 26 | 33 |
| ARM64 `libqplay.so` | 3,657,208 bytes | 3,736,872 bytes |
| ARM64 `libqplay.so` symbols | Many application names retained | Application names largely obfuscated |

The package includes 6,767 files under `assets/offline/`, making it a useful
content and behavior reference. It should not be treated as proof that the
old client can use those assets without matching scripts, checksums, and
server-side responses.

## Native observations

The Spectron `libqplay.so` still exports the native CyaSSL implementation. A
few useful relative addresses are:

* `CyaInt::ValidateDate` at `0x2c2940`;
* `CyaInt::CyaSSL_connect` at `0x2d2bcc`;
* `CyaInt::CyaSSL_CTX_load_verify_buffer` at `0x2d35d8`.

The same library contains the strings `SetSigningCertificate`,
`GRAALRELOADED-version:`, `127.0.0.1`, `graal://`, and `graal3://`. It also
contains the ordinary `http://` and `https://` vocabulary and the familiar
game-server error messages. These strings establish that custom routing and
signing-related code is present. They do not establish which host is used at
runtime, nor do they prove that the old certificate problem is fixed.

The APK also bundles `libxposed.so`, SHA-256
`0300bf22966ff43a03495292493530e8e048032a808f80132e5360d8f8bdf456`.
Its native imports include `dlopen`, `dlsym`, `mprotect`, and
`dl_iterate_phdr`. Its string table includes `A64_HOOK`,
`inline hook %p->%p successfully! %zu bytes overwritten`, and `libqplay.so`.
The ARM64 library exports these JNI entry points:

* `JNI_OnLoad` at `0x832e8`, returning JNI 1.6;
* `Java_com_WebTop_onCreated` at `0x85de8`;
* `Java_com_WebTop_onmsg` at `0x85d34`;
* `Java_com_WebTop_getMainUrl` at `0x85f84`.

The exported `onCreated` body is a short save-and-return stub in this file.
The `onmsg` entry point dispatches through an object method, while
`getMainUrl` builds and returns a native string. The combination is consistent
with a custom WebTop or hook bridge, but it does not by itself identify a
game-server endpoint.

The hook path can be followed statically. The library constructor at `0x864b0`
starts a worker at `0x862d4`; that worker waits for `libqplay.so`, then the
resolver at `0x80fe4` performs nine `dlsym` lookups. The generic hook wrapper at
`0x7deec` delegates to an ARM64 inline-hook backend at `0xa6068`. Three of the
resolved exports are explicitly hooked: two obfuscated qplay functions receive
the replacements at `0x7ffdc` and `0x804d8`, and `_Z16DetectFridaLoop1bbb`
receives `0x80fbc`. The target names and relative addresses are recorded in
`artifacts/spectron_hook_analysis.json`.

The six command names compared by the native WebTop dispatcher at `0x842e4`
are `crash`, `freeze`, `abort`, `load_menu`, `setscript`, and `gs2call`.
The first three deliberately write through address zero, spin, or call
`abort`; the others forward WebTop payloads into native helpers. This is a
remote-control and modding interface with destructive commands, not an old
client compatibility patch.

The stripped `libxposed.so` was also decompiled far enough to resolve the
WebTop URL builder. `Java_com_WebTop_getMainUrl` is exported at relative
address `0x85f84` and appears at `0x185f84` in the Ghidra image. It decrypts a
five-byte device string as `NOID`, then formats the URL template
`https://spectronnative-page.onrender.com?device=%s`. The value returned by
the supplied APK is therefore:

```text
https://spectronnative-page.onrender.com?device=NOID
```

`Java_com_WebTop_onCreated` is a no-op in this library. The Java `WebTop`
class loads `libxposed.so`, creates a WebView, and exposes a JavaScript bridge
named `native`. Its message handler can evaluate JavaScript, load DEX bytes,
and perform reflection. This is a remote control and modding layer, not a
replacement for the original connector or a direct fix for its expired
certificate. The URL was recovered statically. The analysis did not open the
page or contact any remote service.

The Spectron ARM64 `libqplay.so` is a separate native build, not a lightly
patched copy of the 1.8 library. Its ELF entry point is `0xdf800` rather than
the original `0xe0170`, and the known loading-state marker moves from file
offset `0x2ce1d0` to `0x2db730`. These differences make direct symbol-address
transfers unsafe.

The offline ELF report makes that separation measurable. The original has
6,674 dynamic-symbol table entries and 6,671 named entries; Spectron has
6,773 and 6,770. There are 1,036 exact dynamic-name matches, mostly shared
third-party code. A function-level feature export reduces that to 1,008
one-to-one named function anchors. A simple application-name heuristic finds
1,035 readable names in the original but only 28 in Spectron, where the C++
names have been obfuscated.
The `.text` section also moves from file offset `0x0e0170` and size
`0x1ed970` to `0x0df800` and size `0x1fb870`. This is why an address copied from
the translated 1.8 IDA database is not meaningful in the modded build.

The report records the exact embedded identity strings without publishing a
private credential. The six-certificate trust text is 12,820 bytes at
`0x2dcef8` in the original and `0x2ea9e0` in Spectron, with the same SHA-256
`c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0`. The
`PjosLg8D` marker is at `0x2e1788` and `0x2ef7c8`; its following 360-character
public-key text begins 16 bytes later in both files and has SHA-256
`336e42a7b288feb8611ddbbcb19c135f2049a01169df9f15878e1dcb2d1facaa`. The
native DES-decoded DER remains 269 bytes with SHA-256
`35e7245d68e6ab6c84bd55061704fe2d3d16800cbe0a671aceae6c85e1301b82`.

The last text hash corrects an earlier archive typo. The previous value
`22d742...` did not hash the 360-byte embedded Base64 text. The value above is
the direct hash of the bytes found in both libraries; the decoded DER identity
was already correct. `artifacts/spectron_native_compare.json` and
`tools/compare_spectron_native.py` now provide the reproducible comparison.

There is one exact binary match that matters for the connector investigation.
The 12,820-byte base64 string beginning with `6erxf21jcqpGrZR4` appears at
file offset `0x2dcef8` in the original ARM64 library and at `0x2ea9e0` in the
Spectron ARM64 library. Both strings have SHA-256
`c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0`, and a
byte-for-byte comparison is equal. Decoding either copy with the original
native key rule produces the same six-block historical bundle, including the
malformed AlphaSSL PEM markers. The
Spectron package therefore does not fix the expired connector trust chain by
embedding a newer certificate. Any working behavior in that package could
instead come from its separate routing, hook, package, or service logic. The
static comparison does not establish which of those mechanisms is decisive.

The connector signing key is not different either. The 360-character
DES-wrapped public-key text following `PjosLg8D` is byte-for-byte identical
in the two ARM64 libraries. A raw Base64 decode is encrypted data, not DER;
after the native bit-reversed DES transform it produces the same 269-byte RSA
public key recorded in `artifacts/helper_toolchain_replay.json`, SHA-256
`35e7245d68e6ab6c84bd55061704fe2d3d16800cbe0a671aceae6c85e1301b82`. This
rules out the Spectron key as a source of a current connector signing key.

As a further check, `tools/match_spectron_function_signatures.py` compared the
bytes and sizes of 1,305 original IDA default functions against 5,782 named
Spectron text functions. It found one unique byte-identical match, but the
Spectron name was itself obfuscated and did not recover a useful source name.
The result is a negative control: the two builds do not provide a reliable
address or source-name translation for the remaining original `sub_` entries.
The exact counts and the single obfuscated match are recorded in
`artifacts/spectron_function_signature_match.json`.

## Cross-build semantic translation

The byte-identical test is intentionally strict. It is useful for ruling out
unsafe address copying, but it leaves a better option for the named 1.8
functions: compare normalized function structure in a clean IDA pass. The
exporter `tools/ida_export_function_features.py` records instruction and
basic-block counts, normalized mnemonic shape, register shape, string
references, and direct call names. PC-relative addresses and relocation
details are removed from the comparison so a rebuilt function can still be
recognized when its layout moved.

The matcher `tools/match_spectron_semantic_functions.py` used the original
v4 translated database and the supplied Spectron ARM64 library. The original
database contains 11,297 function starts and the Spectron library contains
11,678. The first pass maps 3,700 named 1.8 functions to unique Spectron
targets. Of those, 3,641 are high confidence and were applied to a disposable
Spectron IDA copy, while 59 medium-confidence rows remain review-only. There
are 1,019 ambiguous rows and 614 unmatched rows, so the pass does not pretend
to translate every function.

The method has a built-in validation set because 1,008 function names occur
once in each build. The unique semantic matcher reproduced 396 of those
shared-name matches with zero wrong matches. This does not prove every
obfuscated match, but it is a useful measured check on the normalization
rules. The output uses a `v18_` prefix, keeps both original and target
addresses, and never copies an original address into the 2.2 image.

The verified database copies are local because packed IDA databases are too
large for this repository:

* `analysis/spectron_libqplay_translated_v1.i64` contains the 3,641 automated
  high-confidence labels.
* `analysis/spectron_libqplay_translated_v2.i64` adds four reviewed context
  anchors for the premium marker, loading-screen getter, connecting window,
  and JNI loop.
* `analysis/spectron_libqplay_translated_v3.i64` adds six reviewed connector
  and socket anchors on top of the v2 copy.
* `analysis/spectron_libqplay_translated_v4.i64` adds 16 reviewed core
  anchors for resource loading, rendering, GUI setup, scripting, input, and
  client support on top of the v3 copy.

The second copy was reopened and checked. Its SHA-256 is
`fab82bedbafb864513dfbfc144f657d7542816d2ff883abe1a55c16753f55618`.
The translation map, checkpoint, manual evidence, and IDA scripts are
`artifacts/spectron_semantic_function_translation_20260826.json`,
`artifacts/spectron_translation_checkpoint_20260826.json`,
`artifacts/spectron_manual_translation_anchors_20260826.json`,
`tools/ida_export_function_features.py`,
`tools/match_spectron_semantic_functions.py`,
`tools/ida_apply_spectron_translation.py`,
`tools/ida_apply_spectron_manual_anchors.py`, and
`tools/ida_verify_spectron_manual_anchors.py`.

The manual anchors are deliberately labeled as cross-build correspondences,
not restored debug symbols. For example, the Spectron premium getter is the
function that builds the same encoded `a9a` marker and is called by the
translated sigcheck path. The loading getter is the one-byte accessor paired
with the mapped setter and called by Spectron's JNI render loop. The
connecting-window candidate owns the `Connecting to the server...` and
`StartConnectMessage` strings. The JNI loop itself retains the exact exported
name `Java_com_quattroplay_GraalClassic_Natives_QPlayLoop`.

The exact-name inventory adds the 612 shared names that did not enter the
strict semantic map. In total, 1,008 names occur once in each feature export:
396 are already covered by the semantic map and 612 are preserved exact-name
anchors only. The inventory contains 381 PLT or import names, 27 JNI names,
and 600 other readable names. These rows record both build-specific addresses
and function ranges, but they do not rename anything because the Spectron
name is already present. The generator and artifact are
`tools/generate_spectron_exact_name_anchors.py` and
`artifacts/spectron_exact_shared_name_anchors_20260826.json`.

I also reviewed six functions that sit directly on the connector and game
socket path. The new anchors cover connector-mode parameter construction,
HTTP download completion, CyaSSL setup, nonblocking socket connection, the
game protocol reader, and the low-level socket reader. Their Spectron
addresses are `0x2094c0`, `0x205958`, `0x20c59c`, `0x20ccd8`, `0x204274`, and
`0x20d614`, respectively. The evidence includes matching error strings,
parser or caller context, and the relevant control flow. These are now
available as `v18_` labels in the third disposable IDA copy through
`artifacts/spectron_network_manual_translation_anchors_20260826.json`.
They narrow the remaining SSL investigation to the actual 2.2 code path
without transferring 1.8 addresses.

The third copy was reopened and checked after applying the six network
anchors. Its SHA-256 is
`3e85fe26f63574232b445c249775f52b53efb12a71a5e046375ea216b61d1c95`.
The close-and-reopen result recorded six verified names with zero failures.

## Spectron core anchors

The next review pass focused on code that connects the network result to a
visible game. These rows were selected from clean Spectron pseudocode, not
from an address delta. The generator also checked the expected target string
set before emitting the artifact. The 16 rows are:

| 1.8 role | Spectron address | Preserved evidence |
| --- | ---: | --- |
| `TResourceFunctions_updateGameObjectsForFile_TString_const` | `0xee558` | Extension dispatch, `.enc` stripping, `khead`, `zone_head`, GANI update, and map refresh |
| `TResourceFunctions_updateResourceObject_TString_const_bool` | `0xef090` | `webfiles` path construction, resource lookup, linked-object refresh, and update notification |
| `TResourceFunctions_initStaticVars_void` | `0xf0058` | Exact image-extension table and one-block static initializer |
| `TFileScripting_script_decompressFile` | `0xff028` | Resource iteration, decompression, and `Unzipped ... into ... files` reporting |
| `TFileScripting_initStaticVars_void` | `0xff65c` | Exact executable deny-list, archive list, path characters, and package extensions |
| `TClientEnvironment_drawGame_bool` | `0x16027c` | `RenderGUI`, frame clearing, display-state handling, and successful return |
| `TGUIScriptLoader_showGameGui_void` | `0x16b848` | `StartScript_GraalGui`, `GUIContainer`, `GraalControl`, and `GraalControl3D` |
| `TGUIScriptLoader_hideConnectingWindow_void` | `0x16bed8` | `StartConnectMessage` lookup and active-dialog hide operation |
| `TGUIScriptLoader_createMessageBoxDialog_void` | `0x16bf80` | `StartScript_MessageBoxDialog` lookup or creation and script loading |
| `TGUIScriptLoader_showMessageBox_TString_const_TString_const_bool` | `0x16c0ac` | `MessageBoxDialog_Text`, text assignment, dialog push, and loading interaction |
| `TGUIScriptLoader_runFailedsafeConnector_void` | `0x16c3a0` | `StartScript_Connector` lookup or creation and recovery activation |
| `TInput_graalControlHasFocus_bool` | `0x16cac8` | Focused-control checks for `ChatBar` and `ChatBar3D` |
| `TClient_uploadFile_TString_const` | `0x1ed4c4` | 20,000,000-byte limit, upload queueing, and file log path |
| `TClient_logGameEcho` | `0x1f6538` | Per-line logging to the `game` channel |
| `THTTPRequest_runScript_void` | `0x207db8` | HTTP response reading, size guard, script parsing, and execution |
| `TServerList_showConnectingWindow_void` | `0x2092a0` | `ServerListGui`, GUI container handoff, connecting state, and game GUI transition |

The target functions retain 12 obfuscated C++ names and two IDA default
`sub_` names. The two defaults are useful negative controls for the symbol
translation problem: behavior and exact strings support the role, but there
was no target application name to preserve. The artifact records the current
target name, both build-specific ranges, all selected string references, and
the evidence for every row. It is
`artifacts/spectron_core_manual_translation_anchors_20260826.json`, generated
by `tools/generate_spectron_core_anchors.py`.

The 16 names were applied to a fresh copy of the v3 database with the existing
manual-anchor IDA script. A clean reopen found all 16 function starts and
reported zero failures. The resulting v4 database SHA-256 is
`3d4f217fcd20e21839957f4bd68a5fefa3998294fb6eebe93df760dd06e966b3`.
The checkpoint now records the four earlier context anchors, the six network
anchors, and these 16 core anchors separately.

## Spectron runtime-path anchors

The v5 review followed the state machine from a downloaded map or file packet
through the client and script subsystems. These functions were selected from
matching pseudocode and distinctive strings. They are useful when following a
runtime trace because the target names are mostly default `sub_` labels.

| 1.8 role | Spectron address | Preserved evidence |
| --- | ---: | --- |
| `TClient_setServerLevelFile` | `0x1eead4` | Normalizes the server level name and selects `.gmap` or a level resource |
| `TClient_enterServerMapFile` | `0x1ef0a0` | Copies map metadata, selects the first level, and enters it |
| `TClient_handleMapLevelPacket` | `0x1f6108` | Decodes map coordinates and level data before entry |
| `TClient_finishFileDownload` | `0x1ef8fc` | Emits completion, saves cache data, updates packages, and validates the resource key |
| `TClient_processFileChunk` | `0x1f1074` | Creates or reuses cache state, accounts bytes, and emits progress or completion events |
| `TClient_handleTextControlPacket` | `0x1f6670` | Handles GraalEngine, QEngine, getstats, stats, and receivetext |
| `TClient_processTextControlAction` | `0x1f73d0` | Routes text actions to the active weapon or QEngine statistics path |
| `TClient_setEncryptedScript` | `0x1f696c` | Decodes and routes encrypted weapon or class scripts |
| `TClient_loadEncryptedScript` | `0x1f6dec` | Decodes and loads encrypted weapon or class scripts |
| `TServerList_onClientDisconnected_void` | `0x2087f4` | Clears the connection, hides the dialog, reports SSL state, and calls onDisconnected |
| `TServerList_handleServerWarp_void` | `0x20a010` | Parses warp fields and calls the connector onServerWarp event |
| `TServerList_handleClient_void` | `0x2089d0` | Processes packages, timeout transitions, reconnects, and deleted players |
| `TClient_initStaticVars_void` | `0x1ec294` | Initializes loopback default state, client lists, and download tables |

The target function rows include five IDA default `sub_` names and eight
obfuscated C++ names. The two text-control functions were reviewed as a pair:
both parse or forward the same QEngine statistics and active-weapon
`receivetext` protocol, but their argument layouts differ. The two encrypted
script functions were also reviewed as a pair. One routes to the encrypted
setter and the other to the encrypted loader, which is why they remain
separate anchors even though their string sets overlap.

The map and file rows explain the local world transition. The map-level
handler and server-map entry both recognize `.gmap`, update the active-player
map state, select the first level, and call level entry. The file chunk and
completion rows retain `.gupd` handling, cache accounting, download events,
package updates, and resource-key validation. These static correspondences do
not prove that a live service still emits the same packet sequence.

The full evidence is in
`artifacts/spectron_runtime_path_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_runtime_path_anchors.py`. The 13 names
were applied to a fresh copy of v4 and verified after reopening. The resulting
v5 database SHA-256 is
`2c059f8bc96b90e46542f3fb3d05a6cd5a99af112acd516751f42b1bf4c0e421`.

## Spectron update and protocol anchors

The v6 review covered the request-side helpers that feed the file and resource
path. These are separate from the larger runtime-path anchors because their
main value is explaining queue ordering and the wire representation of image
checks rather than rendering a screen.

| 1.8 role | Spectron address | Preserved evidence |
| --- | ---: | --- |
| `TClient_requestDownload_TString_const` | `0x1ecd80` | Duplicate suppression, `.gupd` priority insertion, and image request dispatch |
| `TClient_requestUpdate_TString_const` | `0x1ecef0` | Modified-file checks, `.gupd` priority insertion, and update request dispatch |
| `TClient_processServerModifies` | `0xecba0` | Active-player transition reset and server-level modification application |
| `TClient_sendWantImageUpdateCRC_TString_const` | `0x1f8cc0` | Resource lookup, `.gupd` CRC calculation, and five-character checksum encoding |
| `TClient_sendWantImageUpdateModTime_TString_const` | `0x1f911c` | Resource lookup, URL handling, modification-time encoding, and request timestamp |

The two queue functions retain their separate request tables. Download
requests check the general requested-file set as well as modified, old, and
global sets. Update requests use the modified, old, and global sets. Both keep
`.gupd` files at the same priority boundary and only send immediately while
the queue is below the same threshold.

The checksum helper calculates a CRC for local `.gupd` content before encoding
it into the outgoing request. The modification-time helper reads the resource
timestamp and uses the same compact character encoding. URL-backed resources
take the same HTTP branch in both routines. The server-modify helper is an
exact size and block-count match, and its pseudocode preserves the level-entry
versus in-place modification decision.

The full artifact is
`artifacts/spectron_update_protocol_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_update_protocol_anchors.py`. The five
names were applied to a fresh copy of v5 and verified after reopening. The
resulting v6 database SHA-256 is
`a8b96aeb48438b222828348b990ee944252e14c02763bfe097d63dc8bab4bbe3`.

## Spectron client action anchors

The v7 review followed the adjacent client action serializers. These targets
retain the protocol format strings and the matching parameter shapes in their
obfuscated C++ names, which makes them stronger anchors than address order
alone.

| 1.8 role | Spectron address | Preserved format or signature evidence |
| --- | ---: | --- |
| `TClient_sendLevelWarpModtime_double_double_TString_const_uint` | `0x1f7968` | `ddsu`, two coordinates, text, and timing value |
| `TClient_sendBoardModify_int_int_int_int_int_int` | `0x1fa098` | `iiiiis` and six integer-like board fields |
| `TClient_sendBoardModify2_TString_const_int_int_int_int_int_int` | `0x1fa3b0` | `siiiiis` and named board payload |
| `TClient_sendBomb_double_double_int_int_bool_TString_const` | `0x1fa7a4` | `ffiibs`, coordinates, flags, and text |
| `TClient_sendTriggerAction_TServerNPC_double_double_TString_const_TString_const` | `0x1fb89c` | `offss`, NPC, coordinates, and two strings |
| `TClient_sendProjectile_double_double_double_double_double_double_double_TString_const_TString_const_TString_const` | `0x1fbc80` | `dddddddsss` and seven numeric values |
| `TClient_sendShot_double_double_int_int_int_bool_bool` | `0x1fcdc8` | `ddiiibb` |
| `TClient_sendPlayerHurt_TServerPlayer_TServerNPC_double_double_int` | `0x1fd43c` | `ooddi`, player, NPC, coordinates, and integer |
| `TClient_sendWeaponHit_double_double_double_TServerNPC` | `0x1fd8e0` | `dddo`, three numeric values and NPC |
| `TClient_sendExplosion_int_int_double_double_bool` | `0x1fdde0` | `iiddb` |
| `TClient_sendSetText_TString_const_TString_const_TString_const_TString_const` | `0x1fe670` | `ssss` and four text fields |

The level-warp timing target also retains the compact coordinate encoding and
the connector-versus-game-server output split. The board helpers preserve
their short and long payload paths. The action helpers keep their diagnostic
format branch and normal packet dispatch, while the text helper retains the
long-string container used for values beyond the compact encoding limit.

The full evidence is in
`artifacts/spectron_client_action_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_action_anchors.py`. All 11 names
were applied to a fresh copy of v6 and verified after reopening. The resulting
v7 database SHA-256 is
`dff0fadfadfbbd4cb815b013ad589965545acb6b521518af091b61e89b266a64`.

## Spectron remaining client outbound anchors

The v8 pass reviewed the rest of the readable outbound client method cluster.
It contains 29 one-to-one role anchors. Twenty-eight add new context labels
to the translated target database, while the image-update row corroborates a
function already found by the strict semantic matcher. These are not guessed
from address arithmetic alone. The target method order follows the readable
1.8 order, the obfuscated C++ signatures preserve the argument shapes, and the
packet bodies retain the same compact or long-string serialization families.

| 1.8 role | Spectron address | Target shape or preserved cue |
| --- | ---: | --- |
| `TClient_sendLevelWarp_double_double_TString_const` | `0x1f76b0` | two coordinates and a level string |
| `TClient_sendLevelLinking_TString_const_double_double` | `0x1f7c88` | level string followed by two coordinates |
| `TClient_sendEnterLevel_void` | `0x1f8110` | no arguments, compact enter-level packet |
| `TClient_sendDownloadFile_TString_const_TString_const_TString_const` | `0x1f8290` | three strings and long-string handling |
| `TClient_sendUploadStart_TString_const` | `0x1f8514` | one string, upload-start dispatch |
| `TClient_sendSaveFile_TString_const_int_TString_const` | `0x1f86c0` | string, integer, and string |
| `TClient_sendUploadEnd_TString_const` | `0x1f88e8` | one string, upload-end dispatch |
| `TClient_sendWantImage_TString_const` | `0x1f8a94` | one string, resource or URL request |
| `TClient_sendWantImageUpdate_TString_const` | `0x1f943c` | `.gmap` and `.gupd` selection branch |
| `TClient_sendWantGaniScript_TString_const_uint` | `0x1f94d8` | string and unsigned script value |
| `TClient_sendWantWeaponScript_TString_const` | `0x1f9724` | one string, weapon-script request |
| `TClient_sendWantClassScript_TString_const_uint` | `0x1f98d0` | string and unsigned script value |
| `TClient_sendToAllChat_TString_const` | `0x1f9b1c` | one string, chat dispatch |
| `TClient_sendIsPKer_TServerPlayer` | `0x1f9d70` | server-player pointer argument |
| `TClient_sendCarryThrow_void` | `0x1f9f14` | no arguments, carry or throw packet |
| `TClient_sendRemoveBomb_double_double` | `0x1faad0` | two coordinates |
| `TClient_sendFireSpying_int_int` | `0x1fad20` | two integer fields |
| `TClient_sendPreloadLevel_TServerLevel` | `0x1faed8` | server-level pointer and level metadata |
| `TClient_sendPlayerProperties_TString_const` | `0x1fb194` | one string, player properties |
| `TClient_sendNPCProperties_TString_const` | `0x1fb340` | one string, NPC properties |
| `TClient_sendFlag_TString_const` | `0x1fb4ec` | one string and `client.` flag guard |
| `TClient_sendUnsetFlag_TString_const` | `0x1fb6c4` | one string and `client.` flag guard |
| `TClient_sendExtra_double_double_int` | `0x1fc440` | two coordinates and an integer |
| `TClient_sendTakeExtra_double_double_int` | `0x1fc6e0` | two coordinates and an integer |
| `TClient_sendRemoveExtra_double_double` | `0x1fc980` | two coordinates |
| `TClient_sendOpenChest_int_int` | `0x1fcbf0` | two integer fields |
| `TClient_sendDeleteWeapon_TServerWeapon` | `0x1fd0e0` | server-weapon pointer argument |
| `TClient_sendDeleteNPC_TServerNPC` | `0x1fd280` | server-NPC pointer argument |
| `TClient_sendServerWarp_TString_const` | `0x1fdbe0` | one string, server-warp dispatch |

The first group completes level entry and file or image requests. The middle
group covers scripts, chat, player state, properties, and flags. The final
group covers map-side actions, extras, chest and object deletion, and server
warp. The source review also checked the target bodies for the common client
send slot, compact coordinate rounding, diagnostic format branches, and
long-string escape paths where those branches were present.

The exact obfuscated target names, source and target instruction counts,
string references, and review notes are preserved in
`artifacts/spectron_client_outbound_manual_translation_anchors_20260826.json`.
The artifact was generated by
`tools/generate_spectron_client_outbound_anchors.py`. All 29 names were
resolved and verified after reopening the eighth disposable database,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v8.i64`.
Its SHA-256 is
`29e9eed59176cdf495705a88e1d193000f59d46eefba5f151e9d213d8ec4f58d`, and the
checkpoint records the same hash. These anchors explain the local serializer
layout. They do not prove that a current external server accepts the old
packet protocol.

## Spectron resource resolver anchors

The v9 pass moved from packet construction into the resource resolver cluster.
These six functions are useful for explaining why a client can reach the map
and file path but still fail to produce a usable local resource. The target
signatures retain the argument shapes, and the decompiled bodies preserve the
resource tables, alternative links, path roots, stream checks, and download
fallbacks.

| 1.8 role | Spectron address | Preserved behavior |
| --- | ---: | --- |
| `TResourceFunctions_validateFileKey_TString_const` | `0xef5a0` | encoded-key lookup, alternative creation, and resource refresh |
| `TResourceFunctions_getMatchingResourceObjects_TString_const_int_bool` | `0xef69c` | wildcard matching, alternative expansion, result limit, and optional sort |
| `TResourceFunctions_getFilesForPattern_TString_const_int` | `0xef8d4` | data or user root selection and relative file-list construction |
| `TResourceFunctions_getResourceStream_TString_const_bool_bool` | `0xefcd0` | absolute or level lookup, update, stream return, and download fallback |
| `TResourceFunctions_gamefileexists_TString_const` | `0xefe58` | short resource-existence predicate |
| `TResourceFunctions_getGameFile_TString_const_bool` | `0xefe78` | stored path construction and optional download fallback |

The matching helper handles both a direct level-resource request and wildcard
iteration over the resource hash list. It appends linked alternatives, stops
at the requested limit, and sorts when the caller asks for ordered results.
The file-list helper then turns those resource paths into names relative to the
data or user root. This matches the source path and explains why `.gmap` and
`.gupd` lookups can share the same underlying resource tables.

The stream helper chooses the absolute-path or level-resource path, checks
whether the selected object can be loaded, optionally updates it, and returns
the stream. A missing resource takes the download path and can return an empty
stream object for the caller. The game-file pair supplies the corresponding
existence test and stored path construction. The key validator attaches a
decoded key to the matching resource alternative before refreshing it.

The exact obfuscated target names, source and target sizes, signature cues,
and review notes are preserved in
`artifacts/spectron_resource_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_resource_anchors.py`. All six names were
applied and verified after reopening the ninth disposable database,
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v9.i64`.
Its SHA-256 is
`1e63b822e0d9cd8d9d1ea7f3db5fe03e4b8dbbaf451d22fae6784106c4c34e83`, and the
checkpoint records the same hash. These are semantic labels for the resource
path, not restored original debug symbols.

## Spectron client script bridge anchors

The v10 pass reviewed the script-call bridge that feeds player actions and
client packet helpers. All 13 target functions were IDA default `sub_` names,
so this pass is a direct example of why the readable 1.8 symbols are useful
for the stripped 2.2 build. The anchors use decompiled behavior, ordered
function context, target size and block checks, and distinctive strings where
available.

| 1.8 role | Spectron address | Preserved behavior |
| --- | ---: | --- |
| `GSFunctionsClient_script_uploadfile` | `0x15ab64` | allowed-upload filtering and client upload dispatch |
| `GSFunctionsClient_script_updateterrain` | `0x15ac54` | active-player terrain or buffer refresh |
| `GSFunctionsClient_script_triggeraction` | `0x15aca0` | NPC action selection, coordinate adjustment, and packet forwarding |
| `GSFunctionsClient_script_setsleevecolor` | `0x15b260` | appearance slot 2 setter |
| `GSFunctionsClient_script_setskincolor` | `0x15b2d4` | appearance slot 0 setter |
| `GSFunctionsClient_script_setshoecolor` | `0x15b348` | appearance slot 3 setter |
| `GSFunctionsClient_script_setcoatcolor` | `0x15b3bc` | appearance slot 1 setter |
| `GSFunctionsClient_script_setbeltcolor` | `0x15b430` | appearance slot 4 setter |
| `GSFunctionsClient_script_callweapon` | `0x15b4a4` | weapon index validation and action callback |
| `GSFunctionsClient_script_requesttext` | `0x15b958` | `clientrc` authorization and request-text dispatch |
| `GSFunctionsClient_script_findlevel` | `0x15c51c` | normalized map search and current-level fallback |
| `GSFunctionsClient_script_adventure_openserverlist` | `0x15ca50` | `onOpenServerList` event dispatch |
| `GSFunctionsClient_script_sendtext` | `0x15d400` | command filtering and four-string text packet forwarding |

The five color rows preserve the appearance-list indexes in the order
`sleeve`, `skin`, `shoe`, `coat`, and `belt`, which maps to target slots 2, 0,
3, 1, and 4. The trigger-action body retains both the player-side action and
the client-side packet, while the weapon-call body keeps the selected weapon
index check and compact or long script argument conversion.

The request-text row retains the `graalengine` and `clientrc` security gate and
the `Unauthorized attempt to use clientrc` error. The send-text row retains
the `add`, `delete`, `irc`, and `lister` filters before forwarding the
four-string packet. The level lookup still lowercases map names and falls back
to the current level, and the server-list row still emits `onOpenServerList`.

The exact target default names, target shape checks, source and target counts,
and pseudocode review notes are in
`artifacts/spectron_script_bridge_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_bridge_anchors.py`. All 13 names
were applied and verified after reopening
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v10.i64`.
Its SHA-256 is
`ef32e71f5dda36f208fe2e61f08f1dbf849e12cc1b223c3d9b2af19e408d6b92`, and the
checkpoint records the same hash. These labels are semantic translations, not
claims that original debug symbols survived in the target.

## Spectron client request and window-state anchors

The v11 review followed the next readable `TClient` cluster. These functions
sit immediately after the earlier outbound serializers and preserve the same
method order in Spectron, even though the target names are obfuscated. The
matching decision used the exact source role, target order, argument shape,
instruction counts, basic-block counts, and a pseudocode review of the body.

| 1.8 role | Source | Spectron target | Target shape or evidence |
| --- | ---: | ---: | --- |
| `TClient_sendWeaponImgChange_TString_const` | `0x1f8480` | `0x1fe088` | one string, `onSendWeaponImage` path |
| `TClient_sendRCChat_TString_const` | `0x1f8534` | `0x1fe234` | one string, `onSendRCChat` path |
| `TClient_sendRequestText_TString_const_TString_const_TString_const` | `0x1f85e8` | `0x1fe3e0` | three strings, `sss` request encoding |
| `TClient_sendRequestFileDeletion_TString_const` | `0x1f88fc` | `0x1fe960` | one string, filename extraction |
| `TClient_sendRequestFolderDeletion_TString_const` | `0x1f89d4` | `0x1feb28` | one string, folder deletion event |
| `TClient_sendRequestFileRename_TString_const_TString_const` | `0x1f8a88` | `0x1fecd4` | two strings, compact or long encoding |
| `TClient_sendRequestFilesMove_TString_const_TString_const` | `0x1f8cd0` | `0x1ff020` | two strings, compact or long encoding |
| `TClient_sendRequestUpdatePackage_TUpdatePackage_bool` | `0x1f8e60` | `0x1ff2b8` | update-package pointer and boolean |
| `TClient_sendHaveWindow_bool_TString_const` | `0x1f9198` | `0x1ff6c0` | boolean and string, `bs` encoding |
| `TClient_sendPingAnswer_int` | `0x1f92b4` | `0x1ff8c8` | integer clamp and compact encoding |
| `TClient_sendWindowList_TString_const` | `0x1f93e8` | `0x1ffaa0` | one string, window-list event |

The target methods retain the same sequence of event callbacks and ordinary
client dispatches as the 1.8 bodies. The request-text, rename, move, and
window-presence methods preserve the short and long string branches. The
update-package method still walks package entries, handles `.gupd` and
checksum state, and respects the downloads-blocked flag. The ping helper still
limits the value before using the compact two-character representation.

The full target names, source and target feature counts, signature fragments,
and hash checks are in
`artifacts/spectron_client_request_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_request_anchors.py`. All 11 names
were applied to a copy of v10 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v11.i64`. Its SHA-256 is
`6a34445aa580201a046e227b9ec447b73ee37251e7b716b349474e278e3d1daa`, and the
checkpoint records the same hash. These labels translate local client logic;
they do not establish compatibility with a current external service.

## Spectron client inbound and state-transition anchors

The v12 review moved from outbound requests into the inbound client state
paths. These pairs were selected from body-level pseudocode review, preserved
method context, target shape, and distinctive state or resource behavior. Six
of the eight target functions still had IDA default names before this pass.

| 1.8 role | Source | Spectron target | Target shape or evidence |
| --- | ---: | ---: | --- |
| `TClient_manageDataByScript_uchar_TString_const` | `0x1e7bf0` | `0x1ebf78` | bool and string, `onData` array event |
| `TClient_uploadFilesToServer_void` | `0x1e9198` | `0x1ed624` | upload queue loop and completion event |
| `TClient_processServerModifies2` | `0x1ea9f4` | `0x1eedfc` | level cleanup and modify or enter branch |
| `TClient_enterServerMapTile` | `0x1eac34` | `0x1ef24c` | `.gmap` lookup and bounded tile selection |
| `TClient_handleUpdatePackageDownloaded` | `0x1ec044` | `0x1f08ec` | package state, object event, completion branch |
| `TClient_updateGlobalPlayer` | `0x1ed3e8` | `0x1f1d98` | player lists, login/logout, mass message |
| `TClient_updateGaniFromString` | `0x1f1dd0` | `0x1f65d4` | GANI reload from serialized lines |
| `TClient_handleGaniUpdate` | `0x1f2a20` | `0x1f7268` | update packet parsing and GANI reload |

The data-event row preserves the script array slots and the final event
dispatch. The upload row retains the pending-file loop, upload-start and
save-file sequence, list cleanup, and completion callback. The server-map rows
keep the active-player transition state, map bounds clamping, `.gmap` lookup,
and selected-level entry. The package-completion row retains package version
state, both completion events, and the executable-replacer condition.

The global-player row is a particularly useful anchor for runtime behavior. It
still creates or updates players, moves logged-out players to the deleted list,
merges mass messages, and assigns login or logout identifiers. The two GANI
rows retain the short-string parsing, line-list conversion, and animation
replacement path.

The full source and target feature counts, target names, required string checks,
and pseudocode evidence are in
`artifacts/spectron_client_inbound_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_inbound_anchors.py`. All eight
names were applied to a copy of v11 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v12.i64`. Its SHA-256 is
`3b95170bd3689c176a15503764476a13db7c50e194ae771b7c39d9d33e1badfa`, and the
checkpoint records the same hash. These labels translate local client state;
they do not establish compatibility with a current external service.

## Spectron login, event, and small state-helper anchors

The v13 review followed the client inbound pass into the compact helpers that
feed login and connection state. All eight target functions had default IDA
names before this pass.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGameEnvironment_emit_onFolderLog` | `0x1e96dc` | `0x1edb9c` | first transformed one-string folder-log helper |
| `TGameEnvironment_emit_onRCChat` | `0x1e975c` | `0x1edc54` | second transformed one-string RC-chat helper |
| `TClient_handleServerLoginSignature` | `0x1e97dc` | `0x1edd0c` | signature storage and login event dispatch |
| `TClient_setGhostMessage` | `0x1e9840` | `0x1edda8` | four-instruction global string assignment |
| `TClient_setDisconnectReason` | `0x1e9850` | `0x1eddb8` | four-instruction global string assignment |
| `TClient_setServerWarpDestination` | `0x1e9860` | `0x1eddc8` | four-instruction global string assignment |
| `TClient_setLoginAccountName` | `0x1e9870` | `0x1eddd8` | three-instruction global string assignment |
| `TClient_handlePlayerLoginLogout` | `0x1f17b4` | `0x1f3018` | packet prefix decode and updateGlobalPlayer call |

The first two target helpers use compile-time transformed event literals. Their
identity is supported by their preserved order and by the first helper's use
from the target upload-file size-error path, which corresponds to the source
onFolderLog event. The login-signature helper follows the same source order,
stores its argument, and dispatches the transformed no-argument login event.
The four setters are direct assignment bodies with the same shape and order as
the source run.

The player-login target is a useful example of a source-level refactor. The
1.8 handler contains packet decoding and the player update logic in one large
body. Spectron moves the prefix decode into `0x1f3018` and calls the already
translated `v18_TClient_updateGlobalPlayer` routine. This is a high-confidence
role anchor, not a claim that the two functions have identical bytes or
identical boundaries.

The evidence is in
`artifacts/spectron_login_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_login_helper_anchors.py`. All eight names
were applied to a copy of v12 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v13.i64`. The database SHA-256 is
`40fd845df92e2443481d2a3e08299749ba46e3dcde4529769b0a028e65fc1d01`. These
labels clarify local login and event flow; they do not prove live service
compatibility.

## Spectron client encryption-in tail-thunk

One small client wrapper was kept separate from the login-helper batch because
the semantic matcher intentionally ignores functions smaller than 32 bytes.
The source function at `0x1e96c0` is a 28-byte wrapper that loads the global
client, checks it, and forwards the string to the connection encryption-in
parser. Spectron has the same seven-instruction tail-thunk at `0x1edb80`,
ending at `0x1edb9c`.

The target function already had a mangled IDA boundary,
`_Z10YvswSaABVtRK10C8THgaTQxF`, so this is a normal alias rather than a
reconstructed function. The artifact also records the exact 28 target bytes
and their SHA-256. The name was applied and reopened successfully in
`analysis/spectron_libqplay_translated_v14.i64`, whose SHA-256 is
`417ee107e499d6729ddefad89108a2b105bff1b8120734c3c8e1b7ba1e1967c7`.

The evidence is in
`artifacts/spectron_parse_wrapper_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_parse_wrapper_anchor.py`. This label
clarifies a local connection-state wrapper and does not establish live service
compatibility.

## Spectron player and download lookup anchors

The v15 pass reviewed three small list lookups that feed player state and file
delivery. The semantic matcher did not select them because the target changed
the obfuscated helper and static names, even though the decompiled bodies are
structurally exact at the role level.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_getGlobalPlayerByID_int` | `0x1e7650` | `0x1eb9d8` | active-player list scan and ID comparison |
| `TClient_getDeletedPlayerByID_int` | `0x1e7794` | `0x1ebb1c` | deleted-player list scan and ID comparison |
| `TClient_findDownloadFile_TString_const` | `0x1e8150` | `0x1ec56c` | case-insensitive download-file list scan |

All three source and target bodies retain six basic blocks. The first two
return the matching player object from their respective lists or null. The
third returns the matching download entry after the same case-insensitive name
comparison. The target signatures retain the expected integer or const string
parameters, while the class, list, field, and helper names are obfuscated.

The evidence is in
`artifacts/spectron_lookup_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_lookup_helper_anchors.py`. All three names
were applied to a copy of v14 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v15.i64`. The database SHA-256 is
`d2cf2b3cdf701fcd0afc29a0f919b4db15f351f9dc9e4fe8ccb217702c56e40c`. These
labels improve local player and file-delivery analysis; they do not establish
live service compatibility.

## Java observations

The Java dex files still use the normal Graal activity and renderer bridge:
`QPlayActivity` creates the native renderer and `QPlayRenderer` calls
`Natives.QPlayMain`. The activity has fields and methods named
`signingCertificate`, `GetSigningCertificate`, and `SetSigningCertificate`.
The newer Spectron activity passes `GetSigningCertificate()` into
`PiracyChecker.enableSigningCertificate()` and enables an unauthorized-apps
check. This is an application-signature entitlement check, not the native
HTTPS trust bundle. The original 1.8 dex does not contain this Spectron
PiracyChecker path. These names therefore do not identify an old-client TLS
pinning bypass.

The dex strings do not expose an obvious `con.quattroplay.com` or game-login
hostname. The native library does contain loopback and URL strings, so a
runtime trace is still required before describing the mod as a local-server
client.

## Runtime comparison

The modded package was installed alongside the original on the x86_64
emulator. Its log reached:

```text
Connecting to the login server...
Serverwarp...
Connected.
```

The visible UI reached a custom green menu with `Edit Profile` and `Start`.
The same run logged failures writing some external scoped-storage files,
including level files. Remote HTTP and HTTPS sockets were also observed, so
the `127.0.0.1` string is not evidence of a self-contained offline server.
This runtime observation is separate from the static URL extraction above:
the analysis did not open the recovered WebTop URL or contact a remote service
as part of the static comparison. A playable world was not verified for the
modded package.

A later direct launch of the supplied APK provides an important correction to
the runtime picture. After Start was tapped, the process died with
`SIGSEGV`, fault address `0x0`, at `libxposed.so+0x84348`, with the caller
reported as `Java_com_WebTop_onmsg+104`. The stripped hook library was checked
in IDA at that address. It is the selected `crash` command path in the WebTop
dispatcher: a null store followed by a loop. The qplay scoped-storage write
failures appeared in the same log, but they were not shown to cause the crash.
This run had normal emulator networking, so it is not a no-network control,
and it does not establish a playable-world result. The exact observation and
the static correlation are in
`artifacts/spectron_runtime_crash_control_20260826.json`.

To isolate that fault, I built a private signed control with
`tools/build_spectron_webtop_safe_apk.py`. It replaces only the three
conditional branches that select `crash`, `freeze`, and `abort` with jumps to
the next command comparison. The qplay libraries and the `load_menu`,
`setscript`, and `gs2call` branches are unchanged. The control APK has SHA-256
`d8b44281f2c2a3e8ab6f40358e28d017052a967cdf2a5b9b0c3383535ef07de3`, and its
patched ARM64 `libxposed.so` has SHA-256
`ba6023c42e501c9f1dae17f7d65973d09b399f4f4c8f1acf1e43487b1b01a50c`.

On the same emulator, the safe control stayed alive after Start and reached
the qplay messages `GraalClassic has been activated!`, `Initialized OpenGL`,
`Connecting to the login server...`, two `Serverwarp...` messages, and
`Connected.` The custom green menu first appeared, followed by the welcome
and tutorial dialogs. After those dialogs were advanced, the client rendered
a stable in-game scene with the player, map furniture, HUD controls, and
status icons. This is a stronger isolation result: the destructive WebTop
bridge command is a real blocker, and once it is skipped the supplied 2.2
client reaches local game entry in this environment. Network contact was not
independently audited. The build and runtime record is in
`artifacts/spectron_webtop_safe_runtime_20260826.json`; the standalone byte
patch is reproducible with `tools/patch_spectron_webtop_safe_commands.py`.

## What this changes for the original client

The original client remains the source of truth for the 1.8 protocol. Its
ARM64 symbol translation is complete at 8,601 applied names, and the local
x86_64 no-swap replay reaches a rendered world through the normal packet
table. That replay uses packet 178 for server warp, packet 190 for the
connecting-window completion path, packet 49 for the GMAP transition, and
packet 102 for file responses. A large-file transfer can use 68, 84, 102, 69.

The ARM64-only diagnostic build was also run through the available x86_64
emulator's native translation layer. It completed the same connector, game
login, map, level-file, image, and heartbeat sequence, but remained on the
title or loading image. That result is useful for separating transport and
resource behavior from renderer behavior, but it is not an ARM64 device
validation.

The comparison therefore supports three practical conclusions:

1. The newer package is a useful source of content and behavioral clues.
2. Its native library and hook library are different builds with different
   symbol and routing assumptions.
3. The WebTop URL belongs to the supplied modding layer and was not proven to
   be the old game's login endpoint.
4. Grafting either library into the original package would introduce more
   unknowns than it removes. The useful comparison is an ARM64 loopback run
   using the original client and the already verified local responder.

The live-service login remains unverified. No production endpoint or account
was used for the local replay.
