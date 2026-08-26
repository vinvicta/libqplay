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

## Spectron connection and SSL helper anchors

The v16 pass focused on the connection object because it is the most relevant
static area for the old client’s TLS behavior. Eighteen source and target
helpers retain the same bodies, sizes, instruction counts, and basic-block
counts.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGraalConnection_clearEncryptionKeyIn_void` | `0x1fc200` | `0x201b34` | RC4 or AES incoming-key cleanup |
| `TGraalConnection_clearEncryptionKeyOut_void` | `0x1fc24c` | `0x201b80` | RC4 or AES outgoing-key cleanup |
| `TGraalConnection_clearOutList_void` | `0x1fc298` | `0x201bcc` | outgoing TString list cleanup |
| `TGraalConnection_TGraalConnection__2` | `0x1fc3cc` | `0x201d00` | deleting destructor wrapper |
| `TGraalConnection_setEncryptionParseKey_TString_const` | `0x1fcd50` | `0x202684` | parser-key assignment at field 168 |
| `TGraalConnection_printSocketError_void` | `0x1fce4c` | `0x202780` | socket-error flag at field 272 |
| `TGraalConnection_isblocked_void` | `0x1fea58` | `0x2043ac` | outgoing queue saturation predicate |
| `TGraalConnection_setEnableSSL_bool` | `0x1fea70` | `0x2043c4` | SSL flag propagation to socket |
| `TGraalConnection_setSSLCipherList_TString_const` | `0x1fea98` | `0x2043ec` | cipher-list propagation |
| `TGraalConnection_setSSLProtocol_TString_const` | `0x1feae8` | `0x20443c` | protocol propagation |
| `TGraalConnection_getSSLError_void` | `0x1feb80` | `0x2044d4` | socket error value or -1 |
| `TGraalConnection_getByte228` | `0x1fec48` | `0x204598` | byte field read at 228 |
| `TGraalConnection_setByte228` | `0x1fec50` | `0x2045a0` | byte field write at 228 |
| `TGraalConnection_getDword304` | `0x1fec58` | `0x2045a8` | dword field read at 304 |
| `TGraalConnection_getByte240` | `0x1fec60` | `0x2045b0` | byte field read at 240 |
| `TGraalConnection_getDouble312` | `0x1fec68` | `0x2045b8` | double field read at 312 |
| `TGraalConnection_getDword176` | `0x1fec70` | `0x2045c0` | dword field read at 176 |
| `TGraalConnection_getDword244` | `0x1fec78` | `0x2045c8` | dword field read at 244 |

The SSL setters do not themselves perform certificate verification. They store
the configured values on the connection and copy them to the live socket when
one exists. The adjacent `setSSLVerifyCert` helper was already translated in
the earlier semantic pass. Together, these labels give a clearer static map of
where SSL is enabled, where cipher and protocol settings propagate, and where
the socket error is retrieved.

The evidence is in
`artifacts/spectron_connection_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_connection_helper_anchors.py`. All 18
names were applied to a copy of v15 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v16.i64`. The database SHA-256 is
`bf60436ef5fd788c72b8151b5d7eb60a5a12a0e727932df0db4fb7c315afdf0b`. These
labels describe local TLS plumbing and do not prove compatibility with a live
certificate or server.

## Spectron compact client-state helper anchors

The v17 pass reviewed seven compact forwarding and state setters that sit
between the client protocol helpers and the event paths. All seven source and
target bodies preserve their size, instruction count, and basic-block count.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_callVirtual320` | `0x1e9560` | `0x1eda20` | vtable-320 forwarding wrapper |
| `TClient_setServerOptionsRaw` | `0x1e95a0` | `0x1eda60` | server-options static assignment |
| `TClient_enableGraal2002ServerMode` | `0x1e95b0` | `0x1eda70` | Graal 2002 mode flag setter |
| `TClient_setTimeVarRaw` | `0x1e95c4` | `0x1eda84` | time-variable static assignment |
| `TClient_setPlayerStateFlag1680` | `0x1e9678` | `0x1edb38` | active-player state byte |
| `TClient_setGhostModeValue` | `0x1e9694` | `0x1edb54` | ghost-mode static assignment |
| `TClient_setPlayerStateFlag2328` | `0x1e96a4` | `0x1edb64` | active-player bool state byte |

The first four targets preserve the exact compact forwarding or static
assignment behavior of the source. The final three keep the active-player
null checks and state-byte writes, including the separate ghost-mode static.
The target names were all default IDA names before this pass.

The evidence is in
`artifacts/spectron_client_state_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_state_helper_anchors.py`. All
seven names were applied to a copy of v16 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v17.i64`. The database SHA-256 is
`acb84b3675ece2e5e040ac2eb16b3a15cec4607ecf8b3c5741115074d2954197`. These
labels describe local state plumbing and do not establish live service
compatibility.

## Spectron client connection-state helper anchors

The v18 pass reviewed five compact helpers that connect the client state to
the connection and encrypted-file paths. All five source and target bodies
preserve their size, instruction count, basic-block count, mnemonic hash,
register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClient_getConnectionString8288` | `0x1e9918` | `0x1ede80` | connection field at offset 8288 |
| `TClient_getConnectionString8296` | `0x1e9968` | `0x1eded0` | connection field at offset 8296 |
| `TClient_getConnectionString8304` | `0x1e99b8` | `0x1edf20` | connection field at offset 8304 |
| `TClient_setEncodedFileKeyAndContinue` | `0x1eafe0` | `0x1ef648` | encoded-key setter then download continuation |
| `TClient_saveServerLevelEncrypted` | `0x1e9e9c` | `0x1ee404` | guarded encrypted server-level save |

The first three targets read the live connection pointer from client offset
256, return an empty TString when it is absent, and copy the same connection
field offsets as the source. The encoded-file helper forwards four arguments
to the resource key setter and then invokes the download action continuation.
The server-level helper keeps the null check and forwards the save value to
the encrypted level method.

The evidence is in
`artifacts/spectron_connection_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_connection_state_anchors.py`. All five
names were applied to a copy of v17 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v18.i64`. The database SHA-256 is
`c724dfd0fc8bf61ccf0d9b58742bff9a035af022b7a70a2a8f8bd8f73189f7d2`. These
labels describe local connection and encrypted-file plumbing and do not
establish live service compatibility.

## Spectron HTTP request helper anchors

The v19 pass reviewed 12 helpers in the request-object region. All source and
target bodies preserve their size, instruction count, basic-block count,
mnemonic hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THTTPRequest_getStringField200` | `0x1ff04c` | `0x20499c` | request field at offset 200 |
| `THTTPRequest_getStringField256` | `0x1ff07c` | `0x2049cc` | request field at offset 256 |
| `THTTPRequest_getStringField248` | `0x1ff0ac` | `0x2049fc` | request field at offset 248 |
| `THTTPRequest_getStringField280` | `0x1ff0dc` | `0x204a2c` | request field at offset 280 |
| `THTTPRequest_getStringField264` | `0x1ff10c` | `0x204a5c` | request field at offset 264 |
| `THTTPRequest_getStringField216` | `0x1ff13c` | `0x204a8c` | request field at offset 216 |
| `THTTPRequest_getStringField184` | `0x1ff1a0` | `0x204af0` | request field at offset 184 |
| `THTTPRequest_getStringField296` | `0x1ff1d0` | `0x204b20` | request field at offset 296 |
| `THTTPRequest_getStringField288` | `0x1ff200` | `0x204b50` | request field at offset 288 |
| `THTTPRequest_getStringField168` | `0x1ff230` | `0x204b80` | request field at offset 168 |
| `THTTPRequest_THTTPRequest__2` | `0x1ffd20` | `0x205668` | deleting destructor wrapper |
| `THTTPRequest_sendOutgoing_void` | `0x1ffd6c` | `0x2056b4` | socket send and buffer removal |

The ten string accessors initialize the script return TString and copy the
same request-object field offset as their 1.8 counterparts. The deleting
destructor keeps the request cleanup and `operator delete` sequence. The
outbound helper checks the socket error state, sends the queued bytes, and
removes the bytes successfully written. The offset-256 accessor corroborates
the earlier medium-confidence semantic match through this contiguous region.

The evidence is in
`artifacts/spectron_http_request_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_http_request_anchors.py`. All 12 names
were applied to a copy of v18 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v19.i64`. The database SHA-256 is
`ecd0b6db4a8147fa3771cd02d283b022ddd959cdac17c22301e56b472efeb365`. These
labels describe local request plumbing and do not establish live service
compatibility.

## Spectron socket-state helper anchors

The v20 pass reviewed five compact socket helpers. All source and target
bodies preserve their size, instruction count, basic-block count, mnemonic
hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TSocketConnection_hasError_void` | `0x2062b8` | `0x20c404` | socket status error predicate |
| `TSocketConnection_closeForSubProcesses_void` | `0x2062cc` | `0x20c418` | empty subprocess-close hook |
| `TSocketConnection_setNonBlocking_void` | `0x206320` | `0x20c46c` | `fcntl` nonblocking setup |
| `TSocketConnection_getIPNum_void` | `0x206330` | `0x20c47c` | numeric IP field at offset 8 |
| `TSocketConnection_getIP_void` | `0x2070f4` | `0x20d234` | formatted IP helper |

The first helper reports an error for the same socket status range in both
builds. The subprocess-close hook is empty in both versions. The nonblocking
helper calls `fcntl` with command four and flag 2048. The two address helpers
read the same 32-bit field at socket-object offset eight, with the latter
passing it to the IP-string helper. The formatted-IP row corroborates the
earlier medium-confidence semantic match through the surrounding socket
sequence.

The evidence is in
`artifacts/spectron_socket_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_socket_state_anchors.py`. All five names
were applied to a copy of v19 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v20.i64`. The database SHA-256 is
`6d01c2d7fedfef870e19119d6e9bb302ac88012a80072a9cfe135d312d08c96e`. These
labels describe local socket plumbing and do not establish live service
compatibility.

## Spectron changed socket behavior

Three socket functions changed size between the 1.8 and 2.2 libraries, so the
comparison treats them as behavior pairs instead of exact rename anchors.

| 1.8 role | Source | Spectron target | 1.8 shape | 2.2 shape |
| --- | ---: | ---: | ---: | ---: |
| `TSocketConnection_enableSSLOnSocket_void` | `0x206450` | `0x20c59c` | 868 bytes, 215 instructions, 45 blocks | 792 bytes, 193 instructions, 44 blocks |
| `TSocketConnection_connectSocket_TString_const_int` | `0x206bd8` | `0x20ccd8` | 564 bytes, 141 instructions, 21 blocks | 628 bytes, 154 instructions, 20 blocks |
| `TSocketConnection_read_void` | `0x2074d4` | `0x20d614` | 916 bytes, 228 instructions, 34 blocks | 928 bytes, 231 instructions, 34 blocks |

The SSL setup still requires a valid descriptor and connected status, selects
the same CyaSSL method family, loads the per-socket verify buffer, selects the
same verification mode, applies the cipher list, optionally checks the
configured domain, enables nonblocking TLS, and calls `CyaSSL_connect`. The
2.2 version adds or changes logging and internal symbol names, but the
decompiled policy path is the same.

The connect function still resets the socket, creates an IPv4 TCP socket,
enables nonblocking mode, accepts a numeric address or resolves a hostname,
uses status four for in-progress and status five for completion, retries
`EINTR`, and enters the SSL helper only after a completed TCP connection. The
read function still separates plain, UDP, and CyaSSL reads, treats the same
transient errors as nonfatal, records TLS errors, and closes on fatal or
zero-length results. The 2.2 read path adds a `bytesread==0` diagnostic.

The evidence is in
`artifacts/spectron_socket_behavior_comparison_20260826.json`, generated by
`tools/generate_spectron_socket_behavior_comparison.py`. The artifact records
that all three pairs changed size and that none was treated as an exact body
match. This is static evidence only. It does not prove that a current service
accepts the old certificate, protocol, or client query.

## Spectron HTTP request-state helper anchors

The v21 pass reviewed four compact request-state helpers. All source and
target bodies preserve their size, instruction count, basic-block count,
mnemonic hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THTTPRequest_getRequestCount` | `0x1fec80` | `0x2045d0` | request-count global |
| `THTTPRequest_getLastRequestTime` | `0x1fec90` | `0x2045e0` | last-request-time global |
| `THTTPRequest_getLastWebDownloadTime` | `0x1feca0` | `0x2045f0` | last-download-time global |
| `THTTPRequest_isDownloadingFile_TString_const` | `0x201bec` | `0x2073dc` | download-file lookup predicate |

The first three targets return the same request-count or timestamp globals.
The fourth calls the same download-file lookup and returns whether a match
exists. All four target names were checked in the compact request-state
sequence. The evidence is in
`artifacts/spectron_http_request_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_http_request_state_anchors.py`. All
four names were applied to a copy of v20 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v21.i64`. The database SHA-256 is
`ab2c0ebb20066e28896a6774aa7da1eaa857f55f21c81d427165add8705c9dc6`. These
labels describe local request state and do not establish live service
compatibility.

## Spectron TServerNPC helper anchors

The v22 pass reviewed 15 compact `TServerNPC` helpers. All source and target
bodies preserve their size, instruction count, basic-block count, mnemonic
hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
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

IDA pseudocode confirms that the target block helpers write the same mode and
local-state fields, the draw helpers write the same mode values, and the
visibility helper uses the same override rule. The bow helper retains the
same mode gate and string assignment. The five pelt helpers compare the same
logical pelt field with the corresponding literal. The source callback
records also decode to the named script methods and property getters.

The evidence is in
`artifacts/spectron_npc_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_npc_helper_anchors.py`. All 15 names
were applied to a copy of v21 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v22.i64`. The database SHA-256 is
`5632ecb9a4fef83373c2a21b6a8ca96708e05252a6acedba802cc321e47a0bc0`. These
labels describe local NPC behavior and do not establish live service
compatibility.

## Spectron THTMLAtom helper anchors

The v23 pass reviewed five compact `THTMLAtom` helpers. All source and target
bodies preserve their size, instruction count, basic-block count, mnemonic
hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THTMLAtom_THTMLAtom_THTMLPage` | `0x1cf240` | `0x1d3e94` | constructor and clear call |
| `THTMLAtom_setTextInBuffer_uint_int` | `0x1cf274` | `0x1d3ec8` | buffer start and length stores |
| `THTMLAtom_setLengthInBuffer_int` | `0x1cf280` | `0x1d3ed4` | buffer length store |
| `THTMLAtom_getLengthInBuffer_void` | `0x1cf290` | `0x1d3ee4` | buffer length read |
| `THTMLAtom_getEndInBuffer_void` | `0x1cf298` | `0x1d3eec` | start plus length |

IDA pseudocode confirms the same constructor field initialization and clear
call, the same buffer start and length fields, and the same end calculation.
The five functions remain contiguous in both builds, which also rules out a
generic isolated getter match.

The evidence is in
`artifacts/spectron_html_atom_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_html_atom_anchors.py`. All five names
were applied to a copy of v22 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v23.i64`. The database SHA-256 is
`ee5ce543cb188e0b16b8479b2d19dd76c7ac0e636852d8446a022ce1a5e8da33`. These
labels describe local HTML parsing state and do not establish live service
compatibility.

## Spectron TPlayer helper anchors

The v24 pass reviewed five compact `TPlayer` helpers. All source and target
bodies preserve their size, instruction count, basic-block count, mnemonic
hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_setAttachedTo_TServerPlayer` | `0x16c760` | `0x170318` | attachment pointer and change flag |
| `TPlayer_sendChanges_void` | `0x1731f0` | `0x1771f0` | client-gated property update |
| `TPlayer_setFreezeCounter_int` | `0x1764a8` | `0x17a778` | counter and negative reset |
| `TPlayer_drawSpriteAbsolute_int_int_int` | `0x17bcb8` | `0x180060` | zero-offset absolute wrapper |
| `TPlayer_drawSprite_int_float_float` | `0x17bd88` | `0x180130` | zero-offset sprite wrapper |

IDA pseudocode confirms the same attachment change flag, client-gated update
call, freeze-counter reset behavior, and zero-offset forwarding into the
sprite drawing routines. The target helpers retain the same compact sequence
roles despite obfuscated C++ names.

The evidence is in
`artifacts/spectron_player_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_helper_anchors.py`. All five
names were applied to a copy of v23 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v24.i64`. The database SHA-256 is
`126b3d9ffb27b26e91ccd2f0dfd0d1f48c2f03dd45cf0c1ee4e731b2f9cdec9f`. These
labels describe local player behavior and do not establish live service
compatibility.

## Spectron input and window bridge anchors

The v25 pass reviewed eight compact input and window helpers. All source and
target bodies preserve their size, instruction count, basic-block count,
mnemonic hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TInput_getKeyState_int` | `0x168fdc` | `0x16c9dc` | key-state table read |
| `TInput_graalkeypressed_int_bool` | `0x169158` | `0x16cbac` | bounded key-state write |
| `TWindow_setCursorPosition_int_int` | `0x1066c8` | `0x108eb8` | cursor coordinate stores |
| `TWindow_getScreenWidth_void` | `0x106d30` | `0x109530` | mode-selected width |
| `TWindow_getScreenHeight_void` | `0x106d4c` | `0x10954c` | mode-selected height |
| `TWindow_getCanvasControl_void` | `0x107154` | `0x109954` | canvas lookup |
| `TWindow_init_void` | `0x107f58` | `0x10a8a8` | drawing-panel initialization |
| `TWindow_getPreferredPosition_void` | `0x1081f4` | `0x10ab44` | zeroed position result |

IDA pseudocode confirms the same key-state table, cursor fields, mode mask,
canvas lookup, drawing-panel initialization, and zeroed preferred-position
result. The width and height helpers remain adjacent in both builds, as do
the target input and window class contexts.

The evidence is in
`artifacts/spectron_input_window_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_input_window_anchors.py`. All eight
names were applied to a copy of v24 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v25.i64`. The database SHA-256 is
`a309f9556b21ea43585455a08f5ec0a3291aa60e44d34b475f02672e4341c476`. These
labels describe local input and window behavior and do not establish live
service compatibility.

## Spectron visual helper anchors

The v26 pass reviewed 11 compact animation, particle, and show-image helpers.
All source and target bodies preserve their size, instruction count,
basic-block count, mnemonic hash, register-shape hash, and control-flow shape
hash.

| 1.8 role | Source | Spectron target | Main evidence |
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

IDA pseudocode confirms the same child and property fields, changed-depth
flag, alpha and rotation defaults, one-sixteenth particle conversions,
show-image mode bounds, visibility update, and zero-through-1000 particle
count clamp. These targets also sit in the expected obfuscated animation,
particle, and show-image class contexts.

The evidence is in
`artifacts/spectron_visual_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_visual_helper_anchors.py`. All 11 names
were applied to a copy of v25 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v26.i64`. The database SHA-256 is
`03ce132e9b5953523e6b01c13a1e4e4fa2a540b752127ef87e240a17e403d04d`. These
labels describe local visual state and do not establish live service
compatibility.

## Spectron GS2 script-runtime helper anchors

The v27 pass reviewed 12 compact GS2-facing script-runtime helpers. All source
and target bodies preserve their size, instruction count, basic-block count,
mnemonic hash, register-shape hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
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

IDA pseudocode confirms the same array and script-space fields, pause action
cleanup, timer and schedule forwarding, logging byte, linked-array traversal,
access-right copy, event masks, and conditional universe cleanup. The target
names stay in the obfuscated `G0gxgajWBw`, `N67CMatrxw`, and `e4ZYfa8PV2`
class contexts.

The evidence is in
`artifacts/spectron_script_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_runtime_anchors.py`. All 12 names
were applied to a copy of v26 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v27.i64`. The database SHA-256 is
`4c50294949544e27105f6ee457153dc6d06c5c83e25ce8e539ad64e4ca8d14dd`. These
labels describe local script-runtime behavior and do not establish live
service compatibility.

## Spectron core, world, and script helper anchors

The v28 pass reviewed 30 compact helpers that the broad semantic matcher left
out because they were short or had shape-equivalent lookalikes. The final
assignments use IDA pseudocode, field offsets, neighboring class context, and
exact normalized function hashes. Every source and target body preserves its
size, instruction count, basic-block count, mnemonic hash, register-shape
hash, and control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
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

The most useful additions for GS2 are the class-membership and event
predicates, variable cleanup, show-timer and logging fields, loop limit,
command records, class-filename result, stack-entry type switch, players-array
special case, and static-variable cleanup. The network-facing additions also
tie the old socket allow-list and update-package wrapper back to the native
startup path. The level and tile helpers fill in small but real world-state
operations rather than relying on nearby function names.

The evidence is in
`artifacts/spectron_core_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_core_helper_anchors.py`. All 30 names
were applied to a copy of v27 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v28.i64`. The database SHA-256 is
`fd2c58ef97d63f6d4cfa55ae0e0d4bbf3e57872ab5e0e079f6e777bfbb7b35e4`. These
labels describe local helper behavior and do not establish live service
compatibility.

## Spectron render and GUI helper anchors

The v29 pass reviewed 20 compact texture, OpenGL, drawing-panel, GUI-control,
markup, and scrolling helpers. Every source and target body preserves its size,
instruction count, basic-block count, mnemonic hash, register-shape hash, and
control-flow shape hash.

| 1.8 role | Source | Spectron target | Main evidence |
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
rectangle clearing, panel-operation field offsets, client-bound copy, cursor
booleans, priority bounds, scroll fields, selection state, flow extent, and
relative scroll calculation. The target default names remain where the target
was stripped, but each address is tied to the exact hashed library and target
class context.

The evidence is in
`artifacts/spectron_render_gui_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_render_gui_anchors.py`. All 20 names
were applied to a copy of v28 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v29.i64`. The database SHA-256 is
`2a1af1958e3bc50445a0057c57cbf537ce2a8e8f5c5dd0e28796813d406d944d`. These
labels describe local rendering and GUI behavior and do not establish live
service compatibility.

## Spectron image, folder, and JSON callback anchors

The v30 pass reviewed eight compact image-callback, folder-loader, and YAJL
JSON helpers. Three image callbacks have exact normalized bodies. The folder
loader and four JSON callbacks changed size in Spectron, so their identities
come from the surrounding class calls and the YAJL callback table.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TBitmap_GIF_streamRead` | `0x150a30` | `0x153570` | GIF stream forwarding |
| `TBitmap_JPEG_noopFlush` | `0x150ea0` | `0x153cc8` | JFFLUSH slot and zero return |
| `TBitmap_JPEG_noopError` | `0x150ea8` | `0x153cd0` | JFERROR slot and zero return |
| `TGraalVar_loadFolderRecursive` | `0x213088` | `0x219978` | recursive folder loader |
| `TGraalVar_jsonStringCallback` | `0x22dab4` | `0x237598` | YAJL string slot |
| `TGraalVar_jsonNumberCallback` | `0x22dbbc` | `0x23770c` | YAJL number slot |
| `TGraalVar_jsonStartArrayCallback` | `0x22de60` | `0x237c78` | YAJL start-array slot |
| `TGraalVar_jsonStartMapCallback` | `0x22e12c` | `0x2379bc` | YAJL start-map slot |

The GIF stream reader forwards user-data offset 104 to the stream read
method. The JPEG callbacks are the distinct zero-return helpers installed in
the flush and error slots by the corresponding writer and reader paths. The
folder helper preserves child creation, `filesize` and `isfolder` properties,
recursive descent, and the 9999-entry limit. The JSON callback set preserves
scalar writes, numeric conversion, parser-context markers, and object or array
node creation. Spectron's callback table at `0x39af70` places the string,
number, start-map, and start-array targets in their expected slots.

The evidence is in
`artifacts/spectron_json_folder_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_json_folder_anchors.py`. All eight names
were applied to a copy of v29 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v30.i64`. The database SHA-256 is
`f8ed0df56c8d17c244ce56751f4ec1c2e4a50d236b5fce5d3e060e46255fdb45`. These
labels describe local image, filesystem, and JSON behavior and do not
establish live service compatibility.

## Spectron resource-object anchors

The v31 pass reviewed 11 resource functions that the broad matcher could not
assign because Spectron rebuilt the surrounding string, zip, and stream
wrappers. Their identities are supported by class-local method order, caller
relationships, vtable or signature context, and the behavior visible in IDA
pseudocode.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TResourceFunctions_insertResourceObject_TResourceObject` | `0xed260` | `0xee230` | insertion and alternative selection |
| `resourceobjects_filenamecompare_void_const_void_const` | `0xef030` | `0xf0244` | extension, name, and modtime ordering |
| `TResourceFileLink_TResourceFileLink_TString_const` | `0xef184` | `0xf03ec` | link construction and registration |
| `TResourceFileLink_invokeUpdate_TString_const` | `0xef270` | `0xf04f4` | reverse update dispatch |
| `TResourceObjectLink_TResourceObjectLink_void` | `0xef428` | `0xf06d8` | object-link construction |
| `TEncodedFileKey_TEncodedFileKey_TString_const` | `0xef5a0` | `0xf086c` | encoded-key initialization |
| `TResourceObject_TResourceObject_TString_const` | `0xef610` | `0xf0904` | resource-object initialization |
| `TResourceObject_getSize_void` | `0xef7ec` | `0xf0b08` | cached or filesystem size |
| `TResourceObject_addAlternative_TResourceObject` | `0xefbc4` | `0xf0f1c` | alternative preference and sorting |
| `TResourceObject_getStream_void` | `0xefe7c` | `0xf11f0` | zip, cache, and decryption paths |
| `TResourceObject_canBeLoaded_void` | `0xf03a0` | `0xf1860` | download readiness predicate |

The comparator still orders by extension, filename, and modification time.
The link constructors still register their list containers. The resource
object methods retain cached-size lookup, alternative selection, zip entry
reading, `.gani` and encoded-resource decryption, and download-state checks.
The target functions are larger in several cases, so these are semantic
anchors rather than byte-identical matches.

The evidence is in
`artifacts/spectron_resource_object_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_resource_object_anchors.py`. All 11 names
were applied to a copy of v30 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v33.i64`. The database SHA-256 is
`69323a7d78797eaa916e13489ba56e3836c6c9c90c1b15ec6cc2589ae828afba`.
Simple constructor and destructor families with multiple identical candidates
remain unassigned.

## Spectron GS2 script-machine anchors

The v34 pass reviewed seven functions from the GS2 execution machine. These
were not safe broad-map matches because Spectron changed the class names and
expanded several bodies, but the target sequence, method signatures, and
pseudocode preserve the old roles.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_TScriptMachine` destructor | `0x21886c` | `0x21ff78` | owned-list cleanup and machine-count decrement |
| `TScriptMachine_TScriptMachine_void` | `0x218a3c` | `0x220150` | stack, list, and parameter initialization |
| `TScriptMachine_setExecutingObject_TGraalVar_TString_const_TScriptMachine` | `0x218b8c` | `0x2202a4` | script name and active-object state |
| `TScriptMachine_resolveObjectMember_TGraalVar_TString_const_TScriptProperty_TGraalVar_bool` | `0x218e98` | `0x2205c4` | GS2 aliases and property resolution |
| `TScriptMachine_assign_void` | `0x21a3b0` | `0x221ef8` | typed property and variable writes |
| `TScriptMachine_compare_void` | `0x21a6a8` | `0x222218` | string, numeric, and object comparisons |
| `TScriptMachine_compareFloat_double` | `0x21a8b0` | `0x2224e0` | tolerance-based double comparison |

The destructor row is a compiler-generated pair. IDA shows the 1.8 address
with its alternative D2 name, while the target has the corresponding D1/D2
signature family. The large resolver retains the special names `temp`,
`params`, `this`, `thiso`, `player`, `playero`, `level`, `join`, `leave`,
`serverr`, `client`, and `clientr`. Assignment and comparison retain the same
type-dependent virtual dispatch, with extra target instructions attributable
to changed string wrappers. The constructors and destructor are therefore
documented as semantic class anchors, not as recovered original symbols.

The evidence is in
`artifacts/spectron_script_machine_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_machine_anchors.py`. All seven
labels were applied to a copy of v33 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v34.i64`. The database SHA-256 is
`b082b63ff1be3ab1f1d029093b0a7907a62daaea6a136da406e6cb4c15ee2e49`.

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
