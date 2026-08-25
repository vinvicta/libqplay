# Symbol translation

## Result

The original ARM64 database was processed with `tools/ida_translate_symbols.py`.
The script reads the symbol names that survived in the ELF, demangles the C++
names where possible, classifies the result, and applies the names back into
IDA. The run was configured with renaming enabled and finished with:

```json
{
  "apply_renames": true,
  "data": 505,
  "functions": 4714,
  "jump_thunks": 199,
  "plt_thunks": 3183,
  "rename_failures": [],
  "renamed": 8601,
  "translated_symbols": 8601
}
```

The full exports are in `symbols/`. The CSV is convenient for grep, a
spreadsheet, or a quick address lookup. The JSON preserves the same records
with explicit fields.

The translation count is the number of ELF symbol records handled by the
script. IDA's function survey also reports compiler-generated functions and
other analysis-created entries, so its total function count is not expected
to equal 8,601. After the follow-up semantic pass, the original ARM64
database reports 11,272 total functions, 9,627 with names, and 1,645 default
`sub_` names. Those figures describe the IDA database; the 8,601 count
describes the reproducible symbol import and rename pass. The artifact contains
467 cumulative evidence-backed labels in `artifacts/ida_semantic_labels.json`.
The IDB also retains the earlier inferred
`TClient_setSSLParameters_scriptCallback` label outside that artifact. None of
these semantic labels is part of the 8,601 original ELF symbol records.

## Naming policy

The native names are kept close to their demangled ELF form. Characters that
are inconvenient in an IDA identifier are converted to underscores, while
the original mangled symbol remains in the export. PLT entries receive a
`plt_` prefix and jump thunks receive a `j_` prefix so that a thunk is not
mistaken for the implementation it reaches.

Examples:

| Native role | Applied alias | Address in ARM64 database |
| --- | --- | ---: |
| Connector mode selection | `TServerList_enterNextConnectorMode_int` | `0x203df4` |
| Connector login | `TServerList_login` | `0x204420` |
| Game-server connect | `TClient_connectToGameServer` | `0x1e7058` |
| HTTP request creation | `THTTPRequest_sendRequest` | `0x1ffde8` |
| Incoming packet dispatch | `TClient_parse` | `0x1e7cd0` |
| Encrypted level loader | `TServerLevel_LoadEncrypted_void` | `0x1aa198` |

The exact address and alias for every symbol are in the CSV. These names are
analysis labels, not an assertion that every demangled signature was manually
verified. The important connector and packet functions were checked against
cross-references and emulator traces.

Some important callbacks have no surviving ELF symbol. The IDA database now
labels the game-server SSL method at `0x1eb964` as
`TClient_setSSLParameters_scriptCallback`. The `scriptCallback` suffix marks
it as an inferred semantic name, not part of the original symbol import. Its
method-table reference and native behavior are documented in
`artifacts/game_server_tls.json`.

The same database now has evidence-backed names for the login callback,
server-list completion, file-download, and script-window helpers that IDA
originally displayed as `sub_` functions. Examples include
`TClient_handleServerLoginPacket`, `TClient_finishFileDownload`, and
`TGUIScriptLoader_finishServerListConnect`. These remain separate from the
imported symbol CSV because they are semantic labels, not ELF names. The
complete list and the evidence behind each label are in
`artifacts/ida_semantic_labels.json`.

The latest pass extends that coverage across the whole core `TClient` protocol
region, from `0x1e9000` through `0x1f3000`. It labels map entry, NPC creation
and removal, object and effect updates, encrypted-script dispatch, ping and
text handling, and the inbound and outbound handler bridges. A few wrappers
use exact offset-based names such as `TClient_setPlayerStateFlag2328` or
`TClient_getConnectionString8288`. That is deliberate. The instructions prove
the field offset or virtual slot, but they do not recover the original C++
member name. Keeping the uncertainty visible makes these aliases safer to use
in later patches. The current pass also covers the `TGraalConnection` and
`THTTPRequest` TLS or HTTP property bridge, `TSocket` policy and plain-I/O
helpers, and `TGaniObject` or `TGaniParam` field accessors. Those names use the
same offset-based convention where the binary proves a field but not its source
member name. It also covers the network-thread entry point and the
`TUpdatePackage` metadata, download-progress, and script-update wrappers. The
update-package labels use exact field offsets for the remaining undocumented
members.

## Complete function inventory

The symbol table and the IDA function list are different sets. The ELF has
8,601 surviving records, including 505 data records. Of those records, 8,096
land on IDA functions. IDA's analysis adds 11,272 function starts in total:

| Function source | Count |
| --- | ---: |
| Backed by a translated ELF symbol | 8,096 |
| IDA default `sub_` names | 1,645 |
| Named by IDA but not backed by an ELF record | 1,531 |
| Total IDA functions | 11,272 |

The complete address-level inventory is in
`symbols/libqplay.function_inventory.csv` and
`symbols/libqplay.function_inventory.json`. Every row records the IDA name,
address, segment, size, incoming-reference count, thunk and library flags,
and the matching original ELF symbol when one exists. The summary file records
the input hash and counts. This is the honest limit of the available evidence:
the remaining default `sub_` entries are real functions identified by IDA, but
the APK does not contain source names for them. They remain addressable and
searchable without being given guesses that could mislead later protocol work.
The semantic pass names only the small set whose behavior was clear enough to
document. The JNI window is now labeled by the Java method name where the
native call site contains an exact method string. This covers social, store,
URL, keyboard, and device-information bridges, plus
`JNI_setVideoPlayerRectangle` at `0x242df0`. Two string-cache setters at
`0x2401f4` and `0x240204` remain address-based `sub_` entries because their
caller contract is not yet recovered.

The sound script table is also partly recovered. The wrappers at
`0xe1e0c`, `0xe22e8`, `0xe24c4`, `0xe2858`, and `0xe2a7c` now carry
script-prefixed aliases for `play2`, `playlooped2`, `playlooped`,
`setsoundpitchbynote`, and `setsoundpitch`. The adjacent `0xe2008` wrapper is
labeled `TSounds_script_play` from its position in the play overload pair and
its action-NPC-centered behavior. The table names are encoded with the native
`THashList::encodesimple` transform, which is recorded in the research notes.

The environment tables now also expose the remaining script wrappers in this
region: `md5`, `adventure_quit`, the shared `googleplay` version helper, and
the OS, network, and system identification calls. These aliases preserve the
script-facing names with a `script` component so they are not confused with
the underlying C++ methods.

The input and level-object property tables provide another set of exact names.
The input table identifies the hardware-keyboard getter and setter. The control
binding table identifies the `action`, `keycode`, `keytext`, and `slot` getters.
The level-object table identifies the `level`, `x`, `y`, `z`, and `layer`
properties, including their coordinate clamping and vtable forwarding behavior.
The `z` getter was initially present as a code pointer without an IDA function
boundary, so the boundary at `0x169a08` was defined from the property table
reference before applying its label.

The `GuiControlProperties` constructor at `0x1b45c8` registers 55 properties
from the table at `0x3806a0`. That table accounts for the bounds, extent,
client size, clipping, profile, color, visibility, animation, sizing, and
position accessors now labeled in the IDA database. The companion function
table at `0x3810f0` registers 28 script functions. Eleven of its formerly
unnamed wrappers are now labeled, including coordinate conversion, control
lookup, resize, repaint, show or hide, and first-responder helpers. The
`minextent` and `minsize` properties intentionally share one getter and setter
pair, and the table's encoded `showhint` terminator is recorded as an encoding
artifact rather than treated as a different property name.

The file-scripting table at `0x376bd0`, installed by
`TFileScripting_initStaticScriptVars` at `0xfd1d0`, contains 27 script
functions. Twenty-two formerly unnamed callbacks now have exact
script-prefixed labels for script-access paths, file existence and size,
filename escaping, timestamps, folder enumeration, file content, default
viewers, deletion, and resource decompression. The wrappers distinguish
ordinary filesystem paths from packaged level resources, so this table is
useful when tracing startup resource lookup and updates.

A fallback disassembly pass also recovered the seven callback roles installed
by `TStream_fillZipFunctions` at `0xf0e98`: open, read, write, tell, seek,
close, and error. It also identified several compiler-generated static-state
helpers for `TFiles`, `TClient`, `TSocket`, `TServerFlying`, resource link
lists, the restart state, the `TDrawTexture::textures` list, `curanis`,
`TOptions::windowpos`, and `displayedgif`. The ELF relocation records tie the
latter four routines to their global objects. The adjacent sound wrappers also
cover `TSounds::isMusicPlaying` and the exported
`TSounds::soundoffscreendistance` getter and setter. A follow-up read of the
same registration block identified `TSounds_getMusicFilename` and the getter
and setter for `TSounds::disabledsoundeffects`. The proposed names are still
kept in
`artifacts/native_callback_candidates.json` as candidates, not counted among
the 467 applied labels, until the same names are written to IDA and included
in a fresh inventory export. The candidate plan now contains 25 entries.
The same sound table also contributes the short `stopsounds` and
`setmusicvolume` wrappers, bringing the candidate plan to 27 entries.

The server-level property and function tables are the next unapplied group.
`TServerLevelProperties::TServerLevelProperties` at `0x1a1128` registers six
properties from `0x37fce0`, and eighteen script functions from `0x37fe00`.
The property names decode to `height`, `isnopkzone`, `issparringzone`,
`nopkzone`, `tilelayercount`, and `width`. The function names decode to
`getmappartfile`, `findareanpcs`, `putbomb`, `putbomb2`, `putexplosion`,
`putexplosion2`, `reflectarrow`, `removearrow`, `removebomb`, `removeexplo`,
`removeitem`, `shoot`, `testbomb`, `testexplo`, `testitem`, `testsign`,
`testnpc`, and `tiletype`.

The callback bodies provide an unusually complete cross-check. The property
accessors read layer dimensions, zone flags, and the layer-list count. The
function wrappers call the exported `TServerLevel` methods for bombs,
explosions, projectiles, tiles, and collision tests, or delete entries from
the corresponding object lists. The `reflectarrow` record has the known
encoded-zero terminator anomaly, while the short names `removeexplo` and
`testexplo` are preserved exactly as stored by the client.

The twenty-four proposed names are kept separate in
`artifacts/native_callback_candidates.json`. They bring the review-only
native candidate set to 51 entries. The current IDA inventory and the 467
applied semantic labels remain unchanged until the bridge can accept and
verify the batch.

The player table is the next large group. Its constructor at `0x18b9bc`
registers 52 properties from `0x37ce00` and six script functions from
`0x37d7c0`. The names cover player identity, chat, inventory, image state,
coordinates, channel state, ratings, and external-message helpers. Four sets
of properties intentionally share native targets: `fullhearts` with `maxhp`,
`gralats` with `rupees`, `head` with `headimg`, and `hearts` with `hp`.
The candidate artifact records one name per native target and explains each
alias. The nickname getter is included, while the setter already has an ELF
name through the `TServerPlayer::setNick` jump.

The six player callbacks decode to `isguildpm`, `ismasspm`, `pmswaiting`,
`openexternalhistory`, `openexternalpm`, and `showprofile`. The pointer at
`0x18aa68` is present in the table but still lacks an IDA function boundary in
the saved inventory, so the application helper will report it for manual
boundary recovery. The 74 new candidates bring the review-only set to 125.

When the IDA bridge is available, run
`tools/ida_apply_native_callback_candidates.py` in review mode first. It
resolves the existing names, checks each expected function address, reports
missing or mismatched functions, and only writes the proposed names and
evidence comments when `APPLY_RENAMES` is explicitly enabled.

The inventory was generated from the active ARM64 database by
`tools/export_function_inventory.py`. It waits for auto-analysis, joins each
function start against the translated symbol export, and writes the result in
address order. Running it again against a different library revision should
produce a different input hash and must be kept as a separate export.

## Repeating the pass

Run the IDAPython script from IDA's Python console or with the IDA batch
runner. The input must be the same library revision used to build the IDB.
The script deliberately reports a byte or address mismatch instead of
silently applying names to a different build.

The generated summary should have `rename_failures` equal to an empty list.
If a future library revision produces a different count, keep its exports in
a separate directory and record the build identity in the accompanying
notes. Do not overwrite this table without preserving the old hash.
