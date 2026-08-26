# Symbol translation

## Result

The original ARM64 database was processed with `tools/ida_translate_symbols.py`.
The script reads the names that IDA exposes from the ELF, demangles the C++
names where possible, classifies the result, and applies readable aliases back
into IDA. The run was configured with renaming enabled and finished with:

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

The 8,601 figure is an applied alias inventory, not a claim that the APK
contains an unstripped debug symbol table. The original shared object is
reported as stripped and has no `.symtab` or DWARF sections. Its defined
dynamic symbol table contains 6,506 rows. The larger alias inventory includes
separate IDA-visible PLT, jump-thunk, and data aliases, which is why it should
not be compared directly with the dynamic row count. The complete correction
and command-level counts are in
`artifacts/elf_symbol_table_audit_20260826.json`.

IDA's function survey also reports compiler-generated functions and other
analysis-created entries, so its total function count is not expected to equal
8,601. The original pre-persistence inventory reports 11,272 total functions,
9,627 with names, and 1,645 default `sub_` names. Those figures describe the
original IDA snapshot; the 8,601 count describes the reproducible alias import
and rename pass. The artifact contains 467 cumulative evidence-backed labels
in `artifacts/ida_semantic_labels.json`.
The IDB also retains the earlier inferred
`TClient_setSSLParameters_scriptCallback` label outside that artifact. None of
these semantic labels is part of the 8,601 alias inventory rows.

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

## Complete pre-persistence function inventory

The symbol alias export and the IDA function list are different sets. The
alias export contains 8,601 rows, including 505 data aliases. Of those rows,
8,096 land on IDA functions. The APK itself contributes 6,506 defined dynamic
symbol rows, while the alias export keeps PLT and jump-thunk views separate and
includes analysis-visible data names. IDA's first analysis snapshot adds
11,272 function starts in total:

| Function source | Count |
| --- | ---: |
| Backed by a translated alias row | 8,096 |
| IDA default `sub_` names | 1,645 |
| Named by IDA but not backed by an ELF record | 1,531 |
| Total IDA functions | 11,272 |

The complete address-level inventory for that first snapshot is in
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

The later persisted copy is documented separately in
`docs/IDA_RESIDUALS.md`. It contains 11,297 function starts after the
`.eh_frame` callback boundaries were created and leaves 459 default names.
The saved-copy hash and the close-and-reopen verification are in
`artifacts/ida_translation_validation.json`; the exact residual list is in
`artifacts/ida_residual_profile.json`.

To make the handoff from the user's desktop session explicit, I also copied
the exact active snapshot before applying the same pass. Its source database
had SHA-256
`56da88101fe904ca298dcadf31e90433a69c43818c681ccb72364c66ac99eaa4`.
The translated local copy is
`/home/v/Desktop/graal-decomp/analysis/libqplay_translated_from_active.i64`.
A clean IDA 9.3 save and a separate reopen verified all 1,211 names, 11,297
function starts, and 459 remaining default names. The copy is intentionally
local and ignored by the public repository. Its SHA-256 after the final
reopen was
`1b72e100a755939c973ff1c4dcba2c8a9915a454f5f89c4c5d781bd74add421e`.
IDA may update database metadata when that file is opened again, so the hash
is an audit checkpoint rather than a content-addressed release identifier.

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
`artifacts/native_callback_candidates.json` as a review artifact, not counted
among the 467 imported semantic labels. The native callback and script-table
passes were later written to the persisted disposable copy and verified there
with a fresh inventory export. The active desktop database was not changed.
The candidate plan at this stage contained 25 entries.
The same sound table also contributes the short `stopsounds` and
`setmusicvolume` wrappers, bringing the candidate plan to 27 entries.

The server-level property and function tables were the next group in the
review queue.
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
the corresponding object lists. The raw `reflectarrow` record contains the
known encoded-zero sentinel, which `THashList::codesimplefix0` now repairs.
The short names `removeexplo` and `testexplo` are preserved exactly as stored
by the client.

The twenty-four proposed names are kept separate in
`artifacts/native_callback_candidates.json`. They brought the review native
candidate set to 51 entries. The current active IDA inventory and the 467
imported semantic labels remained unchanged until the bridge could accept and
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
`0x18aa68` was present in the table but lacked an IDA function boundary in the
saved inventory, so the application helper reported it for manual boundary
recovery. The 74 new candidates brought the review set to 125.

The NPC constructor at `0x183c18` adds 26 properties from `0x37be28` and 57
script callbacks from `0x37c308`. Their names cover the NPC's health, image,
layer, collision, pelt, weapon, visibility, movement, carry, drawing,
projectile, and show or hide behavior. The property table shares its hearts
and HP accessors, and its image and sprite targets include two inherited ELF
jumps that are already named. Four callback pointers, at `0x180e50`,
`0x18402c`, `0x181d58`, and `0x1a4e98`, needed IDA function boundaries. The
remaining 37 property targets and all 57 script targets are recorded in
`artifacts/native_callback_candidates.json` under the two NPC groups.

Several NPC records, including `peltwithbush`, `peltwithsign`, `peltwithvase`,
`canbecarried`, and `showtext`, contain the old encoded-zero sentinel. The
decoder repairs those bytes, while table position and callback context provide
additional cross-checks for the spellings.
The 94 new NPC candidates brought the review set to 219.

The smaller server-object constructors provide another compact set of exact
table-backed names. `TServerWeaponProperties` at `0x190ca4` registers
`isweapon` from `0x37d8e0`. The bomb, explosion, chest, extra, flying-object,
and sign constructors register their tables at `0x38b058`, `0x38afc8`,
`0x38b0e8`, `0x38b148`, `0x38b1a8`, and `0x38b298`. Those records recover
`power`, `time`, `image`, `dir`, `isopen`, `item`, `type`, `dx`, `dy`, `from`,
and `text`, with the class prefix retained in each proposed native name.

`TServerCarryProperties` at `0x23d694` and `TServerLeapProperties` at
`0x23fde8` do not call `TScriptProperty::addProps` and are recorded as
metadata-only constructors. The seven new candidate groups add 23 unique
native targets, raising the review set from 219 to 242. They were later
applied and verified in the persisted disposable copy; the applier remains
review-only for other IDA databases.

The projectile table at `0x37f6d8` contributes ten read-only names, including
`x`, `y`, `z`, `angle`, `speed`, `zspeed`, `fromplayer`, `fromplayerid`, and
`params`. The level-link table at `0x37f9b0` contributes seven read-only names:
`destlevel`, `destx`, `desty`, `height`, `width`, `x`, and `y`. Their
constructors are `TProjectileProperties` at `0x19ecac` and
`TServerLevelLinkProperties` at `0x1a0494`.

`TTilesLayerProperties` at `0x1a0df4` registers nine properties from
`0x37fb00` and one function from `0x37fcb0`. The function name is
`updateboard`; eight properties have setters and `layerindex` is read-only.
These three groups add 35 unique targets, raising the review set to 277. They
were later applied and verified in the persisted disposable copy; the applier
remains review-only for other IDA databases.

The complete registration scan is in `artifacts/script_table_inventory.json`.
The scan finds 70 property tables and 62 function tables through direct calls to the
two imported `TScriptProperty` registration stubs. The tables contain 678
property records and 776 static function records, plus one dynamic Android
registration slot. The records resolve to 1,779 unique callback targets.

The inventory distinguishes 411 names already present in the semantic-label
artifact, 258 in the curated callback candidate artifact, 204 existing
non-default IDA names, 886 exact new names with saved function boundaries, and
20 exact pointers without saved boundaries. The decoder models the old
zero-byte encoding behavior, so all 1,454 static record names are recovered
exactly. The remaining declared slot is the dynamic Android registration path.
The exact bounded set has a review-only IDA applier in
`tools/ida_apply_script_table_inventory.py`; it is not enabled while the IDA
bridge is unavailable. Each missing boundary has a matching ELF `.eh_frame`
range, and `tools/ida_apply_script_table_boundaries.py` provides a separate
review-only boundary and rename pass for those 20 callbacks.

The four apply passes were then run together in IDA 9.3 IDALIB against a
disposable copy of the database. All 277 native callback candidates, 886
bounded script-table names, 20 FDE-backed script callbacks, and 28 unresolved
application or engine roles resolved at the expected addresses with zero
failures. Five native callback ranges and all twenty script-table ranges were
created from ELF unwind evidence. Two of the latter required shortening a
larger saved IDA function at the exact FDE start before adding the callback.
This first established the names and ranges in memory. A follow-up IDALIB
run saved the disposable database as a packed IDA 9.3 copy, and a separate
read-only process reopened it and found every one of the 1,211 expected names
at the expected address. The final copy contains 11,297 function starts and
459 remaining default `sub_` names. The active desktop IDA database was still
locked and was not changed. The result and saved-copy hash are recorded in
`artifacts/ida_translation_validation.json`.

Exporting the saved copy also gives a useful final coverage snapshot: 8,096
functions are backed by ELF records, 2,742 have non-default IDA names from
the semantic and callback passes, and 459 remain default `sub_` entries. The
private exported inventory is not committed, but its hash and counts are
recorded with the persisted database metadata.

The original saved function inventory has 1,645 IDA-created default `sub_`
functions. `artifacts/symbol_translation_overlay.json` maps 886 of them to exact
script-table names and 271 to curated callback candidates, leaving 488
untranslated entries as an explicit work list. The overlay is generated by
`tools/generate_symbol_translation_overlay.py` and does not claim that any
names were written to IDA.

The unresolved list has now been profiled by region in
`artifacts/unresolved_function_profile.json`. Of the 488 entries, 335 sit in
gaps inside recognizable static library families: 150 in libjpeg, 144 in
FreeType, 14 in zlib, 11 in CyaSSL or its bundled crypto, 4 in GPC, 4 in
bzip2, 3 in GIF support, 2 in YAJL, 1 in the shared LibTomCrypt DES core, and
2 in minizip helpers. The fourth GPC entry is the small helper at `0xe01a0`,
outside the main contiguous GPC gap, which is called by `gpc_tristrip_clip`
and formats the library's `gpc malloc failure` diagnostic for tristrip node
creation. The extra bzip2 entry at `0xe02ac` is an unrolled comparison helper
called by the bundled decoder. The extra JPEG entry at `0xe0454` is called by
the marker parser and decodes image state. Another 19 are addresses referenced by
the ELF `.init_array` or `.fini_array`. Another 104 are compiler-generated
static cleanup wrappers. Their fixed global-object address and tail target
make the family unambiguous: 97 call `TString::clear`, 5 call
`TStringList::~TStringList`, and 2 call `TGraalVar::~TGraalVar`. These wrappers
do not have an independent source body to recover. One entry is a
four-byte compiler-generated branch veneer to the exact
`TCachedStream_get_minfilecachesize` callback at `0x1fa4fc`, and is not an
independent source function. One more entry is the 20-byte AArch64 PLT
resolver slot. The pre-persistence profile therefore leaves 28 application or
engine entries without a safe source-name recovery. Those 28 now have
high-confidence behavior-based role aliases in the persisted copy. IDA also
reclassified the branch veneer as a named thunk while rebuilding that copy,
leaving 459 default functions. The final address-level accounting is in
`docs/IDA_RESIDUALS.md` and `artifacts/ida_residual_profile.json`.

The profile records the address and size of every original unresolved entry,
but deliberately does not turn library-region membership into guessed source
names. This keeps the complete symbol translation separate from the harder
problem of naming compiler-created or static functions whose original names
were never stored in the APK.

`tools/generate_unresolved_function_profile.py` rebuilds this pre-persistence
report from the saved inventory, overlay, symbol export, and ELF section data.
It is a triage aid, not an IDA rename script. The final 459-entry persisted
copy report is generated by `tools/generate_ida_residual_profile.py` and
described in `docs/IDA_RESIDUALS.md`.

A separate role-candidate artifact records 28 behavior-based aliases. The
original four cover the profiler helpers at `0xf9028`, `0xf9060`, and
`0xf9944`, plus the recursive worker at `0x213088` immediately before
`TGraalVar::loadFolder`. Thirteen more cover TBitmap GIF and JPEG stream
callbacks, the generated animation lexer fatal path, three TServerLevel
spatial-query predicates, a player draw-list predicate, a scroll-control
property resolver, and the actionnpc or activeplayer script-object resolver.
The final eleven cover the flex-style animation previous-state helper, a
generic draw-distance comparator, and the nine YAJL callbacks used by
`TGraalVar::readJSON`. All 28 candidates are now high-confidence role
assignments. IDA evidence ties the comparator at `0x20ac18` to both
`getnearestplayers` and `findnearestplayers`, which sort the runtime universe
list before returning their results. These aliases are analysis roles, not
recovered ELF names, and are not included in the applied semantic-label count.
The generator verifies that the role list covers all 28 entries in the
application or engine queue, with no missing or extra addresses.
The roles were applied and verified in the persisted disposable copy; the
candidate artifact remains review-only for the locked desktop database.
`tools/generate_unresolved_function_candidates.py` rebuilds the artifact and
`tools/ida_apply_unresolved_function_candidates.py` keeps the IDA step
review-only.

For a quick consistency check across the published summaries, run
`python3 tools/validate_research_archive.py`. It confirms that the artifacts
refer to the same ARM64 input hash, that the function and callback partitions
still add up, and that the role candidates cover the full 28-entry application
or engine queue. It is offline and does not require IDA.

When the IDA bridge is available, run
`tools/ida_apply_native_callback_candidates.py` in review mode first. It
resolves the existing names, checks each expected function address, reports
missing or mismatched functions, and only writes the proposed names and
evidence comments when `APPLY_RENAMES` is explicitly enabled.

For the complete pass, `tools/ida_apply_all_translations.py` runs the four
appliers in one session. Its two switches are both false by default. Set
`APPLY_BOUNDARIES = True` and `APPLY_RENAMES = True` only after reviewing the
reports. The boundary switch is required for the five native FDE ranges and
the twenty script-table ranges, including the two intentional function splits.

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
