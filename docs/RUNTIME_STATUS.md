# Runtime status

This is the short handoff view. The full reasoning and command history are in
`RESEARCH_NOTES.md`.

## Verified locally

1. The original APK launches on the Android 36 x86_64 emulator after the
   compatibility warning is dismissed.
2. The native library initializes OpenGL and starts the connector path.
3. The connector request shape is known, including the `p=` query, the
   legacy HTTP/1.0 headers, and the three fallback modes.
4. The archived connector body has valid framing and decrypts to a valid
   three-entry ZIP. Its RSA signature passes the native wolfSSL raw-digest
   check against the embedded public key. The first replay used an explicit
   RSA bypass because the original offline checker used the wrong signature
   format; a package-preserving replay should leave that branch unchanged.
5. The response parser lowercases header lines before matching them. Local
   replay variants with lowercase or title-case names, and with either
   `Connection: keep-alive` or `Connection: close`, all reached the game
   responder. A no-`Content-Length` variant also worked when the local
   responder half-closed the response after the body.
6. The repaired x86_64 client completes the NewGraal `fd` and `fc` exchange,
   receives an encrypted login-success packet, and logs `Connected.`.
7. Packet 178 causes the expected server-warp transition and a second game
   connection. Packet 48 is a trigger-action path in this client table.
8. On the second connection, packets 9, 190, and 49 lead to requests for
   `classiciphone.gmap`, three `.code` level containers, and `pics1.png`.
   The responder returns each file through packet 102 and the client sends the
   normal heartbeat packets.
9. The x86_64 diagnostic build renders the level tile field and the game HUD.
   This proves the map, player-property, level-container, image, and renderer
   paths can all run in a controlled local test with that native library. It
   is not a stock loading-state result because several historical x86 test
   APKs used a loading-getter override.
10. The original no-swap handler table routes packet 190 to the native
    connecting-window completion wrapper. The rendered world remains visible
    without the centered connecting control.
11. The symbol translation pass applied 8,601 names to the ARM64 IDA database
    with zero rename failures.
12. An ARM64-only diagnostic build running through the x86_64 emulator's native
    translation layer completes the connector, server warp, encrypted login,
    map, three level-file requests, image request, and heartbeat path. The
    expected map, level, and image files appear in the external cache.
13. A one-instruction ARM64 diagnostic candidate forces the existing
    non-premium initialization branch at `0x15ca7c`. With the exact `.gmap`
    fixture, the normal render loop displays the tiled world, player HUD, and
    status icons through the translated ARM64 draw path.
14. A separate render-boundary diagnostic clears the loading byte only after
    timer and packet processing. It produces the same visible result and
    remains available as a control for the initialization candidate.
15. The supplied conpack tool now produces a client-compatible legacy ZIP
    when its four header fields are matched to the archived package. The
    original connector bytecode survives repack and reaches the same local
    two-connection game replay.
16. Raw HexaParser output is parseable and packable, but its same-line brace
    literals are reversed relative to the native-order reconstruction. In a
    two-port negative control it opened three connections to the alternate
    `14896` listener and none to the expected `14900` listener.
17. `tools/reverse_hexaparser_literals.py` restores the observed literal
    order in the recovered source for static comparison, but a clean replay
    of its compiler output did not reach the expected `14900` listener under
    the same native library, Kahn test signer, TLS fixture, and game responder.
    The adapted stream has 3,582 instructions after its trailing byte is
    removed, compared with 3,143 in the original. The earlier adapted
    screenshot claim is not treated as current runtime evidence.
18. A full-asset, ARM64-only debug APK built from the original 1.8 package and
    the five-step diagnostic chain was installed on the x86_64 emulator. Its
    APK SHA-256 is
    `b1c52234b10fb5a4a2c6c58e85370ccab710b1c355574d295df30b5ed6edddcc`, and
    its packaged ARM64 `libqplay.so` SHA-256 is
    `89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858`.
    Android logged Berberis loading the ARM64 process and `qplay` reached
    OpenGL initialization. The private responder observed the connector
    request, two game connections, encrypted login, the map, three level
    files, `pics1.png`, and continuing heartbeat packets. The captured screen
    reached the tiled world and HUD. The screenshot SHA-256 is
    `fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
    This is a local translated-ARM64 result, not a release APK or a physical
    ARM64-device result.
19. A fresh run of the same ARM64 loading candidate was repeated on a clean
    app-data directory after the configured Android 36 emulator was started
    without wiping its device state. Android loaded the ARM64-only package
    through translation, the local connector responder saw one `/con.png`
    request, and the game responder saw two `14900` connections. Both
    connections completed the `fd`/`fc` exchange and encrypted login result;
    the client then requested `basepackage.gupd`. The bounded responder did
    not return a base package or map, so the screen ended on the stock
    disconnect artwork. The package, native library, captures, and screenshot
    hashes are in `artifacts/arm64_loopback_handshake_replay.json`.
19. The corrected offline parser reproduces the native raw-digest RSA check.
    The saved connector response passes with the embedded key, so the RSA
    bypass used by the first replay is not required for that fixture.
20. A private package-preserving x86_64 candidate was built with the original
    RSA bytes, the certificate diagnostic, loopback transport patches, and the
    fixed local handshake key. Its APK SHA-256 is
    `e794a8c096de46d14e2a98142fd8082c003d4b05e30fd9735e187c365d8e86ab`.
    It remains a private candidate and has not been rerun in this continuation.
21. A matching ARM64-only package-preserving candidate was also built with
    the loading-state candidate. Its APK SHA-256 is
    `dad598e0cec03b501ff8cc30648ad843346fa3a331db3087ffa54ff92938af3a`,
    and its native SHA-256 is
    `888a236bb839eef7ab094196b924796680d23d857a0d7533487bcd3786efb308`.
    Its original RSA branch bytes are `dc 00 00 35`. After clearing only the
    emulator app data, this candidate made a fresh connector request, opened
    two game connections, received the map, three level files, `pics1.png`,
    and continuing heartbeats, then rendered the same world and HUD. Its
    screenshot SHA-256 is
    `fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
    The native RSA bypass was not used. This remains a translated-ARM64
    loopback result, not a physical-device or live-service result.
22. The trust-bundle replacement tool was checked against the original ARM64,
    armeabi, x86, and x86_64 libraries. A one-certificate standard PEM bundle
    encoded at each architecture-specific offset and decoded byte-for-byte.
    These checks were offline and did not establish compatibility with a live
    endpoint.
23. The IDA audit of the nonblocking connector path confirms that status 4
    `EINPROGRESS` completion reaches `TSocketConnection_setStatus_int` with
    status 5, which starts CyaSSL when SSL is enabled. The earlier blocking-I/O
    experiment remains rejected because it froze the renderer.
24. The decoded connector script carries a second TLS configuration for the
    game server. Its `setSSLParameters` certificate is a 718-byte DER object
    with SHA-256
    `2e6425395e91baab7be95d9918de198684bcb718800bff07113e7f336d06ce56`, the
    same expired Eurocenter Games certificate as connector trust-bundle entry
    0. The native callback uses `NakFpz15` and enables `RC4-SHA` with
    `SSLv23`; this is documented offline in `artifacts/game_server_tls.json`.
25. The offline encoder
    `tools/encode_game_server_tls_certificate.py` prepares a replacement for
    script string 143, rejects private-key or multi-certificate PEM input, and
    reproduces the original literal byte-for-byte when fed the recovered
    certificate. It does not disable verification or contact a network.
26. The source-level helper
    `tools/replace_game_server_tls_source.py` finds both recovered
    `setSSLParameters` certificate calls, validates their existing DER values,
    and writes a separate GS2 source file. Feeding it the recovered
    certificate gives an identity source and the same 16,141-byte compiled
    bytecode. A 1,072-character offline test certificate also compiles to
    16,253 bytes. These are compiler and transform checks only.
27. A private ARM64-only package retained the native connector RSA branch,
    replaced the historical trust bundle with a SAN-matching local certificate,
    routed the hostname to loopback, and moved only the HTTPS port to `18443`
    for ADB reverse. Native TLS delivered the 16,446-byte connector fixture.
    The same package then made two encrypted game connections, requested the
    map, three level containers, and `pics1.png`, continued heartbeats, and
    rendered the tiled world and HUD through Berberis. Its APK SHA-256 is
    `2984a6d4b7698a2ab444166265939a75a61c43b679dfd87b0d7a063bf7fd0759`, its
    final native SHA-256 is
    `22a0fd4801f71f29f7c53a7ba77f0c4db669a83fc1ae5a5f53e3ce9b95f33e9a`, and
    its screenshot matches the earlier replay at
    `fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
    The responder was loopback-only and no live service was contacted.
28. The recovered GS2 source was checked for the separate game-server TLS
    literal. The Classic branch sets `usessl` to false, the NewGraal login
    function guards `setSSLParameters` with that flag, and a final assignment
    also clears it. The stale `NakFpz15` certificate is therefore not active
    in the main Classic login path, although it remains relevant to other
    legacy modes or modified scripts.
29. `tools/patch_connector_bytecode_loading_clear.py` inserts the original
    VM's six-byte `loadingscreenenabled = false` sequence into `onServerLogin`
    immediately before the reconnection reset. The patched stream grows from
    15,581 to 15,587 bytes and from 3,143 to 3,146 instructions. A Kahn-signed
    package using the same private ARM64 native library made one connector TLS
    request, two `14900` game connections, completed encrypted login, received
    `classiciphone.gmap` and three level files, and continued heartbeat traffic.
    The title/loading artwork remained in the bounded screenshot, so this
    proves script loading and protocol/resource progress, not a final visible
    world transition. Hashes and scope are in
    `artifacts/bytecode_loading_clear_replay.json`.
30. The direct script patch was then combined with the existing native
    non-premium branch candidate at `0x15ca7c`. The private translated-ARM64
    run again made two `14900` connections, received the map and three level
    files, and sent heartbeats. This time the renderer displayed the green
    world field, HUD, and status icons. The native library SHA-256 is
    `8f7b343d81a1cd8eef390d0a494912f86ab03f7a22f4fe4a2f2bb170409d6722`, the
    APK SHA-256 is
    `57e6987a920b261c9a6b9abeb909cd4156c4995bb4dd6930422b87a27adc3dde`, and
    the screenshot SHA-256 is
    `fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
    Because two changes are present, this confirms compatibility of the
    direct script patch but leaves the native branch as the variable tied to
    the visual transition.
31. The IDA ownership audit is now captured in
    `artifacts/loading_state_ownership.json`. It lists the three native getter
    call sites, the two post-startup setter paths, the `sigcheck` clear, the
    render-loop branch, and packet-190's no-write behavior. The active IDB has
    matching comments at those addresses.
32. The latest file-scripting checkpoint added 22 labels from the table at
    `0x376bd0`, installed by `TFileScripting_initStaticScriptVars` at
    `0xfd1d0`. The cumulative semantic-label artifact now contains 467 entries,
    while the complete IDA inventory remains 11,272 functions. The next zlib
    and static-state names are recorded separately as un-applied candidates.
33. An offline ARM64 disassembly pass tied four more static initializers to
    ELF relocation targets: `TDrawTexture::textures`, `curanis`,
    `TOptions::windowpos`, and `displayedgif`. The proposed names remain
    unapplied until the IDA bridge returns, so the public inventory and the
    applied-label count are unchanged.
34. The same offline pass recovered three sound wrappers at `0xe0af8`,
    `0xe0bf8`, and `0xe0c08`. Vtable relocations identify the first as
    `TSounds_isMusicPlaying`; the other two access the exported
    `TSounds::soundoffscreendistance` global.
35. A follow-up relocation check corrected the next table interpretation.
    `0xe0c18` uses the `TSounds::soundplayer` slot at `0x3757e0` and matches
    `getmusicfilename`. The property pair at `0xe0c84` and `0xe0c70` uses
    `TSounds::disabledsoundeffects` through slot `0x374cb0` and calls the
    comma-text getter and setter. These three names are recorded as unapplied
    candidates. The same table supplies `stopsounds` at `0xe0fa8` and
    `setmusicvolume` at `0xe1350`; their wrappers forward to the exported
    sound methods. The expanded plan now contains 27 entries. No live endpoint was
    contacted.
36. A held-connection replay on 2026-08-25 repeated the ARM64 test with the
    local cached map and package files copied into a private fixture root. The
    map was served under `classiciphone.gmap`, and three matching encrypted
    containers were generated from the local `black.nw-14900.code` fixture for
    `main_aa-02.nw`, `main_ab-01.nw`, and `main_ab-02.nw`. The ARM64-only APK
    completed two encrypted game connections, accepted the map, package
    metadata, tile sheet, and all three containers, and kept sending packet-24
    heartbeats. The screenshot was taken while the second socket was still
    open. It shows the green tiled world, player HUD, and status icons. The
    screenshot hash is
    `fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
    Packet and fixture hashes are recorded in
    `artifacts/arm64_local_fixture_render_replay.json`. The fixtures are local
    compatibility inputs, not a claim about the live server revision.
37. The latest offline symbol pass recovered the six `TServerLevel` property
    accessors and eighteen server-level script wrappers registered from
    `0x37fce0` and `0x37fe00`. Their names decode to level dimensions, zone
    flags, map-part lookup, NPC queries, bomb and explosion operations,
    projectile shooting, collision tests, and tile lookup. The callback bodies
    reach the matching exported `TServerLevel` methods or object lists. The
    names are recorded as unapplied candidates, raising the review-only native
    set from 27 to 51 entries. The IDA bridge timed out again, so no IDB names
    were changed and no endpoint was contacted.
38. The next table audit covered `TServerPlayerProperties` at `0x18b9bc`.
    It registered 52 properties and six script functions from `0x37ce00` and
    `0x37d7c0`. Shared getter and setter targets were deduplicated, the
    existing `TServerPlayer::setNick` ELF jump was left alone, and the one
    callback without an IDA function boundary at `0x18aa68` was retained with
    a review note. The unapplied candidate set now contains 125 unique native
    addresses. No endpoint was contacted.
39. The NPC constructor at `0x183c18` was audited next. Its 26 properties and
    57 script functions are registered from `0x37be28` and `0x37c308`. Four
    callback pointers lack saved IDA function boundaries, and two inherited
    ELF jump targets were left unchanged. The remaining 94 unique native
    targets are recorded as unapplied candidates, raising the review-only set
    to 219. No endpoint was contacted.
40. The compact server-object property constructors were audited offline.
    Weapon, bomb, explosion, chest, extra, flying-object, and sign tables add
    23 unique getter or setter targets, raising the review-only candidate set
    to 242. Carry and leap constructors initialize metadata only and do not
    register script properties in this build. No IDA names changed and no
    endpoint was contacted.
41. The projectile, level-link, and tile-layer tables were audited offline.
    They add 35 unique targets, including 10 projectile properties, 7
    level-link properties, 17 tile-layer getter or setter targets, and the
    `updateboard` callback. The review-only candidate set now contains 277
    entries. No IDA names changed and no endpoint was contacted.
42. A complete offline scan of direct `TScriptProperty::addProps` and
    `addFuncs` calls found 70 property tables and 62 function tables. Their
    1,455 declared records, comprising 1,454 static records and one dynamic
    Android registration slot, resolve to 1,779 unique callback targets. The map
    identifies 886 exact new names with saved boundaries and 20 exact
    pointers without boundaries. The native zero-byte repair is modeled, so
    all 1,454 static record names are exact. No IDA names changed and no
    endpoint was contacted. Each of the 20 pointers also has an ELF `.eh_frame` range;
    `tools/ida_apply_script_table_boundaries.py` keeps those boundary changes
    separate from the ordinary rename pass.
43. The translation overlay accounts for 886 of the saved default `sub_`
    functions through exact table names and another 271 through curated
    callback evidence. The remaining 488 default functions stay explicitly
    unresolved. No speculative names were added and no endpoint was
    contacted.
44. The unresolved-function profile separates those 488 default entries into
    335 likely static third-party functions, 104 compiler-generated cleanup
    wrappers, 19 ELF init/fini entries, one compiler branch veneer, one PLT
    resolver slot, and 28 application or engine entries. The cleanup wrappers
    have proven tail targets: 97 call `TString::clear`, 5 call
    `TStringList::~TStringList`, and 2 call `TGraalVar::~TGraalVar`. The GPC
    count includes `0xe01a0`, which is called by `gpc_tristrip_clip` and
    formats the library's `gpc malloc failure` diagnostic. The bzip2 and JPEG
    families now also include the isolated helpers at `0xe02ac` and `0xe0454`.
    The branch veneer at `0x1f94fc` targets the exact
    `TCachedStream_get_minfilecachesize` callback at `0x1fa4fc`. The report
    also identifies the shared DES core at `0x246b50` and two minizip helpers
    at `0x24840c` and `0x249580` from their exported callers. These are triage
    categories only. No speculative source names were added and no endpoint
    was contacted.
45. A follow-up offline disassembly pass produced seventeen high-confidence
    review-only role candidates. The first four are at `0xf9028`, `0xf9060`,
    `0xf9944`, and `0x213088`, covering the profiler comparator, function-tree
    formatter, profiler reset recursion, and recursive `TGraalVar::loadFolder`
    worker. Thirteen more cover the TBitmap GIF and JPEG callbacks, animation
    lexer fatal handling, TServerLevel spatial predicates, the player draw-list
    predicate, the scroll-control property resolver, and the script-object
    resolver. The candidate artifact does not claim that these aliases exist in
    the ELF, and no IDA names changed or endpoint was contacted.
46. A final structural pass added eleven more role candidates, bringing the
    review-only role artifact to 28 entries. The new entries cover the flex-style
    animation previous-state helper at `0xe01d0`, the generic draw-distance
    comparator at `0x20ac18`, and the nine YAJL callbacks installed at
    `0x387e20` for `TGraalVar::readJSON`. Twenty-seven candidates are marked
    high-confidence; the comparator is medium-confidence because its class
    owner and direct call site remain unresolved. No IDA names changed and no
    endpoint was contacted. The generator also verifies that those 28 roles
    cover every entry in the application or engine profile category.
47. The four naming passes were exercised together in IDA 9.3 IDALIB against a
    disposable copy. All 277 native candidates, 886 bounded script-table
    names, 20 FDE-backed script callbacks, and 28 application or engine roles
    resolved with zero failures. The run added 25 function starts and split
    two previously merged ranges at exact FDE starts. The active desktop IDA
    database remained locked and was not overwritten. IDALIB then saved the
    disposable copy and a separate read-only reopen verified all 1,211 names,
    11,297 function starts, and 459 remaining default `sub_` entries. The
    result and saved-copy hash are in
    `artifacts/ida_translation_validation.json`.
48. A clean 2026-08-25 revalidation used the packaged ARM64-only diagnostic
    APK from fresh app data. After the Android compatibility warning was
    dismissed, the connector responder saw one request and the game responder
    saw two connections. The client completed encrypted login, accepted the
    map, three generated level containers, and the tile sheet, then continued
    heartbeat traffic. The screenshot again showed the green tiled world,
    player HUD, and status icons. The minimal responder also needed a local
    GUI image copied under the requested `guigames_graymessage2.png` name;
    that placeholder and all raw fixtures stayed outside the repository. The
    package, capture, fixture, and screenshot hashes are in
    `artifacts/arm64_diagnostic_apk_revalidation_20260825.json`.

## Not verified

* A live game-server login.
* That the current live connector still accepts the 2019 client query.
* That the current server's certificate and package-signing chain can be
  replaced safely without changing protocol behavior.
* ARM64 runtime behavior on a real ARM64 device, especially renderer entry.
* Whether forcing the non-premium branch is the intended production state
  transition on a physical ARM64 device. The embedded marker statically
  decodes to `classic`, and the ordinary translated ARM64 run remains on the
  title or loading image, while both diagnostics display the world.
* Whether the expanded callback labels should be persisted into the active
  desktop IDA database. The disposable-copy IDALIB validation passed, but the
  active unpacked database remained locked during this pass.
* Whether an unmodified x86_64 build clears its loading state without the
  getter override present in several historical diagnostic APKs.
* Whether the live server sends the same completion sequence as the local
  responder.
* Whether the literal-order adapter generalizes to scripts with different
  syntax or multiline literals. Its current output has not passed the clean
  runtime control for this connector fixture.
* Whether a replacement certificate and the old `RC4-SHA` and `SSLv23`
  settings are accepted by a current authorized game server on a branch that
  actually enables game-server TLS.

## Current blocker

The local native path is complete through rendered-world entry for the x86_64
diagnostic build. The no-swap table has been checked against IDA and the
emulator, and the earlier xchg handler-table patch and packet-182 hide
hypothesis are closed as false leads. Packet 182 maps to the process or
window-list path, while packet 190 reaches the connecting-window completion
wrapper. The recovered source remains useful for review, but the clean
HexaParser output did not reach the expected game port. The original bytecode
does reach it after a direct script-level loading clear, which keeps the
proven VM stream intact. That path currently proves network and resource
progress only; its bounded screenshot still shows the title/loading artwork.

The ARM64 diagnostic run establishes a narrower result. Under the available
x86_64 emulator, Android translated the ARM64 native code far enough to make
both game connections, accept the encrypted login, request the map and level
files, cache the image, and keep the heartbeat alive. The ordinary build did
not leave the title or loading image. The native audit shows why: the flag at
`0x37a549` starts enabled, the normal `classic` initialization path skips its
clear, and the packet-190 completion wrapper does not change it. The
non-premium initialization candidate and the independent render-boundary
control both displayed the world and HUD. A real ARM64 device is still
needed for final runtime validation.

One earlier blocker has been removed from the list. The saved connector
response was initially treated as unsigned because the offline checker used
the wrong RSA encoding. IDA and the corrected parser show that it passes the
native wolfSSL raw-digest check. The local trust replacement replay has now
also completed, so the remaining connector concern is the current authorized
chain and live endpoint behavior, not the saved fixture's RSA branch or the
local native TLS path.

The remaining blockers are external validation rather than an identified
local parser failure:

* the current connector certificate and package-signing chain have not been
  tested against a live service;
* no live game-server login has been attempted or verified;
* the rendered replay uses an x86_64 emulator with Android's ARM64
  translation layer;
* the ARM64-only replay needs a real ARM64 device run to separate native
  renderer behavior from the emulator translation layer.

The packet-59 shortcut remains rejected. The working file path is packet 102,
with optional large-file framing 68, 84, 102, 69. The local responder also
needs to send packet 49 again after the GMAP response because the tested client
otherwise caches the map without completing the pending transition.
