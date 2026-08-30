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
11. The symbol translation pass applied 8,601 readable aliases to the ARM64
    IDA database with zero rename failures. The APK is stripped, so this total
    is an alias inventory rather than a debug-symbol count.
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
20. The corrected offline parser reproduces the native raw-digest RSA check.
    The saved connector response passes with the embedded key, so the RSA
    bypass used by the first replay is not required for that fixture.
21. A private package-preserving x86_64 candidate was built with the original
    RSA bytes, the certificate diagnostic, loopback transport patches, and the
    fixed local handshake key. Its APK SHA-256 is
    `e794a8c096de46d14e2a98142fd8082c003d4b05e30fd9735e187c365d8e86ab`.
    It remains a private candidate and has not been rerun in this continuation.
22. A matching ARM64-only package-preserving candidate was also built with
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
23. The trust-bundle replacement tool was checked against the original ARM64,
    armeabi, x86, and x86_64 libraries. A one-certificate standard PEM bundle
    encoded at each architecture-specific offset and decoded byte-for-byte.
    These checks were offline and did not establish compatibility with a live
    endpoint.
24. The IDA audit of the nonblocking connector path confirms that status 4
    `EINPROGRESS` completion reaches `TSocketConnection_setStatus_int` with
    status 5, which starts CyaSSL when SSL is enabled. The earlier blocking-I/O
    experiment remains rejected because it froze the renderer.
25. The decoded connector script carries a second TLS configuration for the
    game server. Its `setSSLParameters` certificate is a 718-byte DER object
    with SHA-256
    `2e6425395e91baab7be95d9918de198684bcb718800bff07113e7f336d06ce56`, the
    same expired Eurocenter Games certificate as connector trust-bundle entry
    0. The native callback uses `NakFpz15` and enables `RC4-SHA` with
    `SSLv23`; this is documented offline in `artifacts/game_server_tls.json`.
26. The offline encoder
    `tools/encode_game_server_tls_certificate.py` prepares a replacement for
    script string 143, rejects private-key or multi-certificate PEM input, and
    reproduces the original literal byte-for-byte when fed the recovered
    certificate. It does not disable verification or contact a network.
27. The source-level helper
    `tools/replace_game_server_tls_source.py` finds both recovered
    `setSSLParameters` certificate calls, validates their existing DER values,
    and writes a separate GS2 source file. Feeding it the recovered
    certificate gives an identity source and the same 16,141-byte compiled
    bytecode. A 1,072-character offline test certificate also compiles to
    16,253 bytes. These are compiler and transform checks only.
28. A private ARM64-only package retained the native connector RSA branch,
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
29. The recovered GS2 source was checked for the separate game-server TLS
    literal. The Classic branch sets `usessl` to false, the NewGraal login
    function guards `setSSLParameters` with that flag, and a final assignment
    also clears it. The stale `NakFpz15` certificate is therefore not active
    in the main Classic login path, although it remains relevant to other
    legacy modes or modified scripts.
30. `tools/patch_connector_bytecode_loading_clear.py` inserts the original
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
31. The direct script patch was then combined with the existing native
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
    direct script patch but does not isolate the visual transition. A later
    native-only run provides that isolation.
32. The IDA ownership audit is now captured in
    `artifacts/loading_state_ownership.json`. It lists the three native getter
    call sites, the two post-startup setter paths, the `sigcheck` clear, the
    render-loop branch, and packet-190's no-write behavior. The active IDB has
    matching comments at those addresses.
33. The latest file-scripting checkpoint added 22 labels from the table at
    `0x376bd0`, installed by `TFileScripting_initStaticScriptVars` at
    `0xfd1d0`. The cumulative semantic-label artifact now contains 467 entries,
    while the complete IDA inventory remains 11,272 functions. The next zlib
    and static-state names are recorded separately as un-applied candidates.
34. An offline ARM64 disassembly pass tied four more static initializers to
    ELF relocation targets: `TDrawTexture::textures`, `curanis`,
    `TOptions::windowpos`, and `displayedgif`. The proposed names remain
    unapplied until the IDA bridge returns, so the public inventory and the
    applied-label count are unchanged.
35. The same offline pass recovered three sound wrappers at `0xe0af8`,
    `0xe0bf8`, and `0xe0c08`. Vtable relocations identify the first as
    `TSounds_isMusicPlaying`; the other two access the exported
    `TSounds::soundoffscreendistance` global.
36. A follow-up relocation check corrected the next table interpretation.
    `0xe0c18` uses the `TSounds::soundplayer` slot at `0x3757e0` and matches
    `getmusicfilename`. The property pair at `0xe0c84` and `0xe0c70` uses
    `TSounds::disabledsoundeffects` through slot `0x374cb0` and calls the
    comma-text getter and setter. These three names are recorded as unapplied
    candidates. The same table supplies `stopsounds` at `0xe0fa8` and
    `setmusicvolume` at `0xe1350`; their wrappers forward to the exported
    sound methods. The expanded plan now contains 27 entries. No live endpoint was
    contacted.
37. A held-connection replay on 2026-08-25 repeated the ARM64 test with the
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
38. The latest offline symbol pass recovered the six `TServerLevel` property
    accessors and eighteen server-level script wrappers registered from
    `0x37fce0` and `0x37fe00`. Their names decode to level dimensions, zone
    flags, map-part lookup, NPC queries, bomb and explosion operations,
    projectile shooting, collision tests, and tile lookup. The callback bodies
    reach the matching exported `TServerLevel` methods or object lists. The
    names are recorded as unapplied candidates, raising the review-only native
    set from 27 to 51 entries. The IDA bridge timed out again, so no IDB names
    were changed and no endpoint was contacted.
39. The next table audit covered `TServerPlayerProperties` at `0x18b9bc`.
    It registered 52 properties and six script functions from `0x37ce00` and
    `0x37d7c0`. Shared getter and setter targets were deduplicated, the
    existing `TServerPlayer::setNick` ELF jump was left alone, and the one
    callback without an IDA function boundary at `0x18aa68` was retained with
    a review note. The unapplied candidate set now contains 125 unique native
    addresses. No endpoint was contacted.
40. The NPC constructor at `0x183c18` was audited next. Its 26 properties and
    57 script functions are registered from `0x37be28` and `0x37c308`. Four
    callback pointers lack saved IDA function boundaries, and two inherited
    ELF jump targets were left unchanged. The remaining 94 unique native
    targets are recorded as unapplied candidates, raising the review-only set
    to 219. No endpoint was contacted.
41. The compact server-object property constructors were audited offline.
    Weapon, bomb, explosion, chest, extra, flying-object, and sign tables add
    23 unique getter or setter targets, raising the review-only candidate set
    to 242. Carry and leap constructors initialize metadata only and do not
    register script properties in this build. No IDA names changed and no
    endpoint was contacted.
42. The projectile, level-link, and tile-layer tables were audited offline.
    They add 35 unique targets, including 10 projectile properties, 7
    level-link properties, 17 tile-layer getter or setter targets, and the
    `updateboard` callback. The review-only candidate set now contains 277
    entries. No IDA names changed and no endpoint was contacted.
43. A complete offline scan of direct `TScriptProperty::addProps` and
    `addFuncs` calls found 70 property tables and 62 function tables. Their
    1,455 declared records, comprising 1,454 static records and one dynamic
    Android registration slot, resolve to 1,779 unique callback targets. The map
    identifies 886 exact new names with saved boundaries and 20 exact
    pointers without boundaries. The native zero-byte repair is modeled, so
    all 1,454 static record names are exact. No IDA names changed and no
    endpoint was contacted. Each of the 20 pointers also has an ELF `.eh_frame` range;
    `tools/ida_apply_script_table_boundaries.py` keeps those boundary changes
    separate from the ordinary rename pass.
44. The translation overlay accounts for 886 of the saved default `sub_`
    functions through exact table names and another 271 through curated
    callback evidence. The remaining 488 default functions stay explicitly
    unresolved. No speculative names were added and no endpoint was
    contacted.
45. The unresolved-function profile separates those 488 default entries into
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
46. A follow-up offline disassembly pass produced seventeen high-confidence
    review-only role candidates. The first four are at `0xf9028`, `0xf9060`,
    `0xf9944`, and `0x213088`, covering the profiler comparator, function-tree
    formatter, profiler reset recursion, and recursive `TGraalVar::loadFolder`
    worker. Thirteen more cover the TBitmap GIF and JPEG callbacks, animation
    lexer fatal handling, TServerLevel spatial predicates, the player draw-list
    predicate, the scroll-control property resolver, and the script-object
    resolver. The candidate artifact does not claim that these aliases exist in
    the ELF, and no IDA names changed or endpoint was contacted.
47. A final structural pass added eleven more role candidates, bringing the
    review-only role artifact to 28 entries. The new entries cover the flex-style
    animation previous-state helper at `0xe01d0`, the generic draw-distance
    comparator at `0x20ac18`, and the nine YAJL callbacks installed at
    `0x387e20` for `TGraalVar::readJSON`. All 28 candidates are marked
    high-confidence role assignments. IDA evidence now ties the comparator at
    `0x20ac18` to both nearest-player script wrappers, which sort the runtime
    universe list before returning their results. No IDA names changed and no
    endpoint was contacted. The generator also verifies that those 28 roles
    cover every entry in the application or engine profile category.
48. The four naming passes were exercised together in IDA 9.3 IDALIB against a
    disposable copy. All 277 native candidates, 886 bounded script-table
    names, 20 FDE-backed script callbacks, and 28 application or engine roles
    resolved with zero failures. The run added 25 function starts and split
    two previously merged ranges at exact FDE starts. The active desktop IDA
    database remained locked and was not overwritten. IDALIB then saved the
    disposable copy and a separate read-only reopen verified all 1,211 names,
    11,297 function starts, and 459 remaining default `sub_` entries. The
    result and saved-copy hash are in
    `artifacts/ida_translation_validation.json`.
49. A clean 2026-08-25 revalidation used the packaged ARM64-only diagnostic
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
50. A fresh 2026-08-26 HexaParser check passed `go test ./...` at the pinned
    commit using Go 1.22.2. Repeated decompilation produced the same source
    hash, and `tools/repair_hexaparser_source.py` reproduced the known valid
    source repair and 16,141-byte compiler output. The rebuilt stream still
    differs from the original in record lengths and instruction count, so it
    remains a source-level cross-check rather than a runtime replacement. The
    Go module proxy was the only network used for this check. Details are in
    `artifacts/helper_toolchain_replay.json`.
51. A follow-up ARM64-only isolation replay served the original 15,581-byte
    connector script with no script-level loading clear. The native candidate
    at `0x15ca7c` still completed two game connections, loaded the map, three
    encrypted level containers, and `pics1.png`, kept heartbeat traffic alive,
    and displayed the green tiled world, HUD, and status icons. Its screenshot
    hash matched the combined replay at
    `fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`.
    This isolates the observed local visual transition to the native startup
    branch. The full capture metadata is in
    `artifacts/arm64_native_only_original_script_replay_20260826.json`.
52. A matched stock-branch control restored the original `B.LE` instruction at
    `0x15ca7c` while keeping the same diagnostic transport patches, original
    script, responder, and fixtures. It completed the same two connections,
    map, level files, image request, and heartbeat path, but the screen stayed
    on the title/loading artwork. Its APK SHA-256 is
    `fd7c8676939dcf83d929fd5707536d98dbfd8bae009aec9e4f80c71dbaad0031`, its
    native SHA-256 is
    `f36ab1dc978861b26cb7ec3d9ebb9215b8450ffd73f957275a500de7f6492776`, and
    its screenshot SHA-256 is
    `70e6573244e58125d4092d8265c8acc4e2074dd866bd9cd5897ddf079d39e135`.
    This is the matched negative control for item 51. Details are in
    `artifacts/arm64_native_stock_original_script_control_20260826.json`.
53. `tools/build_arm64_loopback_apk.py` now rebuilds the complete private
    ARM64 diagnostic package from the original APK. It keeps the connector
    script unchanged, removes the other ABI directories, applies the five
    tested native edits, normalizes ZIP timestamps, and verifies the signed
    package. Two independent builds produced APK SHA-256
    `394d9ac33fe7b81638029064f2b8ff2183405729f9b5fd94f6808facc13221fc` and
    native SHA-256
    `89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858`.
    Installing that freshly built package and restoring the two loopback
    mappings reproduced the rendered-world screenshot and full resource
    replay. Details are in
    `artifacts/arm64_reproducible_builder_validation_20260826.json`.
54. A paired native TLS validity control was run on the same Android 36
    x86_64 emulator through ARM64 translation. The valid control trusted a
    SAN-matching certificate valid from 2025 through 2035 and sent one
    `GET /con.png` request through the native TLS path. The otherwise matching
    expired control trusted a certificate that ended on 2021-01-01, reached
    the local TCP listener, and closed during TLS with no HTTP request. The
    expired package therefore fails before connector HTTP in this environment.
    The expired and valid package hashes are
    `e7615fcb37112cb86e8d768f51143149b98dcde83c12a5b734ca65e336f29e36` and
    `183ef83ed2772872288c1aa639e0501b5a645df395b0f89887a38ce56c0266f0`.
    The full comparison is in
    `artifacts/connector_tls_expiry_control_20260826.json`.

55. A new reproducible builder, `tools/build_arm64_trust_control.py`, was
    added for the native-verification path. It replaces only the historical
    trust bundle, routes the connector to loopback, moves the connector to
    port `18443`, and installs the deterministic local responder key. The
    RSA result branch and native certificate validation remain unchanged. An
    optional flag selects the already-tested native loading-state branch.
56. The optional working control was run on the same Android 36 x86_64
    emulator using ARM64 translation. With a SAN-matching test certificate
    valid from 2025 through 2035, the package made one native HTTPS connector
    request, opened two encrypted game connections, received the map, three
    level containers, and image assets, continued heartbeat traffic, and
    displayed the tiled world and HUD. Its APK SHA-256 is
    `183ef83ed2772872288c1aa639e0501b5a645df395b0f89887a38ce56c0266f0` and
    its native SHA-256 is
    `7cffcbd8380d5e19324eb6d392e6cd942ce696b9470bbaaa74b037827ebecee7`.
57. The default transport-only form of the same builder kept the stock
    loading branch. It made the same connector and resource requests and
    continued heartbeats, but remained on the title/loading artwork. This
    pairs the stale-trust result with the independent loading-state result.
    The complete comparison is in
    `artifacts/arm64_native_verification_working_control_20260826.json`.
58. A separate IDA 9.3 pass resolved all eleven unnamed functions in the
    CyaSSL and bundled-crypto gap. The aliases cover RSA certificate-signature
    verification, MD5, SHA-1, and SHA-256 transforms, PEM or DER buffer
    loading, the TLS PRF, record-MAC handling, Finished verify-data, and peer
    certificate parsing. Seven are high-confidence historical source-role
    matches and four are descriptive aliases. A clean reopen verified all
    eleven names and reduced the latest disposable copy from 459 to 448
    default `sub_` functions. The full evidence and database hash are in
    `artifacts/cyassl_static_role_audit_20260826.json`.

59. A second static-library audit resolved 27 more high-confidence aliases:
    14 zlib routines, 4 bzip2 routines, 2 minizip helpers, 1 GPC helper, 2
    CyaSSL ASN.1 helpers, 1 LibTomCrypt DES routine, and 3 YAJL allocator
    callbacks. It corrected five stale family classifications from the
    address-boundary profile and corrected the earlier zlib `lm_init` guess
    at `0x288908` to `_tr_init`. A clean reopen of
    `analysis/libqplay_translated_all_v4.i64` verified all 27 names and
    reduced the default-name count from 448 to 421. The database hash is
    `089e588389206929cbcbd7d1d65dd477e0c69eed0841b430636bb7c947594ac3`.
    Details are in `artifacts/static_library_role_audit_20260826.json`.

60. A direct run of the supplied Spectron 2.2 APK reached its custom menu,
    then died after Start with `SIGSEGV` at `libxposed.so+0x84348`, fault
    address `0x0`, called from `Java_com_WebTop_onmsg+104`. IDA confirms that
    address is the intentional WebTop `crash` command path, which stores
    through null and loops. The same run logged qplay failures writing an
    external scoped-storage asset, but that was not shown to cause the crash.
    The emulator had ordinary networking enabled, so this is not a
    no-network or playable-world result. See
    `artifacts/spectron_runtime_crash_control_20260826.json`.

61. A normalized IDA feature pass translated the named original 1.8
    functions to the supplied Spectron ARM64 rebuild. It found 3,700 unique
    targets, with 3,641 high-confidence labels applied and 59 medium-
    confidence rows held for review. The shared-name validation set produced
    396 correct unique matches and zero wrong matches. The persisted Spectron
    copy at
    `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v2.i64`
    adds four manual context anchors for the premium marker, loading getter,
    connecting window, and JNI loop. Its SHA-256 is
    `fab82bedbafb864513dfbfc144f657d7542816d2ff883abe1a55c16753f55618`.
    These are `v18_` analysis labels and reviewed correspondences, not a
    claim that original debug symbols survived in Spectron. See
    `artifacts/spectron_semantic_function_translation_20260826.json`,
    `artifacts/spectron_manual_translation_anchors_20260826.json`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

62. A private signed Spectron control disabled only the ARM64 WebTop
    branches for `crash`, `freeze`, and `abort`. After Start, its process
    remained alive and qplay reached activation, OpenGL initialization,
    login-server connection, two server-warps, and Connected. The custom menu
    then led through the welcome and tutorial dialogs. After advancing them,
    the client rendered a stable local in-game scene with the player, map
    furniture, HUD controls, and status icons. This isolates the intentional
    WebTop death and demonstrates local game entry for the supplied 2.2
    package. It does not establish live-service compatibility. The APK hash is
    `d8b44281f2c2a3e8ab6f40358e28d017052a967cdf2a5b9b0c3383535ef07de3`.
    See `artifacts/spectron_webtop_safe_runtime_20260826.json`.

63. The cross-build name audit found 1,008 one-to-one exact function names
    shared by the original 1.8 and Spectron 2.2 feature exports. Of these,
    396 are already covered by the strict semantic map and 612 are preserved
    exact-name anchors that were outside its size and shape key. The inventory
    has no ambiguous shared names and is kept separate from inferred `v18_`
    labels. See `artifacts/spectron_exact_shared_name_anchors_20260826.json`.

63a. The v231 IDA checkpoint added six high-confidence aliases from the
     password, cache, and file-download property tables. All six target
     functions match the normalized source shape, and a clean serial reopen
     verified every name. The checkpoint has 11,694 functions and 1,073
     remaining default `sub_` names. Three target-only rows for debug-handler
     callbacks and an ABI wrapper remain explicitly separate from the source
     mappings. See
     `artifacts/spectron_file_cache_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_file_cache_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v231.json`.

63b. The v232 IDA checkpoint corrected a false feature-shape match in the
     inbound handler table and added two high-confidence aliases. Handler
     slot 10 maps `TClient_handleServerLoginPacket` to `0x1f37e0`, and slot 48
     maps `TClient_processServerModifies` to `0x1eefa0`. The earlier alias at
     `0xecba0` was removed because that address is a retained
     `yL3_IaDMFt` hash-container export; its original dynamic name was
     restored. The checkpoint has 11,694 functions and 1,071 remaining
     default `sub_` names. See
     `artifacts/spectron_tclient_handler_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_tclient_handler_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v232.json`.

63c. The v233 IDA checkpoint gives three target-only property callbacks
     descriptive `spectron_` labels without claiming 1.8 counterparts. The
     two debug-handler callbacks copy at most 256 integers into separate
     1024-byte target globals. The third is a positive-result ABI adapter for
     the already translated `v18_TClient_updateGlobalPlayer` body. The clean
     reopen has 11,694 functions and 1,068 remaining default `sub_` names. The
     database SHA-256 is
     `21fa935e68dd605c0549656df3a3b832d0c91e080b7d703b2042132ba078ddd6`.
     See
     `artifacts/spectron_target_only_callback_labels_20260828.json`,
     `tools/generate_spectron_target_only_labels.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v233.json`.

63d. The v234 IDA checkpoint recovers the missing target function boundary for
     the `tclient_setplayerhurt` property callback. The source callback at
     `0x1ed158` maps through the target table record at `0x398010` to the
     materialized target range `0x1f1b08-0x1f1b94`, now named
     `v18_TClient_script_tclient_setplayerhurt`. A clean reopen verified the
     boundary and alias. The database has 11,695 functions and 1,068
     remaining default `sub_` names, with SHA-256
     `c7dda722fbab84a403ed8ba21351af98dc01e181c640c5048c126b2ff4f669b2`.
     See
     `artifacts/spectron_tclient_playerhurt_property_manual_translation_anchor_20260828.json`,
     `tools/generate_spectron_tclient_playerhurt_anchor.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v234.json`.

63e. The v235 IDA checkpoint adds 12 high-confidence aliases from the
     GSFunctionsClient and GuiControl property tables. The rows cover five
     carried-object getters, four screen-relative mouse accessors, and three
     GuiControl callbacks. All 12 match normalized instruction shape, and the
     three GuiControl rows match the complete recorded metric set. The clean
     reopen has 11,695 functions and 1,056 remaining default `sub_` names. The
     database SHA-256 is
     `b58d447613b039f930e5ecd179a56a0e5ad19958715445f0663272dc830e0719`.
     See
     `artifacts/spectron_gsfunctions_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_gsfunctions_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v235.json`.

63f. The v236 IDA checkpoint adds 22 high-confidence aliases from the
     identification, time, file-scripting, control-binding, and
     hardware-keyboard tables. The clean reopen has 11,695 functions and
     1,034 remaining default `sub_` names. Twenty-one rows match normalized
     ARM64 instruction shape and 17 match the complete metric set. The target
     `setFileModTime` body is expanded, so its semantic match is recorded with
     the metric differences visible. The database SHA-256 is
     `04b1c4438c1d9473f949a1e27d8cf60b1d1199fddac80440a23429c8e5b1f44a`.
     See
     `artifacts/spectron_time_files_input_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_time_files_input_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v236.json`.

63g. The v237 IDA checkpoint adds seven high-confidence `TLevelObject`
     property aliases and materializes the missing target `z` getter boundary
     at `0x16d460-0x16d480`. All seven rows match the complete recorded feature
     metrics. The clean reopen has 11,696 functions and 1,028 remaining
     default `sub_` names. The database SHA-256 is
     `5229c4d4d67261076bd57c46c8331426ac775afdac6a578f409764b68e5ef872`.
     See
     `artifacts/spectron_level_object_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_level_object_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v237.json`.

63h. The v238 IDA checkpoint adds eight high-confidence aliases from the
     residual `TGaniObject` and `TGaniParam` property tables. The `body` and
     `bodyimg` registrations share one getter, and the target `body` setter
     was already translated. Five rows match the complete feature metrics,
     one keeps normalized shape with a register-detail change, and two global
     movie-reposition wrappers preserve their behavior with target instruction
     form changes. The clean reopen has 11,696 functions and 1,020 remaining
     default `sub_` names. The database SHA-256 is
     `b9e8068236409064bb27bde0f3f564398cc3ed7c664bc46af6eb5c5ce801f6a3`.
     See
     `artifacts/spectron_gani_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_gani_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v238.json`.

63i. The v239 IDA checkpoint adds 30 high-confidence aliases from the
     residual `TOptions` preference table: 17 getters and 13 setters covering
     plugin state, nickname rules, rendering effects, audio preferences, and
     screenshot format. Two video-style setters were already translated and
     were left unchanged. All 30 selected rows match the normalized ARM64
     instruction shape; each retains a target register-detail difference. The
     clean reopen has 11,696 functions and 990 remaining default `sub_` names.
     The database SHA-256 is
     `4b83ebdffa26611933a959770f39e1d43b1ff64d796d7d28c2c04c3aec4ff021`.
     See
     `artifacts/spectron_options_property_residual_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_options_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v239.json`.

63j. The v240 IDA checkpoint adds 42 high-confidence aliases from the
     residual `TParticleEmitterProperties` table: 26 getters and 16 setters
     covering particle placement, terrain behavior, emission timing, clipping,
     counts, and rendering flags. Nine earlier aliases in the same table were
     left unchanged. All 42 selected rows match the complete feature metrics.
     The clean reopen has 11,696 functions and 948 remaining default `sub_`
     names. The database SHA-256 is
     `32225a918d1ac903ae68f624937fe4d4296afe75fec63448ff6aa60b96c6cd72`.
     See
     `artifacts/spectron_particle_emitter_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_particle_emitter_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v240.json`.

63k. The v241 IDA checkpoint adds three high-confidence aliases from the
     residual `TParticleEmitter` script-function table: `addglobalmodifier`,
     `addlocalmodifier`, and `addemitmodifier`. All three source and target
     bodies match the complete feature metrics. The clean reopen has 11,696
     functions and 945 remaining default `sub_` names. The database SHA-256 is
     `c154d03a1b28e31a06faa87876d1108c7acb971c884e4ae984cbe273573ba09e`.
     See
     `artifacts/spectron_particle_emitter_script_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_particle_emitter_script_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v241.json`.

63l. The v242 IDA checkpoint adds 22 high-confidence aliases from the
     residual `TBitmap`, `TServerWeapon`, `TProjectile`, `TServerLevelLink`,
     and `TServerLevel` property tables. The batch contains 19 getters and
     three setters. All 22 rows match normalized ARM64 instruction shape, and
     eight match the complete feature metrics. The other 14 differ only in
     register-detail metadata. The clean reopen has 11,696 functions and 923
     remaining default `sub_` names. The database SHA-256 is
     `6d8eb4e0dcacddce087564e3f14a7b355472cebac32f6854c007e98c740f5f44`.
     See
     `artifacts/spectron_world_object_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_world_object_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v242.json`.

63m. The v243 IDA checkpoint adds nine high-confidence aliases from the
     residual `TPlayer` auxiliary property table and `TTranslations` table.
     The batch contains six getters and three setters. All nine rows match
     normalized ARM64 instruction shape; their only recorded difference is
     register-detail allocation. The clean reopen has 11,696 functions and
     914 remaining default `sub_` names. The database SHA-256 is
     `11d1275fbfca6b7500f430742de9e84f933d53462967e88fa61255ebad3e8e38`.
     See
     `artifacts/spectron_player_translation_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_player_translation_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v243.json`.

63n. The v244 IDA checkpoint adds six high-confidence aliases from the
     residual `TServerNPC` property table. They cover horse and NPC image
     accessors, the `peltwithnpc` flag, and X/Y coordinate setters. All six
     rows match normalized ARM64 instruction shape, and two match the complete
     feature metrics. The clean reopen has 11,696 functions and 908 remaining
     default `sub_` names. The database SHA-256 is
     `10ea7f378ae0fafa155d45da163a116477240c01970e4e61b1e7dba1efd8b942`.
     See
     `artifacts/spectron_server_npc_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_server_npc_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v244.json`.

63o. The v245 IDA checkpoint adds seven high-confidence aliases from the
     residual `TServerNPC` script-function table. They cover the carry, push,
     pull, and `timereverywhere` policy callbacks. All seven rows match
     normalized ARM64 instruction shape; their only recorded difference is
     register-detail allocation. The clean reopen has 11,696 functions and
     901 remaining default `sub_` names. The database SHA-256 is
     `108d94cfb65b8e35d121e75d766b27c9490b82e501787eb0738a355c167f4a13`.
     See
     `artifacts/spectron_server_npc_script_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_server_npc_script_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v245.json`.

63p. The v246 IDA checkpoint adds two high-confidence semantic aliases for
     the residual `TServerNPC` `showimg` and `showimg2` callbacks. Their table
     rows, argument shapes, image-list lookup, allocation, image assignment,
     coordinate updates, and refresh calls align. Spectron makes the image
     string temporary explicit, so both target bodies expand from 344 to 372
     bytes and have recorded shape differences. The clean reopen has 11,696
     functions and 899 remaining default `sub_` names. The database SHA-256 is
     `a8f616f41af51ec0076cbb37e3e9393910894674036e9e732a015ef59d64e515`.
     See
     `artifacts/spectron_server_npc_showimg_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_server_npc_showimg_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v246.json`.

63q. The v247 IDA checkpoint completes the residual `TTilesLayer` property
     table with 17 high-confidence aliases covering color channels, layer
     index, offset, and X/Y/Z coordinates. Every row matches the complete
     ARM64 feature metrics, including the larger offset wrappers. The clean
     reopen has 11,696 functions and 882 remaining default `sub_` names. The
     database SHA-256 is
     `3e0c053b6dc847f21a437e4e77883481a37e5ecc128b3e47971ecd72ed050b4d`.
     See
     `artifacts/spectron_tiles_layer_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_tiles_layer_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v247.json`.

63r. The v248 IDA checkpoint translates 30 residual main `TPlayer` property
     registrations to 27 distinct target callbacks. The duplicate rows are
     intentional: `hearts` and `hp`, `shield` and `shieldimg`, and `sword` and
     `swordimg` share getters in the registration table. All 30 rows match
     normalized ARM64 shape, seven match the complete metric set, and none
     introduce a layout change. The clean reopen has 11,696 functions and 855
     remaining default `sub_` names. The database SHA-256 is
     `780a8ac4584699546ef14a692bd520f13389f5c3918f45b37e33256718028165`.
     See
     `artifacts/spectron_player_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_player_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v248.json`.

63s. The v249 IDA checkpoint translates 30 residual `TGaniObject` and
     `TGaniParam` property registrations to 29 distinct target callbacks. The
     `head` and `headimg` rows share one getter. Twenty-six callback anchors
     match normalized ARM64 shape, eight match the complete metric set, and
     three retain target-shape changes. The target zoom accessor uses encoded
     backing storage, while the rotation-center setter is a shorter rebuilt
     wrapper. The clean reopen has 11,696 functions and 826 remaining default
     `sub_` names. The database SHA-256 is
     `50377973defadbbf25181fdad93a1fcc4a06480f20bcdbd180dd9a63dc27defa`.
     See
     `artifacts/spectron_gani_property_residual_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_gani_property_residual_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v249.json`.

63t. The v250 IDA checkpoint translates 12 residual `TDrawingPanel` property
     and script-table rows to 10 distinct target callbacks. The `height` and
     `parth` rows share one getter, as do `partw` and `width`; the existing
     `enablecache` setter is preserved rather than renamed again. Eight
     callback anchors match the complete ARM64 metric set, and the two
     wrapper differences are limited to target register allocation. The clean
     reopen has 11,696 functions and 816 remaining default `sub_` names. The
     database SHA-256 is
     `d9fa44a190b1b5014dd9e56651fd416c0e1923cba4e2cd8e361314a9ba7a046f`.
     See
     `artifacts/spectron_drawing_panel_property_residual_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_drawing_panel_property_residual_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v250.json`.

63u. The v251 IDA checkpoint translates both `findweapon` callbacks. The
     property callback maps to `0x1705f0`, and the active-player static callback
     maps to `0x171728`. Both target bodies search the weapon list and compare
     names, but they retain distinct calling contexts. Their rebuilt target
     string and player-layout helpers produce larger bodies, so the aliases
     are semantic matches with metric differences recorded explicitly. The
     clean reopen has 11,696 functions and 814 remaining default `sub_` names.
     The database SHA-256 is
     `7ab7b98f01f2a4e5241187e1f5864006a7b8b21f6fa163e61fc3c76081a65e9c`.
     See
     `artifacts/spectron_tplayer_findweapon_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_tplayer_findweapon_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v251.json`.

63v. The v252 IDA checkpoint translates 17 residual `TGUIAnimationProperties`
     callbacks, with ten getters and seven setters. The source and target
     tables retain the same twelve property names and order, and the selected
     callbacks cover current time, amplitude, bounds, delay, duration,
     interval, sound, tab-first-on-show, timing, and transition. All 17 rows
     match the normalized shape and complete ARM64 feature metrics. The clean
     reopen has 11,696 functions and 797 remaining default `sub_` names. The
     database SHA-256 is
     `90a0d433ed61969714d1c853823693ce4286e2d785e159535e7f68e06548af4b`.
     See
     `artifacts/spectron_tgui_animation_property_residual_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_tgui_animation_property_residual_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v252.json`.

63w. The v253 IDA checkpoint translates five distinct `GuiBitmapCtrl`
     callbacks across six registration rows. The `tile` and `wrap` entries
     share one getter, so the batch contains four getters and one setter. All
     five rows match the complete ARM64 feature metrics. The clean reopen has
     11,696 functions and 792 remaining default `sub_` names. The database
     SHA-256 is
     `924bca24389cf9c6f8d07ade1f6a7b31726c8bc7991f7fdbacf6e94967a5028c`.
     See
     `artifacts/spectron_gui_bitmap_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_gui_bitmap_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v253.json`.

63x. The v254 IDA checkpoint translates 11 residual GUI button callbacks from
     the `GuiBitmapButtonCtrl` and `GuiButtonBaseCtrl` property tables. Six
     rows cover the three bitmap modes, and five cover button type, group
     number, and text. Nine rows match the complete ARM64 feature metrics; the
     two button-type rows retain only register-detail differences. The clean
     reopen has 11,696 functions and 781 remaining default `sub_` names. The
     database SHA-256 is
     `078918adcdeadc3fa6a894d07e0f9b1929dacaeb2043de3f9952ed8e2f9289e8`.
     See
     `artifacts/spectron_gui_bitmap_button_property_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_gui_bitmap_button_property_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v254.json`.

63y. The v255 IDA checkpoint translates four residual `GuiControl` property
     callbacks: the cursor getter and the flickering, ordinary-animation, and
     in-or-out-animation setters. All four rows match the complete ARM64
     feature metrics, with no layout or register-detail differences. The clean
     reopen has 11,696 functions and 777 remaining default `sub_` names. The
     database SHA-256 is
     `41201714ed45c2e165f0199268d1863fb6d7895f8067678c6614fc786c5254b6`.
     See
     `artifacts/spectron_guicontrol_property_tail_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_guicontrol_property_tail_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v255.json`.

63z. The v256 IDA checkpoint translates the two remaining `GuiGraalCtrl`
     callbacks for the `isrendering` property. The getter and setter both
     match the complete ARM64 feature metrics, with no layout or register-detail
     differences. The clean reopen has 11,696 functions and 775 remaining
     default `sub_` names. The database SHA-256 is
     `51cc802c6c5ae38aa70bf09119f3caef12fe4e6907403d9a54211e79e110731c`.
     See
     `artifacts/spectron_guigraalctrl_isrendering_manual_translation_anchors_20260828.json`,
     `tools/generate_spectron_guigraalctrl_isrendering_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260828_v256.json`.

63aa. The v257 IDA checkpoint translates 11 residual `GuiScrollCtrl` property
      callbacks covering child margin, constant thumb height, both scrollbar
      names, scroll position, tile, wheel-scroll lines, and first-responder
      state. All 11 rows match normalized ARM64 shape, and nine match the full
      metric set. The two scrollbar getters retain only register-detail
      differences. The clean reopen has 11,696 functions and 764 remaining
      default `sub_` names. The database SHA-256 is
      `91201c29da6a4798a7f1918c2f11fa848cb66848615079beaaf29d04b022d82e`.
      See
      `artifacts/spectron_guiscrollctrl_property_manual_translation_anchors_20260828.json`,
      `tools/generate_spectron_guiscrollctrl_property_anchors.py`, and
      `artifacts/spectron_translation_checkpoint_20260828_v257.json`.

63ab. The v258 IDA checkpoint translates seven residual `GuiStretchCtrl`
      callbacks, including inherited `GuiTextCtrl` maxchars and text rows. All
      seven rows match the complete ARM64 feature metrics, with no layout or
      register-detail differences. The clean reopen has 11,696 functions and
      757 remaining default `sub_` names. The database SHA-256 is
      `7e7aa1628bd8f9123540346c06455d7b2e1aca803092f4ba3466cd4974f2bbd8`.
      See
      `artifacts/spectron_guistretchctrl_property_manual_translation_anchors_20260828.json`,
      `tools/generate_spectron_guistretchctrl_property_anchors.py`, and
      `artifacts/spectron_translation_checkpoint_20260828_v258.json`.

63ac. The v259 IDA checkpoint translates nine residual `GuiTextEditCtrl`
      property callbacks covering denied sound, history size, input type,
      cursor visibility, tab completion, and the text getter. All nine rows
      match the complete ARM64 feature metrics, with no layout or register-detail
      differences. The clean reopen has 11,696 functions and 748 remaining
      default `sub_` names. The database SHA-256 is
      `9b5a46e16dbf912a7e67583b8f626f52878bcbb30225e3674793d3b8ef5114d9`.
      See
      `artifacts/spectron_guitexteditctrl_property_manual_translation_anchors_20260828.json`,
      `tools/generate_spectron_guitexteditctrl_property_anchors.py`, and
      `artifacts/spectron_translation_checkpoint_20260828_v259.json`.

63ad. The v260 IDA checkpoint translates four residual `TGraalVar` property
      callbacks covering the name setter, paused-state getter and setter, and
      joined-classes getter. The pause pair matches the complete ARM64 feature
      metrics. The name setter and joined-classes getter retain rebuilt-wrapper
      shape differences. The clean reopen has 11,696 functions and 744
      remaining default `sub_` names. The database SHA-256 is
      `a8d0c87f225ba9cd5490e7616ea05d983d48c80b8ef07ec7a8da2b91e675e944`.
      See
      `artifacts/spectron_tgraalvar_property_residual_manual_translation_anchors_20260828.json`,
      `tools/generate_spectron_tgraalvar_property_residual_anchors.py`, and
      `artifacts/spectron_translation_checkpoint_20260828_v260.json`.

63ae. The v261 IDA checkpoint translates the last unnamed callback in the
      server and player property block, `TBodyPanel_get_bodycacheperplayer`.
      Its normalized ARM64 shape matches the source, with only a register-detail
      difference. The clean reopen has 11,696 functions and 743 remaining
      default `sub_` names. The database SHA-256 is
      `d2f88d291451b82578968bff85c7018fdba2d2c0a18ec256ac7b3368d73e77de`.
      See
      `artifacts/spectron_tbodypanel_bodycacheperplayer_manual_translation_anchor_20260828.json`,
      `tools/generate_spectron_tbodypanel_bodycacheperplayer_anchor.py`, and
      `artifacts/spectron_translation_checkpoint_20260828_v261.json`.

63af. The v262 IDA checkpoint translates six callbacks from three short
      residual property runs: button style section, script-log write-to-read-only,
      and tile water height. All six rows match normalized ARM64 shape. The
      style-section pair matches the full metric set, while the other four rows
      retain only register-detail differences. The clean reopen has 11,696
      functions and 737 remaining default `sub_` names. The database SHA-256 is
      `6ec4091d8781101661216a2b99f6414cc3f5a07c556185eb40de2e203351d67e`.
      See
      `artifacts/spectron_residual_property_manual_translation_anchors_20260828.json`,
      `tools/generate_spectron_residual_property_anchors.py`, and
      `artifacts/spectron_translation_checkpoint_20260828_v262.json`.

64. Clean IDA review added six high-confidence network context anchors for
    connector-mode construction, HTTP download completion, CyaSSL setup,
    socket connect, game protocol reading, and low-level socket reading. The
    anchors target Spectron addresses `0x2094c0`, `0x205958`, `0x20c59c`,
    `0x20ccd8`, `0x204274`, and `0x20d614`. They are available for a new
    disposable translated IDA copy and do not alter the supplied APK. See
    `artifacts/spectron_network_manual_translation_anchors_20260826.json`.

65. Clean IDA review added 16 high-confidence core anchors for resource
    refresh, decompression, rendering, GUI setup, dialog transitions, input
    focus, uploads, game logging, web-script execution, and the server-list
    handoff. They target Spectron addresses `0xee558`, `0xef090`, `0xf0058`,
    `0xff028`, `0xff65c`, `0x16027c`, `0x16b848`, `0x16bed8`, `0x16bf80`,
    `0x16c0ac`, `0x16c3a0`, `0x16cac8`, `0x1ed4c4`, `0x1f6538`, `0x207db8`,
    and `0x2092a0`. All 16 names reopened successfully in the v4 disposable
    copy. See `artifacts/spectron_core_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

66. Clean IDA review added 13 high-confidence runtime-path anchors for map
    entry, file chunks and completion, text controls, encrypted scripts,
    disconnects, server warps, the server-list loop, and client static state.
    All 13 names reopened successfully in the v5 disposable copy. See
    `artifacts/spectron_runtime_path_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

67. Clean IDA review added five high-confidence update and protocol anchors for
    download and update queues, server modifications, CRC requests, and
    modification-time requests. All five names reopened successfully in the
    v6 disposable copy. See
    `artifacts/spectron_update_protocol_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

68. Clean IDA review added 11 high-confidence client-action anchors for
    level-warp timing, board edits, bombs, triggers, projectiles, shots,
    damage, explosions, and four-string text packets. All 11 names reopened
    successfully in the v7 disposable copy. See
    `artifacts/spectron_client_action_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

69. Clean IDA review added 29 high-confidence outbound client anchors for
    level entry, file and image requests, uploads, scripts, chat, flags,
    extras, object deletion, and server warp. Twenty-eight are new context
    labels and one corroborates an existing semantic match. All 29 names
    reopened successfully in the v8 disposable copy. See
    `artifacts/spectron_client_outbound_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

70. Clean IDA review added six high-confidence resource resolver anchors for
    encoded-key validation, wildcard matching, file-list construction, stream
    loading, game-file existence, and game-file path lookup. All six names
    reopened successfully in the v9 disposable copy. See
    `artifacts/spectron_resource_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

71. Clean IDA review added 13 high-confidence client script bridge anchors for
    upload, terrain and board refresh, trigger actions, appearance colors,
    weapon calls, request text, level lookup, server-list events, and text
    commands. All 13 names reopened successfully in the v10 disposable copy.
    See `artifacts/spectron_script_bridge_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

72. Clean IDA review added 11 high-confidence client request and window-state
    anchors for weapon images, RC chat, request text, file deletion, folder
    deletion, file rename and move, update-package requests, window presence,
    ping answers, and window lists. All 11 names reopened successfully in the
    v11 disposable copy. See
    `artifacts/spectron_client_request_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

73. Clean IDA review added eight high-confidence client inbound and
    state-transition anchors for script data, upload completion, server map
    entry, update-package completion, global-player login and logout handling,
    and GANI updates. All eight names reopened successfully in the v12
    disposable copy. See
    `artifacts/spectron_client_inbound_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

74. Clean IDA review added eight high-confidence login, event, and small
    client-state anchors for folder logging, RC chat, server-login signature
    handling, connection-state strings, and the player login or logout packet
    decoder. All eight names reopened successfully in the v13 disposable
    copy. See
    `artifacts/spectron_login_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

75. A focused IDA check added one high-confidence client encryption-in
    tail-thunk anchor below the semantic matcher minimum-size threshold. The
    target function already had a mangled boundary, and its raw bytes were
    checked as well. The name reopened successfully in the v14 disposable
    copy. See
    `artifacts/spectron_parse_wrapper_manual_translation_anchor_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

76. Clean IDA review added three high-confidence lookup anchors for active
    players, deleted players, and download files. Their source and target
    bodies preserve the same list scans and six-block loop shapes. All three
    names reopened successfully in the v15 disposable copy. See
    `artifacts/spectron_lookup_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

77. Clean IDA review added 18 high-confidence connection and SSL helper
    anchors for encryption cleanup, parser state, SSL configuration, socket
    errors, and low-level connection fields. All 18 names reopened successfully
    in the v16 disposable copy. See
    `artifacts/spectron_connection_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

78. Clean IDA review added seven high-confidence compact client-state anchors
    for virtual forwarding, server options, time state, Graal 2002 mode,
    ghost mode, and active-player flags. All seven names reopened successfully
    in the v17 disposable copy. See
    `artifacts/spectron_client_state_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

79. Clean IDA review added five high-confidence client connection-state anchors
    for connection-string fields, encrypted-file continuation, and encrypted
    server-level saving. All five names reopened successfully in the v18
    disposable copy. See
    `artifacts/spectron_connection_state_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

80. Clean IDA review added 12 high-confidence HTTP request anchors for request
    string fields, the deleting destructor, and outbound-buffer sending. All
    12 names reopened successfully in the v19 disposable copy. See
    `artifacts/spectron_http_request_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

81. Clean IDA review added five high-confidence socket-state anchors for error
    status, subprocess closing, nonblocking setup, and numeric or formatted IP
    access. All five names reopened successfully in the v20 disposable copy.
    See `artifacts/spectron_socket_state_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

82. Static comparison reviewed the three changed-size SSL setup, connect, and
    read functions without forcing exact labels. Their decompiled verification,
    nonblocking, and receive policies remain aligned, with added 2.2 logging
    differences. See
    `artifacts/spectron_socket_behavior_comparison_20260826.json`.

83. Clean IDA review added four high-confidence HTTP request-state anchors for
    request counters, timestamps, and the file-download predicate. All four
    names reopened successfully in the v21 disposable copy. See
    `artifacts/spectron_http_request_state_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

84. Clean IDA review added 15 high-confidence `TServerNPC` helper anchors for
    blocking modes, draw modes, visibility, bow assignment, and pelt
    predicates. All 15 names reopened successfully in the v22 disposable
    copy. See
    `artifacts/spectron_npc_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

85. Clean IDA review added five high-confidence `THTMLAtom` constructor and
    buffer-helper anchors. All five names reopened successfully in the v23
    disposable copy. See
    `artifacts/spectron_html_atom_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

86. Clean IDA review added five high-confidence `TPlayer` helper anchors for
    attachment state, property updates, freeze state, and sprite wrappers.
    All five names reopened successfully in the v24 disposable copy. See
    `artifacts/spectron_player_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

87. Clean IDA review added eight high-confidence input and window bridge
    anchors for key state, cursor position, dimensions, canvas lookup, and
    initialization. All eight names reopened successfully in the v25
    disposable copy. See
    `artifacts/spectron_input_window_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

88. Clean IDA review added 11 high-confidence visual helper anchors for
    animation, particles, and show-image state. All 11 names reopened
    successfully in the v26 disposable copy. See
    `artifacts/spectron_visual_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

89. Clean IDA review added 12 high-confidence GS2-facing script-runtime
    anchors for array, pause, timeout, timer, event-mask, access-right, and
    variable-cleanup behavior. All 12 names reopened successfully in the v27
    disposable copy. See
    `artifacts/spectron_script_runtime_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

90. Clean IDA review added 30 high-confidence core-helper anchors covering
    level objects, GS2 predicates and records, socket policy, update lookup,
    tiles, particles, native callbacks, and related state. All 30 names
    reopened successfully in the v28 disposable copy. See
    `artifacts/spectron_core_helper_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

91. Clean IDA review added 20 high-confidence render and GUI anchors covering
    texture timestamp state, OpenGL, drawing-panel, client bounds, cursor,
    scrolling, and markup selection behavior. All 20 names reopened
    successfully in the v29 disposable copy. See
    `artifacts/spectron_render_gui_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

92. Clean IDA review added eight high-confidence image-callback, recursive
    folder-loader, and YAJL JSON anchors. All eight names reopened
    successfully in the v30 disposable copy. The changed-size assignments
    use their callers and callback-table slots, while the three image
    callbacks also retain exact normalized bodies. See
    `artifacts/spectron_json_folder_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

93. Clean IDA review added 11 high-confidence resource-object anchors for
    resource insertion, comparison, links, encoded keys, object construction,
    alternatives, streams, and loadability. All 11 names reopened
    successfully in the v33 disposable copy. The changed-size assignments use
    class-local behavior, callers, and target signatures. See
    `artifacts/spectron_resource_object_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

94. Clean IDA review added seven high-confidence GS2 script-machine anchors
    for construction, destruction, executing-object setup, member resolution,
    assignment, and comparison. All seven reopened successfully in the v34
    disposable copy. The constructor and destructor rows account for the
    compiler-generated C1, C2, D1, and D2 signatures. See
    `artifacts/spectron_script_machine_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

95. Clean IDA review added eight high-confidence TScriptSpace event anchors
    for error cleanup, event registration, class leave handling, event-state
    lookup, and timeout scheduling. All eight reopened successfully in the v35
    disposable copy. The changed-size rows are supported by class-local order
    and decompiled behavior. See
    `artifacts/spectron_script_space_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

96. Clean IDA review added six high-confidence GS2 execution anchors for
    function invocation, action dispatch, caught-object handling, suspended
    caller wake-up, and action cleanup. All six reopened successfully in the
    v36 disposable copy. See
    `artifacts/spectron_script_execution_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

97. Clean IDA review added three high-confidence top-level GS2 dispatch anchors
    for script execution, action routing, and incoming event queueing. All
    three reopened successfully in the v37 disposable copy. See
    `artifacts/spectron_script_dispatch_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

98. Clean IDA review added six high-confidence GS2 scheduler and cleanup
    anchors for scheduled events, the main action loop, event-object unlinking,
    ignored events, and class replacement. All six reopened successfully in
    the v38 disposable copy. See
    `artifacts/spectron_script_scheduler_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

99. Clean IDA review added six high-confidence event-object and catcher-list
    anchors for construction, deleting destruction, catcher registration, and
    receive dispatch. All six reopened successfully in the v39 disposable
    copy. See
    `artifacts/spectron_event_object_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

100. Clean IDA review added two high-confidence `TScriptAction` lifecycle
     anchors for construction and destruction. Both reopened successfully in
     the v40 disposable copy. See
     `artifacts/spectron_script_action_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

101. Clean IDA review added three high-confidence `TScriptStackEntry` anchors
     for float, string, and object conversion. All three reopened successfully
     in the v41 disposable copy. See
     `artifacts/spectron_stack_entry_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

102. Clean IDA review added four high-confidence machine-helper anchors for
     execution restoration, character extraction, and action-context lookup.
     All four reopened successfully in the v42 disposable copy. See
     `artifacts/spectron_machine_helper_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

103. Clean IDA review added three high-confidence array-mutation anchors for
     single-cell, two-dimensional, and replacement writes. All three reopened
     successfully in the v43 disposable copy. See
     `artifacts/spectron_array_mutation_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

104. Clean IDA review added two high-confidence GS2 string-search anchors for
     all matching indices and substring positions. Both reopened successfully
     in the v44 disposable copy. See
     `artifacts/spectron_string_search_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

105. Clean IDA review added three high-confidence GS2 string-stack helper
     anchors for next-string retrieval, indexed retrieval, and formatting. All
     three reopened successfully in the v45 disposable copy. See
     `artifacts/spectron_string_helper_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

106. Clean IDA review added two high-confidence GS2 variable-construction
     anchors for script variable creation and legacy path resolution. Both
     reopened successfully in the v46 disposable copy. See
     `artifacts/spectron_variable_construction_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

107. Clean IDA review added two high-confidence GS2 script-object anchors for
     diagnostic line messages and object creation. Both reopened successfully
     in the v47 disposable copy. See
     `artifacts/spectron_script_object_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

108. Clean IDA review added two high-confidence GS2 script-state anchors for
     profiling and player-flag updates. Both reopened successfully in the v48
     disposable copy. See
     `artifacts/spectron_script_state_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

109. Clean IDA review added two high-confidence GS2 execution-dispatch anchors
     for script calls and native function dispatch. Both reopened successfully
     in the v49 disposable copy. See
     `artifacts/spectron_execution_dispatch_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

110. Clean IDA review added one high-confidence GS2 tokenizer anchor for
     tokenized string array construction. It reopened successfully in the v50
     disposable copy. See
     `artifacts/spectron_tokenizer_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

111. Clean IDA review added one high-confidence GS2 script-executor anchor for
     the bytecode execution loop. It reopened successfully in the v51
     disposable copy. See
     `artifacts/spectron_script_executor_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

112. Clean IDA review added nine high-confidence GS2 script-property anchors
     for typed reads, typed writes, construction, cloning, and property or
     function registration. All nine reopened successfully in the v52
     disposable copy. See
     `artifacts/spectron_script_property_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

113. Clean IDA review added eight high-confidence GS2 script-universe anchors
     for global variables, static objects, class loading, and zipped script
     packages. All eight reopened successfully in the v53 disposable copy.
     The zip compiler is represented as an IDA split function, with its short
     entry range and large associated instruction set recorded in the artifact.
     See `artifacts/spectron_script_universe_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

114. Clean IDA review added three high-confidence anchors for static
     script-variable construction, recursive JSON serialization, and tile
     definition persistence. All three reopened successfully in the v54
     disposable copy. See
     `artifacts/spectron_static_json_tiles_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

115. Clean IDA review added eight high-confidence anchors across tile
     selection, definition updates, temporary-tile reconciliation, and screen
     rendering. All eight reopened successfully in the v55 disposable copy.
     The two tile-block predicates were already covered by the core-helper
     artifact and were not duplicated. See
     `artifacts/spectron_tiles_update_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

116. Clean IDA review added five high-confidence particle-data anchors for
     animation names, player-look appearance restoration, template copying,
     and coded polygon setup. All five reopened successfully in the v56
     disposable copy. See
     `artifacts/spectron_particle_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

117. Clean IDA review added three high-confidence `TShowImg` anchors for
     mode-prefixed wire strings and indexed network-property encoding. All
     three reopened successfully in the v57 disposable copy. See
     `artifacts/spectron_showimg_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

118. Clean IDA review added two high-confidence particle-emitter anchors for
     static variable-list setup and the guarded emission path. Both reopened
     successfully in the v58 disposable copy. See
     `artifacts/spectron_particle_emitter_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

119. Clean IDA review added three high-confidence server-animation anchors for
     explosion, carry, and flying projectile behavior. All three reopened
     successfully in the v59 disposable copy. See
     `artifacts/spectron_server_animation_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

120. Clean IDA review added two high-confidence player lifecycle anchors for
     initial level loading and the periodic player timer. Both reopened
     successfully in the v60 disposable copy. See
     `artifacts/spectron_player_lifecycle_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

121. Clean IDA review added two high-confidence player emoticon-coordinate
     getter anchors for X and Y placement. Both reopened successfully in the
     v61 disposable copy. See
     `artifacts/spectron_player_emoticon_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

122. Clean IDA review added two high-confidence player level-entry anchors for
     main-level and server-level transitions. Both reopened successfully in
     the v62 disposable copy. See
     `artifacts/spectron_player_level_entry_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

123. Clean IDA review added four high-confidence player side-level anchors for
     grid setup, level loading, coordinate lookup, and directional occupancy.
     All four reopened successfully in the v63 disposable copy. See
     `artifacts/spectron_player_side_level_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

124. Clean IDA review added two high-confidence player map-position anchors for
     active-map refresh and map-link checks. Both reopened successfully in the
     v64 disposable copy. See
     `artifacts/spectron_player_map_position_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

125. Clean IDA review added three high-confidence player link-traversal anchors
     for level animation, nearby map links, and general object-link traversal.
     All three reopened successfully in the v65 disposable copy. See
     `artifacts/spectron_player_link_traversal_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

126. Clean IDA review added four high-confidence player weapon-state anchors
     for attribute reset, selected weapon removal and selection, and weapon
     lookup. All four reopened successfully in the v66 disposable copy. See
     `artifacts/spectron_player_weapon_state_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

127. Clean IDA review added five high-confidence player draw-state and visual
     setter anchors for the draw rectangle, head, body, sword, and shield
     paths. All five reopened successfully in the v67 disposable copy. See
     `artifacts/spectron_player_visual_setter_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

128. Clean IDA review added eight high-confidence player movement and
     interaction anchors for stone actions, jump checks, movement dispatch,
     item availability and loss, jump animation, and hurt handling. All eight
     reopened successfully in the v68 disposable copy. See
     `artifacts/spectron_player_movement_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

129. Clean IDA review added six high-confidence server-player state anchors for
     default initialization, head updates, level membership, nickname
     propagation, encoded properties, and weapon-image parsing. All six
     reopened successfully in the v69 disposable copy. See
     `artifacts/spectron_server_player_state_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

130. Clean IDA review added seven high-confidence server-NPC state anchors for
     construction, shape callbacks, log naming, default images, movement
     updates, and encoded properties. All seven reopened successfully in the
     v70 disposable copy. See
     `artifacts/spectron_server_npc_state_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

131. Clean IDA review added 17 high-confidence compact server-NPC accessor
     anchors for hurt displacement, blocking, layer, save state, power,
     coordinates, and visibility. All 17 reopened successfully in the v71
     disposable copy. See
     `artifacts/spectron_npc_accessor_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

132. Clean IDA review added two high-confidence server-NPC destructor anchors
     for complete destruction and the deleting-destructor wrapper. Both
     reopened successfully in the v72 disposable copy. See
     `artifacts/spectron_npc_destructor_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

133. Clean IDA review added eight high-confidence exact server-level and
     level-link property anchors for preload, dimensions, zone flags,
     tile-layer count, and destination level access. All eight reopened
     successfully in the v73 disposable copy. See
     `artifacts/spectron_server_level_property_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

134. Clean IDA review added five high-confidence server-level interaction
     anchors for level-link coordinates and indexed explosion, bomb, and arrow
     removal. All five reopened successfully in the v74 disposable copy. See
     `artifacts/spectron_server_level_interaction_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

135. Clean IDA review added seven high-confidence exact server-level lifecycle,
     script-test, and animation helper anchors. All seven reopened successfully
     in the v75 disposable copy. See
     `artifacts/spectron_server_level_lifecycle_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

136. Clean IDA review added four high-confidence server-level side-level and
     flower-hook anchors. The side-level methods preserve the source lookup
     roles across Spectron's expanded grid, and the two flower hooks are exact
     empty-body matches. All four reopened successfully in the v76 disposable
     copy. See
     `artifacts/spectron_server_level_side_helpers_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

137. Clean IDA review added four high-confidence server-level construction,
     encrypted storage, and player-enter dispatch anchors. Their control-flow
     shapes and serialized-format or event-dispatch roles match the 1.8
     functions, with documented 2.2 wrapper-size changes. All four reopened
     successfully in the v77 disposable copy. See
     `artifacts/spectron_server_level_storage_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

138. Clean IDA review recovered the unnamed Spectron `testnpc` callback body at
     `0x1a9bb0` to `0x1a9c2c`, added its explicit function boundary, and applied
     one exact high-confidence label. It reopened successfully in the v78
     disposable copy. See
     `artifacts/spectron_hidden_testnpc_manual_translation_anchor_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

139. Clean IDA review added six high-confidence level and map helper anchors for
     normalized level lookup, level-list indexing, link serialization, current
     map selection, GMAP loading, and map placeholder construction. All six
     reopened successfully in the v79 disposable copy. See
     `artifacts/spectron_level_map_lookup_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

140. Clean IDA review added one high-confidence `TGaniObject` constructor
     anchor. The target preserves the animation-parameter and color-variable
     initialization, including the `attr` and `black` literals. It reopened
     successfully in the v80 disposable copy. See
     `artifacts/spectron_gani_constructor_manual_translation_anchor_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

141. Clean IDA review added two high-confidence Gani helper anchors for the
     color-variable string setter and sprite image-name selection. Both
     reopened successfully in the v81 disposable copy. See
     `artifacts/spectron_gani_helper_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

142. Clean IDA review added four high-confidence Gani runtime anchors for
     matrix setup, parameter and attribute access, and animation start. All
     four reopened successfully in a serial check of the v82 disposable copy.
     See `artifacts/spectron_gani_runtime_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

143. Clean IDA review added three high-confidence Gani serialization and draw
     anchors for parameter decoding, animation reload, and player rendering.
     All three reopened successfully in the v83 disposable copy. See
     `artifacts/spectron_gani_render_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

144. Clean IDA review added two high-confidence Gani frame and playback
     anchors for the complete frame-property pipeline and animation loop.
     Both reopened successfully in the v84 disposable copy. See
     `artifacts/spectron_gani_frame_playback_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

145. Clean IDA review added 50 high-confidence Gani lifecycle anchors. The set
     covers GaniObject teardown, inherited accessors, virtual hooks, property
     destructor pairs, event forwarding, TColorVar cleanup, animation flags,
     owner-list operations, encrypted script loading and saving, type
     classification, construction, cache cleanup, resource loading, and
     static property setup. All 50 reopened successfully in the v85 disposable
     copy. The full semantic-label reopen check also passed with zero failures.
     See `artifacts/spectron_gani_lifecycle_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

146. Clean IDA review added two high-confidence TPlayer core anchors. The set
     covers the network-property serializer and integer constructor, with
     matching property cases, field use, initialization order, and preserved
     literals. Both reopened successfully in the v86 disposable copy. The
     full semantic-label reopen check still passed with zero failures. See
     `artifacts/spectron_tplayer_core_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

147. Clean IDA review added three high-confidence resource and parser anchors.
     The set covers the generated Gani lexer, cached-resource path selection,
     and update-package directive loading. All three reopened successfully in
     the v87 disposable copy. The full semantic-label reopen check still
     passed with zero failures. See
     `artifacts/spectron_resource_parser_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

148. Clean IDA review added five high-confidence static utility anchors. The
     set covers engine statistics, profiler output, GUI button styles, ZIP
     resource scanning, and translation plural rules. All five reopened
     successfully in the v88 disposable copy. The full semantic-label reopen
     check still passed with zero failures. See
     `artifacts/spectron_static_utility_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

149. Clean IDA review added four high-confidence font and bitmap anchors. The
     set covers glyph setup, font atlas generation, font resource loading, and
     bitmap loading with retry behavior. All four reopened successfully in
     the v89 disposable copy. The full semantic-label reopen check still
     passed with zero failures. See
     `artifacts/spectron_font_bitmap_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

150. The next IDA pass translated the large MNG animation-step decoder. The
     source and target both contain 4,081 instructions and 16,324 bytes, with
     matching pixel-pass helpers and four-call structure. The target has one
     additional basic block as a rebuild difference. The label reopened
     successfully in the v90 disposable copy. See
     `artifacts/spectron_mng_animation_manual_translation_anchor_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

151. The following IDA pass translated two adjacent script-machine methods:
     function-parameter preparation and native callback dispatch. The target
     keeps the same stack conversions, callback packing, and result updates,
     while adding newer string handling and an `e` parameter type. Both labels
     reopened successfully in the v91 disposable copy. See
     `artifacts/spectron_script_machine_tail_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

152. The next IDA pass translated the remaining script stream parser and
     function/class profile printer. The target keeps the GS2 record walk,
     `public.` handling, function registration, timing, sorting, and `Class `
     output. It uses rebuilt wrappers and long-double profile temporaries, and
     does not expose the source's separate percent literal reference. Both
     labels reopened successfully in the v92 disposable copy. See
     `artifacts/spectron_script_stream_profile_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

153. The next IDA pass translated the generated animation-lexer fatal
     callback. The target is called by the already translated lexer and has
     the same compact exit-wrapper shape, but calls `exit(0)` instead of the
     source's `exit(2)`. The label reopened successfully in the v93 disposable
     copy. See
     `artifacts/spectron_ani_lexer_fatal_manual_translation_anchor_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

154. The next IDA pass translated eight double and short numeric-array string
     methods: indexed setters, indexed reads, comma-separated reads, and
     string-list writes. The labels reopened successfully in the v94 disposable
     copy. See
     `artifacts/spectron_number_array_string_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

155. The next IDA pass translated the client-environment build-time and
     time-expiry helpers. The source uses a fixed 2019-02-13 date and 15-day
     window, while Spectron reads both values from globals. Both labels
     reopened successfully in the v95 disposable copy. See
     `artifacts/spectron_client_environment_clock_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

156. The next IDA pass translated three `TGraalClientVar` methods covering
     flag send and unset, string change suppression, and indexed string change
     suppression. The labels reopened successfully in the v96 disposable copy.
     See
     `artifacts/spectron_client_var_core_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

157. The next IDA pass translated four `TStringList` comma-text methods covering
     quoted parsing, construction, single-quote serialization, and double-quote
     serialization. The labels reopened successfully in the v97 disposable
     copy. The target constructor carries an additional byte flag, and the
     rebuilt string wrapper makes the parser and serializer call counts differ,
     so these are semantic anchors rather than exact byte matches. See
     `artifacts/spectron_tstringlist_comma_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

158. The next IDA pass translated seven extended `TStringList` methods covering
     assignment, range append, key/value access, newline serialization, file
     output, and tokenization. The labels reopened successfully in the v98
     disposable copy. The target keeps the same list and tokenizer decisions
     while exposing rebuilt string-wrapper calls and fewer standalone literal
     references. See
     `artifacts/spectron_tstringlist_extended_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

159. The next IDA pass translated nine `THashList` and `THashStrings` methods
     covering bucket lookup, case folding, encoded lookup, list assignment,
     sorting, value updates, and name/value serialization. The labels reopened
     successfully in the v99 disposable copy. The target hash-list assignment
     has a narrower boolean signature and omits the source encoded-add branch,
     which is documented as a behavior difference. See
     `artifacts/spectron_hash_family_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

160. The next IDA pass translated seven `TOptions` methods covering GUI-style
     change events, decoded nickname, account, and password getters, account
     persistence, and the options refresh timer. The labels reopened
     successfully in the v100 disposable copy. The two style targets were
     default `sub_` names before translation, and the target account setter
     uses `accountname_new` where 1.8 uses `accountname`. See
     `artifacts/spectron_options_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

161. The next IDA pass translated ten `TTexture` methods covering bitmap
     dimensions, GPU texture creation and dimensions, construction and
     destruction, Graal bitmap lookup, registry cleanup, and static registry
     initialization. The labels reopened successfully in the v101 disposable
     copy. The target preserves the lazy-load and registry behavior while
     exposing typed string wrappers and extra Graal overloads. See
     `artifacts/spectron_texture_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

162. The next IDA pass translated five `TDrawingPanelTexture` methods covering
     both destructors, the window-backed constructor, and GPU texture width
     and height accessors. The labels reopened successfully in the v102
     disposable copy. See
     `artifacts/spectron_drawing_panel_texture_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

163. The next IDA pass translated four `TDrawTexture` methods covering static
     texture-list initialization, global cleanup, full reload, and OpenGL
     binding. The labels reopened successfully in the v103 disposable copy.
     The static initializer was a default `sub_` target before translation.
     See `artifacts/spectron_draw_texture_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

164. The next IDA pass translated five `TBitmapArrayHolder` methods covering
     construction, destruction, rectangle discovery, lazy rectangle lookup,
     and bitmap-array registry initialization. The labels reopened
     successfully in the v104 disposable copy. See
     `artifacts/spectron_bitmap_array_holder_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

165. The next IDA pass translated five `TColorManager` methods covering
     activation, top-entry lookup, transform-stack cleanup, top-entry removal,
     and matrix-list initialization. The labels reopened successfully in the
     v105 disposable copy. See
     `artifacts/spectron_color_manager_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

166. The next IDA pass translated six font and resource methods covering TFont
     construction and texture creation, TFontManager file lookup and static
     registries, UTF-8 range registration, and TFontData construction. The
     labels reopened successfully in the v106 disposable copy. See
     `artifacts/spectron_font_runtime_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

167. The next IDA pass translated two `TWindow` input methods covering mouse
     normalization, cursor adjustment, key normalization, control bindings,
     and control-key events. The labels reopened successfully in the v107
     disposable copy. See
     `artifacts/spectron_window_input_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

168. The next IDA pass translated six `TDrawingPanel` methods covering both
     constructors, image wrappers, named image filters, and named palette
     selection. The labels reopened successfully in the v108 disposable copy.
     See
     `artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

169. The next IDA pass translated four HTML color and image-animation methods
     covering dual-list color registry construction, animation construction,
     complete destruction, and deleting-destruction delegation. The labels
     reopened successfully in the v109 disposable copy. See
     `artifacts/spectron_image_html_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

170. The next IDA pass translated four panel and bitmap-loader methods covering
     window-backed panel construction, extension dispatch, forced redownload,
     and level-image lookup. The labels reopened successfully in the v110
     disposable copy. See
     `artifacts/spectron_panel_bitmap_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

171. The next IDA pass translated the changed `TBitmap` GIF decoder, including
     animation-step construction, transparency and delay handling, and the
     target's explicit error diagnostics. The label reopened successfully in
     the v111 disposable copy. See
     `artifacts/spectron_gif_decoder_manual_translation_anchor_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

172. The next IDA pass translated two residual `TWindow` methods covering
     main-window close-query shutdown and the window-backed pixel-buffer
     factory. The labels reopened successfully in the v112 disposable copy.
     See
     `artifacts/spectron_window_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
173. The next IDA pass translated three residual sound-runtime methods covering
     sound dispatch and caching, note-based pitch calculation, and Java sound
     playback. The labels reopened successfully in the v113 disposable copy.
     The target keeps the source extension, cache, `powf`, and
     `startSound([BII)V` responsibilities. Its missing `steps` special case
     and the unresolved sound-effect constructor remain explicit differences.
     See
     `artifacts/spectron_sound_runtime_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
174. The next IDA pass translated ten residual `TPixelBuffer` methods covering
     field setters, pointer clearing, lazy pixel allocation, and the base
     texture hooks. The labels reopened successfully in the v114 disposable
     copy. The three empty base hooks and the indirect rectangle update remain
     explicitly separate from the derived OpenGL implementation. See
     `artifacts/spectron_pixelbuffer_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
175. The next IDA pass corrected one medium-confidence destructor collision and
     translated four lifecycle rows for the separate `TPixelBuffer` and
     `TBitmap` target classes. The labels reopened successfully in the v115
     disposable copy. See
     `artifacts/spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
176. The next IDA pass translated four image-animation and palette residual
     methods covering the two zero-return base hooks and the MNG or palette
     deleting destructors. The labels reopened successfully in the v116
     disposable copy. See
     `artifacts/spectron_animation_palette_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
177. The next IDA pass translated 23 panel and renderer residual methods. It
     covers the 18 panel-interface base hooks, the inherited panel-port flush
     hook, screen-capture and pixel hooks, and the graphic-operation texture
     flush loop. The target has one explicit 2.2-only panel hook inserted
     after `setArrays`; it remains unlabeled because there is no 1.8 source
     counterpart. The labels reopened successfully in the v117 disposable
     copy. See
     `artifacts/spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
178. The next IDA pass translated 14 residual methods at the panel-interface
     and dummy-panel boundary. It covers three empty `TPanelInterface` hooks,
     the `TDummyPanel` draw and clipping hooks, the zero-return panel factory,
     and the complete or deleting destructor pair. The labels reopened
     successfully in the v118 disposable copy. See
     `artifacts/spectron_dummy_panel_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
179. The next IDA pass translated ten residual concrete renderer methods. It
     covers the OpenGL pixel-buffer texture predicate, projection and model
     matrix copies, the triangle-strip hook, shader hooks, and alpha-reference
     wrapper. The labels reopened successfully in the v119 disposable copy.
     See
     `artifacts/spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
180. The next IDA pass translated seven residual screen-panel and GLES-window
     methods. It covers the polygon-font stub, offscreen and resize hooks,
     complete and deleting destructors, the window-backed pixel-buffer
     factory, and the native-mode predicate. The labels reopened successfully
     in the v120 disposable copy. See
     `artifacts/spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
181. The next IDA pass translated nine residual font and font-manager methods.
     It covers font and character-info deleting destructors, texture binding,
     ascent and descent calculations, font-cache cleanup, and manager text
     metric helpers. The labels reopened successfully in the v121 disposable
     copy. See
     `artifacts/spectron_font_manager_font_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
182. The next IDA pass translated 16 residual screen-panel, font-option,
     font-data, and window-properties methods. It covers the screen-panel
     native predicate and destructor pair, six font-option accessors, the
     font-data deleting destructor and hash-list helpers, and the
     window-properties destructor family with both adjusted-this thunks. The
     labels reopened successfully in the v122 disposable copy. See
     `artifacts/spectron_font_options_font_data_residual_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
183. The next IDA pass translated 89 residual `GuiControlProfile` accessors.
     It covers scalar fields, alignment and point wrappers, font-style
     strings, color setters and getters, background inset, resource-file
     notification, and the profile font-color helper. The labels reopened
     successfully in the v123 disposable copy, with the target-only method
     and two source coverage gaps left explicit. See
     `artifacts/spectron_gui_control_profile_accessor_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.
184. The next IDA pass translated six residual `GuiControlProfileProperties`
     and `GuiControlProfile` destructor-family methods. It covers four exact
     properties destructor and thunk rows plus the two main profile
     destructors with their documented 2.2 layout growth. The labels reopened
     successfully in the v124 disposable copy. See
     `artifacts/spectron_gui_control_profile_destructor_manual_translation_anchors_20260826.json`
     and `artifacts/spectron_translation_checkpoint_20260826.json`.

185. The next IDA pass translated 61 residual `GuiControl` property and
    script-wrapper methods. Their source and Spectron blocks align at a fixed
    `+0x4500` delta, and all 61 pairs have exact normalized shape matches.
    Seven rows inside the enclosing sequence were already mapped, while the
    target-only helper at `0x1b7078` remains an explicit gap. The labels
    reopened successfully in the v125 disposable copy. See
    `artifacts/spectron_guicontrol_property_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

186. The next IDA pass translated 13 residual `GuiControl` base and
    virtual-hook methods. They align with the Spectron `w9XxgaJdbx` class at
    a fixed `+0x41c0` delta, with exact normalized shapes and no string
    references. The labels reopened successfully in the v126 disposable
    copy without changing the default `sub_` count. See
    `artifacts/spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

187. The next IDA pass translated eight residual `GuiControl` event and sizing
    methods. They align with the target class at a fixed `+0x4500` delta, with
    exact normalized shapes and no string references. Six enclosing rows were
    already mapped, and the unnamed source `sub_1B2FDC` row remains explicit.
    The labels reopened successfully in the v127 disposable copy. See
    `artifacts/spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

188. The next IDA pass translated 12 residual `GuiControl` style, geometry,
    profile, and color methods. Eleven pairs are exact shape matches, while
    `getStyle` records the target's explicit wrapper growth and the resulting
    `+0x4534` alignment shift. The labels reopened successfully in the v128
    disposable copy, which has 1,514 default `sub_` functions remaining. See
    `artifacts/spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

189. The next IDA pass translated eight residual `GuiControl` event-dispatch
    methods. Six target bodies expand around encoded event strings and
    temporary wrappers, while both mouse-wheel methods are exact shape
    matches. The labels reopened successfully in the v129 disposable copy,
    which retains 1,514 default `sub_` functions. See
    `artifacts/spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

190. The next IDA pass translated two residual `GuiControl` initialization
    methods. It covers the complete field and child-list initializer and the
    parameterized C2 constructor. The labels reopened successfully in the
    v130 disposable copy, which retains 1,514 default `sub_` functions. See
    `artifacts/spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

191. The next IDA pass resolved the remaining `GuiControl_create_TString_const`
    factory ambiguity. The source and target wrappers have identical
    normalized metrics and both allocate `0x1c8` bytes before calling the
    parameterized constructor. The label reopened successfully in the v131
    disposable copy, which retains 1,514 default `sub_` functions. See
    `artifacts/spectron_guicontrol_create_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

192. The next IDA pass translated 19 residual `TSocket` accessor, output, and
    factory methods. Eighteen pairs are exact normalized-shape matches, and
    the remaining allowed-port setter is a documented wrapper layout change.
    The labels reopened successfully in the v132 disposable copy, which has
    1,497 default `sub_` functions. See
    `artifacts/spectron_tsocket_accessor_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

193. The next IDA pass translated four residual `TSocket` SSL and
    outgoing-buffer methods. All four pairs are exact normalized-shape
    matches, and the labels reopened successfully in the v133 disposable
    copy, which retains 1,497 default `sub_` functions. See
    `artifacts/spectron_tsocket_ssl_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

194. The next IDA pass translated two residual `TSocket` receive methods:
    package splitting and native reads. The labels reopened successfully in
    the v134 disposable copy, which retains 1,497 default `sub_` functions.
    See
    `artifacts/spectron_tsocket_receive_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

195. The next IDA pass translated four residual `TSocket` lifecycle methods:
    `preDestroy`, `checkAllowBind`, `bind`, and `runScript`. The nearby
    `checkScriptActive` row was already present in the semantic map and was
    preserved as a boundary. All four labels reopened successfully in the
    v135 disposable copy, which retains 1,497 default `sub_` functions. See
    `artifacts/spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

196. The next IDA pass translated three residual `TSocket` host and logging
    helpers: cached IPv4 storage, the SSL logging callback thunk, and host
    resolution. The nearby plain send and receive helpers were already in the
    semantic map. All three labels reopened successfully in the v136
    disposable copy, which retains 1,495 default `sub_` functions. See
    `artifacts/spectron_tsocket_host_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

197. The next IDA pass translated the four-function `TSocketProperties`
    destructor family: complete and deleting destructors plus both
    non-virtual thunks. All four labels reopened successfully in the v137
    disposable copy, which retains 1,495 default `sub_` functions. See
    `artifacts/spectron_tsocket_properties_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

198. The next IDA pass translated five socket-cache support methods: static
    initialization, host and port matching, and the complete and deleting
    cached-host destructors. All five labels reopened successfully in the
    v138 disposable copy, which retains 1,495 default `sub_` functions. See
    `artifacts/spectron_socket_cache_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

233. The next IDA pass translated the exact-shape `TString_clear_void` method.
    The target class-qualified name and sibling method cluster resolve the
    otherwise identical-shape `CanTfaz6bZ::clear` collision. The alias reopened
    successfully in the v175 disposable copy, which has 11,694 functions,
    3,641 high-confidence labels, and 1,250 default `sub_` names. See
    `artifacts/spectron_tstring_clear_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tstring_clear_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

234. The next IDA pass translated two static cleanup callbacks:
    `TClient_clearStaticStrings` and `TSocket_clearStaticStrings`. Their
    target classes are `w6qzgacqqy` and `XJLBgarMnA`, established by the
    surrounding client and socket method families. The target bodies add one
    target-only string cleanup apiece, so both rows are recorded as reviewed
    layout-change anchors. Both aliases reopened successfully in the v176
    disposable copy, which has 11,694 functions, 3,641 high-confidence labels,
    and 1,248 default `sub_` names. See
    `artifacts/spectron_static_clear_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_static_clear_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

235. A follow-up IDA data-reference audit corrected the older review role for
    source callback `0xe06a8`. Its three cleared objects belong to the old
    Android TapJoy and video state group, and `TServerFlying::animate` has zero
    references to them. The descriptive source role is
    `Android_TapJoy_video_clearStaticStrings`. No target alias was applied:
    target `0xe0220` is request state and target `0xe0438` is a separate video
    and Android runtime group. See
    `artifacts/spectron_static_callback_role_correction_20260827.json`,
    `tools/generate_spectron_static_callback_role_correction.py`, and
    `tools/ida_dump_function_data_refs.py`.

244. The next IDA pass translated the named `TClientEnvironment_clearRestartState`
    callback. Source `0xe0814` maps to target `0xdfdb4`, whose cleanup-table
    slot, `a7qxJaHqKV` field set, `sub_E0970` initializer, and restart-path
    uses identify the same saved-restart state. The target adds one
    `CanTfaz6bZ` cleanup, so this is recorded as a layout change. The v185
    copy has 11,694 functions, 3,641 high-confidence labels, and 1,233
    default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_client_environment_restart_state_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_client_environment_restart_state_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

245. The next IDA pass translated `TParticleEmitter_initStaticScriptVars_void`.
    Source `0x23b348` maps to target `0x2451f4`, which constructs the target
    modifier and emitter property classes already matched to the 1.8
    constructors. The pair is an exact normalized-shape match with 76 bytes,
    19 instructions, one block, five branches, four calls, and one return.
    The v186 copy has 11,694 functions, 3,641 high-confidence labels, and
    1,233 default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_particle_emitter_script_vars_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_particle_emitter_script_vars_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

268. The next IDA pass resolved eight small `GuiTextListCtrl` methods. They
    cover the cell-size getter, sort-column property, clear-rows and
    remove-row wrappers, text and numerical sorting, and column-offset
    insertion. The Spectron pseudocode places them in the obfuscated
    `u0eyga1eqx` class, and every complete feature field matches. Four target
    `sub_` names were replaced by `v18_` aliases. The labels reopened
    successfully in the v209 copy, which has 11,694 functions, 3,641
    high-confidence labels, and 1,213 default `sub_` names, with zero semantic
    reopen failures. See
    `artifacts/spectron_gui_text_list_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_gui_text_list_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

269. The next IDA pass resolved six small hash-container lifecycle helpers.
    They cover the `THashListObject` and `THashListLink` constructors, the
    `THashString` value setter, both `THashListIterator` lifecycle methods,
    and `THashStringsIterator_use_THashStrings`. Their target pseudocode
    preserves the source field writes, iterator registration and removal, and
    next-object search across the obfuscated `J7zOgaf09K`, `U1slUah2F0`,
    `NYF9TaOVKR`, `R_MvgaEQlv`, and `Zb7cUaSFEU` classes. Five rows match every
    recorded feature. The remaining constructor differs only in register
    detail, while its normalized shape matches. All six aliases reopened
    successfully in the v210 copy, which has 11,694 functions, 3,641
    high-confidence labels, and 1,213 default `sub_` names, with zero semantic
    reopen failures. See
    `artifacts/spectron_hash_lifecycle_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_hash_lifecycle_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

270. The next IDA pass resolved three small `GuiTextListEntry` property
    helpers: the flickertime getter and setter and the profile fallback getter.
    Their target pseudocode is identical to the source, including the `+144`,
    `+200`, and `+208` receiver fields, and their callback references occupy
    the matching property-table slots. All three target `sub_` names were
    replaced by `v18_` aliases and reopened successfully in the v211 copy,
    which has 11,694 functions, 3,641 high-confidence labels, and 1,210
    default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_gui_text_list_entry_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_gui_text_list_entry_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

271. The next IDA pass resolved three compact encryption and script-variable
    helpers. `TEncryption_initStaticScriptVars_void` maps to the target
    property-registration bridge with the same 15-entry count. The
    `TGraalVar_isPaused_void` and `TGraalVar_setProtectedObject_int` methods
    map into the target `G0gxgajWBw` class and preserve receiver offsets `+17`
    and `+18`. All three target ABI names received `v18_` aliases and reopened
    successfully in the v212 copy, which has 11,694 functions, 3,641
    high-confidence labels, and 1,210 default `sub_` names, with zero semantic
    reopen failures. See
    `artifacts/spectron_encryption_graalvar_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_encryption_graalvar_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

272. The next IDA pass resolved 13 compact residual helpers that fall below
    the broad semantic matcher cutoff. They cover TGaniObject and TPlayer
    properties, drawing-panel cache state, TClient inbound handlers,
    TCachedStream cache-size setters, TFileDownload script callbacks,
    TCallStackEntry, and TScriptUniverse. Property-table and handler-table
    positions disambiguate the short bodies. All 13 rows match normalized
    shape; two match every feature and 11 differ only in register detail. One
    child-field getter records a source `+748` to target `+772` layout shift.
    Twelve default target names were replaced because the clear-files target
    already had an ABI name. The aliases reopened successfully in the v213
    copy, which has 11,694 functions, 3,641 high-confidence labels, and 1,198
    default `sub_` names, with zero semantic reopen failures. The source
    `TFileDownload_canDownload_void` body remains a folded-body note because
    its client-present predicate shares the translated TPlayer online target
    and has no distinct target table entry. See
    `artifacts/spectron_compact_residual_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_compact_residual_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

273. The next IDA pass resolved four methods from the compact
    `T2DMatrixManager` block. The target ABI names place them in
    `AUzMgaePtJ`, and the target pseudocode preserves the activation test,
    top-entry lookup, matrix deletion loop, and pop operation. All four rows
    match normalized shape and differ only in register detail. The aliases
    reopened successfully in the v214 copy, which has 11,694 functions,
    3,641 high-confidence labels, and 1,198 default `sub_` names, with zero
    semantic reopen failures. The matching static initializer remains
    deferred because its compact shape collides with several unrelated target
    initializers. See
    `artifacts/spectron_t2d_matrix_manager_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_t2d_matrix_manager_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

274. The next IDA pass resolved 29 methods from the compact random-generator
    family. The shared `MRandomGenerator` constructors map to `o3AZxayNqc`,
    the LCG block maps to `Vx2_xajLEd`, and the R250 block maps to
    `ZwL1xarB5e`. The set includes constructors, factories, property
    destructors and thunks, object destructors, and the process-wide
    generator initializer. All 29 rows match normalized shape; eight match
    every feature and 21 differ only in register detail. The aliases reopened
    successfully in the v215 copy, which has 11,694 functions, 3,641
    high-confidence labels, and 1,198 default `sub_` names, with zero
    semantic reopen failures. The static initializer is now resolved by its
    `Lry_xa0Aed` target global and contiguous `Vx2_xajLEd` class context. See
    `artifacts/spectron_mrandom_family_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_mrandom_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

275. The next IDA pass resolved the four remaining reviewed `TStringList`
    methods: the deleting destructor wrapper, repeated-value removal,
    case-insensitive lookup, and indexed string access. The target block is
    the obfuscated `vuuHgangcF` class and its rebuilt `CanTfaz6bZ` and
    `C8THgaTQxF` string wrappers. Three rows match every recorded feature
    metric. The case-insensitive lookup is a reviewed layout-change row
    because Spectron adds temporary wrapper conversion and cleanup. The
    aliases reopened successfully in the v216 copy, with zero semantic
    reopen failures. See
    `artifacts/spectron_tstringlist_residual_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tstringlist_residual_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

276. The next IDA pass resolved 49 residual methods across the contiguous
    `TExplosion`, `TServerBomb`, `TServerChest`, `TServerExtra`,
    `TServerFlying`, `TServerLeap`, and `TServerSign` blocks. The rows cover
    compact getters, level-bound constructors, native and script-property
    initializers, property destructors, object destructors, and deleting
    destructor wrappers. All 49 rows match normalized shape; nine match every
    feature and 40 differ only in register detail. Seven default target names
    were replaced. The aliases reopened successfully in the v217 copy, which
    has 11,694 functions, 3,641 high-confidence labels, and 1,191 default
    `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_server_object_lifecycle_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_server_object_lifecycle_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

277. The next IDA pass resolved 39 residual `GuiMLTextCtrl` rows in the
    stripped Spectron library. The pass covers field and HTML-page accessors,
    script line and text wrappers, selection state, reflow, mouse input, the
    style hook, and the control and property destructor entries. Twenty-seven
    rows match every recorded feature metric, 30 preserve normalized shape,
    and nine are explicit layout-change correspondences caused by rebuilt
    string-wrapper or base-control code. All 39 aliases reopened successfully
    in v218, which has 11,694 functions, 3,641 high-confidence labels, and
    1,165 remaining default `sub_` names. See
    `artifacts/spectron_gui_ml_text_residual_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_gui_ml_text_residual_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

278. The v219 IDA pass resolved 30 residual GUI text-list property accessors.
    The source and target property tables preserve the same order, and IDA
    pseudocode confirms the same byte, integer, or pointer-presence operation
    for each row. All 30 rows match the normalized and full feature metrics,
    and all 30 names reopened successfully with zero failures. The v219 copy
    has 11,694 functions and 1,135 remaining default `sub_` names. See
    `artifacts/spectron_gui_text_list_entry_property_manual_translation_anchors_20260828.json`,
    `tools/generate_spectron_gui_text_list_entry_property_anchors.py`, and
    `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v219.i64`.

279. The v220 IDA pass resolved ten adjacent GUI text-list methods covering
    sort-order getters and setters, hint and geometry accessors, and the
    script-facing profile setter. All ten rows match normalized shape, four
    match the complete metric set, and all ten names reopened successfully.
    The v220 copy has 11,694 functions and 1,125 remaining default `sub_`
    names. See
    `artifacts/spectron_gui_text_list_residual_manual_translation_anchors_20260828.json`,
    `tools/generate_spectron_gui_text_list_residual_anchors.py`, and
    `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v220.i64`.

280. The v221 IDA pass resolved 16 residual drawing-panel and ShowImg GUI
    property callbacks. Six cover panel rectangle, cache, and filter
    properties, while ten cover ShowImg offsets, layer, direction, animation,
    and image-position refresh behavior. All 16 rows match normalized shape,
    15 match the complete metric set, and all names reopened successfully.
    The v221 copy has 11,694 functions and 1,109 remaining default `sub_`
    names. Two nearby target-only cleanup helpers were reviewed and left
    unaliased because no 1.8 counterpart was demonstrated. See
    `artifacts/spectron_gui_drawing_showimg_property_manual_translation_anchors_20260828.json`,
    `tools/generate_spectron_gui_residual_property_anchors.py`, and
    `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v221.i64`.

281. The v222 IDA pass resolved the three residual `GuiBrowserCtrl` property
    getters for allow-zoom, URL, and text. All three rows match the complete
    recorded feature set, and all names reopened successfully. The v222 copy
    has 11,694 functions and 1,106 remaining default `sub_` names. See
    `artifacts/spectron_gui_browser_property_manual_translation_anchors_20260828.json`,
    `tools/generate_spectron_gui_browser_property_anchors.py`, and
    `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v222.i64`.

282. The v223 IDA pass resolved five residual `GuiContextMenuCtrl` callbacks
    for popup height, close, open state, and width. All five rows match the
    complete recorded feature set, and all names reopened successfully. The
    v223 copy has 11,694 functions and 1,101 remaining default `sub_` names.
    See
    `artifacts/spectron_gui_context_menu_property_manual_translation_anchors_20260828.json`,
    `tools/generate_spectron_gui_context_menu_property_anchors.py`, and
    `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v223.i64`.

283. The v224 IDA pass resolved six residual array and popup GUI callbacks.
    Five rows match the complete recorded feature set, and the context-menu
    rows lookup is a high-confidence wrapper-change correspondence. All six
    names reopened successfully. The v224 copy has 11,694 functions and
    1,095 remaining default `sub_` names. See
    `artifacts/spectron_gui_array_popup_residual_manual_translation_anchors_20260828.json`,
    `tools/generate_spectron_gui_array_popup_residual_anchors.py`, and
    `/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v224.i64`.

267. The next IDA pass resolved eight small `THTMLPage` methods. They cover
    font-pointer cleanup, dirty and word-wrap state, parse tags, selection,
    URL and line initialization, and tab-stop replacement. The Spectron
    targets all belong to the obfuscated `AS80gaE4zW` class family, and every
    complete feature field matches. The aliases reopened successfully in the
    v208 copy, which has 11,694 functions, 3,641 high-confidence labels, and
    1,217 default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_html_page_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_html_page_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

266. The next IDA pass resolved the complete `TSoundPlayerJava` D1 destructor.
    Source `0xe35c8` maps to target `ohGYZakbFKD1Ev` at `0xe417c`, directly
    before the D0 destructor already translated at `0xe4190`. Both bodies
    install their class vtable and clear the embedded string without deleting
    the object. The normalized shape matches with only register detail
    differing. The alias reopened successfully in the v207 copy, which has
    11,694 functions, 3,641 high-confidence labels, and 1,217 default `sub_`
    names, with zero semantic reopen failures. See
    `artifacts/spectron_sound_java_d1_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sound_java_d1_anchor.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

265. The next IDA pass resolved three remaining `TSounds` tail methods.
    `TSounds_stopSFX_TString_const` at `0xe0ea4` maps to target `0xe1a78`,
    `TSounds_script_setSoundPitch` at `0xe2a7c` maps to target `0xe366c`, and
    `TSounds_initStaticVars_void` at `0xe2a88` maps to target `0xe3678`.
    The first two are exact complete feature matches. The initializer keeps
    the same one-block allocation order and call structure, with the target
    second helper allocation changing from `0x18` to `0x20`. All three
    aliases reopened successfully in the v206 copy, which has 11,694
    functions, 3,641 high-confidence labels, and 1,217 default `sub_` names,
    with zero semantic reopen failures. See
    `artifacts/spectron_sounds_tail_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sounds_tail_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

264. The next IDA pass resolved 18 short Java sound interface methods.
    Fourteen `TSoundPlayer` base methods map to the `gqiNgaG64J` target table,
    two `TSoundEffectJava` capability methods map to `QPh5pbnC3y`, and two
    `TSoundPlayerJava` capability methods map to `ohGYZakbFK`. Every recorded
    feature matches exactly, and the method-table order and decompiled stub
    behavior agree. All 18 aliases reopened successfully in the v205 copy,
    which has 11,694 functions, 3,641 high-confidence labels, and 1,218
    default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_sound_base_interface_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sound_base_interface_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

263. The next IDA pass resolved the two Java sound deleting-destructor
    wrappers. Source `TSoundEffectJava_TSoundEffectJava__2` at `0xe2c14` maps
    to `QPh5pbnC3yD0Ev` at `0xe3804`; source
    `TSoundPlayerJava_TSoundPlayerJava__2` at `0xe360c` maps to
    `ohGYZakbFKD0Ev` at `0xe4190`. The constructor-shaped source names are
    deleting destructors because both bodies call the complete destructor and
    then `operator delete`. Both aliases reopened successfully in the v204
    copy, which has 11,694 functions, 3,641 high-confidence labels, and 1,218
    default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_sound_java_destructor_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sound_java_destructor_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

262. The next IDA pass resolved seven small Java sound bridge methods. The
    two `TSoundPlayerJava` rows map to target class `ohGYZakbFK`, and the five
    `TSoundEffectJava` rows map to target class `QPh5pbnC3y`. Their source and
    target method-table records, receiver behavior, class-local order, and
    complete ARM64 feature fingerprints agree. All seven aliases reopened
    successfully in the v203 copy, which has 11,694 functions, 3,641
    high-confidence labels, and 1,218 default `sub_` names, with zero
    semantic reopen failures. See
    `artifacts/spectron_sound_java_small_methods_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sound_java_small_methods_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

261. The next IDA pass resolved the complete seven-method `TSoundEffect`
    virtual interface. Source methods from `0xe2b24` through `0xe2b4c` map in
    method-table order to target `fEVMgax6LJ` methods from `0xe3714` through
    `0xe373c`. Every recorded feature matches exactly, including register
    detail. All seven aliases reopened successfully in the v202 copy, which
    has 11,694 functions, 3,641 high-confidence labels, and 1,218 default
    `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_tsound_effect_methods_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tsound_effect_methods_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

260. The next IDA pass resolved the remaining short `TSounds` control
    callbacks. Source `TSounds_setMusicVolume` at `0xe1350` maps exactly to
    target `sub_E1F28` at `0xe1f28`; source `TSounds_updateMusic_void` at
    `0xe1888` maps to target `0xe2470`. The update row is distinguished from
    the stop-MIDI wrapper by its sound-player virtual slot `+48` instead of
    `+72`. Both aliases reopened successfully in the v201 copy, which has
    11,694 functions, 3,641 high-confidence labels, and 1,218 default
    `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_sounds_control_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sounds_control_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

259. The next IDA pass resolved the `TSoundEffect` constructor and
    `TSounds_getSoundEffect_TString_const` cache lookup. Source `0xe0dc0`
    maps to target `0xe1970`, and source `0xe0e48` maps to target `0xe1a1c`.
    The constructor is a documented layout change caused by Spectron's
    target-only `CanTfaz6bZ` helper-string lifetime; the lookup preserves the
    lower-case, hash, case-insensitive lookup, and temporary cleanup flow.
    Both aliases reopened successfully in the v200 copy, which has 11,694
    functions, 3,641 high-confidence labels, and 1,219 default `sub_` names,
    with zero semantic reopen failures. See
    `artifacts/spectron_sounds_effect_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sounds_effect_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

258. The next IDA pass resolved the three `TSounds` music-state wrappers that
    the broad matcher had left ambiguous. Source `0xe0af8`, `0xe0b3c`, and
    `0xe0b7c` map to target `0xe16a8`, `0xe16ec`, and `0xe172c`; the sound
    player global, callback-table references, and virtual slots `+56`, `+80`,
    and `+88` distinguish them from unrelated shape-compatible wrappers.
    The normalized shape fingerprints agree, with only register-detail
    fingerprints differing. All three aliases reopened successfully in the
    v199 copy, which has 11,694 functions, 3,641 high-confidence labels, and
    1,219 default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_sounds_music_state_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_sounds_music_state_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

257. The next IDA pass resolved the corrected Android, TapJoy, and video
    static-state pair. Source `sub_E0AD0` at `0xe0ad0` maps to target
    `sub_E1640` at `0xe1640`, while the corrected source cleanup role at
    `0xe06a8` maps to target `sub_E0438` at `0xe0438`. The seven mapped
    fields cover the TapJoy strings, video callback state, and cached video
    rectangle. Target-only `qword_3A59C8` is documented separately because
    it is initialized and cleared only by the target pair. The v198 copy has
    11,694 functions, 3,641 high-confidence labels, and 1,220 default
    `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_android_tapjoy_video_state_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_android_tapjoy_video_state_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

256. The next IDA pass translated the `TSocket` static-string initializer.
    Source `sub_E0AB4` at `0xe0ab4` maps to target `sub_E12DC` at `0xe12dc`,
    preserving the two allowed-connection and allowed-port string fields and
    their static callback relationship. Spectron adds one `CanTfaz6bZ` string
    with matching cleanup evidence, so this is a high-confidence layout-change
    match. The v197 copy has 11,694 functions, 3,641 high-confidence labels,
    and 1,222 default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_tsocket_static_state_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tsocket_static_state_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

255. The next IDA pass translated the `TClient` static-string initializer.
    Source `sub_E0A2C` at `0xe0a2c` maps to target `sub_E1118` at `0xe1118`,
    preserving all eleven client string fields and their order. The target
    adds one `CanTfaz6bZ` string with matching cleanup evidence, so this is a
    high-confidence layout-change match. The v196 copy has 11,694 functions,
    3,641 high-confidence labels, and 1,223 default `sub_` names, with zero
    semantic reopen failures. See
    `artifacts/spectron_tclient_static_strings_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tclient_static_strings_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

254. The next IDA pass translated the `THTMLDefinitions` default initializer.
    Source `sub_E09F4` at `0xe09f4` maps to target `sub_E0FC4` at `0xe0fc4`,
    preserving the horizontal-line color bytes, bitmap-indent value, and
    adjacent cleared state used by the matching HTML page consumers. The
    normalized function shape is exact; only the recorded register-detail
    fingerprint differs. The v195 copy has 11,694 functions, 3,641
    high-confidence labels, and 1,224 default `sub_` names, with zero
    semantic reopen failures. See
    `artifacts/spectron_thtml_definitions_defaults_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_thtml_definitions_defaults_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

253. The next IDA pass translated the `TGUIRender` border-color initializer.
    Source `sub_E0984` at `0xe0984` maps to target `sub_E0F0C` at `0xe0f0c`,
    preserving five RGBA defaults used by the matching `renderBorder` paths.
    The target adds one adjacent `CanTfaz6bZ` string and cleanup callback, so
    this is a high-confidence layout-change match. The v194 copy has 11,694
    functions, 3,641 high-confidence labels, and 1,225 default `sub_` names,
    with zero semantic reopen failures. See
    `artifacts/spectron_tgui_render_colors_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tgui_render_colors_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

252. The next IDA pass translated the `GuiStretchCtrl` mode-table initializer.
    Source `sub_E0960` at `0xe0960` maps to target `sub_E0E54` at `0xe0e54`,
    preserving the `alwaysOn`, `alwaysOff`, and `dynamic` table and the
    adjacent three-record `GuiStretchCtrl` property table. The target adds
    one adjacent `CanTfaz6bZ` string and cleanup callback, so this is a
    high-confidence layout-change match. The v193 copy has 11,694 functions,
    3,641 high-confidence labels, and 1,226 default `sub_` names, with zero
    semantic reopen failures. See
    `artifacts/spectron_gui_stretch_modes_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_gui_stretch_modes_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

251. The next IDA pass translated the `GuiGraalCtrl` alignment-table
    initializer. Source `sub_E0930` at `0xe0930` maps to target `sub_E0DAC`
    at `0xe0dac`, preserving the five-entry horizontal and vertical tables,
    their static-initializer slots, and the nearby `GuiGraalCtrl` property
    record. The target adds one adjacent `CanTfaz6bZ` string and cleanup
    callback, so this is a high-confidence layout-change match. The v192 copy
    has 11,694 functions, 3,641 high-confidence labels, and 1,227 default
    `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_gui_alignment_tables_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_gui_alignment_tables_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

250. The next IDA pass translated the `GuiButtonBaseCtrl` button-type table
    initializer. Source `sub_E090C` at `0xe090c` maps to target `sub_E0D10`
    at `0xe0d10`, preserving the three-entry `PushButton`, `ToggleButton`,
    and `RadioButton` table and its property getter and setter. The target
    initializes one neighboring `CanTfaz6bZ` string, so the pair is recorded
    as a high-confidence layout-change match. The v191 copy has 11,694
    functions, 3,641 high-confidence labels, and 1,228 default `sub_` names,
    with zero semantic reopen failures. See
    `artifacts/spectron_gui_button_types_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_gui_button_types_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

249. The next IDA pass translated `initializeDisplayedGif`. Source `0xe08fc`
    maps to target `0xe0b80`, where the target `DiZVgajboR` global preserves
    the shared displayed-GIF state used by the player, server-player,
    explosion, bomb, carry, and extra-object draw paths. The target initializer
    also initializes a neighboring `CanTfaz6bZ` string, so the pair is recorded
    as a high-confidence layout-change match. The v190 copy has 11,694
    functions, 3,641 high-confidence labels, and 1,229 default `sub_` names,
    with zero semantic reopen failures. See
    `artifacts/spectron_displayed_gif_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_displayed_gif_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

248. The next IDA pass translated `TOptions_initializeWindowPosition`. Source
    `0xe08e4` maps to target `0xe0b3c`, where the obfuscated `K7FLgag3II`
    options class stores the same two `-1` window-position defaults in
    `y3nkMaCRLg` and `dword_3A198C`. The target also initializes a neighboring
    `CanTfaz6bZ` string, so the pair is recorded as a high-confidence
    layout-change match. The v189 copy has 11,694 functions, 3,641
    high-confidence labels, and 1,230 default `sub_` names, with zero semantic
    reopen failures. See
    `artifacts/spectron_options_window_position_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_options_window_position_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

247. The next IDA pass translated `clearCurAnis`. Source `0xe083c` maps to
    target `0xdfe08`, the cleanup callback for the target `RGiAvaPk9a`
    current-animation state. The source clears a 248-byte `curanis` object
    with vector stores. The target cleanup loop clears the corresponding 31
    string-sized fields with `C8THgaTQxF::clear` and then clears the adjacent
    `CanTfaz6bZ` object at `qword_3A0E70`. Its `sub_E09E0` initializer, cleanup
    table slot, and references from the target animation consumers establish
    the role despite the implementation change. The v188 copy has 11,694
    functions, 3,641 high-confidence labels, and 1,231 default `sub_` names,
    with zero semantic reopen failures. See
    `artifacts/spectron_clear_cur_anis_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_clear_cur_anis_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

246. The next IDA pass translated `TResource_initializeLinkLists`. Source
    `0xe070c` maps to target `0xe0564`, whose static-initializer table
    slot, `KKhLga4xoI` constructor calls, and assignments to the already
    identified `OOmzgapOmy` and `H4zIGaBY6x` resource-link lists resolve
    the same 76-byte exact normalized initializer shape that had previously
    collided with the particle-emitter candidate. The v187 copy has 11,694
    functions, 3,641 high-confidence labels, and 1,232 default `sub_` names,
    with zero semantic reopen failures. See
    `artifacts/spectron_resource_link_lists_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_resource_link_lists_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

243. The next IDA pass translated two `TClientEnvironment` profiler cleanup
    callbacks. Source `0x15c620` maps to target `0x15f678`, where the target
    `runTimers` method registers the callback with `atexit`; source `0x15c62c`
    maps to target `0x15f684`, registered by `drawGame`. Both target functions
    were default-named and both are exact normalized-shape matches. The v184
    copy has 11,694 functions, 3,641 high-confidence labels, and 1,234
    default `sub_` names, with zero semantic reopen failures. See
    `artifacts/spectron_client_environment_static_clear_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_client_environment_static_clear_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

242. The next IDA pass translated the remaining short
    `TClientEnvironment_initGraphics_void` wrapper. Source `0x15ce2c` maps
    to target `0x15fe84`, between the target free-graphics and window-size
    methods in the obfuscated `a7qxJaHqKV` class. The pair is an exact
    normalized-shape match: 24 bytes, six instructions, four blocks, and
    three branches. The alias reopened successfully in the v183 copy, which
    has 11,694 functions, 3,641 high-confidence labels, and 1,236 default
    `sub_` names. See
    `artifacts/spectron_client_environment_graphics_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_client_environment_graphics_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

241. The next IDA pass translated four small `TGameEnvironment` startup and
    property callbacks in the obfuscated `QYZugaRKGu` class. The target
    registration table decodes `allplayerscount`, `adventure_quit`,
    `ispremiumversion`, and `isdemoversion`, pointing to `0xea84c`, `0xea870`,
    `0xea860`, and `0xea868`. Three pairs are exact normalized matches; the
    quit callback adds one target-only exit flag and is recorded as a layout
    change. All four aliases reopened successfully in the v182 copy, which
    has 11,694 functions, 3,641 high-confidence labels, and 1,236 default
    `sub_` names. See
    `artifacts/spectron_game_environment_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_game_environment_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

240. The next network-focused IDA pass translated four residual `TSocket`
    methods. The client-list cleanup at target `0x20ab0c` preserves the
    `"clients"` hash lookup, variable removal, callback, and client-pointer
    reset with a small layout change. The source deleting-destructor label
    maps to target D0 at `0x20ac44`, and the source error and IP property
    adapters map to default target functions `0x20ad1c` and `0x20ad78`.
    Those two wrappers match the exact normalized shape and call the already
    translated target error and IP methods. All four aliases reopened
    successfully in the v181 copy, which has 11,694 functions, 3,641
    high-confidence labels, and 1,238 default `sub_` names. See
    `artifacts/spectron_tsocket_residual_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tsocket_residual_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

239. The next network-focused IDA pass translated the remaining request reset
    method and the four request-properties destructor ABI entries. The source
    `THTTPRequest_clearRequest_void` role maps to target `0x204d5c`, which
    retains the keep-alive check, socket release, `data` variable removal,
    response-stream reset, counters, flags, and temporary-string cleanup. The
    target body is slightly shorter, so it is recorded as a layout change.
    The four adjacent properties rows are the complete D2 destructor, deleting
    D0 destructor, and their adjusted-this thunks. The source constructor-like
    labels are classified by their bodies and target D2 or D0 ABI names. All
    five aliases reopened successfully in the v180 copy, which has 11,694
    functions, 3,641 high-confidence labels, and 1,240 default `sub_` names.
    See `artifacts/spectron_http_request_cleanup_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_http_request_cleanup_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

238. The next IDA pass translated four exact-shape server-list state methods
    in the Spectron 2.2 build. The aliases cover the remove-vars-on-logout
    setter, allow-login-reconnect getter, and server-start parameter and
    connection setters at targets `0x2082b0`, `0x2082c0`, `0x2082f0`, and
    `0x208304`. Pseudocode ties them to
    `xiYWfajld1::x7tqLaYXTv`, `xiYWfajld1::mLqqLax7Qv`,
    `xiYWfajld1::OcLpLarkhv`, and `xiYWfajld1::Jq54MaebUU`; the latter three
    are corroborated by already translated neighboring methods. All four
    aliases reopened successfully in the v179 copy, which has 11,694
    functions, 3,641 high-confidence labels, and 1,240 default `sub_` names.
    See `artifacts/spectron_server_list_state_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_server_list_state_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

237. The next IDA pass translated five server-list anchors in the Spectron
    2.2 build. Four exact-shape getters map the server-start parameters,
    server-start connection text, and both server-name callback forms to
    target addresses `0x208318`, `0x208350`, `0x208388`, and `0x2083c0`.
    Target setter and getter pairs share the globals
    `xiYWfajld1::OcLpLarkhv` and `xiYWfajld1::Jq54MaebUU`, while both name
    getters and the larger handoff use `xiYWfajld1::VoXXfaKA21`.
    The fifth alias maps the source connection-attribute handoff at
    `0x202f30` to target `0x20a1f4`. Its name, address, port, restart, tile,
    local-player, and window-identifier responsibilities match, but its
    larger 2.2 body is recorded as a layout change. All five aliases reopened
    successfully in the v178 copy, which has 11,694 functions, 3,641
    high-confidence labels, and 1,244 default `sub_` names. See
    `artifacts/spectron_server_list_connection_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_server_list_connection_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

236. The next network-focused IDA pass translated two response-side HTTP
    methods in the obfuscated `ZAuvgaUl6u` request class:
    `THTTPRequest_read_void` at target `0x206414` and
    `THTTPRequest_parseData_void` at target `0x207bec`. The read method keeps
    socket receive, response-stream append, byte accounting, and timestamp
    updates, while the parser keeps the `data` lookup, line-array construction,
    and script callback loop. Both rows are high-confidence semantic matches
    with explicit implementation-change notes. The aliases reopened with zero
    failures in the v177 copy, which has 11,694 functions, 3,641 automatic
    high-confidence labels, and 1,248 default `sub_` names. See
    `artifacts/spectron_http_request_receive_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_http_request_receive_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

232. The next IDA pass translated six exact-shape `TString` methods: signed,
    unsigned, and 64-bit integer insertion, prefix testing, and the bounded
    and unbounded case-insensitive comparison thunks. All six labels reopened
    successfully in the v174 disposable copy, which has 11,694 functions,
    3,641 high-confidence labels, and 1,250 default `sub_` names. The local
    address deltas are `+0x14d8` for the insertion trio and `+0x1720` for the
    prefix and comparison cluster. See
    `artifacts/spectron_tstring_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_tstring_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

231. The next IDA pass translated five exact-shape hash-container methods:
     two `THashList` lifecycle and iterator helpers plus three `THashStrings`
     count, lifecycle, and membership helpers. All five labels reopened
     successfully in the v173 disposable copy, which has 11,694 functions,
     3,641 high-confidence labels, and 1,250 default `sub_` names. The local
     address deltas are `+0xbec`, `+0xc4c`, and `+0xc74`. See
     `artifacts/spectron_hash_container_manual_translation_anchors_20260827.json`,
     `tools/generate_spectron_hash_container_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260826.json`.

230. The next IDA pass translated eight exact-shape `TSounds` methods:
     offscreen-distance state, disabled-effects comma text, stop-sounds,
     resource cleanup, MIDI shutdown, and absolute playback. All eight labels
     reopened successfully in the v172 disposable copy, which has 11,694
     functions, 3,641 high-confidence labels, and 1,250 default `sub_` names.
     The address deltas remain class-local groups at `+0xbb0`, `+0xbd4`, and
     `+0xbe8`. See
     `artifacts/spectron_sounds_manual_translation_anchors_20260827.json`,
     `tools/generate_spectron_sounds_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260826.json`.

229. The next IDA pass translated six exact-shape `TList` methods: indexed
     replacement, repeated-value removal, full-list append, signed and
     unsigned indexed access, and the qsort thunk. All six labels reopened
     successfully in the v171 disposable copy, which has 11,694 functions,
     3,641 high-confidence labels, and 1,255 default `sub_` names. The source
     and target rows share the `+0xfd0` delta and the complete normalized
     feature record. See
     `artifacts/spectron_tlist_manual_translation_anchors_20260827.json`,
     `tools/generate_spectron_tlist_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260826.json`.

228. The next IDA pass translated nine exact-shape `TEncryption` methods:
     DES encryption and decryption, the script MD5 wrapper, RSA signing, RC4
     cleanup and processing, and AES cleanup, encryption, and decryption. All
     nine labels reopened successfully in the v170 disposable copy, which has
     11,694 functions, 3,641 high-confidence labels, and 1,255 default `sub_`
     names. The source and target rows split into `+0xbe8` and `+0x2294`
     class-local deltas. See
     `artifacts/spectron_encryption_manual_translation_anchors_20260827.json`,
     `tools/generate_spectron_encryption_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260826.json`.

227. The next IDA pass translated six exact-shape `TFiles` methods: file size,
     UTC modification time, filename extraction, lower-case filename
     handling, and the URL-aware filename and extension helpers. All six
     labels reopened successfully in the v169 disposable copy, which has
     11,694 functions, 3,641 high-confidence labels, and 1,256 default
     `sub_` names. The source and target rows share the `+0xbe8` delta and the
     complete normalized feature record. See
     `artifacts/spectron_files_manual_translation_anchors_20260827.json`,
     `tools/generate_spectron_files_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260826.json`.

226. The next IDA pass translated five exact-shape `TCompression` methods:
     both `CompressBuf` overloads, the TString decompression wrapper, and both
     `CompressBuf2` overloads. All five labels reopened successfully in the
     v168 disposable copy, which has 11,694 functions, 3,641 high-confidence
     labels, and 1,256 default `sub_` names. The source and target rows share
     the `+0xbe8` delta and the complete normalized feature record. See
     `artifacts/spectron_compression_manual_translation_anchors_20260827.json`,
     `tools/generate_spectron_compression_anchors.py`, and
     `artifacts/spectron_translation_checkpoint_20260826.json`.

225. The next IDA pass translated 12 exact-shape methods in the server-object
    cluster: the `TServerBomb` time, order-point, and image helpers, the
    `TServerChest` open setter, six `TServerFlying` scalar accessors plus its
    order-point helper, and the `TExplosion` constructor. Eight target bodies
    had default `sub_` names before the pass. All 12 labels reopened
    successfully in the v167 disposable copy, which has 11,694 functions,
    3,641 high-confidence labels, and 1,256 default `sub_` names. See
    `artifacts/spectron_server_object_scalar_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_server_object_scalar_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

224. The next IDA pass translated the remaining 24 named `TShowImg` methods
    and `TShowImgProperties` destructor-family rows. Twenty-two pairs match
    the complete normalized feature set, while the two properties-class
    destructor bodies are documented as layout-aware lifecycle matches because
    their vtable literals changed. The target functions all retained
    obfuscated C++ names before the pass, so the default `sub_` count remains
    1,264. All 24 labels reopened successfully in the v166 disposable copy,
    which has 11,694 functions and 3,641 high-confidence labels. See
    `artifacts/spectron_showimg_residual_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_showimg_residual_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

223. The next IDA pass translated the 85 reviewed `TShowImg` property
    callbacks from the identical 48-name registration tables. The source
    table is at `0x389fa0`, the Spectron table is at `0x39d0f0`, and each
    record is `0x30` bytes with getter and setter pointers at `+0x10` and
    `+0x18`. Eighty-four rows match complete normalized fingerprints, and
    the `code` getter is a documented layout change. The three null setters
    are `actor`, `imageindex`, and `emitter`; the `code` setter preserves the
    existing `v18_TGaniParam_writeFloat_double` alias. All 85 rows reopened
    successfully in the v165 disposable copy, which has 11,694 functions,
    3,641 high-confidence labels, and 1,264 default `sub_` names. See
    `artifacts/spectron_showimg_property_manual_translation_anchors_20260827.json`,
    `tools/generate_spectron_showimg_property_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

222. The next IDA pass translated the final seven named `TServerPlayer` rows:
    the attached-object setter, nickname cleanup, D0 deleting destructor,
    both static initializers, and the local X and Y setters. The attachment
    row is confirmed by the `attachedtoobject` property-table pointer, and all
    seven pairs have exact normalized fingerprints. The source
    `TServerPlayer_TServerPlayer__2` alias is corrected in the notes to the D0
    destructor symbol `_ZN13TServerPlayerD0Ev`. All seven labels reopened
    successfully in the v164 disposable copy, which has 11,694 functions and
    1,333 default `sub_` names. See
    `artifacts/spectron_tserverplayer_tail_manual_translation_anchors_20260826.json`,
    `tools/generate_spectron_tserverplayer_tail_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

221. The next IDA pass translated 25 residual `TServerPlayer` callbacks from
    the shared 52-entry property table and six-entry script-function table.
    The source and target tables preserve the same decoded names, which
    resolves the target reorder around image and text accessors. Twenty-three
    pairs have exact normalized fingerprints. The headset getter and
    show-profile callback are high-confidence layout changes, and three small
    script callbacks were given explicit target boundaries before labeling.
    Two shared implementations, the player index and log name helpers, kept
    their existing aliases. All 25 labels reopened successfully in the v163
    disposable copy, which has 11,694 functions and 1,334 default `sub_`
    names. See
    `artifacts/spectron_tserverplayer_residual_manual_translation_anchors_20260826.json`,
    `tools/generate_spectron_tserverplayer_residual_anchors.py`, and
    `artifacts/spectron_translation_checkpoint_20260826.json`.

220. The next IDA pass translated 39 exact-shape residual methods from the
    ordered `TServerPlayer` property block. Four existing v18 labels were used
    as sequence checkpoints for the paused, combat, attachment, chat, and MP
    rows. The new source range `0x18a55c..0x18aa5c` maps to
    `0x18edbc..0x18f2bc` in `MpGzgariDy`, with a constant `+0x4860` code
    relocation. The pass replaced 38 default target names. All 39 labels
    reopened successfully in the v161 disposable copy, which has 11,693
    functions and 1,358 default `sub_` names. See
    `artifacts/spectron_tserverplayer_property_block_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

219. The next IDA pass translated seven exact-shape TPlayer flag setters:
    six boolean setters and the integer enabled-features setter. The six
    boolean rows form a contiguous source block at `0x17b59c..0x17b7b8`,
    while `setEnabledFeatures` follows the already translated `setPaused`
    interstitial at `0x17b8a0`. The matching obfuscated `W6NzgawMJy` targets
    are at `0x17f940..0x17fb5c` and `0x17fc44`, with a constant `+0x43a4`
    code relocation. All seven labels reopened successfully in the v160
    disposable copy, which has 11,693 functions and 1,396 default `sub_`
    names. See
    `artifacts/spectron_tplayer_flag_setter_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

218. The next IDA pass translated 21 exact-shape scalar getters from
    `TPlayer`: local coordinates, health, inventory, combat power, movement
    flags, and visibility state. The source block at
    `0x17afd8..0x17b510` maps to the obfuscated `W6NzgawMJy` block at
    `0x17f37c..0x17f8b4`, with a constant `+0x43a4` code relocation. The
    target encoded-storage pointer and mask offsets are source plus 24 bytes
    throughout this block. All 21 labels reopened successfully in the v159
    disposable copy, which has 11,693 functions and 1,396 default `sub_`
    names. See
    `artifacts/spectron_tplayer_scalar_getter_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

217. The next IDA pass translated ten exact-shape scalar setters from
    `TPlayer`: gralats, alignment, sword power, magic points, maximum health,
    shield power, bombs, arrows, glove power, and carry sprite. The source
    block at `0x16cec4..0x16d5cc` maps to the obfuscated `W6NzgawMJy` block at
    `0x170ac4..0x1711cc`, with a constant `+0x3c00` code relocation. The
    target object-layout constants are not a uniform field-offset shift, so
    this is recorded as a class-local block mapping. All ten labels reopened
    successfully in the v158 disposable copy, which has 11,693 functions and
    1,396 default `sub_` names. See
    `artifacts/spectron_tplayer_scalar_setter_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

216. The next IDA pass translated the 37-function scalar getter and setter
    block at the front of `TServerPlayer`. The target `MpGzgariDy` block keeps
    the same alternating order and exact normalized fingerprints. Its code
    addresses are source plus `0x47e8`, and its object fields are source plus
    24 bytes. All 37 labels reopened successfully in the v157 disposable copy,
    which has 11,693 functions and 1,396 default `sub_` names. See
    `artifacts/spectron_tserverplayer_accessor_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

215. The follow-up IDA pass translated the remaining 53 exact-shape `CyaInt`
    methods. Combined with the preceding 30-row batch, every one of the 266
    named `CyaInt` methods in the original feature export now has a reviewed
    semantic target or existing map entry. The second batch covers RSA
    verification and decryption, TLS I/O callbacks, verification-mode setters,
    DTLS and timeout helpers, TLS 1.0 through 1.2 client methods, OCSP and
    X.509 accessors, and TLS mutex wrappers. All 53 labels reopened
    successfully in the v156 disposable copy, which has 11,693 functions and
    1,396 default `sub_` names. See
    `artifacts/spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

214. The next IDA pass translated 30 residual `CyaInt` TLS and cryptography
    methods. It covers verification paths, certificate and private-key
    buffers, session and cipher accessors, protocol selectors, error helpers,
    and master-secret derivation. Every pair matched the complete normalized
    feature set, and every target address was the source plus `0xd590`. All 30
    labels reopened successfully in the v155 disposable copy, which has
    11,693 functions and 1,396 default `sub_` names. This is static evidence
    identifying the trust and handshake code, not a claim that verification is
    bypassed. See
    `artifacts/spectron_cyaint_tls_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

213. The next IDA pass translated the final 11 exact-shape
    `GSFunctionsClient` table callbacks. They cover Adventure window and mode
    helpers, fullscreen state, application activity, and the two URL bridges.
    Each target pointer matched the `+0x13010` table-field relocation, and all
    11 labels reopened successfully in the v154 disposable copy, which has
    11,693 functions and 1,396 default `sub_` names. See
    `artifacts/spectron_gsfunctions_client_exact_residual_v4_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

212. The next IDA pass materialized and translated 12 `GSFunctionsClient`
    callbacks whose Spectron table pointers landed in code that IDA had left
    unbounded. Raw ARM64 control flow established every range, including 17
    explicit return instructions, and adjacent relocated table entries gave
    an independent structural check. All 12 names and function ends reopened
    successfully in the v153 disposable copy, which has 11,693 functions and
    1,407 default `sub_` names. See
    `artifacts/spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

211. The next IDA pass translated the last nine already-bounded exact-shape
    `GSFunctionsClient` callbacks from the current table audit. They cover the
    Adventure nickname helper, level origin, screen dimensions, mouse-button
    state, log output, and RPG messages. Each target pointer was confirmed by
    the `+0x13010` table-field relocation, and every pair matched the
    normalized code-shape fingerprints. The labels reopened successfully in
    the v152 disposable copy, which has 11,681 functions and 1,407 default
    `sub_` names. See
    `artifacts/spectron_gsfunctions_client_exact_residual_v3_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

210. The next IDA pass translated a second group of 20 exact-shape
    `GSFunctionsClient` callbacks covering shooting parameters, image and
    weapon state, mouse globals, URL and key helpers, file cleanup, and
    Adventure file operations. Each target callback pointer was confirmed by
    the same `+0x13010` table-field relocation, and every pair matched the
    normalized code-shape fingerprints. The labels reopened successfully in
    the v151 disposable copy, which has 11,681 functions and 1,416 default
    `sub_` names. See
    `artifacts/spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

209. The next IDA pass translated 20 exact-shape `GSFunctionsClient` callbacks:
    collection and statistics getters, carry and version state, OpenGL and
    gravity, map and mouse state, scripted controls, weapons, and image
    setters. Each target callback pointer was confirmed through the same
    `+0x13010` table-field relocation, and all 20 pairs matched the normalized
    code-shape fingerprints. The labels reopened successfully in the v150
    disposable copy, which has 11,681 functions and 1,436 default `sub_`
    names. See
    `artifacts/spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

208. The next IDA pass translated the remaining `randomstring` GSFunctions
    callback. Its source table pointer at `0x3872c0` and target pointer at
    `0x39a3e0` preserve the position immediately after `strequals`. The target
    retains trailing-comma trimming, random list selection, and cleanup, with
    a small 260-to-264-byte wrapper-induced layout change. The label reopened
    successfully in the v149 disposable copy, which has 11,681 functions and
    1,456 default `sub_` names. See
    `artifacts/spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

207. The next IDA pass translated 13 remaining GSFunctions callbacks using
    the preserved static script-table order and normalized function shape.
    They cover `getstringkeys`, `callnpc`, map coordinates, image dimensions,
    empty-global cleanup, arcsine and arccosine, `aindexof`, `echo`, `trace`,
    and `findpathinarray`. Eight pairs are exact normalized-shape matches and
    five are high-confidence layout-change matches. The target
    `getstringkeys` pointer at `0x2111d8` had no IDA function boundary, so its
    `0x2111d8..0x211424` range was materialized before labeling. All 13 labels
    reopened successfully in the v148 disposable copy, which has 11,681
    functions and 1,457 default `sub_` names. See
    `artifacts/spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

206. The next IDA pass translated six exact-shape GSFunctions callbacks:
    `degtorad`, `radtodeg`, temporary-string cleanup, case-insensitive
    comparison, `uppercase`, and `lowercase`. It also materialized the
    script-table `radtodeg` range. All six labels reopened successfully in
    the v146 disposable copy, which has 11,680 functions and 1,469 default
    `sub_` names. See
    `artifacts/spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

205. The next IDA pass translated five exact-shape `TUpdatePackageProperties`
    lifecycle helpers: the uninstall jump thunk, complete and deleting
    destructors, and both non-virtual thunks. All five labels reopened
    successfully in the v145 disposable copy, which retains 1,473 default
    `sub_` functions. See
    `artifacts/spectron_update_package_properties_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

204. The next IDA pass translated six update-package event and lookup helpers:
    failure and download-complete notifications, downloading and privileged
    package containment, and force or no-force wrappers. All six labels
    reopened successfully in the v144 disposable copy. Two default target
    names were replaced, leaving 1,473. See
    `artifacts/spectron_update_package_wrapper_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

203. The next IDA pass translated one exact-shape `TUpdatePackage` deleting
    destructor. Its source label is constructor-like, but the body calls the
    constructor entry followed by `operator delete`. The label reopened
    successfully in the v143 disposable copy, which retains 1,475 default
    `sub_` functions. See
    `artifacts/spectron_update_package_destructor_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

202. The next IDA pass translated 20 exact-shape `TClient` and
    `TUpdatePackage` accessors, covering the base-package pointer, download
    counters, package flags and numeric fields, and six string getters. All
    20 labels reopened successfully in the v142 disposable copy. They replace
    20 default `sub_` names, leaving 1,475. See
    `artifacts/spectron_update_package_accessor_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

201. The next IDA pass translated seven exact-shape client-thread helpers:
    socket locking, incoming reads, incoming and outgoing queue cleanup,
    the thread-disable guard, and outgoing sends. All seven labels reopened
    successfully in the v141 disposable copy, which retains 1,495 default
    `sub_` functions. See
    `artifacts/spectron_client_thread_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

200. The next IDA pass translated three residual `TPlayerList` methods:
    the staff-guild setter, static initializer, and empty static-script
    initializer. All three labels reopened successfully in the v140
    disposable copy, which retains 1,495 default `sub_` functions. See
    `artifacts/spectron_player_list_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

199. The next IDA pass translated five residual URL-cache support methods:
    insertion, static setup, file loading, and complete and deleting
    cache-entry destructors. All five labels reopened successfully in the
    v139 disposable copy, which retains 1,495 default `sub_` functions. See
    `artifacts/spectron_url_cache_residual_manual_translation_anchors_20260826.json`
    and `artifacts/spectron_translation_checkpoint_20260826.json`.

## Spectron 2.2 package check

The target-specific local builder is now complete at the byte and APK
packaging level. It uses `cong.quattroplay.com` as the preserved hostname,
patches the target trust text at `0x2ea9e0`, routes the target resolver at
`0x20c20c` to loopback, and moves the two HTTPS parser defaults at `0x2065e0`
and `0x206764` to port `18443`. Its deterministic outgoing-key trampoline
uses the zero-filled cave at `0x1c4000` and resumes the target
`setEncryptionOut` body at `0x202fec`. Native certificate peer and hostname
verification remain enabled.

The supplied Spectron APK was rebuilt as an ARM64-only private package. The
builder also skipped the three destructive WebTop commands that caused the
earlier `libxposed.so` crash control. `zipalign` and APK signature verification
passed. The resulting APK SHA-256 is
`45f469692cb6ee2e8d0f1529d8b0871dafdf718e2c8b6e345cb5082e40257751`, and the
patched ARM64 qplay SHA-256 is
`45a7f97df9b40cdac6fbd42dc715bbabf3bbdb9b33876990e232133a8818941e`.
The reproducible builder is `tools/build_spectron_loopback_apk.py`, and the
byte-level guards are in
`artifacts/spectron_loopback_patch_audit_20260828.json`.

This paragraph describes the packaging check itself. A separate local replay
was run afterward, with the responder and ADB reverse mappings documented
below. The package check did not perform a DNS lookup or contact `cong`,
`cong2`, or any other external service.

## Spectron 2.2 target loopback replay

The target-specific package was then installed on the available Android 36
x86_64 emulator. Android loaded its ARM64 library through the translation
layer. The test used a local certificate for `cong.quattroplay.com`, forwarded
HTTPS port `18443`, and retained the native connector RSA result branch,
certificate verification, and hostname verification.

The local TLS responder received `GET /con.png` with
`Host: cong.quattroplay.com:18443` and `User-Agent: Graal/6.171`. The archived
16,446-byte connector response was accepted without a certificate error. The
game responder then observed two encrypted connections. Both completed the
synthetic login exchange. The second connection requested the base package,
`classiciphone.gmap`, five level resources, and continued with packet-24
heartbeats. The process stayed alive through the replay.

The unmodified target-specific build reached those same network and resource
milestones but retained the stock title/loading artwork. The corrected
loading control changes one instruction in the target's translated
`TClientEnvironment::sigcheck` routine: it replaces the conditional at
`0x15fad8` with an unconditional branch to the already present clear block at
`0x15fb1c`. That package displayed the green tiled world with the HUD and
status indicators.

The corrected private APK SHA-256 is
`6988410c57bcc4874b9e6932e82d1eeba3e9a39e684a26112b54586a76022b02`, and its
ARM64 native library SHA-256 is
`85aafee0d551ffdf4460833adf1f87a0eb26408aedeff862bc9041a380e2dfde`. The
rendered screenshot SHA-256 is
`08dc6793c3087caec00f1194e4966b1ab4753b53eacc0a1b2a86b92ad16c596e`.
The client and server capture hashes, exact patch map, and fixture hashes are
in `artifacts/spectron_arm64_loopback_loading_replay_20260828.json`.

One earlier private trial changed `0x15faac`, the executable-path branch. It
did not change the screen and is not treated as a loading fix. The corrected
branch was identified by reading the full target pseudocode and mapping the
same premium-condition and clear-block relationship seen in the 1.8 IDA
database.

This is a local translated-ARM64 result. It does not prove current live
service compatibility or native rendering on a physical ARM64 device. The
responder, certificate key, APK, captures, and game assets remain outside the
repository, and both reverse mappings were removed after the run.

## Spectron 2.2 clean-cache reproducibility pass

The same package was rebuilt from the supplied APK with the current builder
and produced the same APK hash. Before launching it, I removed only the nine
external cache files used by the private replay and verified that the target
cache directory was empty. This matters because clearing Android app data does
not necessarily clear the external game cache.

The clean pass again produced one native TLS request for `/con.png` with host
`cong.quattroplay.com:18443` and user agent `Graal/6.171`. The certificate was
accepted, and the game responder completed two encrypted connections. The
second connection downloaded `basepackage.gupd`, the gray message image, the
map, and five level resources. The target APK already contains
`assets/offline/levels/tiles/pics1.png`, so it did not need a separate tile-sheet
request. Packet-24 heartbeats continued after the resource sequence.

The target loading control again changed the screen from the title or loading
artwork to the green tiled world with the HUD and status indicators. The
rebuilt APK hash is
`6988410c57bcc4874b9e6932e82d1eeba3e9a39e684a26112b54586a76022b02`, the clean
run screenshot hash is
`08dc6793c3087caec00f1194e4966b1ab4753b53eacc0a1b2a86b92ad16c596e`, and the
four private capture hashes are recorded in
`artifacts/spectron_arm64_clean_cache_replay_20260828.json`.

This is a stronger local reproduction of the resource path, not a new claim
about the live service. It still runs translated ARM64 code on an x86_64
emulator, uses synthetic game responses, and leaves the loading branch as a
diagnostic control. The app was stopped and the reverse mappings were removed
after capture.

The matched stock-branch control was run with the same clean-cache procedure,
same local TLS certificate, same encrypted responder, and same fixture hashes.
It completed the network and resource milestones but remained on the original
title/loading artwork. Its APK hash is
`45f469692cb6ee2e8d0f1529d8b0871dafdf718e2c8b6e345cb5082e40257751`, and its
screen hash is
`bcf5f1c8423d1cecce5b6debb8f8126828bffb824cb299518c55771eeb65e788`. The
four capture hashes and the build report are in
`artifacts/spectron_arm64_stock_clean_cache_control_20260828.json`. Since the
only native difference is the conditional at `0x15fad8`, this is the strongest
local causal comparison for the loading-state candidate, while still not being
a production or physical-device validation.

## Spectron 2.2 v322 TGraalVar runtime translation

The v322 pass continues from the verified v321 database and recovers twelve
source-backed names in the obfuscated `G0gxgajWBw` implementation of
`TGraalVar`. This was an offline IDA review, not a client run. The automatic
matcher had left the rows unresolved because the target rebuild changes the
string, list, hash, and array wrapper classes. The source and target Hex-Rays
pseudocode still agree on the operations and method-local order.

The translated rows are:

| Source method | Target | Applied alias | Behavior retained |
| --- | ---: | --- | --- |
| `TGraalVar_receiveEvent_script_event` | `0x2136c4` | `v18_TGraalVar_receiveEvent_script_event` | event name and virtual +128 forward |
| `TGraalVar_getVarNames_bool_bool_bool` | `0x214520` | `v18_TGraalVar_getVarNames_bool_bool_bool` | filtered enumeration, deduplication, sort |
| `parseDynamicFunctionParameters_char_const_std_va_list` | `0x214a78` | `v18_parseDynamicFunctionParameters_char_const_std_va_list` | all GS2 format cases |
| `TGraalVar_executeStringFunctionF_TString_const_char_const` | `0x215148` | `v18_TGraalVar_executeStringFunctionF_TString_const_char_const` | parse, invoke, return-string extraction |
| `TGraalVar_saveString_TString_const_uint` | `0x2154e0` | `v18_TGraalVar_saveString_TString_const_uint` | path, stream, file, resource update |
| `TGraalVar_saveLines_TString_const_uint` | `0x215660` | `v18_TGraalVar_saveLines_TString_const_uint` | line-list serialization |
| `TGraalVar_loadString_TString_const` | `0x2157a8` | `v18_TGraalVar_loadString_TString_const` | path, stream load, virtual setter |
| `TGraalVar_setVarValueAsFloat_TString_const_double` | `0x2158e4` | `v18_TGraalVar_setVarValueAsFloat_TString_const_double` | lookup and numeric fallback |
| `TGraalVar_getVarValue_TString_const` | `0x2159f4` | `v18_TGraalVar_getVarValue_TString_const` | copied value and persistent fallback |
| `TGraalVar_setArrayCellObject_int_TGraalVar` | `0x216174` | `v18_TGraalVar_setArrayCellObject_int_TGraalVar` | bounds, cell assignment, update flag |
| `TGraalVar_getVarValueAsFloat_TString_const` | `0x216454` | `v18_TGraalVar_getVarValueAsFloat_TString_const` | lookup and numeric projection |
| `TGraalVar_updateArrayString_void` | `0x216558` | `v18_TGraalVar_updateArrayString_void` | comma-separated cache rebuild |

The event forwarder is the cleanest row: its source and target bodies both
have one block and 24 instructions, and both construct the event string before
calling virtual slot `+128`. The remaining eleven are explicit layout-change
matches. Their target bodies add conversions for `C8THgaTQxF` and related
obfuscated containers, but retain the source decision trees. The dynamic
parameter parser keeps the `b`, `c`, `s`, `d`, `f`, `i`, `o`, `p`, and `u` cases.
The save/load pair preserves the script-access path and stream operations.
The value accessors preserve their primary lookup and persistent-hash
fallbacks. The object-array setter at `0x216174` is independently supported
by its bounds check, virtual `+200` assignment, and array-updated call; it is
not the nearby string-cell setter.

The target alias application renamed twelve functions and added twelve
evidence comments with zero failures. Reopening the saved copy verified all
twelve names. The v322 database contains 11,707 functions and zero audited
default names. Its name origins are 6,240 translated `v18_` aliases, 417
target-only descriptive labels, 990 retained target names, seven JNI exports,
and 4,053 other IDA or PLT names. The complete dynamic-symbol audit remains
at 6,770 named rows and 6,600 defined rows, with 5,782 exact function starts,
482 data items, 336 other non-code items, and 170 undefined imports. The
source-backed alias count rises to 4,564.

The database hash is
`af0f2361668f7cd375b33242a0b21591a53446c332c0e77c8a4e51e3c6bdf1ad`. The
anchor, application, reopen-verification, audit, and checkpoint records are
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_application_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v322_20260829.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v322_20260829.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v322_20260829.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v322.json`.

This pass changed only a private IDA copy and the research archive. It did not
patch the APK, contact a game server, or test a live endpoint.

## Spectron 2.2 v323 TGraalVar continuation

The v323 pass is a static translation checkpoint, not a new runtime attempt.
It continues from the verified v322 IDA copy and reviews the next 23 methods
in the obfuscated `G0gxgajWBw` implementation. The group covers script
lifecycle wrappers, function checks, list sorting, persistent-variable
serialization, value accessors, recursive copying, function enumeration,
array construction, static property registration, and string parsing.

Six short methods have exact recorded feature metrics. The other seventeen
are high-confidence layout-change matches because Spectron rebuilt the source
string, list, hash, and iterator classes. The source and target decompilations
still agree on the key virtual slots and data flow. The target-only method at
`0x214fd8` remains excluded because its source counterpart is not established.

The application renamed all 23 target functions and added 23 evidence
comments with zero failures. A fresh reopen verified all 23 names in an
11,707-function database. The final name audit has zero default names and
reports 6,263 translated `v18_` aliases, 417 target-only descriptive labels,
967 retained target names, seven JNI exports, and 4,053 other IDA or PLT
names. The dynamic-symbol audit reports 4,587 source-backed aliases and
1,855 exact retained names, while preserving 5,782 exact dynamic function
starts, 482 data items, 336 other non-code items, and 170 undefined imports.

The v323 database is
`analysis/spectron_libqplay_translated_v323_tgraalvar_runtime_continuation_final.i64`
with SHA-256
`588e39f73c0946aea4ed45265820c9d95a73689339c365840b308170d36d0b4d`.
The anchor, application, reopen-verification, audit, and checkpoint records
are listed in
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_application_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v323_20260829.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v323_20260829.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v323_20260829.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v323.json`.

This pass changed only the private IDA copy and archive. It did not patch the
APK, alter TLS behavior, contact a game server, or test a live endpoint.

## Spectron 2.2 v348 RSA public-encryption translation

The v348 checkpoint is a static continuation from v347. It resolves the
source `TEncryption_rsa_encrypt_TString_const_TString_const` row at
`0xf7218` to target `0xf94ac`, raw symbol
`_ZN10cHovga0n1u10D855FaUMK1ERK10C8THgaTQxFS2_`, and applies the alias
`v18_TEncryption_rsa_encrypt_TString_const_TString_const`.

The source and target bodies are both 296 bytes, 74 instructions, 12 basic
blocks, 14 branches, and seven calls, with identical normalized feature hashes.
The direct algorithm is decisive: both decode a public RSA key, initialize an
RNG, query the RSA output size, call public-key encryption, append a positive
result, and free the key. The nearby target `0xf96f8` is still the private-key
signing row because it calls `RsaPrivateKeyDecode` and `RsaSSL_Sign`.

The new alias was applied to a fresh v347-derived IDB and verified after
reopening. The v348 database has 11,707 functions, zero audited default names,
6,441 translated aliases, 439 target-only descriptive labels, 768 retained
target names, 4,796 source-backed dynamic rows, 1,656 exact retained dynamic
names, and 5,782 exact dynamic function starts. The semantic map now has 3,722
mapped pairs. The database SHA-256 is
`40ff536a25df6624d1ac25bc9052e85d107dddb996dc5e46b791d1df936a75c0`.

The v348 pass has no runtime effect. It did not patch the APK, rerun the
loopback client, contact a live service, or change the TLS diagnosis.

## Spectron 2.2 v347 encoded string residual

The v347 checkpoint is a static continuation from v346. It labels 19 target
functions in the obfuscated `CanTfaz6bZ` copy-on-write XOR-encoded string
buffer and its `C8THgaTQxF` bridge. Direct target pseudocode shows lazy
three-byte key initialization, shared-buffer release and assignment,
make-unique copying, conversion to and from the ordinary target string,
encoded comparison, decoded case-insensitive comparison, byte-buffer
assignment, one-based decoded indexing, and XOR-aware append.

The target-only policy is important here. The target buffer is not the same
class as the target `vuuHgangcF` container that already has source-backed
`v18_TStringList` aliases. Three rows happen to share ordinary source metrics,
but their bodies implement encoded storage. The label artifact therefore
records three exact and normalized metric collisions, zero source
counterparts, and zero semantic promotions.

All 19 labels were applied and verified after reopening the saved IDB. The
v347 database has 11,707 functions, 6,440 translated aliases, 439 target-only
descriptive labels, 769 retained target names, 4,795 source-backed dynamic
rows, 1,657 exact retained dynamic names, and 5,782 exact dynamic function
starts. The semantic map remains unchanged at 3,721 mapped pairs. The saved
database is
`analysis/spectron_libqplay_translated_v347_encoded_string.i64` with SHA-256
`fe1bbbdf27b25b2fe13d088fb01944a624e8fe8a11898a377ff66f49b892a59b`.

This checkpoint changes no APK and has no runtime effect. The verified
loopback world-rendering result and the native TLS and hostname-verification
diagnosis remain the same. No live service or external resource was contacted.

## Spectron 2.2 v346 resource path helper residual

The v346 checkpoint adds one descriptive target-only label at `0xefbcc`, raw
symbol `_ZN10f6WHgaQkAF10iaBygafTIxERK10C8THgaTQxFb`. Static pseudocode shows a
resource path and update helper. It chooses an absolute or level-relative
resource, checks loadability, optionally updates an existing object or starts
a missing download, and returns the composed local path through a hidden
`TString` output.

This helper is distinct from the target's existing
`v18_TResourceFunctions_getGameFile_TString_const_bool` alias at `0xefe78`.
It has no exact or normalized feature match in the 1.8 inventory and no code
caller beyond its dynamic-symbol data record, so the applied name is
`spectron_TResourceFunctions_resolveResourcePath_TString_const_bool` rather
than a second source-backed alias.

The label was applied to the v345 IDB and verified after reopening. The v346
database has 11,707 functions, zero audited default names, 6,440 translated
aliases, 420 target-only descriptive labels, 4,795 source-backed dynamic
rows, 1,676 exact retained dynamic names, and 5,782 exact dynamic function
starts. The semantic map is unchanged. Its SHA-256 is
`bfb7f36be1a572c5428192c90ee3288035805a2e34b7ead439437c4b1ccf2392`.

This is static evidence only. It did not change the verified APK, the
loopback runtime, the connector TLS diagnosis, or the live-service boundary.

## Spectron 2.2 v345 resource-object static residuals

The v345 static checkpoint translates three adjacent resource-runtime helpers:
the `TResourceObject` static initializer and the two `TEncodedFileKey` ABI
forms. Source addresses `0xf0434`, `0xf0464`, and `0xf04a4` map to target
addresses `0xf1910`, `0xf1940`, and `0xf1980`. The target raw symbols and the
applied `v18_` aliases remain paired in the anchor artifact.

All three source and target bodies are 296 bytes with 74 instructions, nine
basic blocks, ten branches, and four calls. Their normalized mnemonic,
opcode-shape, register-shape, and whole-body hashes match. Direct pseudocode
resolves the roles across the rebuilt target wrappers: the initializer
allocates and installs the resource-object hash list, while the key forms
reset the vtable, clear both strings, and optionally release the object.

The aliases were applied to a fresh v344-derived IDB and verified after
reopening. The v345 database has 11,707 functions and zero audited default
names. It contains 6,440 translated aliases, 419 target-only descriptive
labels, 789 retained target names, seven JNI exports, and 4,052 other IDA or
PLT names. Dynamic coverage reports 4,795 source-backed aliases, 1,677 exact
retained names, and 5,782 exact dynamic function starts. The semantic map
contains 3,721 mapped pairs, 3,661 high-confidence pairs, 1,015 remaining
automatic ambiguities, and 608 unmatched source functions.

The saved IDB is
`analysis/spectron_libqplay_translated_v345_resource_object_static.i64` with
SHA-256
`0b455dfb6777c8ca571f86e19612d30a7dca6c3d9b9e47590e31a6bfcea4442f`.
This was static IDA work only. It did not change the verified APK, loopback
runtime, TLS diagnosis, or live-service boundary.

## Spectron 2.2 v344 resource-stream crypto residuals

The v344 revision is a static IDA checkpoint for the adjacent resource-stream
encryption and decryption methods. Source `TResourceFunctions_encryptTStream`
at `0xece78` maps to target `0xede48`, and source
`TResourceFunctions_decryptTStream` at `0xecfa0` maps to target `0xedf70`.
The raw target symbols are retained in the anchor artifact, while the IDA
database now carries the `v18_` aliases.

The automatic shape matcher had left both source rows ambiguous because each
body is 296 bytes with 74 instructions, nine basic blocks, ten branches, and
four calls. Direct source and target Hex-Rays pseudocode resolves the order:
the first pair calls the encrypt-memory helper and the second calls the
decrypt-memory helper. Both bodies lower-case the resource filename, derive
the same eight-byte key schedule, read the `TString` payload, transform the
bytes in memory, and clear the temporary string. All normalized feature hashes
match; only the register-detail hash differs.

The aliases were applied to a fresh v343-derived database and verified after
reopening. The v344 database contains 11,707 functions, zero audited default
names, 6,437 translated aliases, 4,791 source-backed dynamic rows, and 1,680
exact retained dynamic names. All 5,782 defined dynamic function symbols
still resolve to exact IDA function starts. The semantic map reports 3,718
mapped source-target pairs and 1,018 remaining automatic ambiguities.

Its SHA-256 is
`d7d4887e86d0570d7f2518bd545d3caa139aa0a1c5e0ca5c39d5c00b50b7669a`.
The records are
`artifacts/spectron_resource_stream_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_resource_stream_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_resource_stream_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v344_resource_stream.json`,
`artifacts/spectron_name_coverage_audit_v344.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v344.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v344.json`,
`artifacts/spectron_semantic_translation_v344.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v344.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v344.

## Spectron 2.2 v343 TDrawingPanel residuals

The v343 revision is a static IDA checkpoint for three raw methods in the
obfuscated `V8fxgahcBw` drawing-panel class. It covers operation-list cleanup,
image operation creation, and text operation creation. Each source and target
body has direct compact pseudocode and an exact normalized ARM64 feature match.

The clear method walks the list at panel slot 15, destroys each non-null
operation through its virtual cleanup slot, and clears the list. The image and
text methods allocate 0x30 and 0x88 bytes respectively, construct the drawing
operation with a local coordinate point, and queue it through the target's
`V8fxgahcBw::km8T2anEQ2` helper.

The aliases were applied to a fresh v342-derived database and verified after
reopening. The v343 database contains 11,707 functions, zero audited default
names, 6,435 translated aliases, 4,789 source-backed dynamic rows, and 1,682
exact retained dynamic names. All 5,782 defined dynamic function symbols still
resolve to exact IDA function starts.

Its SHA-256 is
`bb51b5b8ceb13acae2d5843019473ab988f0f931d2a5bce484f0ff3f32103ae8`.
The records are
`artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_drawing_panel_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_drawing_panel_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v343_drawing_panel_residual.json`,
`artifacts/spectron_name_coverage_audit_v343.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v343.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v343.json`,
`artifacts/spectron_semantic_translation_v343.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v343.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v343.

## Spectron 2.2 v342 TInput modifier-state residuals

The v342 revision is a static IDA checkpoint for three raw modifier accessors
in the obfuscated `GaA2gaD2MX` input class. It covers shift, control, and alt
state queries. Each source and target body has direct compact pseudocode and
an exact normalized ARM64 feature match.

The source methods use `plt_TInput_getKeyState_int`; the target methods use
`GaA2gaD2MX::xiDpfajGaA`. Each method tests a primary modifier entry with the
incoming key argument, then tests its adjacent fallback entry with zero when
the primary result is false. The three byte pairs are qword_A0 offsets 0 and
1, 2 and 3, and 4 and 5.

The aliases were applied to a fresh v341-derived database and verified after
reopening. The v342 database contains 11,707 functions, zero audited default
names, 6,432 translated aliases, 4,786 source-backed dynamic rows, and 1,685
exact retained dynamic names. All 5,782 defined dynamic function symbols still
resolve to exact IDA function starts.

Its SHA-256 is
`ec767e7a86e12b169f0053d4d1b783aa01fc8b7efa90863b69912553aa451ae7`.
The records are
`artifacts/spectron_input_modifiers_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_input_modifiers_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_input_modifiers_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v342_input_modifiers_residual.json`,
`artifacts/spectron_name_coverage_audit_v342.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v342.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v342.json`,
`artifacts/spectron_semantic_translation_v342.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v342.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v342.

## Spectron 2.2 v341 GuiControl color-setter residuals

The v341 revision is a static IDA checkpoint for four raw GuiControl color
setters in the obfuscated w9XxgaJdbx class. It covers red, green, blue, and
alpha updates, including the shared color refresh and rectangle invalidation.
Every source and target row has direct compact pseudocode and an exact
normalized ARM64 feature match.

The aliases were applied to a fresh v340-derived database and verified after
reopening. The v341 database contains 11,707 functions, zero audited default
names, 6,429 translated aliases, 4,783 source-backed dynamic rows, and 1,688
exact retained dynamic names. All 5,782 defined dynamic function symbols still
resolve to exact IDA function starts.

Its SHA-256 is
`f892d0eb81a79a242c41aeb19742dc33693863fd0373217727d2bba154d33d73`.
The records are
`artifacts/spectron_colorset_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_colorset_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_colorset_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v341_colorset_residual.json`,
`artifacts/spectron_name_coverage_audit_v341.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v341.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v341.json`,
`artifacts/spectron_semantic_translation_v341.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v341.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v341.

## Spectron 2.2 v340 TTilesBlock and TTilesPanel residuals

The v340 revision is a static IDA checkpoint for four raw tile and panel
methods. It covers image destruction, transparency and black-mask queries,
and the boolean TTilesPanel constructor. Every source and target row has
direct compact pseudocode and an exact normalized ARM64 feature match. Three
rows reinforce existing semantic candidates; the panel constructor adds new
context.

The aliases were applied to a fresh v339-derived database and verified after
reopening. The v340 database contains 11,707 functions, zero audited default
names, 6,425 translated aliases, 4,779 source-backed dynamic rows, and 1,692
exact retained dynamic names. All 5,782 defined dynamic function symbols still
resolve to exact IDA function starts.

Its SHA-256 is
`24a96367fa0730d1a125d146f4fd8e304ba96f6676c15deb2807d085671734d1`.
The records are
`artifacts/spectron_tiles_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tiles_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tiles_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v340_tiles_residual.json`,
`artifacts/spectron_name_coverage_audit_v340.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v340.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v340.json`,
`artifacts/spectron_semantic_translation_v340.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v340.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v340.

## Spectron 2.2 v339 rectangle and region geometry residuals

The v339 revision is a static IDA checkpoint for four raw geometry methods:
float and double rectangle union, empty-region construction, and region-list
cleanup. Every source and target row has direct compact pseudocode and an
exact normalized ARM64 feature match. Three rows reinforce existing semantic
candidates; the region constructor adds new context.

The aliases were applied to a fresh v338-derived database and verified after
reopening. The v339 database contains 11,707 functions, zero audited default
names, 6,421 translated aliases, 4,774 source-backed dynamic rows, and 1,696
exact retained dynamic names. All 5,782 defined dynamic function symbols still
resolve to exact IDA function starts.

Its SHA-256 is
`d50a0755bb461dada6b011b4df4ca01f9a0cbaf0112805b0ff1e5ab48764bebe`.
The records are
`artifacts/spectron_geometry_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_geometry_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_geometry_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v339_geometry_residual.json`,
`artifacts/spectron_name_coverage_audit_v339.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v339.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v339.json`,
`artifacts/spectron_semantic_translation_v339.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v339.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v339.

## Spectron 2.2 v338 THTMLPage lifecycle residuals

The v338 revision is a static IDA checkpoint for seven raw lifecycle methods
in the obfuscated `AS80gaE4zW` class. The source and target entries have direct
compact pseudocode, exact normalized ARM64 metrics, and matching class-local
order. The aliases cover tab stops, line tags, styles, sub-pages, lists, and
the two linked-list cleanup routines.

The aliases were applied to a fresh v337-derived database and verified after
reopening. The v338 database contains 11,707 functions, zero audited default
names, 6,417 translated aliases, 4,769 source-backed dynamic rows, and 1,700
exact retained dynamic names. All 5,782 defined dynamic function symbols still
resolve to exact IDA function starts.

Its SHA-256 is
`26584982aa976361088e7978b162d12e1be4bf2bf9991bf9484c56e92bba8c2d`.
The records are
`artifacts/spectron_html_page_lifecycle_manual_translation_anchors_20260829.json`,
`artifacts/spectron_html_page_lifecycle_manual_translation_application_20260829.json`,
`artifacts/spectron_html_page_lifecycle_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v338_html_page_lifecycle.json`,
`artifacts/spectron_name_coverage_audit_v338.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v338.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v338.json`,
`artifacts/spectron_semantic_translation_v338.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v338.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v338.

## Spectron 2.2 v337 libjpeg helper residuals

The v337 revision is a static IDA checkpoint for twelve raw libjpeg helper
symbols. Eight target entries at `0x2a2358` through `0x2a23b0` implement the
memory-manager methods. Four more at `0x2a52b0` through `0x2a534c` implement
rounding, block-row copying, and far-buffer clearing.

All twelve source and target rows have direct pseudocode and exact normalized
ARM64 feature matches. The aliases were applied to a fresh v336-derived
database and verified after reopening. The v337 database contains 11,707
functions, zero audited default names, 6,410 translated aliases, 4,762
source-backed dynamic rows, and 1,707 exact retained dynamic names. All 5,782
defined dynamic function symbols still resolve to exact IDA function starts.

Its SHA-256 is
`391d3bb01245f636760daeb8cef80012e602dfc04423d104a44ceb8e1e4d7113`.
The records are
`artifacts/spectron_libjpeg_helper_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_libjpeg_helper_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_libjpeg_helper_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v337_libjpeg_helper_residual.json`,
`artifacts/spectron_name_coverage_audit_v337.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v337.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v337.json`,
`artifacts/spectron_semantic_translation_v337.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v337.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v337.

## Spectron 2.2 v336 GSFunctionsInitstaticscriptvars and TFormat2 residuals

The v336 revision is a static IDA checkpoint for the contiguous Format2
parameter block at target `0x2130b0` through `0x213598`. It maps the count-37
script-function initializer, four numeric accessors, the D1 and D0
destructors, and two string accessors. Four rows are exact normalized matches,
and the remaining five record the target's rebuilt wrapper layout or register
detail.

The aliases were applied to a fresh v335-derived database and verified after
reopening. The v336 database has 11,707 functions, zero audited default names,
6,398 translated aliases, 4,750 source-backed dynamic rows, and 1,719 exact
retained dynamic names. All 5,782 defined dynamic symbols still resolve to
exact IDA function starts. Its SHA-256 is
`55662a1b9e5989c1e14350ab585015ccb6af0af123f12fab0dcab414f54ca199`.

The records are
`artifacts/spectron_format2_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_format2_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_format2_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v336_format2_residual.json`,
`artifacts/spectron_name_coverage_audit_v336.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v336.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v336.json`,
`artifacts/spectron_semantic_translation_v336.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v336.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v336.

## Spectron 2.2 v335 GSFunctionsClient and TAdventure residuals

The v335 revision is a static IDA checkpoint for four raw target entries in
the GSFunctionsClient and TAdventure blocks. It maps the static `shootparams`
initializer, Adventure resource cleanup, the empty mouse-move callback, and
the empty Adventure static-script initializer. Three rows are exact
normalized matches and the static-variable row differs only in register-detail
allocation.

The aliases were applied to a fresh v334-derived database and verified after
reopening. The v335 database has 11,707 functions, zero audited default names,
6,389 translated aliases, 4,740 source-backed dynamic rows, and 1,728 exact
retained dynamic names. All 5,782 defined dynamic symbols still resolve to
exact IDA function starts. Its SHA-256 is
`dae970eb4edf7237544073da7badb3cfe0bd9d3ccb03e8ec9bde5b5c7de73a16`.

The records are
`artifacts/spectron_adventure_static_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_adventure_static_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_adventure_static_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v335_adventure_static_residual.json`,
`artifacts/spectron_name_coverage_audit_v335.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v335.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v335.json`,
`artifacts/spectron_semantic_translation_v335.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v335.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v335.

## Spectron 2.2 v334 bitmap JPEG static initializer

The v334 revision is a static IDA checkpoint for the residual JPEG static
property initializer at target `0x1541bc`. It maps the source
`TBitmap_jpeg_initStaticScriptVars_void` at `0x151394` to the stripped target
`_Z10eY1M1algS6v`. Both functions make a one-entry property-table registration
call. The target uses its rebuilt `cWWYfaxbT2` helper and a relocated table,
so this is recorded as a high-confidence layout-change alias.

The alias was applied to a fresh v333-derived copy and verified after
reopening. The v334 database has 11,707 functions, zero audited default names,
6,385 translated aliases, 4,736 source-backed dynamic rows, and 1,732 exact
retained dynamic names. All 5,782 defined dynamic symbols still resolve to
exact IDA function starts. Its SHA-256 is
`c2002066a0412b180afd6abb36fe08f0873403d3068a2a0bdd88deb997101398`.

The records are
`artifacts/spectron_bitmap_jpeg_static_manual_translation_anchors_20260829.json`,
`artifacts/spectron_bitmap_jpeg_static_manual_translation_application_20260829.json`,
`artifacts/spectron_bitmap_jpeg_static_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v334_bitmap_jpeg_static.json`,
`artifacts/spectron_name_coverage_audit_v334.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v334.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v334.json`,
`artifacts/spectron_semantic_translation_v334.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v334.json`.

This checkpoint did not change the verified loopback package, connector TLS
result, or local protocol responder. No live endpoint was contacted, and no
new runtime replay was performed for v334.

## Spectron 2.2 v333 THashIntVar translation

The v333 revision is a static IDA checkpoint for the two raw destructor
entries between the translated `THTMLColors` and `TImageAnimation` methods.
It translates the complete and deleting `THashIntVar` pair to the target
`SrwA5a7Ukj` D1 and D0 boundaries. Both bodies reset the vtable, clear the
member at offset 8, and the deleting form calls `operator delete`. It does
not change the previously verified loopback package, connector TLS result,
or local protocol responder.

Both aliases were applied to a fresh v332-derived database and verified after
reopening. The two rows are high-confidence layout matches because only the
register-detail hash changes between source and target. The v333 database has
11,707 functions, zero audited default names, 6,384 translated aliases, 4,735
source-backed dynamic rows, and 1,733 exact retained target names. All 5,782
defined dynamic function symbols still resolve to exact IDA function starts.

The database is
`analysis/spectron_libqplay_translated_v333_hashintvar_residual.i64` with
SHA-256
`c6f31412206a9a893fedf594fac90dff2f13be69f2db28fcda80cc2c67ad7f4d`.
The records are
`artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_hashintvar_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_hashintvar_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v333_hashintvar_residual.json`,
`artifacts/spectron_name_coverage_audit_v333.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v333.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v333.json`,
`artifacts/spectron_semantic_translation_v333.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v333.json`.

This checkpoint is static evidence only. No APK was patched, no live endpoint
was contacted, and no new runtime replay was performed for v333.

## Spectron 2.2 v332 TPanelOperation translation

The v332 revision is a static IDA checkpoint for the next contiguous drawing
panel block. It translates five `TPanelOperation::getBounds` methods, the
line, curve, and clear destructor boundaries, the
`TDrawingPanelProperties` destructor family, and the derived rectangle,
stretched-image, and image operation cleanup entries. It does not change the
previously verified loopback package, connector TLS result, or local protocol
responder.

The five bounds methods are exact normalized ARM64 matches. The clear and
stretched methods copy the operation rectangle, the curve and line methods
compute endpoint minima and absolute extents, and the text method preserves a
zeroed result rectangle. The source database's constructor-shaped names on
the six four-byte operation entries are resolved as D1 and D0 destructor
boundaries by the source alternative names and the target's explicit C++ ABI
symbols. The `V8fxgahcBwProperties` family keeps the 16-byte secondary-base
thunks, and the three derived operation families keep their embedded
`TResourceFileUser` cleanup offsets.

All 20 aliases were applied to a fresh v331-derived database and verified
after reopening. Thirteen rows are exact feature matches and seven differ
only in register-detail allocation. Every row has source and target compact
Hex-Rays pseudocode and is marked high confidence.

The v332 database contains 11,707 functions and zero audited default names,
with 6,382 translated `v18_` aliases, 4,732 source-backed dynamic rows, and
1,735 exact retained target names. All 5,782 defined dynamic function symbols
still resolve to exact IDA function starts.

The database is
`analysis/spectron_libqplay_translated_v332_paneloperation_residual.i64` with
SHA-256
`f77edbe5076211bd3bd5a18c549f0c3cbaeeb88d2da7bc9c52a2733c1d87cdc2`.
The records are
`artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_paneloperation_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_paneloperation_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v332_paneloperation_residual.json`,
`artifacts/spectron_name_coverage_audit_v332.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v332.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v332.json`,
`artifacts/spectron_semantic_translation_v332.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v332.json`.

This checkpoint is static evidence only. No APK was patched, no live endpoint
was contacted, and no new runtime replay was performed for v332.

## Spectron 2.2 v331 static-variable runtime translation

The v331 revision is a static IDA checkpoint for the class-local block that
follows the v330 TScriptUniverse methods. It covers the universe static
initializer, the `TGraalPlayersArrayVar` destructor pair, the `TStaticVar` and
`TActionScriptVar` factories, and all property and object destructor forms in
the block. It does not change the previously verified loopback package,
connector TLS result, or local protocol responder.

The target class names are obfuscated, but the bodies preserve the source
sequence. The `e4ZYfa8PV2Properties` methods reset their vtables and call the
base `TProperties` destructor. The `JE42uaVwcK` pair follows the translated
array-cell accessor and calls the `G0gxgajWBw` base destructor. The
`NgNBgaN3oA` factory allocates `0x88` bytes for a static variable, and the
`mH33wa4I1q` factory repeats the same operation for an action variable. Their
complete and deleting destructors preserve garbage-collector cleanup, base
destruction, and `operator delete`.

All 22 aliases were applied to a fresh v330-derived IDA database and all 22
were verified after reopening. Ten rows are exact normalized feature matches.
The other twelve differ only in the register-detail hash, reflecting target
register allocation. Compact pseudocode was available for all 22 source and
target functions, and every row is marked high confidence.

The v331 database contains 11,707 functions and zero audited default names,
with 6,362 translated `v18_` aliases, 4,706 source-backed dynamic rows, and
1,755 exact retained target names. All 5,782 defined dynamic function symbols
still resolve to exact IDA function starts.

The database is
`analysis/spectron_libqplay_translated_v331_tscript_var_residual.i64` with
SHA-256
`f6bb72c43b0022b372d6d98e4143aa920a7e3c43cd5a89ede10e7510cd00178c`.
The records are
`artifacts/spectron_tscript_var_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v331_tscript_var_residual.json`,
`artifacts/spectron_name_coverage_audit_v331.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v331.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v331.json`,
`artifacts/spectron_semantic_translation_v331.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v331.json`.

This is static evidence only. No APK was patched, no live endpoint was
contacted, and no new runtime replay was performed for v331.

## Spectron 2.2 v330 TScriptUniverse residual translation

The v330 revision is a static IDA checkpoint for the next target
`e4ZYfa8PV2` TScriptUniverse block. It does not change the previously verified
loopback package, connector TLS result, or local protocol responder.

| 1.8 source | Spectron target | Applied alias | Review result |
| ---: | ---: | --- | --- |
| `0x22b1f8` | `0x234bc0` | `v18_TScriptExecutionStats_TScriptExecutionStats__2` | exact D0 destructor |
| `0x22b3b4` | `0x234d98` | `v18_TScriptUniverse_setExecutingNPC_TServerNPC` | same execution-state stores; register-detail change |
| `0x22b3d0` | `0x234db4` | `v18_TScriptUniverse_setExecutingPlayer_TServerPlayer` | same execution-state stores; register-detail change |
| `0x22b614` | `0x235000` | `v18_TScriptUniverse_removeStaticObject_TGraalVar` | exact field-12 removal helper |
| `0x22c068` | `0x235a50` | `v18_TScriptUniverse_addToFreeMachines_TScriptMachine` | exact membership and append helper |
| `0x22c210` | `0x235bf8` | `v18_TScriptUniverse_TScriptUniverse__2` | exact D0 destructor |

The target parameter classes provide useful confirmation. `LBgVgaqANQ` is the
target TServerNPC class, `MpGzgariDy` is TServerPlayer, `G0gxgajWBw` is
TGraalVar, and `mTAogaaEip` is TScriptMachine. The source and target bodies
also line up with the neighboring translated `clearVars`, `addStaticObject`,
`getFreeMachine`, and `clearGraalScriptMachines` methods.

The application renamed all six functions and added six evidence comments
with zero failures. Reopening the fresh copy verified all six names. The
database contains 11,707 functions, zero audited default names, 6,340
translated `v18_` aliases, and 419 target-only descriptive labels. Dynamic
coverage reports 4,679 source-backed aliases and 1,776 exact retained names.
All 5,782 defined dynamic function symbols still resolve to exact IDA
function starts.

The v330 database is
`analysis/spectron_libqplay_translated_v330_tscript_universe_residual.i64`
with SHA-256
`be32d09e08a76b3641beff951644ec78167fcc2735d5fc5ea58f9ee12acf97a1`.
The complete records are
`artifacts/spectron_tscript_universe_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_universe_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_universe_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v330_tscript_universe_residual.json`,
`artifacts/spectron_name_coverage_audit_v330.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v330.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v330.json`,
`artifacts/spectron_semantic_translation_v330.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v330.json`.

This is static evidence only. No APK was patched, no live endpoint was
contacted, and no new runtime replay was performed for v330.

## Spectron 2.2 v329 TScriptSpace residual translation

The v329 pass is a static IDA translation checkpoint. It follows the v328
script-machine tail into the raw `N67CMatrxw` TScriptSpace block and adds two
source-backed aliases plus two target-only descriptive labels.

| Source role | Spectron address | Applied name | Match class |
| --- | ---: | --- | --- |
| `TScriptSpace_freeSuspendedStates_void` | `0x230198` | `v18_TScriptSpace_freeSuspendedStates_void` | exact normalized metrics |
| `TScriptSpace_joinClass_TString_const_bool` | `0x233114` | `v18_TScriptSpace_joinClass_TString_const_bool` | layout change |
| target-only `receiveEvent` overload | `0x23332c` | `spectron_TScriptSpace_receiveEvent_TString_const_CanTfaz6bZ_const_TGraalVar` | descriptive target label |
| target-only queue cleanup helper | `0x2339b4` | `spectron_TScriptSpace_clearScheduledEventsAndCancelActions_void` | descriptive target label |

The exact row deletes all saved script-machine states from the suspended-state
list and clears field 16, with the same 124-byte ARM64 feature record in both
builds. The class-join row preserves the source empty-script setup, class
lookup, permission check, join, catcher installation, and update action. The
target adds temporary `CanTfaz6bZ` and list-wrapper cleanup, so its body is
larger but its role is clear.

The `0x23332c` function takes a normalized target event-name wrapper and
repeats the translated receive-event queue policy. It remains separate from
the existing source-backed C8THgaTQxF overload. The `0x2339b4` function has no
arguments, destroys all scheduled events, and marks all pending actions
canceled. Neither target-only function has a distinct 1.8 source boundary.

The source aliases and target-only labels were applied to fresh v328-derived
copies and verified after reopening. The v329 database contains 11,707
functions, zero audited default names, 6,334 translated aliases, and 419
target-only descriptive labels. Dynamic coverage reports 4,673 source-backed
aliases and 1,782 exact retained names, while all 5,782 defined dynamic
function symbols still have exact IDA starts.

The v329 database is
`analysis/spectron_libqplay_translated_v329_tscript_space_residuals.i64` with
SHA-256
`c84c8bd4abe51302092c82db16003712e870b0ed8a541a9417f6c563f540b6ee`.
The records are
`artifacts/spectron_tscript_space_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_space_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_space_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_tscript_space_residual_labels_20260829.json`,
`artifacts/spectron_tscript_space_residual_label_application_20260829.json`,
`artifacts/spectron_tscript_space_residual_label_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v329.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v329.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v329.json`,
`artifacts/spectron_semantic_translation_v329.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v329.json`.

This is static analysis only. It does not change the previously verified
loopback runtime result or the TLS diagnosis, and it does not contact a live
service.

## Spectron 2.2 v328 TScriptMachine static-tail translation

The v328 pass closes the next two raw functions after the v327 property
constructor and destructor work. It translates the static script-variable
initializer and the deleting `TCallStackEntry` destructor.

The target `DgaM1aDf85` helper is the source
`TScriptMachine_initStaticScriptVars_void` role. Both helpers allocate the
class-specific `TCallStackEntryProperties` object, call its default
constructor, store the global pointer, and return the address of that global.
The target allocates 0x68 bytes for the rebuilt `l8eTfaIl5YProperties` object,
where 1.8 allocates 0x58 bytes, so this is recorded as a layout-change match.
The target `l8eTfaIl5Y` D0 body is an exact normalized match for the source
`TCallStackEntry_TCallStackEntry__2` deleting destructor: it calls the D2 body
and then releases the receiver with `operator delete`.

Both aliases were applied to a fresh v327-derived copy and verified after
reopening. The v328 database contains 11,707 functions and zero audited
default names. Its name origins are 6,332 translated `v18_` aliases, 417
target-only descriptive labels, 898 retained target names, seven JNI exports,
and 4,053 other IDA or PLT names. Dynamic-symbol coverage reports 4,671
source-backed aliases, 1,786 exact retained names, and 136 other retained
target names, with 5,782 exact dynamic function starts.

The nearby `mTAogaaEip::xxpwPaW5SX` overload at `0x221928` remains outside the
source-backed alias count. Its pseudocode converts a `C8THgaTQxF` string into
the target `CanTfaz6bZ` wrapper and forwards to the already translated large
resolver overload. No distinct 1.8 function boundary was established for
that adapter.

The final private database is
`analysis/spectron_libqplay_translated_v328_script_machine_static_tail.i64`
with SHA-256
`01e5dc66c7446c46101a09486f23c1a86822e9973b57b5897fa93a4d1f11526a`. The
machine-readable records are
`artifacts/spectron_script_machine_static_tail_manual_translation_anchors_20260829.json`,
`artifacts/spectron_script_machine_static_tail_manual_translation_application_20260829.json`,
`artifacts/spectron_script_machine_static_tail_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v328.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v328.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v328.json`,
`artifacts/spectron_semantic_translation_v328.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v328.json`.

This was a static translation pass only. It did not patch the APK, rerun the
loopback client, alter TLS behavior, contact a game server, or test a live
endpoint.

## Spectron 2.2 v327 property construction and cleanup translation

The v327 pass closes the next raw target cluster after the v326 format and
property work. It translates the named `TProperties` constructor and
compiler, the global property-list lookup, the `TObjectCreator` registration
constructor, the static script-property registry helper, and the object
creator plus derived-property destructor pairs.

The source and target pseudocode agree on the important ownership behavior.
The property constructor initializes the hash-list base, creates the property
list, stores the display name, initializes the owner and flags, and registers
the object globally. The compiler guards on the compiled state, rebuilds the
list, recursively compiles inherited properties, removes replaced entries,
and releases temporary storage. The object-creator constructor stores its
string and callback and adds itself to the global registry. The destructor
pairs preserve vtable replacement, derived and base string cleanup, receiver
adjustment, and deleting-form `operator delete` placement.

All 15 rows are high-confidence layout-change anchors. The target's rebuilt
string and container wrappers alter the normalized metrics, so none are
reported as exact metric matches even though the control-flow and cleanup
roles line up. The nearby one-argument target constructor at `0x22e838`,
`_ZN10cWWYfaxbT2C1ERK10CanTfaz6bZ`, remains a target-only overload because no
independent 1.8 counterpart was established.

All 15 aliases were applied to a fresh v326-derived copy and verified after
reopening. The v327 database contains 11,707 functions and zero audited
default names. Its name origins are 6,330 translated `v18_` aliases, 417
target-only descriptive labels, 900 retained target names, seven JNI exports,
and 4,053 other IDA or PLT names. Dynamic-symbol coverage reports 4,669
source-backed aliases, 1,788 exact retained names, and 136 other retained
target names, with 5,782 exact dynamic function starts.

The final private database is
`analysis/spectron_libqplay_translated_v327_property_constructor_destructor.i64`
with SHA-256
`cc731360c7c08f825a7905c760897d3a7aede1dccdb4322d56d72f5c2e0c2f13`. The
machine-readable records are
`artifacts/spectron_property_constructor_destructor_manual_translation_anchors_20260829.json`,
`artifacts/spectron_property_constructor_destructor_manual_translation_application_20260829.json`,
`artifacts/spectron_property_constructor_destructor_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v327.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v327.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v327.json`,
`artifacts/spectron_semantic_translation_v327.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v327.json`.

This was a static translation pass only. It did not patch the APK, rerun the
loopback client, alter TLS behavior, contact a game server, or test a live
endpoint.

## Spectron 2.2 v326 format-parameter and property translation

The v326 pass closes the next raw target cluster after the v325 script
destructor work. It translates the `TScriptMachine::FormatParameters`
destructor and eight accessors, the `TCallStackEntryProperties` destructor
family, the `TProperties` destructor family, and two derived-property object
writers.

The eight accessors are a particularly strong match. The target's obfuscated
`OV5NOaoBLl` methods call the next or indexed script-machine float readers in
the same order as the source. The integer variants retain the `0.0001` bias
and negative correction, while the floating-point and string variants remain
direct forwarding wrappers. The destructor rows agree through D1, D2, and D0
C++ ABI forms, vtable replacement, receiver adjustment, base cleanup, and
`operator delete` placement. The object writers preserve the source callback
and temporary-string cleanup sequence while using rebuilt target string
classes.

Eleven rows retain exact normalized feature metrics and nine are recorded as
layout changes. All 20 aliases were applied to a fresh v325-derived copy and
verified after reopening. The v326 database contains 11,707 functions and
zero audited default names. Its name origins are 6,315 translated `v18_`
aliases, 417 target-only descriptive labels, 915 retained target names, seven
JNI exports, and 4,053 other IDA or PLT names. Dynamic-symbol coverage reports
4,647 source-backed aliases, 1,803 exact retained names, and 143 other
retained target names, with 5,782 exact dynamic function starts.

The final private database is
`analysis/spectron_libqplay_translated_v326_format_parameters_property.i64`
with SHA-256
`08ae63229dfbcabf94d314cda677a2c45b60e17b9c2fee8351a298b3cf6eb991`.
The machine-readable records are
`artifacts/spectron_format_parameters_property_manual_translation_anchors_20260829.json`,
`artifacts/spectron_format_parameters_property_manual_translation_application_20260829.json`,
`artifacts/spectron_format_parameters_property_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v326.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v326.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v326.json`,
`artifacts/spectron_semantic_translation_v326.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v326.json`.

This was a static translation pass only. It did not patch the APK, rerun the
loopback client, alter TLS behavior, contact a game server, or test a live
endpoint.

## Spectron 2.2 v325 TScript destructor translation

The v325 pass closes eight raw symbols left in the v324 script-runtime block.
It translates the TScript log-name helper, the deleting TScript destructor,
the TScriptFunctionProperties destructor pair and non-virtual thunks, and the
TFunctionProfile destructor pair.

Three rows have exact normalized metrics. The five layout-change rows differ
only in target string-wrapper or register-detail behavior. The source and
target bodies agree on the C++ ABI sequence: vtable reset, base destruction,
optional name-string cleanup, receiver adjustment for thunks, and
`operator delete` for the D0 forms. The log-name helper still builds the
`Class ` prefix followed by the script name.

All eight aliases were applied to a fresh v324-derived copy and verified after
reopening. The v325 database contains 11,707 functions and zero audited
default names. Its name origins are 6,295 translated `v18_` aliases, 417
target-only descriptive labels, 935 retained target names, seven JNI exports,
and 4,053 other IDA or PLT names. The dynamic-symbol audit reports 4,624
source-backed aliases, 1,823 exact retained names, 146 other retained target
names, seven linker-boundary aliases, 169 PLT veneers, and one undefined
`__sF` import without an in-library veneer.

The final private database is
`analysis/spectron_libqplay_translated_v325_tscript_destructor_final.i64` with
SHA-256
`229e4729eed1be2759935c1604ac6e3987ffe6fbe91c2b5a0dca16ae344c0757`.
The machine-readable records are
`artifacts/spectron_tscript_destructor_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_destructor_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_destructor_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v325.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v325.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v325.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v325.json`.

This pass changed only the private IDA copy and archive. It did not patch the
APK, rerun the client, alter TLS behavior, contact a game server, or test a
live endpoint.

## Spectron 2.2 v324 TScript runtime translation

The v324 pass is a static continuation from v323. It translates 24 methods in
the `TScriptFunction`, `TScript`, and `TScriptEnvironment` families. The group
covers script-function construction and cleanup, direct and inherited function
lookup, event registration and catcher installation, profiler time,
bytecode optimization, encrypted script loading, and variable-construction
helpers.

Three methods have exact normalized metric matches. The remaining 21 are
high-confidence layout-change matches caused by the target's rebuilt string,
list, hash, and iterator classes. The source and target pseudocode preserve
the same control-flow decisions. The bytecode optimizer still walks the same
51-block, 32-branch method, with the target's larger instruction record
explaining the metric difference. The environment static initializer is also
explicitly a layout change because its registry setup is expanded into
separate object constructions in the target.

The application renamed all 24 target functions and added 24 evidence comments
with zero failures. Reopening the saved database verified all 24 names. The
v324 database contains 11,707 functions and zero audited default names. Its
name origins are 6,287 translated `v18_` aliases, 417 target-only descriptive
labels, 943 retained target names, seven JNI exports, and 4,053 other IDA or
PLT names. The dynamic-symbol audit reports 4,614 source-backed aliases,
1,831 exact retained names, 148 other retained target names, seven
linker-boundary aliases, 169 PLT veneers, and one undefined `__sF` import
without an in-library veneer.

The final private database is
`analysis/spectron_libqplay_translated_v324_tscript_runtime_final.i64` with
SHA-256
`975367646c22c2f21d1c7ffc8380e0b48a6c259864a1f8b192e043c3e0992e06`.
The machine-readable records are
`artifacts/spectron_tscript_runtime_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_runtime_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_runtime_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v324.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v324.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v324.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v324.json`.

This pass changed only the private IDA copy and archive. It did not patch the
APK, rerun the client, alter TLS behavior, contact a game server, or test a
live endpoint.

## Spectron 2.2 v321 GUI boundary translation

The v321 pass closes the remaining comparison gap around eleven GUI methods.
The original 1.8 ELF dynamic table exposed positive-size `FUNC` rows that the
source IDA database had treated as data. A separate offline pass restored all
eleven source boundaries before matching them to the corresponding Spectron
methods.

Ten pairs match the normalized ARM64 feature record at high confidence. The
`GuiButtonCtrl::drawWithStyle` pair is medium confidence: class-local method
order, shared `Buttons` and `Taskbar.Button` strings, identical call and
branch counts, and reviewed pseudocode all agree, while the rebuilt Spectron
body is eight bytes and two instructions shorter. The difference is preserved
in the evidence rather than treated as an exact byte-level match.

The alias application renamed and verified all eleven target functions with
zero failures. The final v321 copy contains 11,707 functions and zero audited
default names. Its name origins are 6,228 translated `v18_` aliases, 417
target-only descriptive labels, 1,002 retained target names, seven JNI exports,
and 4,053 other IDA or PLT names.

The complete dynamic-symbol audit still accounts for data and imports instead
of forcing every named row into the function list. It reports 6,770 named
dynamic rows, 6,600 defined rows, 5,782 exact functions, 482 data items, 336
other non-code items, and 170 undefined imports. Exact PLT veneers cover 169
of the undefined imports. The remaining `__sF` object has no in-library
veneer. The post-alias status counts are 4,552 source-backed `v18_` aliases,
1,890 exact retained names, 151 other retained target aliases, and seven
linker-boundary aliases.

The current private database is
`analysis/spectron_libqplay_translated_v321_gui_missing_function_aliases_final.i64`
with SHA-256
`b7d17b9a5dbc34922cc40fe030cb539d69dcf89fe8a5f64bae83e962309263ab`.
The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v321.json`; the source
boundary, GUI anchor, reopen-verification, name, and dynamic-symbol records
are listed in that checkpoint and in the README.

## Spectron 2.2 function-name coverage audit

The v320 pass compares the retained Spectron dynamic table with the translated
IDA function index. Twelve section-defined `FUNC` symbols had positive ELF
sizes and valid AArch64 prologues but no IDA function boundary. A fresh copy
of v319 now materializes those exact `address` through `address + size`
intervals and keeps the target's retained mangled names.

The reopened v320 database has 11,707 functions. All 5,782 section-defined
dynamic `FUNC` rows now have exact IDA starts, with zero missing boundaries.
The complete joined inventory covers 6,770 named dynamic rows. Its 988 rows
without an IDA function at the symbol value remain unpromoted because they are
data, undefined imports, or other non-function entries. This closes a real
boundary gap without claiming that the stripped source-name table has been
recovered.

The complete address-and-item audit accounts for all 6,600 defined named
symbols: 5,782 exact functions, 482 data items, and 336 other non-code items.
It records 1,901 exact retained names, 4,541 reviewed `v18_` aliases, 151
other retained target aliases, seven linker-boundary aliases, and 170
undefined imports with no library address. Exact PLT veneer names represent
169 of those imports, while `__sF` has no in-library veneer. The full record is
`artifacts/spectron_dynamic_symbol_coverage_audit_20260828.json`.

The v320 database is
`analysis/spectron_libqplay_translated_v320_dynamic_functions.i64` with
SHA-256
`17015ba3140200199269ca94675e043e1e87cbefcdfa473680062a55ac96a0d6`.
The boundary audit, application report, name audit, dynamic join, and
checkpoint are
`artifacts/spectron_dynamic_symbol_boundaries_20260828.json`,
`artifacts/spectron_dynamic_function_application_20260828.json`,
`artifacts/spectron_name_coverage_audit_v320_20260828.json`,
`artifacts/spectron_symbol_translation_inventory_20260828.json`, and
`artifacts/spectron_translation_checkpoint_20260828_v320.json`.

The v319 IDA checkpoint closes a small naming gap that was hidden by the
earlier “zero `sub_` names” count. A complete audit of the 11,695-function
translated database found nine remaining `nullsub_*` names. Each is a four-byte
AArch64 function whose complete body is `RET`. They were renamed to stable
target-only labels of the form `spectron_nullsub_stub_0x...` and verified after
a close and reopen with zero failures.

The v319 database is
`analysis/spectron_libqplay_translated_v319_nullsub_labels.i64` with SHA-256
`ca68997409b58ee6342a5288319c4d3b834fde1a7d526aa62db962c46164defd`. The name
audit reports zero default function names in the checked `sub_`, `nullsub_`,
`j_`, `loc_`, and `unk_` families. Its origin counts are 6,217 `v18_`
translated aliases, 417 target-only descriptive labels, 1,001 retained
target-style C++ names, seven JNI exports, and 4,053 other IDA or PLT names.

This is a coverage result, not a claim that the stripped target's original
source symbols were restored. The 1.8 semantic map contains 3,700 unique
target matches, of which 3,641 high-confidence aliases were applied and 59
medium-confidence rows remain review-only. The full before and after name
inventories are in
`artifacts/spectron_name_coverage_audit_v318_20260828.json` and
`artifacts/spectron_name_coverage_audit_20260828.json`. The nine reviewed
labels and the v319 checkpoint are in
`artifacts/spectron_nullsub_target_only_labels_20260828.json` and
`artifacts/spectron_translation_checkpoint_20260828_v319.json`.

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
* Whether any of the expanded callback, CyaSSL, or static-library aliases
  should be persisted into the active desktop IDA database. The disposable-
  copy IDALIB validations passed, but the active unpacked database remained
  locked during these passes.
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
HexaParser output did not reach the expected game port. The original VM
stream reaches the full local resource path with its original connector
script when the native startup candidate is present, and the rendered result
was reproduced without the direct script-level loading clear. The direct
script insertion remains a compatible control, not the isolated render fix.

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

## v349 static audio-family follow-up

The v349 work is a static translation checkpoint and does not change the
runtime result. It reconciles ten `TSounds`, `TSoundPlayerJava`, and
`TSoundEffectJava` source rows with their target functions. The target IDA
copy already contained the `v18_` aliases, so the pass added review comments
and made the source-to-target relationships explicit in the semantic map.

The runtime conclusions therefore remain unchanged:

* the loopback connector replay still reaches the encrypted login path;
* the client still requests the map, level files, and image resources;
* the corrected loading-state diagnostic still reaches the green tiled world,
  HUD, and status icons;
* no live game server or production connector was contacted;
* TLS peer and hostname verification remain preserved in the diagnostic path.

The five larger sound routines reviewed during v349 are not runtime patches.
They remain layout-change candidates because the target's obfuscated string and
Java object wrappers add or remove instructions. Nothing from that group was
inserted into the APK or used to alter the loading repair.

The v349 static records are in
`artifacts/spectron_sounds_exact_manual_translation_anchors_20260829.json`,
`artifacts/spectron_semantic_translation_v349.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v349.json`. The saved IDA
copy is `analysis/spectron_libqplay_translated_v349_sounds_exact.i64` with
SHA-256
`ede4f9187e01c4a415181f423dd9c7b8467deb38595d399dcb19341fd9203faf`.

## v350 layout-aware audio follow-up

The v350 pass is also static and does not alter the working runtime repair.
It translates the five larger sound routines whose target layouts differ from
the source build:

* `TSounds_initStaticVars_void` remains the two-collection initializer, with
  target `KKhLga4xoI` and `vuuHgangcF` wrappers.
* `TSoundEffect_TSoundEffect_TString_const` keeps the name normalization and
  field initialization, with an added `CanTfaz6bZ` bridge.
* `TSounds_play_impl_TString_const_bool_bool_double_double` keeps the sound
  extension, cache, resource, and playback state machine.
* `TSounds_script_setSoundPitchByNote` keeps the note table and `powf` pitch
  calculation.
* `TSoundEffectJava_play_void` keeps Java playback and state updates while
  dropping the source `steps` special case.

These aliases do not represent runtime patches. The loopback connector result,
the encrypted login trace, the resource requests, the green-world diagnostic,
the TLS verification behavior, and the live-service boundary are unchanged.
No emulator or live endpoint was used for v350.

The layout-aware checkpoint is
`artifacts/spectron_translation_checkpoint_20260829_v350.json`. Its saved IDA
copy is `analysis/spectron_libqplay_translated_v350_sounds_layout.i64` with
SHA-256
`056db23f2015b33134e1fc2bcb99deb5821b96c9590646eb6100c0f7d3462870`.

## v351 static hash-family follow-up

The v351 pass is also static. It adds eight source-backed hash-container
relationships to the semantic map and does not change the working runtime
repair. The exact rows are the normal THashList string add and remove
wrappers. The encoded add and remove overloads and the four THashStrings
lookup or serialization methods use changed target string and iterator
wrappers, so they are documented as layout-aware.

The loopback connector result, encrypted login trace, resource requests,
green-world diagnostic, TLS verification behavior, and live-service boundary
are unchanged. No emulator or live endpoint was used for v351.

The v351 checkpoint is
`artifacts/spectron_translation_checkpoint_20260829_v351.json`. Its saved IDA
copy is `analysis/spectron_libqplay_translated_v351_hash_residual.i64` with
SHA-256
`0fb0662dffea1f1f6223e0e52745a19505687a79cf47f207280ce098f61b87f0`.

## v352 semantic-map reconciliation

The v352 work is static metadata only. It reconciles 509 aliases that were
already present in the target IDB and backed by earlier reviewed anchor
artifacts. It does not change the runtime APK, the loopback responder, the
TLS trust path, the loading-state repair, or any production endpoint.

The target database is unchanged from v351 and retains SHA-256
`0fb0662dffea1f1f6223e0e52745a19505687a79cf47f207280ce098f61b87f0`. The
runtime conclusion remains the same: the corrected local replay reaches the
encrypted login flow, receives the requested resource set, and renders the
green tiled world with HUD and status icons. No live service was contacted.

The semantic map now has 4,254 mapped pairs and 89 unmatched source rows. The
new checkpoint is
`artifacts/spectron_translation_checkpoint_20260829_v352.json`.
