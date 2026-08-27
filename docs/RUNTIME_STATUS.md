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
