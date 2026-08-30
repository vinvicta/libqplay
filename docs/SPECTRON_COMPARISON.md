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

## Dynamic exports in the stripped 2.2 library

The word "stripped" needs one qualification for this APK. The Spectron
library has no `.symtab`, no `.strtab`, no DWARF sections, and no
`.gnu_debuglink`. Those are the tables that would normally carry static
source names and compiler debug information. The dynamic tables `.dynsym` and
`.dynstr` are still present and contain a substantial export inventory.

The offline parser counts 6,773 dynamic entries in Spectron, of which 6,770
have names. There are 6,602 non-undefined entries, 6,595 entries assigned to
ordinary sections, and 5,782 section-defined `FUNC` entries. The equivalent
1.8 library has 6,674 dynamic entries, 6,671 named entries, and 5,709
section-defined functions. The complete row-level audit is in
`artifacts/spectron_symbol_table_audit_20260827.json`.

The retained names split into two useful groups. The application C++ exports
are mostly obfuscated names such as `XJLBgarMnA` and `C8THgaTQxF`, so the
dynamic table alone cannot restore the old class and method names. The TLS
implementation, by contrast, still uses a recognizable `CyaInt` namespace.
Spectron exports 256 section-defined functions in that CyaInt or CyaSSL
family, along with 28 named JNI entry points. The target application
connection helper is:

```text
_ZN10XJLBgarMnA7connectERK10C8THgaTQxFi
```

at `0x20ad98`, size 596. The TLS anchors include `CyaSSL_connect` at
`0x2d2bcc`, `ValidateDate` at `0x2c2940`,
`CyaSSL_check_domain_name` at `0x2d3358`, and
`CyaSSL_CTX_load_verify_buffer` at `0x2d35d8`. These addresses are relative
to the target library image and must not be copied into the 1.8 database.

There are 1,036 exact dynamic-name matches between the two libraries. That
number is useful as a shared-runtime baseline, but it does not mean that the
obfuscated C++ names are equivalent. The new artifact stores every named
dynamic row for both builds, which lets later work select a raw export first,
then attach a reviewed `v18_` semantic alias only when the function body and
call context support it. The audit is offline and contacted no endpoint.

The generator is `tools/generate_spectron_symbol_table_audit.py`.

## v322 TGraalVar semantic comparison

The v322 translation pass uses the Spectron library's obfuscated
`G0gxgajWBw` class as a direct comparison point for the source `TGraalVar`
runtime. The target's retained export names are not useful source names, but
the decompiled bodies preserve the same method responsibilities. Twelve rows
were reviewed from disposable source and target IDA copies:

| Source role | Spectron address | Applied alias | Review basis |
| --- | ---: | --- | --- |
| event forwarding | `0x2136c4` | `v18_TGraalVar_receiveEvent_script_event` | fixed event string and virtual +128 call |
| variable-name enumeration | `0x214520` | `v18_TGraalVar_getVarNames_bool_bool_bool` | visibility filters, deduplication, sort |
| dynamic parameter parsing | `0x214a78` | `v18_parseDynamicFunctionParameters_char_const_std_va_list` | complete GS2 format switch |
| formatted string execution | `0x215148` | `v18_TGraalVar_executeStringFunctionF_TString_const_char_const` | parse, invoke, return-string extraction |
| string persistence | `0x2154e0` | `v18_TGraalVar_saveString_TString_const_uint` | path, stream, write, resource update |
| line persistence | `0x215660` | `v18_TGraalVar_saveLines_TString_const_uint` | line-list iteration and write |
| string loading | `0x2157a8` | `v18_TGraalVar_loadString_TString_const` | path, load, virtual setter |
| numeric setter | `0x2158e4` | `v18_TGraalVar_setVarValueAsFloat_TString_const_double` | primary and persistent lookup paths |
| value getter | `0x2159f4` | `v18_TGraalVar_getVarValue_TString_const` | copied value and persistent fallback |
| object-array setter | `0x216174` | `v18_TGraalVar_setArrayCellObject_int_TGraalVar` | bounds, virtual +200 assignment, update flag |
| floating-point getter | `0x216454` | `v18_TGraalVar_getVarValueAsFloat_TString_const` | lookup and numeric projection |
| array-string updater | `0x216558` | `v18_TGraalVar_updateArrayString_void` | comma-separated cache rebuild |

The target rebuild replaces the source string and container implementations,
so eleven rows have explicit metric differences. The event forwarder retains
the one-block, 24-instruction shape. The dynamic-parameter parser retains all
of the source `va_list` cases, including coordinate triples. The object-array
setter is separated from the nearby string-cell setter by its index check,
virtual `+200` call, and array-updated operation. These are semantic aliases,
not assertions that the stripped 2.2 ELF still contains the original source
names.

The anchor artifact stores every source and target feature record, direct-call
set, function range, pseudocode fingerprint, and review note. All twelve names
were applied to a fresh v321-derived database and verified after reopening.
The final database hash is
`af0f2361668f7cd375b33242a0b21591a53446c332c0e77c8a4e51e3c6bdf1ad`. The
records are
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_application_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_gap_manual_translation_verification_20260829.json`,
and `artifacts/spectron_translation_checkpoint_20260829_v322.json`.

## v323 TGraalVar continuation comparison

The next class-local block gives another 23 source-to-target correspondences.
The target export names remain obfuscated, but its Hex-Rays output preserves
the source responsibilities and the important virtual slots. The six short
wrappers are exact metric matches. The other seventeen are high-confidence
layout-change matches caused by the target's rebuilt string and container
types.

| Source role | Spectron address | Applied alias | Review basis |
| --- | ---: | --- | --- |
| run script | `0x213c84` | `v18_TGraalVar_runScript_void` | script-space forwarder |
| leave class | `0x214a4c` | `v18_TGraalVar_leaveClass_TString_const` | lazy creation and leave |
| cancel events | `0x214fc4` | `v18_TGraalVar_cancelEvents_TString_const` | script-space forwarder |
| set script from string | `0x214fec` | `v18_TGraalVar_setScript_TString_const` | script-space setter |
| set script from object | `0x215014` | `v18_TGraalVar_setScript_TScript` | overload and object parameter |
| free script | `0x21503c` | `v18_TGraalVar_freeScript_void` | script-space release |
| function existence | `0x217198` | `v18_TGraalVar_hasFunction_TString_const` | primary, global, and table lookup |
| list sort | `0x21727c` | `v18_TGraalVar_sortList_bool` | temporary records and qsort |
| value sort | `0x217444` | `v18_TGraalVar_sortListByValue_TString_const_TString_const_bool` | numeric or string qsort |
| subvariable listing | `0x217754` | `v18_TGraalVar_listSubVars_TStringList_TString_const` | recursive persistent hash walk |
| save variables | `0x21797c` | `v18_TGraalVar_saveVarsToArray_void` | visible property export |
| numeric or string write | `0x21805c` | `v18_TGraalVar_writeFloatOrString_TString_const` | numeric test and setter choice |
| set subvariable | `0x218134` | `v18_TGraalVar_setSubVar_TString_const` | dotted path recursion |
| set named value | `0x218468` | `v18_TGraalVar_setVarValue_TString_const_TString_const` | direct lookup or equals fallback |
| array member lookup | `0x218d70` | `v18_TGraalVar_getArrayMember_TString_const` | case-insensitive scan |
| recursive copy | `0x219050` | `v18_TGraalVar_copyFrom_TGraalVar` | properties, arrays, and child variables |
| function enumeration | `0x219ed0` | `v18_TGraalVar_getFunctions_void` | function metadata objects |
| write string list | `0x21a64c` | `v18_TGraalVar_writeStringList_TStringList` | array length synchronization |
| insert float cell | `0x21a970` | `v18_TGraalVar_insertArrayCellFloat_int_double` | numeric cell construction |
| insert string cell | `0x21aa0c` | `v18_TGraalVar_insertArrayCellString_int_TString_const` | string cell construction |
| insert object cell | `0x21aab0` | `v18_TGraalVar_insertArrayCellObject_int_TGraalVar` | object cell construction |
| static property initialization | `0x21ab54` | `v18_TGraalVar_initStaticScriptVars_void` | property table registration |
| string write and parse | `0x21ab98` | `v18_TGraalVar_writeString_TString_const` | quoted and comma text parsing |

The pair at `0x213c84` is a direct four-instruction wrapper around the
attached script space. The methods at `0x21727c` and `0x217444` preserve the
temporary record arrays and value comparators. `copyFrom` keeps the typed
property switch, array cloning, and recursive child traversal. The three
array constructors preserve the float, string, and object virtual setter
slots at `+192`, `+200`, and `+208`. The static initializer at `0x21ab54`
allocates the target property object and registers the same property-definition
table as the source.

The nearby target method at `0x214fd8` is intentionally excluded. It calls a
target script-space helper but has no independently established source
counterpart. The comparison record keeps the raw target symbol rather than
turning a positional guess into a source alias.

The v323 anchor artifact stores all 23 source and target feature records,
function ranges, direct-call lists, and compact Hex-Rays fingerprints. The
application renamed all 23 target functions and the reopen check verified all
23. The resulting database has 11,707 functions, zero audited default names,
6,263 translated `v18_` aliases, 4,587 source-backed dynamic rows, and 1,855
exact retained dynamic names. Defined dynamic function coverage remains 5,782
exact starts. The database hash is
`588e39f73c0946aea4ed45265820c9d95a73689339c365840b308170d36d0b4d`.

The v323 records are
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_application_20260829.json`,
`artifacts/spectron_tgraalvar_runtime_continuation_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v323_20260829.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v323_20260829.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v323_20260829.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v323.json`.

## v348 RSA public-encryption comparison

The v348 pass resolves the source RSA public-encryption row that remained
ambiguous after the v170 encryption review. The source function is
`TEncryption_rsa_encrypt_TString_const_TString_const` at `0xf7218`. The
target function at `0xf94ac` has raw symbol
`_ZN10cHovga0n1u10D855FaUMK1ERK10C8THgaTQxFS2_` and now carries the alias
`v18_TEncryption_rsa_encrypt_TString_const_TString_const`.

| Source address | Target address | Target raw symbol | Applied alias | Evidence |
| ---: | ---: | --- | --- | --- |
| `0xf7218` | `0xf94ac` | `_ZN10cHovga0n1u10D855FaUMK1ERK10C8THgaTQxFS2_` | `v18_TEncryption_rsa_encrypt_TString_const_TString_const` | public-key decode, RNG setup, RSA size query, public encryption, append, cleanup |

The source and target are identical across the complete normalized feature
record: 296 bytes, 74 instructions, 12 basic blocks, 14 branches, seven
calls, and matching mnemonic, opcode-shape, register-shape, and coarse shape
hashes. Direct pseudocode resolves the class-local ambiguity. The source uses
`RsaPublicKeyDecode`, `InitRng`, `RsaEncryptSize`, and `RsaPublicEncrypt`; the
target calls the corresponding `CyaInt` methods and appends through
`C8THgaTQxF::f7_SgaGITO`.

The target sibling at `0xf96f8` remains the RSA signing translation from v170.
It calls `RsaPrivateKeyDecode` and `RsaSSL_Sign`, so it is not a second
candidate for the public-encryption row. The target xrefs for the new alias
are `0x236d0` and `0x3895d0`. The source xrefs are `0x20aa0` and `0x3765d0`.

The v348 alias was applied to a fresh v347-derived IDA database and verified
after reopening. The database has 11,707 functions, 6,441 translated aliases,
439 target-only descriptive labels, 768 retained target names, 4,796
source-backed dynamic rows, 1,656 exact retained dynamic names, and 5,782
exact dynamic function starts. The semantic map now contains 3,722 mapped
pairs, 3,662 high-confidence pairs, 1,014 remaining automatic ambiguities,
and 608 unmatched source functions. The database hash is
`40ff536a25df6624d1ac25bc9052e85d107dddb996dc5e46b791d1df936a75c0`.

The complete v348 records are
`artifacts/spectron_rsa_encrypt_manual_translation_anchor_20260829.json`,
`artifacts/spectron_rsa_encrypt_manual_translation_application_20260829.json`,
`artifacts/spectron_rsa_encrypt_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v348_rsa_encrypt.json`,
`artifacts/spectron_name_coverage_audit_v348.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v348.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v348.json`,
`artifacts/spectron_semantic_translation_v348.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v348.json`.

This is an offline comparison and IDA labeling result. It does not change the
APK or make a live RSA, TLS, or game-server request.

## v347 encoded string buffer comparison

The v347 pass reviews a target-only string subsystem rather than forcing a
source match. The target class is `CanTfaz6bZ`, a copy-on-write buffer with a
lazy three-byte XOR key. Its adjacent bridge methods use the ordinary target
`C8THgaTQxF` string wrapper.

| Target address | Applied label | Recovered operation |
| ---: | --- | --- |
| `0xf37bc` | `spectron_C8THgaTQxF_decodeFromCanTfaz6bZ_const` | decode an encoded buffer into a string return value |
| `0xf3888` | `spectron_C8THgaTQxF_assignCanTfaz6bZ` | clear the string wrapper and delegate to the decoder |
| `0xf8b90` | `spectron_CanTfaz6bZ_initXorKey_void` | initialize the three-byte XOR key once |
| `0xf8c64` | `spectron_CanTfaz6bZ_clear_void` | release or decrement shared encoded storage |
| `0xf8ca8` | `spectron_CanTfaz6bZ_assign_CanTfaz6bZ_const` | copy-on-write reference-counted assignment |
| `0xf8d00` | `spectron_CanTfaz6bZ_encodeFromC8THgaTQxF` | encode a target string into the buffer |
| `0xf8de0` | `spectron_CanTfaz6bZ_decodeToC8THgaTQxF` | decode into a target string |
| `0xf8e54` | `spectron_CanTfaz6bZ_decodeToC8THgaTQxF_variant` | alternate const decode form |
| `0xf8ec8` | `spectron_CanTfaz6bZ_equals_CanTfaz6bZ_const` | compare encoded length and bytes |
| `0xf8f54` | `spectron_CanTfaz6bZ_startsWithEncoded_CanTfaz6bZ_const` | compare an encoded prefix |
| `0xf8fc8` | `spectron_CanTfaz6bZ_startsWithIgnoreCase_CanTfaz6bZ_const` | decoded case-insensitive prefix test |
| `0xf9090` | `spectron_CanTfaz6bZ_equalsIgnoreCase_CanTfaz6bZ_const` | decoded case-insensitive equality |
| `0xf9178` | `spectron_CanTfaz6bZ_decodeCopyToC8THgaTQxF` | wrapper around decode conversion |
| `0xf9198` | `spectron_CanTfaz6bZ_assignFromC8THgaTQxF` | assign from an ordinary target string |
| `0xf91b8` | `spectron_CanTfaz6bZ_setXorEncodedBuffer_char_const_int` | allocate and encode a byte span |
| `0xf9264` | `spectron_CanTfaz6bZ_makeUnique_void` | detach shared storage before mutation |
| `0xf92d8` | `spectron_CanTfaz6bZ_assignCStringXorEncoded_char_const` | encode and assign a C string |
| `0xf9310` | `spectron_CanTfaz6bZ_indexDecoded_int` | one-based decoded byte access |
| `0xf9374` | `spectron_CanTfaz6bZ_appendXorEncoded_CanTfaz6bZ_const` | append while correcting XOR offsets |

The source 1.8 inventory has no safe one-to-one counterpart for this class.
Three target rows, `0xf8c64`, `0xf8f54`, and `0xf9178`, collide with ordinary
source feature metrics. Direct pseudocode separates them from
`TString_clear_void`, `TString_starts_TString_const`, and small source
wrappers, so the artifact records these as metric collisions only. It claims
zero source counterparts and leaves the semantic map unchanged.

The labels were applied to a fresh v346-derived IDA database and verified
after reopening. The v347 database contains 6,440 translated aliases, 439
target-only descriptive labels, 769 retained target names, 4,795
source-backed dynamic rows, 1,657 exact retained dynamic names, and 5,782
exact dynamic function starts. Its hash is
`fe1bbbdf27b25b2fe13d088fb01944a624e8fe8a11898a377ff66f49b892a59b`.

The complete records are
`artifacts/spectron_encoded_string_target_only_labels_20260829.json`,
`artifacts/spectron_encoded_string_target_only_label_application_20260829.json`,
`artifacts/spectron_encoded_string_target_only_label_verification_20260829.json`,
`artifacts/spectron_features_v347_encoded_string.json`,
`artifacts/spectron_name_coverage_audit_v347.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v347.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v347.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v347.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v346 resource path helper comparison

The v346 pass reviews a target resource-runtime function that has no safe
source-backed counterpart. The target address is `0xefbcc`, raw symbol
`_ZN10f6WHgaQkAF10iaBygafTIxERK10C8THgaTQxFb`, and the applied descriptive
label is `spectron_TResourceFunctions_resolveResourcePath_TString_const_bool`.

| Target address | Raw target symbol | Applied label | Comparison result |
| ---: | --- | --- | --- |
| `0xefbcc` | `_ZN10f6WHgaQkAF10iaBygafTIxERK10C8THgaTQxFb` | `spectron_TResourceFunctions_resolveResourcePath_TString_const_bool` | target-only resource path, update, and download helper |

The body is 260 bytes with 65 instructions, 12 basic blocks, 22 branches,
and 12 calls. It shares high-level path construction with source
`TResourceFunctions_getGameFile_TString_const_bool` at `0xeec84`, and its
absolute lookup is related to source
`TResourceFunctions_getLevelFileResourceAbsPath_TString_const` at `0xedf40`.
However, the target already has a separate `getGameFile` body at `0xefe78`
with the reviewed source-backed alias. The new helper has no exact, 11-field
normalized, or 10-field normalized feature match in the 1.8 inventory. Its
only incoming reference is the dynamic-symbol record at `0x154b0`, so no code
caller is inferred.

The label was applied and verified after reopening the v346 IDA database. The
semantic map is carried forward unchanged. The v346 database has 11,707
functions, 6,440 translated aliases, 420 target-only descriptive labels,
4,795 source-backed dynamic rows, 1,676 exact retained dynamic names, and
5,782 exact dynamic function starts. Its SHA-256 is
`bfb7f36be1a572c5428192c90ee3288035805a2e34b7ead439437c4b1ccf2392`.

The complete v346 records are
`artifacts/spectron_resource_path_helper_target_only_labels_20260829.json`,
`artifacts/spectron_resource_path_helper_target_only_label_application_20260829.json`,
`artifacts/spectron_resource_path_helper_target_only_label_verification_20260829.json`,
`artifacts/spectron_features_v346_resource_path_helper.json`,
`artifacts/spectron_name_coverage_audit_v346.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v346.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v346.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v346.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v345 resource-object static comparison

The v345 pass compares the three raw target helpers immediately before the
resource-stream methods. The source cluster is the `TResourceObject` static
initializer followed by the two `TEncodedFileKey` ABI forms.

| Source role | Source address | Spectron address | Raw target symbol | Applied alias |
| --- | ---: | ---: | --- | --- |
| `TResourceObject_initStaticVars_void` | `0xf0434` | `0xf1910` | `_Z10dZEN2aa5nYv` | `v18_TResourceObject_initStaticVars_void` |
| `TEncodedFileKey_TEncodedFileKey` | `0xf0464` | `0xf1940` | `_ZN10uVBvgaZvcvD2Ev` | `v18_TEncodedFileKey_TEncodedFileKey` |
| `TEncodedFileKey_TEncodedFileKey__2` | `0xf04a4` | `0xf1980` | `_ZN10uVBvgaZvcvD0Ev` | `v18_TEncodedFileKey_TEncodedFileKey__2` |

The initializer allocates a 0x28-byte hash-list wrapper, calls its
constructor, and stores the result in the resource-object static slot. Both
key forms reset their vtable and clear the strings at offsets `+16` and `+8`.
The deleting form then releases the object. The target D2 function also has a
D1 alternate dynamic spelling, which is preserved as an ABI detail rather
than treated as a fourth source function.

All three pairs have identical normalized feature shape: 296 bytes, 74
instructions, nine basic blocks, ten branches, and four calls. Only the
register-detail hash changes. Direct source and target pseudocode, direct
allocation or clear calls, and the adjacent method order resolve the three
rows that the automatic matcher left ambiguous.

The aliases were applied and verified after reopening the v345 database. It
has 11,707 functions, zero audited default names, 6,440 translated aliases,
4,795 source-backed dynamic rows, 1,677 exact retained dynamic names, and
5,782 exact dynamic function starts. The semantic map contains 3,721 mapped
source-target pairs, including these three resolved ambiguity rows.

The complete records are
`artifacts/spectron_resource_object_static_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_resource_object_static_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_resource_object_static_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v345_resource_object_static.json`,
`artifacts/spectron_name_coverage_audit_v345.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v345.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v345.json`,
`artifacts/spectron_semantic_translation_v345.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v345.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v344 resource-stream crypto comparison

The v344 pass compares the adjacent resource-stream encryption and decryption
methods. The target class is the obfuscated `f6WHgaQkAF` resource runtime.
Both source and target bodies have direct compact Hex-Rays pseudocode.

| Source role | Source address | Spectron address | Applied alias | Match class |
| --- | ---: | ---: | --- | --- |
| `TResourceFunctions_encryptTStream_TString_const_TStream` | `0xece78` | `0xede48` | `v18_TResourceFunctions_encryptTStream_TString_const_TStream` | normalized shape, encrypt call |
| `TResourceFunctions_decryptTStream_TString_const_TStream` | `0xecfa0` | `0xedf70` | `v18_TResourceFunctions_decryptTStream_TString_const_TStream` | normalized shape, decrypt call |

The two target bodies are both 296 bytes long with 74 instructions, nine
basic blocks, ten branches, and four calls. Their normalized mnemonic,
opcode, register-shape, and whole-body hashes match the source rows. The only
metric difference is register-detail allocation. Since shape alone cannot
separate the pair, the source encrypt-memory call maps to target
`cHovga0n1u::thgvgajjVu`, while the source decrypt-memory call maps to target
`cHovga0n1u::b2hvgavNWu`. The adjacent order is also preserved.

The aliases were applied and verified after reopening the v344 database. It
has 11,707 functions, zero audited default names, 6,437 translated aliases,
4,791 source-backed dynamic rows, 1,680 exact retained dynamic names, and
5,782 exact dynamic function starts. The semantic map now contains 3,718
mapped source-target pairs, including these two manually resolved rows.

The complete comparison records are
`artifacts/spectron_resource_stream_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_resource_stream_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_resource_stream_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v344_resource_stream.json`,
`artifacts/spectron_name_coverage_audit_v344.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v344.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v344.json`,
`artifacts/spectron_semantic_translation_v344.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v344.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v343 TDrawingPanel residual comparison

The v343 pass compares three raw target methods in the obfuscated `V8fxgahcBw`
drawing-panel class. Every row has direct source and target compact Hex-Rays
pseudocode and an exact normalized ARM64 feature match.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TDrawingPanel_clearCache_void` | `0x11a8c8` | `v18_TDrawingPanel_clearCache_void` | exact list cleanup and virtual destruction |
| `TDrawingPanel_drawImage_int_int_TString_const` | `0x11acb8` | `v18_TDrawingPanel_drawImage_int_int_TString_const` | exact 0x30-byte image operation |
| `TDrawingPanel_drawText_int_int_TString_const` | `0x11cd54` | `v18_TDrawingPanel_drawText_int_int_TString_const` | exact 0x88-byte text operation |

The clear method preserves the operation-list traversal and final clear call.
The image and text methods preserve local point construction, allocation,
operation construction, and queueing. All three rows are new context in the
automatic semantic map, and no alias relies on name similarity alone.

The aliases were applied and verified after reopening the v343 database. It
has 11,707 functions, zero audited default names, 6,435 translated aliases,
4,789 source-backed dynamic rows, 1,682 exact retained dynamic names, and
5,782 exact dynamic function starts. Its SHA-256 is
`bb51b5b8ceb13acae2d5843019473ab988f0f931d2a5bce484f0ff3f32103ae8`.
The complete comparison records are
`artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_drawing_panel_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_drawing_panel_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v343_drawing_panel_residual.json`,
`artifacts/spectron_name_coverage_audit_v343.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v343.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v343.json`,
`artifacts/spectron_semantic_translation_v343.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v343.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v342 TInput modifier-state residual comparison

The v342 pass compares three raw target methods in the obfuscated `GaA2gaD2MX`
input class. Every row has direct source and target compact Hex-Rays
pseudocode and an exact normalized ARM64 feature match.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TInput_getShiftKeyState_void` | `0x16c9f0` | `v18_TInput_getShiftKeyState_void` | exact primary and fallback query |
| `TInput_getControlKeyState_void` | `0x16ca24` | `v18_TInput_getControlKeyState_void` | exact primary and fallback query |
| `TInput_getAltKeyState_void` | `0x16ca58` | `v18_TInput_getAltKeyState_void` | exact primary and fallback query |

The source and target methods both call their build-specific key-state helper
with the incoming integer argument. A false primary result triggers a second
call with zero. The shift, control, and alt methods use adjacent byte pairs at
qword_A0 offsets 0 and 1, 2 and 3, and 4 and 5. All three rows are new context
in the automatic semantic map, and no alias relies on name similarity alone.

The aliases were applied and verified after reopening the v342 database. It
has 11,707 functions, zero audited default names, 6,432 translated aliases,
4,786 source-backed dynamic rows, 1,685 exact retained dynamic names, and
5,782 exact dynamic function starts. Its SHA-256 is
`ec767e7a86e12b169f0053d4d1b783aa01fc8b7efa90863b69912553aa451ae7`.
The complete comparison records are
`artifacts/spectron_input_modifiers_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_input_modifiers_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_input_modifiers_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v342_input_modifiers_residual.json`,
`artifacts/spectron_name_coverage_audit_v342.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v342.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v342.json`,
`artifacts/spectron_semantic_translation_v342.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v342.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v341 GuiControl color-setter residual comparison

The v341 pass compares four raw target methods in the obfuscated w9XxgaJdbx
control class. Every row has direct source and target compact Hex-Rays
pseudocode and an exact normalized ARM64 feature match.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `GuiControl_setRed_float` | `0x1bea8c` | `v18_GuiControl_setRed_float` | exact channel 60 setter |
| `GuiControl_setGreen_float` | `0x1bead0` | `v18_GuiControl_setGreen_float` | exact channel 61 setter |
| `GuiControl_setBlue_float` | `0x1beb14` | `v18_GuiControl_setBlue_float` | exact channel 62 setter |
| `GuiControl_setAlpha_float` | `0x1beb58` | `v18_GuiControl_setAlpha_float` | exact channel 63 setter |

Every setter preserves the compare, conditional write, shared color-state
refresh, and rectangle-invalidation sequence. All four rows are new context
in the automatic semantic map, and no alias relies on name similarity alone.

All four aliases were applied and verified after reopening the v341 database.
It has 11,707 functions, zero audited default names, 6,429 translated aliases,
4,783 source-backed dynamic rows, 1,688 exact retained dynamic names, and
5,782 exact dynamic function starts. Its SHA-256 is
`f892d0eb81a79a242c41aeb19742dc33693863fd0373217727d2bba154d33d73`.
The complete comparison records are
`artifacts/spectron_colorset_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_colorset_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_colorset_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v341_colorset_residual.json`,
`artifacts/spectron_name_coverage_audit_v341.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v341.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v341.json`,
`artifacts/spectron_semantic_translation_v341.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v341.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v340 TTilesBlock and TTilesPanel residual comparison

The v340 pass compares four raw target methods in the tile and panel block.
Every row has direct source and target compact Hex-Rays pseudocode and an
exact normalized ARM64 feature match.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TTilesBlock_destroyImage_void` | `0x23a9a4` | `v18_TTilesBlock_destroyImage_void` | exact virtual image cleanup |
| `TTilesBlock_isTransparentWithout_int_int` | `0x23aad4` | `v18_TTilesBlock_isTransparentWithout_int_int` | exact transparency mask query |
| `TTilesBlock_isBlackWithout_int_int` | `0x23ad2c` | `v18_TTilesBlock_isBlackWithout_int_int` | exact black mask query |
| `TTilesPanel_TTilesPanel_bool` | `0x23ae18` | `v18_TTilesPanel_TTilesPanel_bool` | exact constructor initialization |

The image method preserves the virtual destructor call and pointer reset. The
two query methods preserve the four-column bit index and separate 16-bit
masks. The panel constructor preserves its boolean mode and zeroed fields.
Three rows reinforce existing medium-confidence semantic candidates; the
constructor is new context.

All four aliases were applied and verified after reopening the v340 database.
It has 11,707 functions, zero audited default names, 6,425 translated aliases,
4,779 source-backed dynamic rows, 1,692 exact retained dynamic names, and
5,782 exact dynamic function starts. Its SHA-256 is
`24a96367fa0730d1a125d146f4fd8e304ba96f6676c15deb2807d085671734d1`.
The complete comparison records are
`artifacts/spectron_tiles_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tiles_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tiles_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v340_tiles_residual.json`,
`artifacts/spectron_name_coverage_audit_v340.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v340.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v340.json`,
`artifacts/spectron_semantic_translation_v340.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v340.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v339 rectangle and region geometry residual comparison

The v339 pass compares four raw target methods in the rectangle and region
geometry block. Every row has direct source and target compact Hex-Rays
pseudocode and an exact normalized ARM64 feature match.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TFloatRectangle_unionRects_TFloatRectangle_const` | `0x1ea7e4` | `v18_TFloatRectangle_unionRects_TFloatRectangle_const` | exact float edge union |
| `TDoubleRectangle_unionRects_TDoubleRectangle_const` | `0x1ea860` | `v18_TDoubleRectangle_unionRects_TDoubleRectangle_const` | exact double edge union |
| `TRegion_TRegion_void` | `0x1ea8dc` | `v18_TRegion_TRegion_void` | exact empty constructor |
| `TRegion_clear_void` | `0x1ea8e4` | `v18_TRegion_clear_void` | exact list cleanup |

The rectangle rows preserve the minimum-origin and maximum-edge calculation.
The region rows preserve empty construction and cleanup of every list entry,
including virtual destruction and head reset. Three rows reinforce existing
medium-confidence semantic candidates, while the constructor is new context.

All four aliases were applied and verified after reopening the v339 database.
It has 11,707 functions, zero audited default names, 6,421 translated aliases,
4,774 source-backed dynamic rows, 1,696 exact retained dynamic names, and
5,782 exact dynamic function starts. Its SHA-256 is
`d50a0755bb461dada6b011b4df4ca01f9a0cbaf0112805b0ff1e5ab48764bebe`.
The complete comparison records are
`artifacts/spectron_geometry_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_geometry_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_geometry_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v339_geometry_residual.json`,
`artifacts/spectron_name_coverage_audit_v339.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v339.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v339.json`,
`artifacts/spectron_semantic_translation_v339.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v339.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v338 THTMLPage lifecycle residual comparison

The v338 pass compares seven raw target methods in the obfuscated
`AS80gaE4zW` HTML-page class. Every row has direct source and target compact
Hex-Rays pseudocode and an exact normalized ARM64 feature match.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `THTMLPage_initTabStops_void` | `0x1d5f6c` | `v18_THTMLPage_initTabStops_void` | exact member reset |
| `THTMLPage_initLineTags_void` | `0x1d606c` | `v18_THTMLPage_initLineTags_void` | exact member reset |
| `THTMLPage_freeLineTags_void` | `0x1d6104` | `v18_THTMLPage_freeLineTags_void` | exact linked-node cleanup |
| `THTMLPage_initStyles_void` | `0x1d614c` | `v18_THTMLPage_initStyles_void` | exact member reset |
| `THTMLPage_initSubPages_void` | `0x1d62f0` | `v18_THTMLPage_initSubPages_void` | exact member reset |
| `THTMLPage_initLists_void` | `0x1d73c0` | `v18_THTMLPage_initLists_void` | exact member reset |
| `THTMLPage_freeSubPages_void` | `0x1d7724` | `v18_THTMLPage_freeSubPages_void` | exact linked-node cleanup |

The initializer rows preserve the source field offsets. The two cleanup rows
preserve the linked-list traversal, node destruction, deletion, and head
reset. The target method order matches the source class sequence, so these are
not name-only or address-only assignments.

All seven aliases were applied and verified after reopening the v338
database. The database has 11,707 functions, zero audited default names,
6,417 translated aliases, 4,769 source-backed dynamic rows, 1,700 exact
retained dynamic names, and 5,782 exact dynamic function starts. Its SHA-256
is
`26584982aa976361088e7978b162d12e1be4bf2bf9991bf9484c56e92bba8c2d`.
The complete comparison records are
`artifacts/spectron_html_page_lifecycle_manual_translation_anchors_20260829.json`,
`artifacts/spectron_html_page_lifecycle_manual_translation_application_20260829.json`,
`artifacts/spectron_html_page_lifecycle_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v338_html_page_lifecycle.json`,
`artifacts/spectron_name_coverage_audit_v338.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v338.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v338.json`,
`artifacts/spectron_semantic_translation_v338.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v338.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v337 libjpeg helper residual comparison

The v337 pass compares twelve raw target symbols in two libjpeg helper
clusters. Every row has direct source and target Hex-Rays pseudocode and an
exact normalized ARM64 feature match.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `jpeg_get_small_jpeg_common_struct_ulong` | `0x2a2358` | `v18_jpeg_get_small_jpeg_common_struct_ulong` | exact malloc helper |
| `jpeg_free_small_jpeg_common_struct_void_ulong` | `0x2a2360` | `v18_jpeg_free_small_jpeg_common_struct_void_ulong` | exact free helper |
| `jpeg_get_large_jpeg_common_struct_ulong` | `0x2a2368` | `v18_jpeg_get_large_jpeg_common_struct_ulong` | exact malloc helper |
| `jpeg_free_large_jpeg_common_struct_void_ulong` | `0x2a2370` | `v18_jpeg_free_large_jpeg_common_struct_void_ulong` | exact free helper |
| `jpeg_mem_available_jpeg_common_struct_long_long_long` | `0x2a2378` | `v18_jpeg_mem_available_jpeg_common_struct_long_long_long` | exact third-argument return |
| `jpeg_open_backing_store_jpeg_common_struct_backing_store_struct_long` | `0x2a2380` | `v18_jpeg_open_backing_store_jpeg_common_struct_backing_store_struct_long` | exact tag and callback dispatch |
| `jpeg_mem_init_jpeg_common_struct` | `0x2a23a8` | `v18_jpeg_mem_init_jpeg_common_struct` | exact zero return |
| `jpeg_mem_term_jpeg_common_struct` | `0x2a23b0` | `v18_jpeg_mem_term_jpeg_common_struct` | exact empty hook |
| `jdiv_round_up_long_long` | `0x2a52b0` | `v18_jdiv_round_up_long_long` | exact upward division |
| `jround_up_long_long` | `0x2a52c0` | `v18_jround_up_long_long` | exact multiple rounding |
| `jcopy_block_row_short_64_short_64_uint` | `0x2a5338` | `v18_jcopy_block_row_short_64_short_64_uint` | exact 128-byte copy |
| `jzero_far_void_ulong` | `0x2a534c` | `v18_jzero_far_void_ulong` | exact memset helper |

The first eight methods preserve the source memory-manager order, including
the backing-store method's write of tag 49 before its indirect callback. The
second four methods preserve the source arithmetic and buffer-helper bodies
around the translated JPEG compressor sequence. No row relies on a name-only
or address-only guess.

All twelve aliases were applied and verified after reopening the v337
database. The database has 11,707 functions, zero audited default names,
6,410 translated aliases, 4,762 source-backed dynamic rows, 1,707 exact
retained dynamic names, and 5,782 exact dynamic function starts. Its SHA-256
is
`391d3bb01245f636760daeb8cef80012e602dfc04423d104a44ceb8e1e4d7113`.
The complete comparison records are
`artifacts/spectron_libjpeg_helper_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_libjpeg_helper_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_libjpeg_helper_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v337_libjpeg_helper_residual.json`,
`artifacts/spectron_name_coverage_audit_v337.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v337.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v337.json`,
`artifacts/spectron_semantic_translation_v337.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v337.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v336 GSFunctionsInitstaticscriptvars and TFormat2 residual comparison

The v336 pass compares the next contiguous raw target block in the Format2
parameter runtime. The target class is `giqpgaXJ_p`; source and target
preserve the function-table registration, numeric conversion, string
conversion, destructor ABI, and method order.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `gsfunctions_initStaticScriptVars_void` | `0x2130b0` | `v18_gsfunctions_initStaticScriptVars_void` | count-37 registration; register-detail change |
| `TFormat2_FormatParameters_getNextS32_void` | `0x213218` | `v18_TFormat2_FormatParameters_getNextS32_void` | exact numeric accessor |
| `TFormat2_FormatParameters_getNextU32_void` | `0x2132a0` | `v18_TFormat2_FormatParameters_getNextU32_void` | exact numeric accessor |
| `TFormat2_FormatParameters_getIndexedS32_int` | `0x213360` | `v18_TFormat2_FormatParameters_getIndexedS32_int` | exact indexed accessor |
| `TFormat2_FormatParameters_getIndexedU32_int` | `0x2133d0` | `v18_TFormat2_FormatParameters_getIndexedU32_int` | exact indexed accessor |
| `TFormat2_FormatParameters_TFormat2_FormatParameters` | `0x213440` | `v18_TFormat2_FormatParameters_TFormat2_FormatParameters` | D1/D2 cleanup; register-detail change |
| `TFormat2_FormatParameters_getIndexedString_int` | `0x213454` | `v18_TFormat2_FormatParameters_getIndexedString_int` | rebuilt string-wrapper layout |
| `TFormat2_FormatParameters_getNextString_void` | `0x2134f0` | `v18_TFormat2_FormatParameters_getNextString_void` | rebuilt string-wrapper layout |
| `TFormat2_FormatParameters_TFormat2_FormatParameters__2` | `0x213598` | `v18_TFormat2_FormatParameters_TFormat2_FormatParameters__2` | deleting D0; register-detail change |

The four numeric accessors preserve the same virtual getter at slot 224 and
the same truncation logic. The string methods preserve virtual slot 232,
temporary conversion, assignment, cleanup, and dummy fallback. The D1 and D0
entries reset the vtable and clear the embedded member at offset 24, with D0
then deleting the object. Direct pseudocode makes the target's expanded
wrapper calls explainable rather than treating body size as a mismatch.

All nine aliases were applied and verified after reopening the v336 database.
The database has 11,707 functions, zero audited default names, 6,398
translated aliases, 4,750 source-backed dynamic rows, 1,719 exact retained
dynamic names, and 5,782 exact dynamic function starts. Its SHA-256 is
`55662a1b9e5989c1e14350ab585015ccb6af0af123f12fab0dcab414f54ca199`.
The complete comparison records are
`artifacts/spectron_format2_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_format2_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_format2_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v336_format2_residual.json`,
`artifacts/spectron_name_coverage_audit_v336.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v336.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v336.json`,
`artifacts/spectron_semantic_translation_v336.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v336.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v335 GSFunctionsClient and TAdventure residual comparison

The v335 pass compares four raw target entries in the GSFunctionsClient and
TAdventure blocks. The target retains obfuscated names, while the source
names, direct pseudocode, normalized features, and local method order provide
the translation evidence.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `gsfunctions_client_initStaticVars_void` | `0x15de64` | `v18_gsfunctions_client_initStaticVars_void` | static allocation; register-detail change |
| `TAdventure_freeResources_void` | `0x15e528` | `v18_TAdventure_freeResources_void` | exact graphics and sound cleanup |
| `TAdventure_handleMouseMove_void` | `0x15ef90` | `v18_TAdventure_handleMouseMove_void` | exact empty callback |
| `TAdventure_initStaticScriptVars_void` | `0x15f27c` | `v18_TAdventure_initStaticScriptVars_void` | exact empty initializer |

The source and target static-variable initializers allocate eight bytes,
clear the qword, and publish the pointer in a build-specific global. The
three remaining pairs preserve either the two-call Adventure cleanup or an
empty callback body. The target's nearby empty entry at `0x15f724` is not
translated because no source counterpart was established.

All four aliases were applied and verified after reopening the v335 database.
The database has 11,707 functions, zero audited default names, 6,389
translated aliases, 4,740 source-backed dynamic rows, 1,728 exact retained
dynamic names, and 5,782 exact dynamic function starts. Its SHA-256 is
`dae970eb4edf7237544073da7badb3cfe0bd9d3ccb03e8ec9bde5b5c7de73a16`.
The complete comparison records are
`artifacts/spectron_adventure_static_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_adventure_static_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_adventure_static_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v335_adventure_static_residual.json`,
`artifacts/spectron_name_coverage_audit_v335.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v335.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v335.json`,
`artifacts/spectron_semantic_translation_v335.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v335.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v334 bitmap JPEG static initializer comparison

The v334 pass compares the residual JPEG static initializer immediately
before the target TGA helper block. The source and target use different
property-registration symbols and table addresses, but both pass a null
receiver, one table pointer, and a count of one.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TBitmap_jpeg_initStaticScriptVars_void` | `0x1541bc` | `v18_TBitmap_jpeg_initStaticScriptVars_void` | one-entry registration; register-detail change |

The source boundary is `0x151394`, and the raw target symbol is
`_Z10eY1M1algS6v`. Source pseudocode calls
`TScriptProperty_addProps_TProperties_TPropertyPropDef_int`, while target
pseudocode calls `cWWYfaxbT2::hFWn2apYKC`. The target's next boundaries are the
already translated `tga_error_string`, `tga_create`, and `tga_info` helpers.
Direct compact pseudocode and this local method order make the row
high-confidence even though the target wrapper layout changes the register
detail hash.

The alias was applied and verified after reopening the v334 database. The
database has 11,707 functions, zero audited default names, 6,385 translated
aliases, 4,736 source-backed dynamic rows, 1,732 exact retained dynamic
names, and 5,782 exact dynamic function starts. Its SHA-256 is
`c2002066a0412b180afd6abb36fe08f0873403d3068a2a0bdd88deb997101398`.
The complete comparison records are
`artifacts/spectron_bitmap_jpeg_static_manual_translation_anchors_20260829.json`,
`artifacts/spectron_bitmap_jpeg_static_manual_translation_application_20260829.json`,
`artifacts/spectron_bitmap_jpeg_static_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v334_bitmap_jpeg_static.json`,
`artifacts/spectron_name_coverage_audit_v334.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v334.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v334.json`,
`artifacts/spectron_semantic_translation_v334.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v334.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v333 THashIntVar residual comparison

The v333 pass compares the two raw destructor boundaries immediately after
the translated `THTMLColors` methods and before the translated
`TImageAnimation` family.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `THashIntVar_THashIntVar` | `0x11df60` | `v18_THashIntVar_THashIntVar` | complete D1/D2 cleanup; register-detail change |
| `THashIntVar_THashIntVar__2` | `0x11df74` | `v18_THashIntVar_THashIntVar__2` | deleting D0 cleanup; register-detail change |

Both bodies reset the vtable and clear their string-like member at offset 8.
The deleting form then calls `operator delete`. The source and target have
the same normalized instruction count, control-flow shape, opcode sequence,
register shape, and cleanup order. The only metric difference is
`register_detail_hash`, caused by the target's rebuilt `CanTfaz6bZ` wrapper.
The source alternative C++ name and target D1 or D0 names establish the ABI
relationship, while the surrounding `THTMLColors` and `TImageAnimation`
methods confirm the class-local placement.

Both aliases were applied and verified after reopening the v333 database. The
v333 database has 11,707 functions, zero audited default names, 6,384
translated aliases, 4,735 source-backed dynamic rows, 1,733 exact retained
target names, and 5,782 exact dynamic function starts. Its SHA-256 is
`c6f31412206a9a893fedf594fac90dff2f13be69f2db28fcda80cc2c67ad7f4d`.
The complete comparison records are
`artifacts/spectron_hashintvar_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_hashintvar_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_hashintvar_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v333_hashintvar_residual.json`,
`artifacts/spectron_name_coverage_audit_v333.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v333.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v333.json`,
`artifacts/spectron_semantic_translation_v333.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v333.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v332 TPanelOperation residual comparison

The v332 pass compares the next complete drawing-panel sequence after the
v331 static-variable methods. The target's raw symbols are obfuscated, but
the source and target preserve operation field offsets, four-field bounds
results, destructor ABI forms, resource-member cleanup, and local order.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TPanelOperation_Clear_getBounds_void` | `0x11d318` | `v18_TPanelOperation_Clear_getBounds_void` | exact normalized bounds copy |
| `TPanelOperation_DrawCurve_getBounds_void` | `0x11d344` | `v18_TPanelOperation_DrawCurve_getBounds_void` | exact endpoint bounds |
| `TPanelOperation_DrawStretched_getBounds_void` | `0x11d3d4` | `v18_TPanelOperation_DrawStretched_getBounds_void` | exact normalized bounds copy |
| `TPanelOperation_DrawLine_getBounds_void` | `0x11d400` | `v18_TPanelOperation_DrawLine_getBounds_void` | exact endpoint bounds |
| `TPanelOperation_DrawText_getBounds_void` | `0x11d464` | `v18_TPanelOperation_DrawText_getBounds_void` | exact zeroed result |
| line D1 boundary | `0x11d47c` | `v18_TPanelOperation_DrawLine_TPanelOperation_DrawLine` | empty ABI boundary |
| curve D1 boundary | `0x11d480` | `v18_TPanelOperation_DrawCurve_TPanelOperation_DrawCurve` | empty ABI boundary |
| clear D1 boundary | `0x11d484` | `v18_TPanelOperation_Clear_TPanelOperation_Clear` | empty ABI boundary |
| line D0 boundary | `0x11d530` | `v18_TPanelOperation_DrawLine_TPanelOperation_DrawLine__2` | exact delete form |
| curve D0 boundary | `0x11d534` | `v18_TPanelOperation_DrawCurve_TPanelOperation_DrawCurve__2` | exact delete form |
| clear D0 boundary | `0x11d538` | `v18_TPanelOperation_Clear_TPanelOperation_Clear__2` | exact delete form |
| `TDrawingPanelProperties` D2 | `0x11d4cc` | `v18_TDrawingPanelProperties_TDrawingPanelProperties` | layout match; base cleanup |
| properties D1 thunk | `0x11d4e8` | `v18_non_virtual_thunk_to_TDrawingPanelProperties_TDrawingPanelProperties` | exact receiver adjustment |
| `TDrawingPanelProperties` D0 | `0x11d4f0` | `v18_TDrawingPanelProperties_TDrawingPanelProperties__2` | layout match; base cleanup |
| properties D0 thunk | `0x11d528` | `v18_non_virtual_thunk_to_TDrawingPanelProperties_TDrawingPanelProperties__2` | exact receiver adjustment |
| `DrawRectangle` D1 | `0x11d5ec` | `v18_TPanelOperation_DrawRectangle_TPanelOperation_DrawRectangle` | layout match; resource cleanup |
| `DrawRectangle` D0 | `0x11d600` | `v18_TPanelOperation_DrawRectangle_TPanelOperation_DrawRectangle__2` | layout match; delete |
| `DrawStretched` D2 | `0x11d630` | `v18_TPanelOperation_DrawStretched_TPanelOperation_DrawStretched` | layout match; resource cleanup |
| `DrawStretched` D0 | `0x11d644` | `v18_TPanelOperation_DrawStretched_TPanelOperation_DrawStretched__2` | layout match; delete |
| `DrawImage` D0 | `0x11d688` | `v18_TPanelOperation_DrawImage_TPanelOperation_DrawImage__2` | layout match; delete |

The five bounds pairs are exact across the recorded normalized feature set.
The source and target use the same rectangle fields and control-flow shape.
The seven layout rows differ only in `register_detail_hash`, which records
the target compiler's register allocation after its wrapper rebuild. The
three D1 operation entries are empty boundaries, and the three D0 entries
call `operator delete`. The two properties thunks subtract 16 bytes from a
secondary receiver, while the derived operation destructors clean an embedded
`TResourceFileUser` before their deleting forms release the object.

The v332 anchor artifact has 20 high-confidence rows, 13 exact metric rows,
seven layout rows, and compact pseudocode for every source and target row.
Three rows corroborate target addresses already present in the v331 semantic
map; 17 add new reviewed context. All names were applied and verified after
reopening the v332 database.

The v332 database has 11,707 functions, zero audited default names, 6,382
translated aliases, 4,732 source-backed dynamic rows, 1,735 exact retained
target names, and 5,782 exact dynamic function starts. Its SHA-256 is
`f77edbe5076211bd3bd5a18c549f0c3cbaeeb88d2da7bc9c52a2733c1d87cdc2`.
The complete comparison records are
`artifacts/spectron_paneloperation_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_paneloperation_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_paneloperation_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v332_paneloperation_residual.json`,
`artifacts/spectron_name_coverage_audit_v332.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v332.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v332.json`,
`artifacts/spectron_semantic_translation_v332.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v332.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v331 static-variable residual comparison

The v331 pass compares the next complete class-local sequence after the v330
universe methods. The target class names are obfuscated, but the source and
target retain the same C++ destructor forms, secondary-base adjustments,
factory allocation sizes, and base cleanup calls.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TScriptUniverse_initStaticScriptVars_void` | `0x236d04` | `v18_TScriptUniverse_initStaticScriptVars_void` | same property initializer |
| `TScriptUniverseProperties_TScriptUniverseProperties` | `0x236d18` | `v18_TScriptUniverseProperties_TScriptUniverseProperties` | D1 destructor; register-detail change |
| property D1 non-virtual thunk | `0x236d34` | `v18_non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties` | exact thunk |
| `TScriptUniverseProperties_TScriptUniverseProperties__2` | `0x236d3c` | `v18_TScriptUniverseProperties_TScriptUniverseProperties__2` | D0 destructor; register-detail change |
| property D0 non-virtual thunk | `0x236d74` | `v18_non_virtual_thunk_to_TScriptUniverseProperties_TScriptUniverseProperties__2` | exact thunk |
| `TGraalPlayersArrayVar_TGraalPlayersArrayVar` | `0x236d98` | `v18_TGraalPlayersArrayVar_TGraalPlayersArrayVar` | D1 destructor; register-detail change |
| `TGraalPlayersArrayVar_TGraalPlayersArrayVar__2` | `0x236dac` | `v18_TGraalPlayersArrayVar_TGraalPlayersArrayVar__2` | D0 destructor; register-detail change |
| `jump_TScriptEnvironment_destroyScriptVariable_TGraalVar__2` | `0x236ddc` | `v18_jump_TScriptEnvironment_destroyScriptVariable_TGraalVar__2` | exact forwarder |
| `TStaticVar_create_TString_const` | `0x236f80` | `v18_TStaticVar_create_TString_const` | exact factory shape |
| `TStaticVar_TStaticVar` | `0x23702c` | `v18_TStaticVar_TStaticVar` | D2 destructor; register-detail change |
| `TStaticVar_TStaticVar__2` | `0x23705c` | `v18_TStaticVar_TStaticVar__2` | exact D0 destructor |
| `TActionScriptVar_create_TString_const` | `0x2372c4` | `v18_TActionScriptVar_create_TString_const` | exact factory shape |
| `TStaticVarProperties_TStaticVarProperties` | `0x2373d4` | `v18_TStaticVarProperties_TStaticVarProperties` | D2 destructor; register-detail change |
| static-property D1 non-virtual thunk | `0x2373f0` | `v18_non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties` | exact thunk |
| `TActionScriptVarProperties_TActionScriptVarProperties` | `0x2373f8` | `v18_TActionScriptVarProperties_TActionScriptVarProperties` | D1 destructor; register-detail change |
| action-property D1 non-virtual thunk | `0x237414` | `v18_non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties` | exact thunk |
| `TStaticVarProperties_TStaticVarProperties__2` | `0x23741c` | `v18_TStaticVarProperties_TStaticVarProperties__2` | D0 destructor; register-detail change |
| static-property D0 non-virtual thunk | `0x237454` | `v18_non_virtual_thunk_to_TStaticVarProperties_TStaticVarProperties__2` | exact thunk |
| `TActionScriptVarProperties_TActionScriptVarProperties__2` | `0x23745c` | `v18_TActionScriptVarProperties_TActionScriptVarProperties__2` | D0 destructor; register-detail change |
| action-property D0 non-virtual thunk | `0x237494` | `v18_non_virtual_thunk_to_TActionScriptVarProperties_TActionScriptVarProperties__2` | exact thunk |
| `TActionScriptVar_TActionScriptVar` | `0x23749c` | `v18_TActionScriptVar_TActionScriptVar` | D1 destructor; register-detail change |
| `TActionScriptVar_TActionScriptVar__2` | `0x2374b0` | `v18_TActionScriptVar_TActionScriptVar__2` | D0 destructor; register-detail change |

The first target function is an obfuscated replacement for the source static
property initializer. The `e4ZYfa8PV2Properties` and `JE42uaVwcK` pairs are
identified by their vtable writes, base-destructor calls, ABI forms, and their
position beside translated methods. The four-byte `D6TlgajP1m` wrapper is a
direct forwarding boundary.

The `NgNBgaN3oA` and `mH33wa4I1q` factories each allocate `0x88` bytes and
call the corresponding constructor. Their complete destructors preserve the
source garbage-collector and base cleanup, and their D0 bodies release the
object. The property families retain all four secondary-base thunk
boundaries. Ten rows are exact normalized feature matches; twelve differ only
in register-detail allocation. Compact pseudocode is available for every row.

The v331 database has 11,707 functions, zero audited default names, 6,362
translated aliases, 4,706 source-backed dynamic rows, 1,755 exact retained
target names, and 5,782 exact dynamic function starts. Its SHA-256 is
`f6bb72c43b0022b372d6d98e4143aa920a7e3c43cd5a89ede10e7510cd00178c`.
The complete comparison records are
`artifacts/spectron_tscript_var_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_var_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v331_tscript_var_residual.json`,
`artifacts/spectron_name_coverage_audit_v331.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v331.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v331.json`,
`artifacts/spectron_semantic_translation_v331.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v331.json`.

This comparison is static evidence. It does not change the runtime diagnosis,
patch the APK, or contact a live endpoint.

## v330 TScriptUniverse residual comparison

The v330 pass compares the next six source and target boundaries in the
script-universe runtime. The target class is the obfuscated `e4ZYfa8PV2`
family, with readable parameter classes preserved for several methods.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| `TScriptExecutionStats_TScriptExecutionStats__2` | `0x234bc0` | `v18_TScriptExecutionStats_TScriptExecutionStats__2` | exact D0 destructor |
| `TScriptUniverse_setExecutingNPC_TServerNPC` | `0x234d98` | `v18_TScriptUniverse_setExecutingNPC_TServerNPC` | register-detail change |
| `TScriptUniverse_setExecutingPlayer_TServerPlayer` | `0x234db4` | `v18_TScriptUniverse_setExecutingPlayer_TServerPlayer` | register-detail change |
| `TScriptUniverse_removeStaticObject_TGraalVar` | `0x235000` | `v18_TScriptUniverse_removeStaticObject_TGraalVar` | exact normalized metrics |
| `TScriptUniverse_addToFreeMachines_TScriptMachine` | `0x235a50` | `v18_TScriptUniverse_addToFreeMachines_TScriptMachine` | exact normalized metrics |
| `TScriptUniverse_TScriptUniverse__2` | `0x235bf8` | `v18_TScriptUniverse_TScriptUniverse__2` | exact D0 destructor |

The source and target deleting destructors both call the complete destructor
and then `operator delete`. The static-object remover performs the same
field-12 null guard and hash-list removal, while the free-machine helper
performs the same membership test and conditional append. The two execution
setters preserve the current and action context stores. The target parameter
classes are `LBgVgaqANQ` for TServerNPC, `MpGzgariDy` for TServerPlayer,
`G0gxgajWBw` for TGraalVar, and `mTAogaaEip` for TScriptMachine.

Four rows have identical normalized feature metrics. The setters retain the
same 28-byte one-block shape but differ in register-detail allocation, which
is recorded as a layout difference rather than hidden. Direct pseudocode was
available for all six rows, and the methods occur in the expected sequence
around the already translated universe constructors, clear helpers, and
free-machine methods.

The application renamed all six target functions and added six evidence
comments with zero failures. Reopening the fresh IDA copy verified all six
names. The v330 checkpoint contains 11,707 functions, zero audited default
names, 6,340 translated aliases, 419 target-only descriptive labels, 4,679
source-backed dynamic rows, 1,776 exact retained dynamic names, and 5,782
exact dynamic function starts.

The machine-readable records are
`artifacts/spectron_tscript_universe_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_universe_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_universe_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v330_tscript_universe_residual.json`,
`artifacts/spectron_name_coverage_audit_v330.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v330.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v330.json`,
`artifacts/spectron_semantic_translation_v330.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v330.json`.

The v330 private database hash is
`be32d09e08a76b3641beff951644ec78167fcc2735d5fc5ea58f9ee12acf97a1`. This
pass is static only. It does not change the loopback runtime result or the TLS
diagnosis and does not contact a live endpoint.

## v329 TScriptSpace residual comparison

The v329 pass follows the v328 static script-machine tail into the next raw
`N67CMatrxw` methods. It combines direct Hex-Rays review with the address-
independent feature records. Two functions receive source-backed aliases and
two additional target boundaries receive descriptive labels.

| Source role | Spectron address | Applied name | Match class |
| --- | ---: | --- | --- |
| `TScriptSpace_freeSuspendedStates_void` | `0x230198` | `v18_TScriptSpace_freeSuspendedStates_void` | exact metrics |
| `TScriptSpace_joinClass_TString_const_bool` | `0x233114` | `v18_TScriptSpace_joinClass_TString_const_bool` | layout change |
| target-only `receiveEvent` overload | `0x23332c` | `spectron_TScriptSpace_receiveEvent_TString_const_CanTfaz6bZ_const_TGraalVar` | descriptive label |
| target-only queue cleanup helper | `0x2339b4` | `spectron_TScriptSpace_clearScheduledEventsAndCancelActions_void` | descriptive label |

The `freeSuspendedStates` row is a 124-byte exact normalized match. Both
functions walk the receiver's suspended-state list, destroy each machine
state, clear the list, and null the field. The class-join row preserves the
source decision tree and class-local placement. Its target body is larger
because the 2.2 string and list wrappers require explicit temporary
construction and cleanup.

The raw `0x23332c` body is a distinct overload that takes a `CanTfaz6bZ`
event-name wrapper. It retains the queue limit, duplicate-event logic,
priority insertion, and activation behavior of the existing translated
`receiveEvent` entry. The raw `0x2339b4` body has no arguments, deletes all
scheduled events, and marks all pending actions canceled. The source database
has no distinct 1.8 boundaries for either target-only method, so both labels
stay outside the source mapping count.

The v329 application renamed both source-backed functions and both target-only
functions, and all four names were verified after reopening. The database has
11,707 functions, zero audited default names, 6,334 translated `v18_` aliases,
419 target-only descriptive labels, and 5,782 exact dynamic function starts.
Dynamic coverage reports 4,673 source-backed aliases and 1,782 exact retained
names.

The v329 database hash is
`c84c8bd4abe51302092c82db16003712e870b0ed8a541a9417f6c563f540b6ee`. Its
records are
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

## v328 TScriptMachine static-tail comparison

The v328 pass follows the property block into the static script-machine
initializer and `TCallStackEntry` cleanup tail. These two rows are supported
by compact Hex-Rays pseudocode, target symbol signatures, and their exact
class-local order.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| static script-variable initializer | `0x227780` | `v18_TScriptMachine_initStaticScriptVars_void` | layout change |
| deleting TCallStackEntry destructor | `0x227808` | `v18_TCallStackEntry_TCallStackEntry__2` | exact metrics |

The initializer has the same 12-instruction normalized shape in both builds.
Its target pseudocode allocates `0x68` bytes for the rebuilt
`l8eTfaIl5YProperties` object instead of the source `0x58`-byte
`TCallStackEntryProperties` object, which explains the single register-detail
change recorded in the anchor artifact. The deleting destructor is identical
at the normalized feature level: it calls the D2 destructor and then
`operator delete`.

The nearby target overload at `0x221928` is deliberately not counted as a
source alias. It converts the `C8THgaTQxF` string wrapper into the
`CanTfaz6bZ` wrapper and forwards to the already translated main resolver.
That is useful target behavior, but the 1.8 database has no distinct source
function boundary for this adapter.

Both aliases were applied to a fresh v327-derived database and verified after
reopening. The result has 11,707 functions, zero audited default names, and
6,332 translated `v18_` aliases. Dynamic coverage reports 4,671
source-backed aliases, 1,786 exact retained names, and 136 other retained
target names. The database hash is
`01e5dc66c7446c46101a09486f23c1a86822e9973b57b5897fa93a4d1f11526a`.

The v328 records are
`artifacts/spectron_script_machine_static_tail_manual_translation_anchors_20260829.json`,
`artifacts/spectron_script_machine_static_tail_manual_translation_application_20260829.json`,
`artifacts/spectron_script_machine_static_tail_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v328.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v328.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v328.json`,
`artifacts/spectron_semantic_translation_v328.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v328.json`.

## v327 property construction and cleanup comparison

The v327 pass follows the v326 format and property block into the adjacent
constructors, registry helpers, and cleanup methods. The target C++ symbols
remain obfuscated, but class-local order, constructor side effects, C++ ABI
forms, and matching ownership operations make these high-confidence semantic
translations.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| named property constructor | `0x22e49c` | `v18_TProperties_TProperties_TString_const_TString_const` | layout change |
| compile inherited properties | `0x22e568` | `v18_TProperties_compileProperties_void` | layout change |
| property-list lookup | `0x22e748` | `v18_getPropertyList_TString_const` | layout change |
| object-creator constructor | `0x22e790` | `v18_TObjectCreator_TObjectCreator_TString_const_TGraalVar_TString_const` | layout change |
| static script-property registration | `0x22f540` | `v18_TScriptProperty_initStaticScriptVars_void` | layout change |
| object-creator D1 destructor | `0x22f554` | `v18_TObjectCreator_TObjectCreator` | layout change |
| object-creator D0 destructor | `0x22f568` | `v18_TObjectCreator_TObjectCreator__2` | layout change |
| script-property D2 destructor | `0x22f598` | `v18_TScriptProperty_TScriptProperty` | layout change |
| script-property D0 destructor | `0x22f5d8` | `v18_TScriptProperty_TScriptProperty__2` | layout change |
| animation-property D1 destructor | `0x22f620` | `v18_TAniProperty_TAniProperty` | layout change |
| animation-property D0 destructor | `0x22f660` | `v18_TAniProperty_TAniProperty__2` | layout change |
| joined-classes-property D1 destructor | `0x22f6a8` | `v18_TJoinedClassesProperty_TJoinedClassesProperty` | layout change |
| joined-classes-property D0 destructor | `0x22f6e8` | `v18_TJoinedClassesProperty_TJoinedClassesProperty__2` | layout change |
| accept-string-property D1 destructor | `0x22f730` | `v18_TAcceptStringProperty_TAcceptStringProperty` | layout change |
| accept-string-property D0 destructor | `0x22f770` | `v18_TAcceptStringProperty_TAcceptStringProperty__2` | layout change |

Every row is recorded as a layout-change anchor because the rebuilt target
wrappers alter the normalized instruction and register metrics. The semantic
evidence remains strong: the constructor and compiler perform the same list,
registry, inheritance, replacement, and temporary-storage operations; the
static helper builds the same global registration state; and the destructor
families retain the expected vtable, base cleanup, receiver-adjustment, and
deleting-form sequence. The nearby one-argument constructor at `0x22e838`
remains raw because no independent 1.8 source counterpart was found.

All 15 aliases were applied to a fresh v326-derived database and verified
after reopening. The result has 11,707 functions, zero audited default names,
and 6,330 translated `v18_` aliases. Dynamic coverage reports 4,669
source-backed aliases, 1,788 exact retained names, and 136 other retained
target names. The database hash is
`cc731360c7c08f825a7905c760897d3a7aede1dccdb4322d56d72f5c2e0c2f13`.

The v327 records are
`artifacts/spectron_property_constructor_destructor_manual_translation_anchors_20260829.json`,
`artifacts/spectron_property_constructor_destructor_manual_translation_application_20260829.json`,
`artifacts/spectron_property_constructor_destructor_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v327.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v327.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v327.json`,
`artifacts/spectron_semantic_translation_v327.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v327.json`.

## v326 format-parameter and property comparison

The v326 pass continues directly after the v325 script-runtime destructors.
The target names are obfuscated, but the `OV5NOaoBLl` accessor sequence and
the D1, D2, and D0 destructor forms make this one of the cleaner remaining
class-local matches.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| format-parameter D2 cleanup | `0x22c810` | `v18_TScriptMachine_FormatParameters_TScriptMachine_FormatParameters` | layout change |
| call-stack property D1/D2 cleanup | `0x22c858` | `v18_TCallStackEntryProperties_TCallStackEntryProperties` | register-detail change |
| call-stack property D1 thunk | `0x22c874` | `v18_non_virtual_thunk_to_TCallStackEntryProperties_TCallStackEntryProperties` | exact metrics |
| call-stack property D0 cleanup | `0x22c87c` | `v18_TCallStackEntryProperties_TCallStackEntryProperties__2` | register-detail change |
| call-stack property D0 thunk | `0x22c8b4` | `v18_non_virtual_thunk_to_TCallStackEntryProperties_TCallStackEntryProperties__2` | exact metrics |
| format-parameter D0 cleanup | `0x22c8bc` | `v18_TScriptMachine_FormatParameters_TScriptMachine_FormatParameters__2` | layout change |
| next float to unsigned integer | `0x22ca58` | `v18_TScriptMachine_FormatParameters_getNextU32_void` | exact metrics |
| next float to signed integer | `0x22caa0` | `v18_TScriptMachine_FormatParameters_getNextS32_void` | exact metrics |
| next float passthrough | `0x22cae8` | `v18_TScriptMachine_FormatParameters_getNextF64_void` | exact metrics |
| indexed float to unsigned integer | `0x22caf0` | `v18_TScriptMachine_FormatParameters_getIndexedU32_int` | exact metrics |
| indexed float to signed integer | `0x22cb38` | `v18_TScriptMachine_FormatParameters_getIndexedS32_int` | exact metrics |
| indexed float passthrough | `0x22cb80` | `v18_TScriptMachine_FormatParameters_getIndexedF64_int` | exact metrics |
| next string passthrough | `0x22cb88` | `v18_TScriptMachine_FormatParameters_getNextString_void` | layout change |
| indexed string passthrough | `0x22cb94` | `v18_TScriptMachine_FormatParameters_getIndexedString_int` | layout change |
| TProperties D1/D2 cleanup | `0x22cc48` | `v18_TProperties_TProperties` | layout change |
| TProperties D1 thunk | `0x22ccbc` | `v18_non_virtual_thunk_to_TProperties_TProperties` | exact metrics |
| TProperties D0 cleanup | `0x22ccc4` | `v18_TProperties_TProperties__2` | exact metrics |
| TProperties D0 thunk | `0x22cce4` | `v18_non_virtual_thunk_to_TProperties_TProperties__2` | exact metrics |
| joined-class object writer | `0x22ce20` | `v18_TJoinedClassesProperty_writeObject_TGraalVar_TGraalVar` | layout change |
| animation object writer | `0x22cea0` | `v18_TAniProperty_writeObject_TGraalVar_TGraalVar` | layout change |

Eleven of the 20 rows have exact normalized metrics. The remaining nine are
not weak matches: the target format wrapper owns a larger string array, the
property classes use rebuilt containers, and the object writers explicitly
convert and clear target string wrappers. The accessor calls and order remain
the same, while the destructor thunks preserve the expected receiver
adjustment.

All 20 aliases were applied and verified after reopening the fresh v326
database. It contains 11,707 functions, zero audited default names, and 6,315
translated `v18_` aliases. Dynamic coverage reports 4,647 source-backed
aliases, 1,803 exact retained names, and 143 other retained target names. The
database hash is
`08ae63229dfbcabf94d314cda677a2c45b60e17b9c2fee8351a298b3cf6eb991`.

The v326 records are
`artifacts/spectron_format_parameters_property_manual_translation_anchors_20260829.json`,
`artifacts/spectron_format_parameters_property_manual_translation_application_20260829.json`,
`artifacts/spectron_format_parameters_property_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v326.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v326.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v326.json`,
`artifacts/spectron_semantic_translation_v326.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v326.json`.

## v325 TScript destructor comparison

The v325 pass closes eight raw symbols that sit around the v324 TScript
runtime block. Their target names are still obfuscated in the original ELF,
but the C++ ABI forms and cleanup sequences line up with the source methods.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| script log name | `0x21b324` | `v18_TScript_getLogName_void` | layout change |
| deleting TScript destructor | `0x21bcfc` | `v18_TScript_TScript__2` | exact metrics |
| TScriptFunctionProperties destructor | `0x21e4f8` | `v18_TScriptFunctionProperties_TScriptFunctionProperties` | layout change |
| property D1 thunk | `0x21e514` | `v18_non_virtual_thunk_to_TScriptFunctionProperties_TScriptFunctionProperties` | exact metrics |
| deleting property destructor | `0x21e51c` | `v18_TScriptFunctionProperties_TScriptFunctionProperties__2` | layout change |
| property D0 thunk | `0x21e554` | `v18_non_virtual_thunk_to_TScriptFunctionProperties_TScriptFunctionProperties__2` | exact metrics |
| TFunctionProfile destructor | `0x21e55c` | `v18_TFunctionProfile_TFunctionProfile` | layout change |
| deleting profile destructor | `0x21e570` | `v18_TFunctionProfile_TFunctionProfile__2` | layout change |

The source database's historical aliases make the property and profile
entries look like constructors, but their pseudocode comments expose the D1,
D2, and D0 destructor symbols. Both builds reset the appropriate vtable slots,
destroy the base or name string, adjust the receiver for non-virtual thunks,
and call `operator delete` for the deleting forms. `getLogName` is also
distinctive because both bodies assemble the literal `Class ` followed by the
script name at object offset 8.

Three rows have exact normalized metrics. The five layout-change rows differ
only in the rebuilt target string wrapper or register-detail allocation. All
eight aliases were applied and verified after reopening the fresh v325
database. It contains 11,707 functions, zero audited default names, and 6,295
translated `v18_` aliases. The final database hash is
`229e4729eed1be2759935c1604ac6e3987ffe6fbe91c2b5a0dca16ae344c0757`.

The v325 records are
`artifacts/spectron_tscript_destructor_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_destructor_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_destructor_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v325.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v325.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v325.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v325.json`.

## v324 TScript runtime comparison

The v324 pass follows the class-local method order into `TScriptFunction`,
`TScript`, and `TScriptEnvironment`. The target has stripped the original
debug names, but the paired Hex-Rays bodies retain the same responsibilities.

| Source role | Spectron address | Applied alias | Match class |
| --- | ---: | --- | --- |
| TScriptFunction constructor | `0x21b490` | `v18_TScriptFunction_TScriptFunction_TScript_TString_const_int_int` | layout change |
| add free call-stack entry | `0x21b5f8` | `v18_TScriptFunction_addToFreeCallStackEntries_TCallStackEntry` | exact metrics |
| clear call-stack entries | `0x21b644` | `v18_TScriptFunction_clearCallStackEntries_void` | exact metrics |
| TScriptFunction destructor | `0x21b6c0` | `v18_TScriptFunction_TScriptFunction` | exact metrics |
| deleting destructor | `0x21b708` | `v18_TScriptFunction_TScriptFunction__2` | layout change |
| TScript constructor | `0x21b728` | `v18_TScript_TScript_TString_const` | layout change |
| caught-event registration | `0x21bd1c` | `v18_TScript_addCatchedEvent_TString_const_TString_const_int` | layout change |
| function lookup | `0x21c0dc` | `v18_TScript_getFunction_TString_const` | layout change |
| event-function lookup | `0x21c460` | `v18_TScript_getEventFunctions_TList_TString_const` | layout change |
| self event catchers | `0x21c5dc` | `v18_TScript_installSelfEventCatchers_TGraalVar` | layout change |
| inherited event catchers | `0x21c758` | `v18_TScript_installEventCatchers_TGraalVar` | layout change |
| profiler accumulation | `0x21ca08` | `v18_TScript_addFunctionProfilerTime_TString_const_double_double` | layout change |
| bytecode optimization | `0x21cc10` | `v18_TScript_optimizeByteCode_void` | layout change |
| encrypted script loading | `0x21db68` | `v18_TScript_loadScriptEncrypted_int_TString_const_uint` | layout change |
| script request check | `0x21dde0` | `v18_TScript_checkRequestScript_int_TString_const_uint` | layout change |
| static runtime variables | `0x21dff8` | `v18_TScript_initStaticVars_void` | layout change |
| static script variables | `0x21e028` | `v18_TScript_initStaticScriptVars_void` | layout change |
| environment property list | `0x21e618` | `v18_TScriptEnvironment_getPropertyList_TString_const` | layout change |
| temporary variable | `0x21e848` | `v18_TScriptEnvironment_makeTempVar_void` | layout change |
| array variable | `0x21e8bc` | `v18_TScriptEnvironment_makeArrayVar_bool` | layout change |
| string-list to variable | `0x21e9ec` | `v18_TScriptEnvironment_makeVarFromStringList_TStringList_const_bool` | layout change |
| comma text to variable | `0x21eaa0` | `v18_TScriptEnvironment_makeVarFromCommaText_TString_const_bool` | layout change |
| variable to string-list | `0x21ec14` | `v18_TScriptEnvironment_makeStringListFromVar_TGraalVar` | layout change |
| environment static setup | `0x21ed10` | `v18_TScriptEnvironment_initStaticVars_void` | layout change |

The exact rows are short list operations whose normalized ARM64 records match
the 1.8 methods completely. The other rows preserve the important decisions
through rebuilt wrapper classes. Function and event lookup still split names,
perform case-insensitive scans, and recurse through inherited scripts. The
optimizer still walks the same bytecode structures, although the target's
instruction records use a larger stride. The environment helpers still link
variables into the active universe and preserve array and comma-text behavior.

The target's environment initializer deserves the explicit layout label. The
source packs much of its static registration into a compact helper, while the
target constructs event-name objects and registry entries in separate stages.
That size difference is therefore expected and is not evidence of a mistaken
pairing.

All 24 target functions were renamed and verified after reopening the fresh
database. The v324 database has 11,707 functions, zero audited default names,
and 6,287 translated `v18_` aliases. Its final hash is
`975367646c22c2f21d1c7ffc8380e0b48a6c259864a1f8b192e043c3e0992e06`. The
complete evidence is in
`artifacts/spectron_tscript_runtime_manual_translation_anchors_20260829.json`,
`artifacts/spectron_tscript_runtime_manual_translation_application_20260829.json`,
`artifacts/spectron_tscript_runtime_manual_translation_verification_20260829.json`,
`artifacts/spectron_name_coverage_audit_v324.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v324.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v324.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v324.json`.

## Spectron connector endpoint change

The endpoint builder is one of the clearest differences between the two
native builds. The source 1.8 routine at `0x203df4` decodes the host pair
`con.quattroplay.com` and `con2.quattroplay.com`. The Spectron routine at
`0x2094c0` decodes `cong.quattroplay.com` and `cong2.quattroplay.com`.

The rest of the connector layout is familiar. Modes 1 and 2 use HTTPS, mode
3 uses HTTP, and the paths remain `/con.png`, `/con.gs`, and `/conf.gs`. The
target also retains the request builder at `0x205730` and the URL-to-request
wrapper at `0x206bc4`. Its visible query literals are updated to version
`6.171`, build `Oct 30 2022 12:58:55`, and revision parameter `r=2.22`.

The host result comes from the native decoder rather than from a broad text
search. In 1.8, the first-attempt fragment is three encoded bytes that
decode to `con`, and the retry fragment is four bytes that decode to `con2`.
In Spectron, the first fragment is the four-byte sequence `d00H`, which the
same decoder turns into `cong`, and the retry fragment is five encoded bytes
that turn into `cong2`. The shared domain fragment is 16 bytes long and
decodes to `.quattroplay.com` in both files. One domain byte is the native
zero-byte sentinel repaired by `codesimplefix0` before `decodesimple` runs.

This gives the connection failure investigation a concrete first split. A
Spectron run can fail because the `cong` service is unavailable or because
its current certificate does not match the old embedded trust bundle. The
existing static TLS audit already shows that the target retains the same
historical certificate material and the same hostname-verification path as
1.8. The endpoint audit is intentionally offline and does not resolve DNS,
open a socket, or assert that either target hostname is currently active.

The reproducible record is
`artifacts/spectron_connector_endpoint_audit_20260827.json`, generated by
`tools/audit_spectron_connector_endpoints.py`.

## Spectron local loopback package

The target now has a separate local-only builder. It is intentionally not the
same patch as the original 1.8 replay because the target offsets moved. The
builder replaces the target trust text at `0x2ea9e0`, redirects the target
resolver at `0x20c20c` to `127.0.0.1`, and changes the two HTTPS parser
constants at `0x2065e0` and `0x206764` from port 443 to a caller-selected
private port. The certificate path remains enabled, so the local certificate
must contain the exact SAN `cong.quattroplay.com`.

The target's deterministic RC4 test uses the same function-entry technique as
the 1.8 diagnostic, but the target function starts at `0x202fe8`. A
zero-filled 128-byte region at `0x1c4000` is an unused code cave in this exact
library. The trampoline rewrites only the test responder key backing store
and resumes at `0x202fec`; it is not a production encryption change.

The builder also applies the three already-reviewed `libxposed.so` branch
edits by default. Those edits skip the supplied WebTop `crash`, `freeze`, and
`abort` commands, which otherwise terminate the target after Start. Use
`--keep-webtop-commands` when a control run needs the original behavior.
The connector script, qplay game protocol, native peer verification, and
hostname verification are otherwise preserved. The complete byte-level
record is in `artifacts/spectron_loopback_patch_audit_20260828.json`, and the
builder is `tools/build_spectron_loopback_apk.py`.

The package build was checked offline with the supplied APK and a disposable
certificate for `cong.quattroplay.com`. The input APK hash is
`5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c`, the
resulting private APK hash is
`45f469692cb6ee2e8d0f1529d8b0871dafdf718e2c8b6e345cb5082e40257751`, and
its patched ARM64 qplay hash is
`45a7f97df9b40cdac6fbd42dc715bbabf3bbdb9b33876990e232133a8818941e`.
`zipalign` and APK signature verification both passed. This is a packaging
and byte-integrity result only. No emulator was connected for this build
check, and no Spectron endpoint was resolved or contacted.

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
| `TClient_processServerModifies` | `0xecba0` (superseded) | Active-player transition reset and server-level modification application |
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
take the same HTTP branch in both routines. The older v6 artifact's
server-modify row is discussed as a superseded feature-shape collision below.

The server-modify row in this older v6 table was later corrected. The address
`0xecba0` is an exported `yL3_IaDMFt` hash-container method. Its pseudocode
iterates a container and does not touch the TClient transition state. The
actual target handler-table slot 48 points to `0x1eefa0`; the corrected v232
record restores the retained dynamic symbol at `0xecba0` and applies the
readable alias only at `0x1eefa0`.

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

## Spectron TScriptSpace event anchors

The v35 pass reviewed eight event and timer methods in the stripped
`N67CMatrxw` class. The broad matcher left these entries unresolved because
several target bodies grew around new string wrappers, but the target class
order, signatures, and pseudocode preserve the original responsibilities.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_freeScriptErrors_void` | `0x2274d0` | `0x230214` | script-error list release and nulling |
| `TScriptSpace_addScriptError_TString_const` | `0x227558` | `0x23029c` | empty error hook in class order |
| `TScriptSpace_catchEvent_TString_const_TString_const_TString_const` | `0x22755c` | `0x2302a0` | universe event-object and catcher registration |
| `TScriptSpace_catchEvent_TGraalVar_TString_const_TString_const` | `0x2277e4` | `0x230570` | object event-space creation and registration |
| `TScriptSpace_leaveClass_TScript` | `0x227ee8` | `0x230cdc` | event leave callbacks and class removal |
| `TScriptSpace_checkLeaveClasses_void` | `0x2280ac` | `0x230eac` | pending class-name processing |
| `TScriptSpace_getEventState_TString_const_TString_const_bool` | `0x22835c` | `0x231180` | timeout and `on` normalization |
| `TScriptSpace_setTimeout_double` | `0x228510` | `0x231410` | timeout state and script activation |

The two `catchEvent` methods retain the universe lookup, `TClient` depth
check, lazy event-space creation, catcher registration, and unknown-object
list behavior. The class-leave pair retains the `onInitFrame` exception,
event leave callback, active-class removal, pending-name clearing, and
`classUpdateAction(true)` path. `getEventState` keeps the `istimeout` to
`timeout` mapping, lowercasing and `on` prefix removal, object fallback, and
optional state deletion. `setTimeout` keeps the non-positive reset, timeout
state lookup, machine-state cleanup, universe pointer update, and positive
timer activation. The target bodies changed size, but these operations are
visible in the decompiled control flow rather than inferred from proximity.

The evidence is in
`artifacts/spectron_script_space_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_space_anchors.py`. All eight
labels were applied to a copy of v34 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v35.i64`. The database SHA-256 is
`a019e59e27e5e5b3a3e561d4708cdadb3b2c0e8c747b05b22edff749d2eb4a34`.

## Spectron GS2 execution anchors

The v36 pass reviewed six execution helpers in the stripped `N67CMatrxw`
class. Their target signatures, caller relationships, and decompiled bodies
preserve the function and action-dispatch roles from 1.8.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_executeFunction_TScriptFunction_TGraalVar_bool_TScriptMachine` | `0x22871c` | `0x23168c` | free-machine lifecycle and return extraction |
| `TScriptSpace_executeActionSelfCatch_TString_const_TScriptAction` | `0x228930` | `0x231880` | event normalization and self-catch dispatch |
| `TScriptSpace_executeActionNamedObject_TScriptAction` | `0x228ce8` | `0x231c3c` | current-script and class scans |
| `TScriptSpace_executeActionCatch_TGraalVar_TScriptAction` | `0x228eb0` | `0x231e14` | caught-object argument construction |
| `TScriptSpace_checkCallerSuspenseWakeUp_TGraalVar_TString_const_double_int` | `0x228f6c` | `0x231f14` | saved-state wake-up and callback |
| `TScriptSpace_freeActions_void` | `0x22981c` | `0x232944` | action destruction and list clear |

`executeFunction` preserves the busy-state guard, free-machine acquisition,
executing-object setup, function preparation, argument push, status-two
suspension behavior, status-three return extraction, machine cleanup, and
restoration of the previous universe machine. The action helpers continue to
normalize `on` names, avoid duplicate event calls, scan current and joined
classes, resolve catching functions, construct link arguments, and release
returned variables. The caller wake-up helper retains the saved-state fast
path and the full event-state path, including copying the current stack value
when required. The action cleanup helper is an exact normalized-size and
control-flow match.

These assignments are semantic rather than recovered original symbols. The
target bodies range from nearly unchanged to moderately changed size as the
string, list, and variable wrappers were rebuilt.

The evidence is in
`artifacts/spectron_script_execution_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_execution_anchors.py`. All six
labels were applied to a copy of v35 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v36.i64`. The database SHA-256 is
`03b2888be2ce9c992a5849126d856d94a7d010f882c095c9b26275f3e65f875f`.

## Spectron top-level GS2 dispatch anchors

The v37 pass reviewed the three large `TScriptSpace` dispatch bodies that
connect event state to actual action execution.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_executeScript_TString_const_TString_const_TGraalVar` | `0x22919c` | `0x232160` | event-state execution and machine restoration |
| `TScriptSpace_executeAction_TScriptAction` | `0x2294e8` | `0x232520` | target resolution and action routing |
| `TScriptSpace_receiveEvent_TString_const_TString_const_TGraalVar` | `0x229898` | `0x2329c0` | queue limits, duplicate checks, and priority insertion |

`executeScript` preserves the event-state lookup, free-machine acquisition,
script preparation, NPC argument handling, execution status paths, updated
script cancellation, suspended-caller wake-up, and machine cleanup. The top
level action dispatcher retains class-update checks, target-object resolution,
the executing-NPC player lookup, event-state routing, local and caught action
dispatch, fallback script execution, and pending class-leave processing.
`receiveEvent` preserves the inactive-object guard, the 999-event limit and
onAllRCChat exception, overrun reporting, onshow and onhide duplicate policy,
action construction, front insertion for timeout, created, and initialized
events, and script activation.

The target bodies are larger than their 1.8 counterparts, but the state
transitions and helper calls remain explicit in pseudocode. These are semantic
class anchors, not recovered original debug symbols.

The evidence is in
`artifacts/spectron_script_dispatch_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_dispatch_anchors.py`. All three
labels were applied to a copy of v36 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v37.i64`. The database SHA-256 is
`47366d1d75b2b6cf117a605950d7f7d326b9279338cf56374277d50a555e4cd7`.

## Spectron GS2 scheduler and cleanup anchors

The v38 pass reviewed six remaining scheduler and event-cleanup methods in
`N67CMatrxw`.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptSpace_cancelEvents_TString_const` | `0x22a204` | `0x233a68` | scheduled-list deletion and action cancellation |
| `TScriptSpace_checkScheduledEvents_void` | `0x22a354` | `0x233bf0` | timeout polling and repeat scheduling |
| `TScriptSpace_runScript_void` | `0x22a5e0` | `0x233ed8` | action loop and execution context |
| `TScriptSpace_unlinkEventObject_void` | `0x22ac2c` | `0x234554` | catcher removal and object ownership |
| `TScriptSpace_ignoreEvents_TString_const` | `0x22ada8` | `0x2346f4` | catcher and local-name removal |
| `TScriptSpace_setClasses_TString_const` | `0x22b07c` | `0x234a34` | class-list replacement and reinstall |

`cancelEvents` preserves backward deletion of matching scheduled events and
the separate canceled flag on pending actions. `checkScheduledEvents` keeps
the active timeout countdown, due-event queueing, dead-object unlinking,
repeating-event rescheduling, and delayed event-state processing. `runScript`
retains class updates, download deferral and catchers, executing player and
NPC context, profiling, action iteration, error-state stop, action cleanup,
and global-state restoration.

The cleanup helpers preserve the unknown-object ownership checks and global
event-object lookup. `ignoreEvents` removes the named catcher and local list
entry. `setClasses` leaves existing classes, splits and joins the new list,
reinstalls catchers, triggers the class update action, and releases its
temporary list. The changed-size bodies are supported by explicit pseudocode
operations and class-local signatures rather than address proximity alone.

The evidence is in
`artifacts/spectron_script_scheduler_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_scheduler_anchors.py`. All six
labels were applied to a copy of v37 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v38.i64`. The database SHA-256 is
`a6981e19c2ac9e3862a21285f2b23eafec6eb21693fa72f3bed922f6544072f7`.

## Spectron event-object and catcher-list anchors

The v39 pass reviewed six methods that form the event-object and catcher-list
implementation beneath the `TScriptSpace` helpers. The obfuscated target
classes are `pWihMaQxae` for the event object and `SEPCMa33gw` for its catcher
list.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TEventObject_TEventObject__2` | `0x226cac` | `0x22f960` | deleting destructor wrapper |
| `TEventObject_TEventObject_TString_const` | `0x226ce8` | `0x22f9a0` | event-name state and catcher-list construction |
| `TEventObject_addEventCatcher_TString_const_TGraalVar_TString_const` | `0x226f74` | `0x22fc6c` | event lookup, list creation, and catcher insertion |
| `TEventCatcherList_TEventCatcherList_TString_const_TString_const` | `0x226df4` | `0x22facc` | event and function-name state initialization |
| `TEventCatcherList_TEventCatcherList__2` | `0x22a9dc` | `0x234304` | deleting destructor wrapper |
| `TEventCatcherList_receiveEvent_TGraalVar` | `0x22af4c` | `0x2348bc` | catcher iteration and object callback dispatch |

The two deleting destructors are exact normalized matches. Each calls the
complete destructor and then `operator delete`, with the same 32-byte, eight-
instruction, two-block body. The constructors retain their class-local roles:
the event object copies its name and creates the owned catcher storage, while
the catcher list stores the event and catching-function names and initializes
its entries. The target constructors are larger because the 2.2 string and
container wrappers changed.

The registration method preserves the lookup, lowercase-on-create, list
construction, and catcher insertion sequence. The receive method keeps the
catcher loop, linked-object lookup, callback dispatch, and cleanup of entries
whose object has gone away. These are direct class and pseudocode matches,
not guesses based only on nearby addresses.

The evidence is in
`artifacts/spectron_event_object_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_event_object_anchors.py`. All six labels
were applied to a copy of v38 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v39.i64`. The database SHA-256 is
`2a15e694bf0935c07ef45869388dcff311b61d5cef8e850ddd379e040ff2b016`.

## Spectron GS2 script-action anchors

The v40 pass reviewed the two `TScriptAction` lifecycle methods. Their
obfuscated target class is `FOb5fbmyZ8`.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptAction_TScriptAction_TString_const_TString_const_TGraalVar` | `0x227164` | `0x22fe78` | player-prefix normalization, event index, and cloned argument |
| `TScriptAction_TScriptAction` | `0x2272e8` | `0x230024` | complete destructor and field cleanup |

The constructor keeps the `player:` prefix handling, event and function name
fields, event-index lookup, optional argument clone, and two status bytes. Its
target body has the same 14-block shape and grows from 388 to 428 bytes for
the changed 2.2 wrappers. IDA identifies the second row as the complete D2
destructor through its alternative ABI name. It releases the cloned argument
and clears the normalized event, function, and event-name strings in the same
order as the source.

The evidence is in
`artifacts/spectron_script_action_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_action_anchors.py`. Both labels
were applied to a copy of v39 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v40.i64`. The database SHA-256 is
`6772706f004620089eb4def0d79bdebc77ce821e1340f92e798f7b0c1292d45d`.

## Spectron GS2 stack-entry conversion anchors

The v41 pass reviewed three `TScriptStackEntry` conversion methods. Their
obfuscated target class is `ToQnQaIHFG`.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptStackEntry_switchTypeFloat_TScriptMachine_bool` | `0x2199bc` | `0x22141c` | string, property, and variable numeric conversion |
| `TScriptStackEntry_switchTypeString_TScriptMachine_bool` | `0x219a54` | `0x2214dc` | float formatting and property string conversion |
| `TScriptStackEntry_switchTypeObject_TScriptMachine_bool` | `0x219b80` | `0x221630` | property object conversion and quoted text handling |

The float conversion preserves the existing-string parse, existing-float
fast path, property fallback, missing-source zero, and type-one assignment.
The string conversion keeps the near-zero float formatting rule, property or
variable string read, missing-source clear, and type-two assignment. The
object conversion keeps property materialization, the quoted comma-text
special case, variable object reads, and type-three assignment. Each method
remains in the same class-local sequence as the source. The target bodies are
larger because the 2.2 wrappers changed, but their state transitions and
helper calls remain explicit in pseudocode.

The evidence is in
`artifacts/spectron_stack_entry_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_stack_entry_anchors.py`. All three labels
were applied to a copy of v40 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v41.i64`. The database SHA-256 is
`b9527ad01e544f2a3e9afdd4defb46bfb625465f2581b86bfda7e7084ed41914`.

## Spectron GS2 machine-helper anchors

The v42 pass reviewed four small `TScriptMachine` helpers. Their obfuscated
target class is `mTAogaaEip`.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_restoreExecutionVariables_void` | `0x218bd0` | `0x2202fc` | saved execution field reset |
| `TScriptMachine_charAt_void` | `0x21ca00` | `0x224af0` | indexed character extraction |
| `TScriptMachine_findActionPlayer_void` | `0x21df18` | `0x2261fc` | reverse player-property lookup |
| `TScriptMachine_findActionNPC_void` | `0x21dfc0` | `0x2262a4` | reverse NPC-property lookup |

The restoration helper is an exact two-instruction match. It clears the saved
execution-object field, with the target offset moving from 144 to 152 as the
machine layout changed. `charAt` preserves input-count consumption, integer
index conversion, bounds checks, empty-result behavior, and single-character
assignment. The player and NPC helpers preserve the reverse scan of action
variables, dynamic casts to their respective server-property types, and the
global action-context slots. Both lookup bodies have identical normalized
hashes to their 1.8 counterparts.

The evidence is in
`artifacts/spectron_machine_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_machine_helper_anchors.py`. All four
labels were applied to a copy of v41 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v42.i64`. The database SHA-256 is
`ade60a5719a41f9769ddd33fd539031cf69dbc31c49feee70bc48557c9e6e46d`.

## Spectron GS2 array mutation anchors

The v43 pass reviewed three `TScriptMachine` array-writing methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_setArrayCell_void` | `0x21c4d8` | `0x224560` | typed single-cell setter and stack unwind |
| `TScriptMachine_setArrayCell2_void` | `0x21c7c0` | `0x224868` | nested index calculation and typed setter |
| `TScriptMachine_arrayReplace_void` | `0x21cd88` | `0x224e78` | replacement index and out-of-range policy |

The single-cell method preserves index normalization, property resolution,
typed float/string/object writes, and stack unwinding. The two-dimensional
method retains two index calculations, nested-array resolution, the quoted
string special case, typed writes, and four-value cleanup. `arrayReplace`
keeps the replacement index policy, destination and value resolution, typed
write branches, and stack cleanup. The target bodies are larger because the
array and string wrappers changed, but their setter order and branch structure
remain visible in pseudocode.

The evidence is in
`artifacts/spectron_array_mutation_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_array_mutation_anchors.py`. All three
labels were applied to a copy of v42 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v43.i64`. The database SHA-256 is
`28c062661c587455a8177ffbbd2f3cb9715223db80e3ddee953729e29568f8d2`.

## Spectron GS2 string-search anchors

The v44 pass reviewed two `TScriptMachine` search methods. Both target
functions are in the obfuscated `mTAogaaEip` class and were not already present
in the semantic map.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_indicesOf_void` | `0x21d2a4` | `0x2253b4` | result array of all matching indices |
| `TScriptMachine_getPositions_void` | `0x21d4b8` | `0x225600` | result array of substring positions |

`indicesOf` creates the result array, resolves the input array and search
value, compares float, string, and object entries, and appends every matching
zero-based index. The target preserves the same 26-block loop and stack
handling, while the body grows from 520 to 580 bytes around the changed string
wrappers.

`getPositions` resolves the source and search strings, checks their lengths,
scans the source with a byte comparison at each possible offset, and appends
each match. The target keeps the same substring-search behavior and result
array flow, growing from 276 to 388 bytes as the 2.2 string wrappers changed.

The evidence is in
`artifacts/spectron_string_search_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_string_search_anchors.py`. Both labels
were applied to a copy of v43 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v44.i64`. The database SHA-256 is
`a8be3d80ea5f1adb780d714ca960ec88891bd65b2c2d828414a2c096de29b276`.

## Spectron GS2 string-stack helper anchors

The v45 pass reviewed the next three string helpers in the `mTAogaaEip`
`TScriptMachine` sequence.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_getNextString_void` | `0x21d698` | `0x225850` | current string value and stack advance |
| `TScriptMachine_getIndexedString_int` | `0x21d718` | `0x225934` | indexed lookup and string delegation |
| `TScriptMachine_formatString_void` | `0x21d76c` | `0x22599c` | formatter scan and type-two result |

`getNextString` keeps the stack-bound check, string conversion, empty-string
fallback, pointer advance, and input-count decrement. `getIndexedString`
rejects negative indexes, derives the selected position from the input count,
and delegates to the next-string helper. `formatString` retains the backward
scan for the formatter boundary, current-value conversion, formatter parameter
object, exhausted-stack cleanup, and type-two assignment. The changed 2.2
wrappers make the bodies larger, from 128 to 228 bytes, 84 to 104 bytes, and
320 to 460 bytes respectively.

The evidence is in
`artifacts/spectron_string_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_string_helper_anchors.py`. All three
labels were applied to a copy of v44 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v45.i64`. The database SHA-256 is
`23e333de1f861ee226bd87daaba81c9d9fd1558adc48e278b59bca9d3f912319`.

## Spectron GS2 variable-construction anchors

The v46 pass reviewed the two variable-construction methods immediately after
the string helpers in the `mTAogaaEip` `TScriptMachine` sequence.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_makeVar_void` | `0x21db30` | `0x225dec` | type-three or type-four variable result |
| `TScriptMachine_makeOldScriptVar_TString_const_bool` | `0x21dbc8` | `0x225ea4` | legacy dotted-path root resolution |

`makeVar` preserves the current-entry read, variable/member split, type-four
assignment when a member name is present, type-three object assignment
otherwise, and temporary-string cleanup. `makeOldScriptVar` keeps the dotted
name scan and the special roots `this`, `thiso`, `temp`, `player`, `playero`,
`client`, `clientr`, and `serverr`. It also retains the optional universe lookup,
action-player fallback, resolved-object table lookup, virtual fallback, and
temporary-string cleanup. The first body grows from 152 to 184 bytes with the
same seven blocks. The second grows from 848 to 856 bytes with the same 52
blocks.

The evidence is in
`artifacts/spectron_variable_construction_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_variable_construction_anchors.py`. Both
labels were applied to a copy of v45 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v46.i64`. The database SHA-256 is
`8afd65b7124587981a6757cb8fb5b245860df1647ef87b80384722d67cdc81bb`.

## Spectron GS2 script diagnostic and object anchors

The v47 pass reviewed the diagnostic and object-creation methods that follow
the variable-construction helpers in the `mTAogaaEip` sequence.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_getScriptLineMsg2_TScriptFunction_int` | `0x21e0fc` | `0x2263e0` | line, function, and owner diagnostic text |
| `TScriptMachine_createObject_void` | `0x21e2e4` | `0x226684` | creator lookup, registration, and error path |

`getScriptLineMsg2` preserves validation of the function and line index, the
`at line` and `in function` message branches, the optional `of` owner suffix,
and its output-string cleanup. The target grows from 444 to 632 bytes and from
21 to 24 basic blocks around changed string and list wrappers.

`createObject` retains creator lookup, construction from the current stack
value, `unknown_object` and `TGraalVar` handling, `GuiGraalCtrl` filtering,
universe registration, inherited-variable copying, replacement-reference
updates, and the non-existing-type script error. The target grows from 1164 to
1340 bytes and from 53 to 61 basic blocks while keeping the same branch order.

The evidence is in
`artifacts/spectron_script_object_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_object_anchors.py`. Both labels
were applied to a copy of v46 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v47.i64`. The database SHA-256 is
`42edc7d90f88906b11ed4949fbaae28e964c9be32093dbe4cf3e4fd7d17f8f3a`.

## Spectron GS2 script-state anchors

The v48 pass reviewed the profiling and player-flag methods following the
diagnostic and object helpers in the `mTAogaaEip` sequence.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_addTopCallStackProfileTime_TScript` | `0x21ea64` | `0x226eb4` | profiling gate, elapsed time, and call-stack join |
| `TScriptMachine_setPlayerFlagValue_TString_const_bool` | `0x21f03c` | `0x2274a8` | flag parsing and no-send player update |

`addTopCallStackProfileTime` preserves the profiling enable check, script and
machine guards, call-stack depth limit, elapsed-time accumulation, `=>` name
join, profiler callback, and temporary-string cleanup. The target grows from
304 to 332 bytes while retaining the same 12-block flow.

`setPlayerFlagValue` keeps splitting at `=`, defaulting to `1`, coercing a false
boolean to `0`, resetting the action and execution NPC roots, resolving the
player root through the legacy helper, and writing zero, one, or an arbitrary
string through no-send setters. The target grows from 720 to 728 bytes and
from 25 to 26 basic blocks.

The evidence is in
`artifacts/spectron_script_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_state_anchors.py`. Both labels were
applied to a copy of v47 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v48.i64`. The database SHA-256 is
`b8042ef8157620ff8e9acd00a875503a5e4e0255ae7ea5cfdae15b04f81c6801`.

## Spectron GS2 execution-dispatch anchors

The v49 pass reviewed the two large call-dispatch methods that follow the
profiling and player-flag helpers in the `mTAogaaEip` sequence.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_callScriptFunction_TGraalVar_TScriptFunction_int` | `0x21f80c` | `0x227c80` | script call, arguments, and suspended-state recovery |
| `TScriptMachine_functionCall_TString` | `0x21fd10` | `0x228164` | scripted, native, and download dispatch |

`callScriptFunction` retains the call-stack overrun guard, failed-call stack
restore, argument-array construction, script-space creation, function
invocation, returned-object capture, and cascaded-suspend recovery. The target
changes from 1284 to 1252 bytes and from 38 to 37 basic blocks.

`functionCall` retains current-callable lookup, scripted-function resolution,
direct versus object-context dispatch, waiting-for-download handling with
`onClassesDownloaded`, native-property dispatch through parameter preparation
and the C-function bridge, missing-function diagnostics, and failure stack
reset. The target changes from 1848 to 1936 bytes and from 79 to 78 blocks.

The evidence is in
`artifacts/spectron_execution_dispatch_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_execution_dispatch_anchors.py`. Both
labels were applied to a copy of v48 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v49.i64`. The database SHA-256 is
`258a6f0fe2afc8da9eba5b080e326cde15d0abbc8c70a918f098caa44adeda1b`.

## Spectron GS2 tokenizer anchor

The v50 pass reviewed `TScriptMachine_tokenizeString_void`.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_tokenizeString_void` | `0x220450` | `0x228900` | tokenizer and string-array construction |

The method consumes one stack entry, tokenizes its source string using the
delimiter field, returns a type-three null result when no tokens exist, and
otherwise allocates an array with one string variable per token. The target
keeps the same cleanup and result assignment, with twelve basic blocks in both
versions. Its body grows from 404 to 440 bytes around the changed string-list,
array, and variable wrappers.

The evidence is in
`artifacts/spectron_tokenizer_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tokenizer_anchors.py`. The label was
applied to a copy of v49 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v50.i64`. The database SHA-256 is
`3588a42c1687c12bf984df19af0c7e4d091df97174c7043785abb9a64c929e9b`.

## Spectron GS2 script executor anchor

The v51 pass reviewed `TScriptMachine_executeScript_void`, the large bytecode
execution loop at the end of the machine class.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_executeScript_void` | `0x2205e4` | `0x228ab8` | bytecode switch, limits, and helper dispatch |

Both versions decompile to the same large opcode switch and contain the exact
sentinels `Exceeded the string length limit`, `Loop limit exceeded`, and
`timeout`. Their cases dispatch through the reviewed function-call,
object-creation, string-formatting, string-search, tokenizer, and array
helpers, while preserving stack updates, loop-limit handling, and the same
executor tail. The target changes from 15,440 to 15,688 bytes and from 892 to
903 basic blocks.

The evidence is in
`artifacts/spectron_script_executor_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_executor_anchors.py`. The label
was applied to a copy of v50 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v51.i64`. The database SHA-256 is
`455a4e0bd55907163525dd3a91b3e7b718bd1b9737d19cbda39fd7c8b0271765`.

## Spectron GS2 script property anchors

The v52 pass reviewed the `TScriptProperty` layer that sits between the GS2
machine and the native property tables. This cluster is important because it
turns script values into native property calls and builds the property and
function tables used by the rest of the interpreter.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptProperty_readString_TGraalVar` | `0x224ac0` | `0x22d168` | typed string conversion and true or false literals |
| `TScriptProperty_writeFloat_TGraalVar_double` | `0x224cc4` | `0x22d390` | typed numeric conversion and readonly diagnostics |
| `TScriptProperty_writeString_TGraalVar_TString_const` | `0x2251b0` | `0x22d8c0` | text parsing for scalar, object, and string properties |
| `TScriptProperty_writeObject_TGraalVar_TGraalVar` | `0x2255f4` | `0x22dd6c` | Graal variable conversion and object forwarding |
| `TScriptProperty_TScriptProperty_TString_const_bool` | `0x225f68` | `0x22e86c` | name normalization and base initialization |
| `TScriptProperty_clone_void` | `0x226008` | `0x22e94c` | complete property metadata copy |
| `TScriptProperty_addProps_TProperties_TPropertyPropDef_int` | `0x2260dc` | `0x22ea1c` | property definition lookup and subclass creation |
| `TScriptProperty_setFunction_TProperties_char_TString_const_void_TString_const_bool` | `0x2264b4` | `0x22ef54` | scope prefixes and function metadata |
| `TScriptProperty_addFuncs_TProperties_TPropertyFuncDef_int` | `0x2266a8` | `0x22f148` | function definition lookup and registration |

The four typed accessors preserve the same property type table and the
separate universe-object calling convention. String reads retain boolean,
numeric, object, and string conversion. Float, string, and object writes keep
the same forwarding paths, small-value normalization, and read-only error
construction. The target bodies are larger, but the typed accessors retain
their source block counts of 29, 61, 43, and 61.

The constructor and clone preserve the base object layout and all accessor
metadata. The registration helpers keep the encoded and case-insensitive
lookup paths, lower unresolved names, choose the typed property subclasses,
and propagate the highest property scope. `setFunction` also retains the
`adventure_` and `tclient_` prefix checks. These details make the mappings
useful for reading the surrounding obfuscated code even though the target
names themselves are not readable.

The evidence is in
`artifacts/spectron_script_property_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_property_anchors.py`. All nine
labels were applied to a copy of v51 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v52.i64`. The database SHA-256 is
`b4ae7f8b981ded05bca5a811276aad0f9756ed2662b34d14d77befe7bd56b17d`.

## Spectron GS2 script universe anchors

The v53 pass reviewed the `TScriptUniverse` layer. This is the part of the
interpreter that owns global variables, static script objects, class scripts,
and the encrypted zipped-script package path.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptUniverse_writeString_TString_const` | `0x22b254` | `0x234c1c` | string value, numeric cache, and link reset |
| `TScriptExecutionStats_TScriptExecutionStats_TGraalVar` | `0x22b3ec` | `0x234dd0` | optional source variable and nested value creation |
| `TScriptUniverse_addStaticObject_TGraalVar` | `0x22b624` | `0x235010` | unknown-object filter and static list registration |
| `TScriptUniverse_TScriptUniverse_void` | `0x22b6e8` | `0x2350dc` | collection setup and players, npcs, allplayers objects |
| `TScriptUniverse_getClassAndCreate_TString_const_bool` | `0x22c260` | `0x235c48` | class lookup, creation, and gani scope rule |
| `TScriptUniverse_addClassScript_TString_const_TString_const` | `0x22cc88` | `0x2366ec` | class stream installation and onClassLoaded events |
| `TScriptUniverse_compileZippedScripts_TString_const` | `0x22cf78` | `0x236a60` | archive verification, decryption, and entry dispatch |
| `TScriptUniverse_addZippedScripts_TString_const_TSocketConnection` | `0x22cf98` | `0x236a80` | connector selection and script TLS metadata |

The global string setter retains the string type, text copy, numeric cache,
and link cleanup. The statistics constructor preserves the optional source
variable, nested value link, zeroed counters, and temporary-string cleanup.
The static-object path still ignores `unknown_object` for replacement, removes
an existing named object, initializes links, and lazily creates the hash list.

The universe constructor is especially useful for orientation in the target.
It creates the same collection lists and installs the `players`, `npcs`, and
`allplayers` static objects. Class lookup still applies the `gani::` privilege
rule and the optional encrypted load. Class installation still updates the
requested-class list, sets the stream when privileges permit, and invokes
`onClassLoaded` on both the universe and the class.

The zipped-script compiler retains the package header parsing, embedded RSA
and SHA-256 verification, RC4 payload decryption, zip iteration limits, and
the `.rk`, `.t`, `NPCS/`, and `CLASSES/` entry branches. IDA represents this
method as a split function. Its displayed entry range is only 32 bytes, while
the associated source and target function records contain 563 and 587
instructions. That boundary detail is kept in the machine-readable evidence
instead of being presented as the full body size. The package installer then
selects `StartScript_Connector` or `StartScript_Fail`, copies `scriptip`,
`scriptsslcipher`, `scriptsslsubject`, and `scriptsslissuer`, and requires
`onCreated` before enabling the connector.

The evidence is in
`artifacts/spectron_script_universe_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_universe_anchors.py`. All eight
labels were applied to a copy of v52 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v53.i64`. The database SHA-256 is
`a8b0e0611f2148be755691539ffa2cf6607c2ed00caf5ff6fe21f4ba2a1e5c80`.

## Spectron static, JSON, and tile anchors

The v54 pass reviewed three methods in the next native cluster. They cover
static script-variable construction, recursive `TGraalVar` JSON output, and
tile-definition persistence.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TStaticVar_TStaticVar_TString_const` | `0x22d3dc` | `0x236ea0` | universe registration and list links |
| `TGraalVar_writeJSONObject_yajl_gen_t_bool` | `0x22e378` | `0x237ec8` | scalar, array, object, and YAJL type branches |
| `TTiles_SaveTileDefinitions_void` | `0x22f32c` | `0x238f48` | levels/tiledefs path and five-field rows |

The static-variable constructor keeps the initialized flag, static properties,
global-universe link, and universe count increment. The JSON writer retains the
same special-property filters for `initialized`, `actionplayer`, `name`, and
`unknown_object`, then emits booleans, strings, numbers, objects, arrays, or
null values through the corresponding YAJL calls. Its four distinctive
literals, including `xmlname`, remain in the target.

The tile saver still clears the pending-save flag, builds a server-specific
`levels/tiledefs` filename, serializes each definition as five comma-separated
fields, creates the directory, and saves the string list. All three target
functions preserve the source basic-block count. The target sizes change from
180 to 224 bytes for the constructor, 1692 to 1816 bytes for the JSON writer,
and 944 to 976 bytes for the tile saver, which is consistent with rebuilt
string and container wrappers rather than a byte-identical build.

The evidence is in
`artifacts/spectron_static_json_tiles_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_static_json_tiles_anchors.py`. All three
labels were applied to a copy of v53 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v54.i64`. The database SHA-256 is
`01d1833774b599fec7dc4279614dd09e0cf51ccc82ec21beed38c2e532559fec`.

## Spectron tile update and draw anchors

The v55 pass followed the static and JSON methods into the main tile update
cluster and the screen renderer.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TTiles_UpdateTempTiles_TString_const` | `0x22f6f4` | `0x239330` | stale and missing temporary tiles |
| `TTiles_GetLevelTiles_TString_const` | `0x22fb48` | `0x2397a0` | matching level tileset and tile type |
| `TTiles_UpdateTiles_void` | `0x22fc98` | `0x239944` | tileset comparison and buffer reset |
| `TTiles_AddTileDefinition_TString_const_TString_const_int_int_int` | `0x22fdb8` | `0x239a80` | definition replacement and dirty flag |
| `TTiles_isTilesImage_TString_const` | `0x230040` | `0x239d6c` | normalized image scan |
| `TTiles_LoadTileDefinitions_void` | `0x230244` | `0x239f8c` | levels/tiledefs parsing and rebuild |
| `TTiles_updateAnimatedTiles_TPlayer_TString_const` | `0x2306fc` | `0x23a598` | 4096-cell visible repaint |
| `TTilesPanel_drawTilesOnScreen_int_int` | `0x231bb4` | `0x23bb2c` | Draw_Tiles grid renderer |

The source and target pseudocode agree on the core tile state transitions.
`UpdateTempTiles` reconciles filenames and dimensions, removes stale entries,
adds missing ones, and refreshes texture sizes. `GetLevelTiles` selects the
matching tile definition and updates the tile type. `UpdateTiles` compares the
active level's selection, invokes the temporary-tile pass, and resets the
player buffer when a change occurs.

The definition insertion and loader retain the same seven-field records and
the `levels/tiledefs` file format. The target intentionally raises the
insertion guard from 9999 to 999999 entries. The animated-tile method still
scans 4096 cells and repaints matching visible cells. The renderer uses the
target's newer graphics operations instead of the original vertex-array
sequence, but it keeps the login guard, `Draw_Tiles` profiler marker,
64-pixel grid, transparent-tile skip, and black-tile path.

The evidence is in
`artifacts/spectron_tiles_update_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tiles_update_anchors.py`. All eight labels
were applied to a copy of v54 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v55.i64`. The database SHA-256 is
`b9957326c9871659765825261e9990b9ac3db2d42d632aa180db0fc47fb85417`.

## Spectron particle-data anchors

The v56 pass followed the tile cluster into five `TParticleDataEx` methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TParticleDataEx_getAnimation_void` | `0x232e64` | `0x23cc14` | gani name and optional animation parameter |
| `TParticleDataEx_setPlayerLook_bool` | `0x2331a8` | `0x23cf70` | player appearance defaults and colors |
| `TParticleDataEx_copyFromTemplate_TParticleDataEx` | `0x2337ec` | `0x23d564` | particle and gani state copy |
| `TParticleDataEx_setCodedPolygon_TString_const` | `0x233f08` | `0x23dca0` | coded polygon field parsing |
| `TParticleDataEx_setTexturedCodedPolygon_TString_const` | `0x233fe0` | `0x23dd7c` | texture field and polygon setup |

These methods preserve their source block counts and their key field offsets.
The getter builds the same full gani name and optional parameter. The
player-look path restores `sword1.png`, the default body and head, `shield1.png`,
and five named colors plus color index 18 when disabling player-look. Template
copying carries over the same animation, direction, look state, four appearance
strings, and six colors.

The coded polygon methods still normalize the first field to type 2 or 3,
remove the type field, and create a temporary variable from the remaining
values. The textured form additionally copies the second field to the gani
texture slot before removing it. The target grows or shrinks only through
rebuilt string-list and string-wrapper calls, from 232 to 256 bytes for the
getter, 396 to 316 for player-look, 380 to 412 for template copy, 216 to 220
for the plain polygon setter, and 276 to 280 for the textured setter.

The evidence is in
`artifacts/spectron_particle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_particle_anchors.py`. All five labels were
applied to a copy of v55 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v56.i64`. The database SHA-256 is
`592fc346da450b304540618a4c14f8ab1a0cff048e4efc59acb3a5fb33a147d0`.

## Spectron TShowImg serialization anchors

The v57 pass reviewed the three remaining unmatched `TShowImg` methods that
encode visual-object state for scripts and the network path.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TShowImg_readString_void` | `0x2349e0` | `0x23e7d0` | mode switch and wire prefixes |
| `TShowImg_writeString_TString_const` | `0x236b8c` | `0x240a14` | prefix dispatch plus ATTR/PARAM |
| `TShowImg_getNetProperty_TServerPlayer_int` | `0x2372d8` | `0x241154` | property-index wire encoder |

`readString` preserves the mode-specific format: `@` for text, `#` for a
polygon, `%` for a textured polygon, and `&` for an animation. The same method
retains the image-part and parameter branches, including the five-value
encoding loop. `writeString` reverses that format by dispatching to the text,
polygon, textured-polygon, animation, sprite, or image handlers and checking
the `ATTR` and `PARAM` prefixes.

`getNetProperty` keeps the indexed encoder for image name, coordinates, image
part, alpha, color, speed, rotation, and layer values. The target still uses
player-relative coordinates for the low property indexes, clamps numeric
values into the same one-byte range, and returns the encoded string through
the caller buffer. Its one extra basic block and 32-byte size increase are
consistent with rebuilt wrapper calls rather than a changed property table.

The evidence is in
`artifacts/spectron_showimg_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_showimg_anchors.py`. All three labels were
applied to a copy of v56 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v57.i64`. The database SHA-256 is
`4ea4e394195d1d7218b67c4e86c8edd45e68ebd0db4b38f3d948f6ae1f60b79c`.

## Spectron particle-emitter anchors

The v58 pass reviewed the two remaining unmatched particle-emitter methods
that initialize particle metadata and create particles during an emission
step.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TParticleEmitter_initStaticVars_void` | `0x23b274` | `0x245114` | complete static variable and modifier lists |
| `TParticleEmitter_emit_T3DFloatPoint_const_uint_bool` | `0x23b394` | `0x245240` | same guarded emission state machine |

The static initializer preserves the lifetime, variable, and modifier lists
exactly, including the `once`, `impulse`, `range`, `replace`, `add`, and
`multiply` entries. The emission routine keeps the same owner and capacity
checks, `Particles_Emit` profiler marker, random-template selection, particle
reuse, kinematic setup, modifier application, optional sound, and final add.
The matching one-block and 44-block shapes make these high-confidence
class-local anchors despite small wrapper changes.

The evidence is in
`artifacts/spectron_particle_emitter_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_particle_emitter_anchors.py`. Both labels
were applied to a copy of v57 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v58.i64`. The database SHA-256 is
`0a3ede671e58cb9a2585eb3388aff048d44ddd5588f1fa674ea4e6bc718003be`.

## Spectron particle-emitter script-property initializer

The v186 pass resolves the remaining particle-emitter static initializer for
script-property metadata. This is distinct from the earlier list initializer:
it constructs the two property objects that expose `TParticleModifier` and
`TParticleEmitter` fields to GS2.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TParticleEmitter_initStaticScriptVars_void` | `0x23b348` | `0x2451f4` | `_Z10L7ezIahlg6v` | exact normalized match |

The source function allocates `TParticleModifierProperties` and
`TParticleEmitterProperties`. The target allocates the corresponding
`ULeBJaZ1WYProperties` and `pdnkJaZ8KKProperties` objects and stores them in
`ULeBJaZ1WYOnln2aNBfC` and `pdnkJaZ8KKOnln2aNBfC`. Those target classes were
already tied to the source property classes by their independently translated
constructors, which makes this stronger than a shape-only match.

Both functions are one-block, 76-byte, 19-instruction initializers with five
branches, four calls, one return, and identical mnemonic, opcode-shape,
register-shape, normalized-shape, and string-reference hashes. The target
function follows the translated list initializer at `0x245114` and precedes
the translated emission method at `0x245240`. The source and target
static-initializer table references are `0x36f068` and `0x383fc8`.

An earlier search candidate at target `0xe0564` was rejected. It has the same
coarse allocation pattern, but constructs generic `KKhLga4xoI` objects owned
by `OOmzgapOmy` and `H4zIGaBY6x`, not the particle-property classes. Keeping
that rejection in the record prevents a convenient hash collision from being
mistaken for a translation.

The evidence is in
`artifacts/spectron_particle_emitter_script_vars_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_particle_emitter_script_vars_anchors.py`. The alias
reopened successfully in
`analysis/spectron_libqplay_translated_v186.i64`. The full semantic reopen
check still reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,233 default `sub_` names. The v186 database
SHA-256 is
`c26614cddb2d45084daed23699bf9eef3d45ef8fe86b4c0214eaf535d267bf5a`.

## Spectron TClient static-string initializer

The v196 pass resolves source `sub_E0A2C` to target `sub_E1118` by following
the static-initializer slots, the complete eleven-field order, and the
independently translated cleanup pair. The target class name is obfuscated as
`w6qzgacqqy`; its existing client reset, connection, script, and cleanup
methods establish that this is the Spectron `TClient` family.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TClient` static-string initializer | `0xe0a2c` | `0xe1118` | `sub_E1118` | layout change |

The source callback is referenced by static-initializer table slot `0x35d298`.
It clears eleven string globals in this order: `serverlevelname`,
`bigfilename`, `lastdownloadfile`, `serverwarpdestination`, `lastserverwarp`,
`requestedmapwarp`, `ghostmessage`, `disconnectreason`,
`currentdownloadfile`, `currentdownloadpackage`, and `loginaccountname`.
The source cleanup callback `TClient_clearStaticStrings` at `0xe05ec`, in
cleanup-table slot `0x35d2e8`, clears the same field set.

Spectron places the corresponding callback in target slot `0x36fb40`.
`sub_E1118` clears the same eleven fields in the same order under
`w6qzgacqqy`, at target addresses `0x3a3748` through `0x3a3678` as recorded
in the artifact. It also initializes target-only `qword_3A3670` through
`CanTfaz6bZ::operator=(const char *)`. The already translated target cleanup
`v18_TClient_clearStaticStrings` at `0xe0128`, in slot `0x36ff18`, clears the
eleven shared fields and then clears that additional string.

The source row is 136 bytes and 34 instructions in one basic block, with one
branch, no direct calls, and one return. The target row is 176 bytes and 44
instructions in one block, with two branches, one direct string-assignment
call, and one return. The extra target string lifetime explains the layout
change while the field order and class-local cleanup relationship preserve
the original role.

The reviewed alias is `v18_TClient_initializeStaticStrings`. It reopened
successfully in
`analysis/spectron_libqplay_translated_v196.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,223 default `sub_` names. The v196 database
SHA-256 is
`7f640cdd78f40b66d562676e6f5525dbab9586981b1a08dccf97fe0db28e8bad`.

The machine-readable record is
`artifacts/spectron_tclient_static_strings_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tclient_static_strings_anchors.py`. The alias only
changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron TSocket static-string initializer

The v197 pass resolves source `sub_E0AB4` to target `sub_E12DC` by following
the adjacent static-initializer tables, both shared socket fields, and the
independently translated cleanup pair. The target class name is obfuscated as
`XJLBgarMnA`, which is already established as the Spectron `TSocket` family.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TSocket` static-string initializer | `0xe0ab4` | `0xe12dc` | `sub_E12DC` | layout change |

The source callback is referenced by static-initializer table slot `0x35d2a0`.
It clears `data_TSocket_allowedsocketsconnect` at `0x390b18` and
`data_TSocket_allowedportsbind` at `0x390b10`, returning the address of the
second field. The source cleanup callback `TSocket_clearStaticStrings` at
`0xe0680`, in cleanup-table slot `0x35d2f0`, calls the native string clear
helper on those same fields.

Spectron places the corresponding callback in target slot `0x36fb88`.
`sub_E12DC` clears `XJLBgarMnA::DcjBgagM_z` at `0x3a4db8` and
`XJLBgarMnA::gwjBgaP1_z` at `0x3a4db0`, returning the latter address. It also
initializes target-only `qword_3A4D90` as a `CanTfaz6bZ` string. The translated
target cleanup `v18_TSocket_clearStaticStrings` at `0xe0258`, in slot
`0x36ff60`, clears the two shared fields and then that extra string.

The source row is 28 bytes and 7 instructions in one basic block, with one
branch, no direct calls, and one return. The target row is 68 bytes and 17
instructions in one block, with two branches, one direct string-assignment
call, and one return. The added target string lifetime explains the layout
change. Both rows have no literal string references, and the data-field and
cleanup evidence provides the role match that the raw shape alone could not.

The reviewed alias is `v18_TSocket_initializeStaticStrings`. It reopened
successfully in
`analysis/spectron_libqplay_translated_v197.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,222 default `sub_` names. The v197 database
SHA-256 is
`8be87e35fedd96c6961e725a5b8f12de9e381a1e25abb35fd6193e64c404002d`.

The machine-readable record is
`artifacts/spectron_tsocket_static_state_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_tsocket_static_state_anchors.py`. The alias only
changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron Android, TapJoy, and video state callbacks

The v198 pass resolves the source callback that was previously mistaken for a
`TServerFlying` cleanup. It pairs the source reset at `0xe0ad0` with target
`sub_E1640`, and the source cleanup at `0xe06a8` with target `sub_E0438`.
The target global block is consumed by the translated JNI, TapJoy, and video
methods, so this is a component-level Android runtime match rather than a
class guess based on address proximity.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| Android/TapJoy/video state initializer | `0xe0ad0` | `0xe1640` | `sub_E1640` | layout change |
| Android/TapJoy/video state cleanup | `0xe06a8` | `0xe0438` | `sub_E0438` | layout change |

The source initializer is registered at `0x35d2a8` and clears the Android
TapJoy strings at `0x391210` and `0x391218`, the video state string at
`0x391238`, and the rectangle coordinates at `0x391228..0x391234`. The source
cleanup is registered at `0x35d2f8` and clears the three string objects. The
TapJoy fields are written by the `MainAndroid_script_settapjoysecret` and
`MainAndroid_script_settapjoyapplicationid` callbacks and read by
`JNI_connectToTapJoyService`. The video and rectangle fields are consumed by
the video callbacks, `openVideoPlayer`, `isVideoPlayerOpen`, and the JNI render
loop.

Spectron registers the reset at `0x36fc88` and the cleanup at `0x370060`.
`sub_E1640` zeros `qword_3A58D8`, `qword_3A58E0`, `qword_3A5920`, and
`dword_3A5908..0x3a5914`, which map to the source fields in the artifact.
The target cleanup `sub_E0438` clears those three target string fields and an
additional `qword_3A59C8` object. The reset initializes that extra object
through `CanTfaz6bZ::operator=(const char *)`, which is the direct reason the
target rows grow from 40 to 76 bytes for the reset and from 48 to 56 bytes for
the cleanup.

The target `dword_3A58D0` reference in the reset is only an address base used
to reach the grouped fields. It is not a fourth shared state store. Keeping it
separate avoids confusing an addressing artifact with a translated field.

This pass also resolves the earlier correction record. The source
`TServerFlying::animate` method at `0x23eeb0` has no references to the cleared
group, while the known `TServerFlying` property object is separate. The
reviewed aliases are `v18_MainAndroid_initializeStaticState` and
`v18_Android_TapJoy_video_clearStaticStrings`. Both reopened successfully in
`analysis/spectron_libqplay_translated_v198.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,220 default `sub_` names. The v198 database
SHA-256 is
`8f0f2b7d7ef3593c95316c88c8ca5c9b7b9e1a1481cdf9da8bc9e02adcfb1ee3`.

The machine-readable record is
`artifacts/spectron_android_tapjoy_video_state_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_android_tapjoy_video_state_anchors.py`. The aliases
only change the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron TSounds music-state wrappers

The v199 pass resolves three source `TSounds` wrappers that the broad feature
matcher had correctly left ambiguous. Their target bodies are in the
obfuscated `IUKzgam4Gy` sound cluster and use the same sound-player global,
null fallback, and virtual-table slots as the source.

| 1.8 role | Source | Spectron target | Target name before alias | Vtable slot | Classification |
| --- | ---: | ---: | --- | ---: | --- |
| `TSounds_isMusicPlaying` | `0xe0af8` | `0xe16a8` | `sub_E16A8` | `+56` | exact normalized shape |
| `TSounds_getMusicPos_void` | `0xe0b3c` | `0xe16ec` | `_ZN10IUKzgam4Gy10HTzYZaBOzKEv` | `+80` | exact normalized shape |
| `TSounds_getMusicLen_void` | `0xe0b7c` | `0xe172c` | `_ZN10IUKzgam4Gy10cR7XZakdcKEv` | `+88` | exact normalized shape |

The source `isMusicPlaying` body reads `TSounds::soundplayer` and calls the
address-point-adjusted virtual slot at `+56`. Its callback-table reference is
at `0x376198`, while the corresponding target reference is at `0x3891b0`.
The source position and length wrappers both return `-1.0` when the player is
absent, then call the `+80` and `+88` slots respectively. Their source table
references are `0x376058` and `0x376088`; the target references are
`0x389058` and `0x389088`.

The ambiguity is useful evidence rather than a problem to hide. The boolean
shape also occurs at target `0x159304` and `0x159d88`, but those bodies read
mainwindow and weapons state. The two float shapes occur together at
`0xe16ec` and `0xe172c`, and the virtual slot plus callback-table order
separates position from length. All three source and target rows have the
same normalized size, instruction, block, branch, call, return, mnemonic,
opcode, register-shape, overall-shape, and string-reference fingerprints. The
register-detail fingerprint is the only recorded difference for each row.

The reviewed aliases are `v18_TSounds_isMusicPlaying`,
`v18_TSounds_getMusicPos_void`, and `v18_TSounds_getMusicLen_void`. All three
reopened successfully in `analysis/spectron_libqplay_translated_v199.i64`.
The full semantic reopen check reports zero failures across 11,694 functions,
with 3,641 high-confidence labels and 1,219 default `sub_` names. The v199
database SHA-256 is
`023b4f6f9254d607adb9aafe0936eb3da608dad6049688446d5496a76a6a9148`.

The machine-readable record is
`artifacts/spectron_sounds_music_state_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_sounds_music_state_anchors.py`. The
aliases only change the persisted IDA analysis copy. No APK or native library
was modified.

## Spectron TSoundEffect constructor and cache lookup

The v200 pass resolves the source sound-effect constructor and the
case-insensitive cache lookup. The constructor belongs to Spectron's
obfuscated `fEVMgax6LJ` object family, while the lookup belongs to the
`IUKzgam4Gy` sound-effects cache.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TSoundEffect_TSoundEffect_TString_const` | `0xe0dc0` | `0xe1970` | `_ZN10fEVMgax6LJC2ERK10C8THgaTQxF` | layout change |
| `TSounds_getSoundEffect_TString_const` | `0xe0e48` | `0xe1a1c` | `_ZN10IUKzgam4Gy10adFVZaKh7HERK10C8THgaTQxF` | exact normalized shape |

The source constructor lowercases the filename, constructs the hash-list base,
clears its temporary string, installs the sound-effect vtable, copies the
original filename, and initializes the playback fields. Spectron performs
the same sequence through `C8THgaTQxF`, `J7zOgaf09K`, and `wiULgacZUI`, then
constructs and clears a target-only `CanTfaz6bZ` helper. The target
`fEVMgax6LJ` method family at `0xe3714..0xe3744` and the Java constructor at
`0xe4098` independently confirm the class role.

The source lookup reads the `TSounds::soundeffects` hash list, lowercases the
requested filename, computes its hash, performs a case-insensitive lookup,
and clears the temporary string. Spectron reads
`IUKzgam4Gy::fqEVZaFC6H` and performs the same sequence through its
obfuscated hash-list helpers. The returned object is the `fEVMgax6LJ` family
constructed by the adjacent target constructor.

The constructor grows from 136 to 172 bytes and from four to six direct calls
because of the target-only helper-string lifetime. The lookup keeps the same
normalized size, instruction, block, branch, call, return, opcode, register
shape, overall-shape, and string-reference fingerprints; only its
register-detail fingerprint and obfuscated direct-call names differ. The
reviewed aliases are `v18_TSoundEffect_TSoundEffect_TString_const` and
`v18_TSounds_getSoundEffect_TString_const`. Both reopened successfully in
`analysis/spectron_libqplay_translated_v200.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,219 default `sub_` names. The v200 database
SHA-256 is
`604ebbe701eca3e90de161f10ac01d8bcbbd201f6ae5761bd0eefcc0c0294df3`.

The machine-readable record is
`artifacts/spectron_sounds_effect_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_sounds_effect_anchors.py`. The aliases
only change the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron TSounds volume and music-update control wrappers

The v201 pass resolves the remaining short sound control callbacks. The
script-facing volume wrapper is an exact feature match, while the native
music-update wrapper is separated from the already translated stop-MIDI
method by its callback-table entry and sound-player virtual slot.

| 1.8 role | Source | Spectron target | Target name before alias | Virtual slot | Classification |
| --- | ---: | ---: | --- | ---: | --- |
| `TSounds_setMusicVolume` | `0xe1350` | `0xe1f28` | `sub_E1F28` | callback forwarding | exact feature match |
| `TSounds_updateMusic_void` | `0xe1888` | `0xe2470` | `_ZN10IUKzgam4Gy10EEuMgaWopJEv` | `+48` | exact normalized shape |

The source volume callback is referenced from the `setmusicvolume` record at
`0x376240` and forwards two script doubles to
`TSounds_setMusicVolume_double_double`. Spectron's corresponding record is at
`0x389240` and forwards the same arguments to
`IUKzgam4Gy::hPTMgaJzKJ`. Every recorded feature agrees for this row.

The source `updateMusic_void` body returns the sound-player global when it is
null and otherwise invokes virtual slot `+48`. The target
`IUKzgam4Gy::EEuMgaWopJ` body has the same behavior and slot. The callback
references are `0x36e748` in the source and `0x387060` in Spectron. This
separates it from target `0xe1c34`, the translated stop-MIDI method, which
uses the same compact normalized shape but invokes virtual slot `+72`.

The reviewed aliases are `v18_TSounds_setMusicVolume` and
`v18_TSounds_updateMusic_void`. Both reopened successfully in
`analysis/spectron_libqplay_translated_v201.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,218 default `sub_` names. The v201 database
SHA-256 is
`17db3651520fac5f9ef448f8b70be215cc6c1c36255ffa0aa21f65436a032c03`.

The machine-readable record is
`artifacts/spectron_sounds_control_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_sounds_control_anchors.py`. The aliases
only change the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron Java sound base interface methods

The v205 pass resolves the remaining short methods in the Java sound
interface. Fourteen source `TSoundPlayer` base methods line up with the
contiguous `gqiNgaG64J` target table. The two Java sound-effect capability
methods line up with `QPh5pbnC3y`, and the two Java sound-player capability
methods line up with `ohGYZakbFK`.

| 1.8 role | Source | Spectron target | Target name before alias | Source table | Target table |
| --- | ---: | ---: | --- | ---: | ---: |
| `TSoundPlayer_canPlayMusic_void` | `0xe3544` | `0xe410c` | `_ZN10gqiNgaG64J10jfRMgatpIJEv` | `0x35ed00` | `0x371a80` |
| `TSoundPlayer_playMusic_TString_const_bool_int` | `0xe354c` | `0xe4114` | `_ZN10gqiNgaG64J10IWJMga2fCJERK10C8THgaTQxFbi` | `0x35ed08` | `0x371a88` |
| `TSoundPlayer_updateMusic_void` | `0xe3550` | `0xe4118` | `_ZN10gqiNgaG64J10EEuMgaWopJEv` | `0x35ed10` | `0x371a90` |
| `TSoundPlayer_isMusicPlaying_void` | `0xe3554` | `0xe411c` | `_ZN10gqiNgaG64J10fXZMgaqJPJEv` | `0x35ed18` | `0x371a98` |
| `TSoundPlayer_stopMusic_void` | `0xe355c` | `0xe4124` | `_ZN10gqiNgaG64J10wNLMganPDJEv` | `0x35ed20` | `0x371aa0` |
| `TSoundPlayer_stopMidi_void` | `0xe3560` | `0xe4128` | `_ZN10gqiNgaG64J10xcTMgag3JJEv` | `0x35ed28` | `0x371aa8` |
| `TSoundPlayer_getMusicPosition_void` | `0xe3564` | `0xe412c` | `_ZN10gqiNgaG64J10uUwHEa8heREv` | `0x35ed30` | `0x371ab0` |
| `TSoundPlayer_getMusicLength_void` | `0xe356c` | `0xe4134` | `_ZN10gqiNgaG64J10CV8GEac7UQEv` | `0x35ed38` | `0x371ab8` |
| `TSoundPlayer_setMusicVolume_int` | `0xe3574` | `0xe413c` | `_ZN10gqiNgaG64J10hPTMgaJzKJEi` | `0x35ed40` | `0x371ac0` |
| `TSoundPlayer_setMusicVolumeAndPan_int_int` | `0xe3578` | `0xe4140` | `_ZN10gqiNgaG64J10cqUMgaI4KJEii` | `0x35ed48` | `0x371ac8` |
| `TSoundPlayer_setMidiVolume_int` | `0xe357c` | `0xe4144` | `_ZN10gqiNgaG64J10Gg4GEaGcRQEi` | `0x35ed50` | `0x371ad0` |
| `TSoundPlayer_canPlaySoundEffects_void` | `0xe3580` | `0xe4148` | `_ZN10gqiNgaG64J10UtswgaQzVvEv` | `0x35ed58` | `0x371ad8` |
| `TSoundPlayer_createSoundEffect_TString_const` | `0xe3588` | `0xe4150` | `_ZN10gqiNgaG64J10ngWMganDMJERK10C8THgaTQxF` | `0x35ed60` | `0x371ae0` |
| `TSoundPlayer_set3DPosition_T3DFloatPoint_const_T3DFloatPoint_const_T3DFloatPoint_const_T3DFloatPoint_const` | `0xe3590` | `0xe4158` | `_ZN10gqiNgaG64J10nQlWHaFZHzERK10V6P7faBscbS2_S2_S2_` | `0x35ed68` | `0x371ae8` |
| `TSoundEffectJava_isLoaded_void` | `0xe3594` | `0xe415c` | `_ZN10QPh5pbnC3y10tDfwgaPLKvEv` | `0x35ee50` | `0x371bd0` |
| `TSoundEffectJava_hasChannel_void` | `0xe359c` | `0xe4164` | `_ZN10QPh5pbnC3y10pTqwgajeUvEv` | `0x35ee60` | `0x371be0` |
| `TSoundPlayerJava_canPlayMusic_void` | `0xe35a4` | `0xe416c` | `_ZN10ohGYZakbFK10jfRMgatpIJEv` | `0x35eda0` | `0x371b20` |
| `TSoundPlayerJava_canPlaySoundEffects_void` | `0xe35ac` | `0xe4174` | `_ZN10ohGYZakbFK10UtswgaQzVvEv` | `0x35edf8` | `0x371b78` |

The source base class returns zero for `canPlayMusic`,
`isMusicPlaying`, and `canPlaySoundEffects`; returns `-1.0` for music
position and length; returns zero for the sound-effect factory; and leaves
the other base hooks empty. The target `gqiNgaG64J` methods preserve those
same stubs in the same table order. The `QPh5pbnC3y` loaded predicate returns
one and its channel predicate reads the byte at `this + 48`, while the two
`ohGYZakbFK` capability predicates return one, exactly matching the source
Java implementations.

All 18 rows match the complete normalized feature record, including register
detail. None has literal string references or direct calls. The method-table
records provide the class and overload-order evidence needed for these very
short functions. All 18 aliases reopened successfully in
`analysis/spectron_libqplay_translated_v205.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,218 default `sub_` names. The v205 database
SHA-256 is
`cc2ce413b073ec7735a890074a7fc6870bf4baba838a7594d49e12c91a01e143`.

The machine-readable record is
`artifacts/spectron_sound_base_interface_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sound_base_interface_anchors.py`. The aliases only
change the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron GuiTextListCtrl method family

The v209 pass resolves eight short list-control methods that fall below the
normal 32-byte semantic-matcher threshold. The target pseudocode identifies
the same obfuscated `u0eyga1eqx` class for every row, and the feature export
matches every recorded field.

| Source role | Source | Spectron target | Target name before alias | Source context | Target context |
| --- | ---: | ---: | --- | ---: | ---: |
| `GuiTextListCtrl_getCellSize_TPoint` | `0x1d8fec` | `0x1ddd28` | `_ZN10u0eyga1eqx10H8ZnobYTN7ER10eY2wgaf6pw` | `0x367298`, `0x3687f8` | `0x37a068`, `0x37b5c8` |
| `GuiTextListCtrl_set_sortcolumn` | `0x1dc960` | `0x1e06fc` | `sub_1E06FC` | `0x383698` | `0x3966f8` |
| `GuiTextListCtrl_script_clearrows` | `0x1de504` | `0x1e22a0` | `sub_1E22A0` | `0x383758` | `0x3967b8` |
| `GuiTextListCtrl_script_sort` | `0x1de6c8` | `0x1e2464` | `sub_1E2464` | `0x383c98` | `0x396cf8` |
| `GuiTextListCtrl_sort_int_bool` | `0x1de6dc` | `0x1e2478` | `_ZN10u0eyga1eqx4sortEib` | `0x22510` | `0x1c428` |
| `GuiTextListCtrl_sortNumerical_int_bool` | `0x1de6f8` | `0x1e2494` | `_ZN10u0eyga1eqx10_ThCQaUFPSEib` | `0x2c350` | `0x210a8` |
| `GuiTextListCtrl_script_removerowbyid` | `0x1df564` | `0x1e33a8` | `sub_1E33A8` | `0x383ab8` | `0x396b18` |
| `GuiTextListCtrl_addColumnOffset_int` | `0x1df690` | `0x1e34d4` | `_ZN10u0eyga1eqx10_jHwgaC36vEi` | `0x374008` | `0x382ea8` |

The cell-size getter reads the value at receiver offset `+472` and writes it
to the result point. The sort-column setter writes `+552`. The clear-rows and
remove-row wrappers use the guard byte at `+204`, and the default sort wrapper
initializes the sort mode at `+540` before calling the common sort routine.

The text sort overload stores mode 2 at `+540`, the inverted direction at
`+544`, and the column at `+552`. The numerical overload uses mode 1 with the
same direction and column fields. The column-offset helper loads the list at
`+520` and appends the supplied integer. These receiver offsets and the
class-local call relationships agree between the two builds.

All eight pairs are exact across size, instruction count, basic-block count,
branch count, call count, return count, mnemonic hash, opcode shape, register
shape, register detail, overall shape, and string-reference hash. The four
target `sub_` names are the rows where the stripped target did not retain an
ABI spelling. The applied aliases use the `v18_` prefix and reopened
successfully in `analysis/spectron_libqplay_translated_v209.i64`. The database
has 11,694 functions, 3,641 high-confidence semantic labels, and 1,213
default `sub_` names. Its SHA-256 is
`9689b137d9e9688ad7669f531ecde91308d812390dc493a2434ba5b22c6a4f4a`.
The machine-readable record is
`artifacts/spectron_gui_text_list_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_gui_text_list_anchors.py`. No APK or
native library was modified.

## Spectron hash-container lifecycle family

The v210 pass resolves six short hash-container helpers that the broad
semantic matcher did not label automatically. The source and target bodies
retain the same normalized control-flow shape, and the target ABI names place
the methods in the corresponding obfuscated hash-container class clusters.

| Source role | Source | Spectron target | Target name before alias | Source context | Target context |
| --- | ---: | ---: | --- | ---: | ---: |
| `THashListObject_THashListObject_TString_const` | `0xea424` | `0xeb010` | `_ZN10J7zOgaf09KC2ERK10CanTfaz6bZ` | `0x3713e8` | `0x386b08` |
| `THashListLink_THashListLink_THashListObject_uint` | `0xea440` | `0xeb02c` | `_ZN10U1slUah2F0C2EP10J7zOgaf09Kj` | `0x36df88` | `0x386f70` |
| `THashString_setValue_TString_const` | `0xeada4` | `0xeb9f0` | `_ZN10NYF9TaOVKR10juVsfa5YWCERK10C8THgaTQxF` | `0x372ee0` | `0x381e28` |
| `THashListIterator_THashListIterator` | `0xeb6c0` | `0xec3ec` | `_ZN10R_MvgaEQlvD1Ev` | `0x36f9b8` | `0x384d70` |
| `THashListIterator_THashListIterator_THashList` | `0xeba5c` | `0xec7f8` | `_ZN10R_MvgaEQlvC2EP10KKhLga4xoI` | `0x3724f8` | `0x385400` |
| `THashStringsIterator_use_THashStrings` | `0xebdb4` | `0xecb58` | `_ZN10Zb7cUaSFEU10q_90ua70AIEP10yL3_IaDMFt` | `0x36e880` | `0x382568` |

The `THashListObject` constructor installs the object vtable, clears the
embedded string field at `+8`, and assigns the incoming string. Its target
counterpart is `J7zOgaf09K`, whose displayed C2 name has a C1 alternative ABI
name. The link constructor stores the object pointer, bucket index at `+24`,
and nulls the two link pointers at `+8` and `+16`. The `THashString` setter is
a direct assignment to its value field at `+8`.

The source iterator row at `0xeb6c0` has the alternative ABI name
`THashListIteratorD2`, so the constructor-shaped display name is a complete
destructor. Its target `R_MvgaEQlvD1Ev` counterpart has the same null-owner
guard and unregisters the iterator from the owning `KKhLga4xoI` list. The
iterator constructor clears its owner and calls the class-local use helper.
The final row stores the `yL3_IaDMFt` container, clears the iterator link,
initializes the bucket index to `-1`, and finds the next object immediately.

All six rows have no literal string references or direct calls in the feature
export. Five match every recorded field, including register detail. The
`THashListObject` constructor matches size, instruction count, basic blocks,
branches, calls, returns, mnemonic, opcode, register shape, overall shape,
and string-reference hash; only `register_detail_hash` differs. That
difference is recorded as a rebuilt register-allocation detail, not as a
behavioral mismatch. The target classes are the short helper types used by
the `KKhLga4xoI` and `yL3_IaDMFt` container families.

The six aliases use the `v18_` prefix and reopened successfully in
`analysis/spectron_libqplay_translated_v210.i64`. The database has 11,694
functions, 3,641 high-confidence semantic labels, and 1,213 default `sub_`
names. Its SHA-256 is
`b4bb37f4af6e3ce32f71329de3d3292f4620b84f380d5f2726a1626161bd739a`. The
machine-readable record is
`artifacts/spectron_hash_lifecycle_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_hash_lifecycle_anchors.py`. No APK or
native library was modified.

## Spectron GuiTextListEntry property family

The v211 pass resolves three short property helpers that the broad semantic
matcher did not label automatically. Their Hex-Rays pseudocode is identical
between the two builds, and the source and target references occupy the
corresponding property-table callback slots.

| Source role | Source | Spectron target | Target name before alias | Source context | Target context |
| --- | ---: | ---: | --- | ---: | ---: |
| `GuiTextListEntry_get_flickertime` | `0x1dc84c` | `0x1e05e8` | `sub_1E05E8` | `0x383150` | `0x3961b0` |
| `GuiTextListEntry_set_flickertime` | `0x1dc85c` | `0x1e05f8` | `sub_1E05F8` | `0x383158` | `0x3961b8` |
| `GuiTextListEntry_get_profile` | `0x1dc894` | `0x1e0630` | `sub_1E0630` | `0x383270` | `0x3962d0` |

The flickertime getter returns whether the float at receiver offset `+144` is
nonzero. The setter converts its byte argument to float and stores it at the
same offset. The profile getter reads the override pointer at `+208` and
returns it when present, otherwise it returns the base profile pointer at
`+200`. These are direct field operations with no literal strings or direct
calls.

All three source and target rows match size, instruction count, basic blocks,
branches, calls, returns, mnemonic hash, opcode shape, register shape,
register detail, overall shape, and string-reference hash. The three target
functions were ordinary IDA `sub_` names, so the applied `v18_` aliases reduce
the default-name count by three. The property-table references distinguish
these rows from unrelated short functions with similar field access.

The aliases reopened successfully in
`analysis/spectron_libqplay_translated_v211.i64`. The database has 11,694
functions, 3,641 high-confidence semantic labels, and 1,210 default `sub_`
names. Its SHA-256 is
`5fe1b5504cbca2cd774a0e7a2e6ef20c6f073bcf880c22b929688ec05f9489d2`. The
machine-readable record is
`artifacts/spectron_gui_text_list_entry_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_gui_text_list_entry_anchors.py`. No APK
or native library was modified.

## Spectron encryption and TGraalVar compact helpers

The v212 pass resolves three short runtime helpers that the broad semantic
matcher did not label automatically. The source and target feature records
match completely, while the target pseudocode preserves both the property
registration count and the script-variable receiver fields.

| Source role | Source | Spectron target | Target name before alias | Source context | Target context |
| --- | ---: | ---: | --- | ---: | ---: |
| `TEncryption_initStaticScriptVars_void` | `0xe6b7c` | `0xe7764` | `_Z10mYk6FatfX1v` | `0x36f320` | `0x380748` |
| `TGraalVar_isPaused_void` | `0xe6b90` | `0xe7778` | `_ZN10G0gxgajWBw10DGtmMaBAwiEv` | `0x35ef98`, `0x35f9b8`, `0x35ff08` | `0x371d18`, `0x372758`, `0x372cc8` |
| `TGraalVar_setProtectedObject_int` | `0xe6b98` | `0xe7780` | `_ZN10G0gxgajWBw10wjnCga8dUAEi` | `0x35efa8`, `0x35f9c8`, `0x35ff18` | `0x371d28`, `0x372768`, `0x372cd8` |

The encryption initializer forwards a null receiver, its static property-table
pointer, and the count `15` to the registration helper. Spectron calls the
obfuscated `cWWYfaxbT2::DpbOGacdQC` bridge and uses the matching table context
at `0x380748`. The paused-state getter reads the byte at receiver offset
`+17`. The protected-object setter stores its byte argument at offset `+18`
and returns the receiver. Both state helpers sit in the named `G0gxgajWBw`
class cluster.

All three rows have no literal string references or direct call names in the
feature export. They match size, instruction count, basic blocks, branches,
calls, returns, mnemonic hash, opcode shape, register shape, register detail,
overall shape, and string-reference hash. The `v18_` aliases reopened
successfully in `analysis/spectron_libqplay_translated_v212.i64`. The database
has 11,694 functions, 3,641 high-confidence semantic labels, and 1,210
default `sub_` names. Its SHA-256 is
`1eeda98f88a0816f00340f010c724695f36f66c08c6622241610ac680e30270d`. The
machine-readable record is
`artifacts/spectron_encryption_graalvar_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_encryption_graalvar_anchors.py`. No APK
or native library was modified.

## Spectron compact residual property and wrapper helpers

The v213 pass resolves 13 small functions that the broad semantic matcher
intentionally leaves out because they are below its size cutoff. The target
roles come from property-table or inbound-handler-table placement, target
pseudocode, and normalized ARM64 shape. This is the kind of cluster where a
short load, test, or forwarding wrapper can have several generic feature
matches, so the table position is important.

| Source role | Source | Spectron target | Target name before alias | Context evidence |
| --- | ---: | ---: | --- | --- |
| `TGaniObject_getChildField748` | `0x15d4e0` | `0x160570` | `sub_160570` | first child-property callback |
| `TPlayer_get_online` | `0x16c5a4` | `0x17015c` | `sub_17015C` | first TPlayer property callback |
| `GuiDrawingPanel_set_enablecache` | `0x1e0078` | `0x1e3f6c` | `sub_1E3F6C` | drawing-panel property reference |
| `TClient_deleteWeapon` | `0x1eb8a0` | `0x1eff78` | `sub_1EFF78` | inbound-handler index 5 and property slot |
| `TClient_clearInDataHandlers` | `0x1eb91c` | `0x1efff4` | `sub_1EFFF4` | inbound handler-state reference |
| `TCachedStream_set_minfilecachesize` | `0x1fa50c` | `0x1ffcbc` | `sub_1FFCBC` | cache-size property order |
| `TCachedStream_set_maxramcachesize` | `0x1fa534` | `0x1ffce4` | `sub_1FFCE4` | cache-size property order |
| `TFileDownload_clearFilesToIgnore_void` | `0x1fbbc8` | `0x2014c0` | `_ZN10uq9xgaUxlx10SgxMcbYBrmEv` | `adventure_clearfilestoignore` table row |
| `TFileDownload_script_Adventure_requestUpdateModTime` | `0x1fbbe8` | `0x2014e0` | `sub_2014E0` | `adventure_requestupdatemodtime` row |
| `TFileDownload_script_adventure_requestupdatecrc` | `0x1fbc04` | `0x2014fc` | `sub_2014FC` | `adventure_requestupdatecrc` row |
| `TFileDownload_script_adventure_requestdownload` | `0x1fbc20` | `0x201518` | `sub_201518` | `adventure_requestdownload` row |
| `TCallStackEntry_get_scriptcallobject` | `0x217e50` | `0x21f460` | `sub_21F460` | first call-stack property callback |
| `TScriptUniverse_script_rungarbagecollector` | `0x22bce0` | `0x2356c4` | `sub_2356C4` | script-universe property context |

The child getter loads the child pointer at receiver offset `+144` and returns
an unsigned field. The source reads `+748`, while the target reads `+772`, so
this row is a layout-aware match rather than a literal field-offset transfer.
The online getter tests the client singleton. The drawing-panel setter stores
the cache flag at panel offset `+140` and clears the cache on disable. The
delete-weapon wrapper uses the active player and the target inbound handler
table index 5. The clear-handler helper zeros the 0x800-byte inbound table.

The two cache-size setters preserve the signed-negative clamp and global store,
with the minimum setter preceding the maximum setter in both property
clusters. The four TFileDownload rows are identified by the decoded target
script-table names and row order. The three request wrappers guard the client
singleton before forwarding the script string. The call-stack getter preserves
the two-level `+224` then `+112` access, and the universe wrapper guards the
global script-universe object before calling garbage collection.

All 13 rows have identical normalized feature fields. Two also match
`register_detail_hash`; the other 11 record only a register-detail change.
There are no literal string references or direct call names in the exported
compact feature records. Twelve target `sub_` names were replaced. The
clear-files target already had an ABI name, so its readable alias is an
overlay on top of that existing name.

One nearby source row is intentionally not assigned a second name. The
`TFileDownload_canDownload_void` body is the same client-present predicate as
the translated `TPlayer_get_online` target, but the target FileDownload table
does not contain a separate callback. This may be compiler or linker folding,
or a removed property in the newer build. It is recorded as an unresolved
possibility in the machine-readable artifact.

The aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v213.i64`.
The database contains 11,694 functions, 3,641 high-confidence semantic
labels, and 1,198 default `sub_` names. Its SHA-256 is
`e6973d7c25827bc7cebf9f7f905376fd3eb6162e514f053c85b81baaa20381c5`. The
machine-readable record is
`artifacts/spectron_compact_residual_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_compact_residual_anchors.py`. No APK or
native library was modified.

## Spectron T2DMatrixManager method block

The v214 pass resolves four compact methods from the source
`T2DMatrixManager` class. The target ABI names place the corresponding block
in `AUzMgaePtJ`, and its helper list is the rebuilt `vy1JgaKVkH` type. The
target class name and local method order provide a useful check beyond the
short-function fingerprints.

| Source role | Source | Spectron target | Target ABI name | Context |
| --- | ---: | ---: | --- | --- |
| `T2DMatrixManager_isActivated_void` | `0xfd1e4` | `0xff800` | `_ZN10AUzMgaePtJ10t5AMgadPuJEv` | class-local reference `0x3810b8` |
| `T2DMatrixManager_getTop_void` | `0xfd20c` | `0xff828` | `_ZN10AUzMgaePtJ10dGBMgabjvJEv` | class-local reference `0x383c90` |
| `T2DMatrixManager_clear_void` | `0xfd258` | `0xff874` | `_ZN10AUzMgaePtJ5clearEv` | class-local reference `0x386728` |
| `T2DMatrixManager_pop_void` | `0xfd478` | `0xffa94` | `_ZN10AUzMgaePtJ3popEv` | class-local reference `0x383e00` |

The activation getter checks the list global and its positive count. The top
getter returns the final matrix pointer. The clear method walks every stored
matrix, deletes it, and clears the list. The pop method removes and deletes
only the final entry. Spectron's pseudocode uses the target global
`AUzMgaePtJ::UuAMgaMjuJ` and the rebuilt list helper, while preserving these
operations and the source method order.

All four source and target rows have the same size, instruction count, block
count, branch count, call count, return count, mnemonic hash, opcode shape,
register shape, overall shape, and string-reference hash. Each differs only in
`register_detail_hash`, which is recorded as a target register-allocation
change. Direct-call names are retained in the machine-readable record because
the source uses `TList` names and the target uses `vy1JgaKVkH` names.

The applied aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v214.i64`.
The database contains 11,694 functions, 3,641 high-confidence semantic
labels, and 1,198 default `sub_` names. Its SHA-256 is
`a0b839b194114b7e7af26f14205e66a68017f38ac828af1d52f10f43f8100694`. The
machine-readable record is
`artifacts/spectron_t2d_matrix_manager_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_t2d_matrix_manager_anchors.py`.

The source `T2DMatrixManager_initStaticVars_void` row is deliberately not
renamed in this pass. Its four-instruction static-allocation shape matches
several unrelated target initializers, and none of the current candidates
stores the `AUzMgaePtJ` matrix-list global. It remains a clear next review item
rather than a speculative alias.

## Spectron MRandomGenerator family

The v215 pass resolves the compact random-generator family as one class
block. The source shared base maps to `o3AZxayNqc`; the LCG implementation
maps to `Vx2_xajLEd`; and the R250 implementation maps to `ZwL1xarB5e`.
The associated property classes carry the same target prefixes.

| Source role | Source | Spectron target | Target ABI name | Context |
| --- | ---: | ---: | --- | --- |
| `MRandomGenerator_initStaticVars_void` | `0x1e3b88` | `0x1e7a58` | `_Z10Byh1xaKnHev` | target global `Lry_xa0Aed`, LCG class block |
| `MRandomGenerator_MRandomGenerator_TString_const` | `0x1e3574` | `0x1e7444` | `_ZN10o3AZxayNqcC1ERK10C8THgaTQxF` | shared base constructor |
| `MRandomGenerator_MRandomGenerator_void` | `0x1e35a4` | `0x1e7474` | `_ZN10o3AZxayNqcC1Ev` | shared default constructor |
| `MRandomLCG_initObject_int` | `0x1e36d0` | `0x1e75a0` | `_ZN10Vx2_xajLEd10j9gLgaw2nIEi` | LCG property and vtable setup |
| `MRandomLCG_MRandomLCG_TString_const` | `0x1e3710` | `0x1e75e0` | `_ZN10Vx2_xajLEdC1ERK10C8THgaTQxF` | LCG constructor order |
| `MRandomLCG_create_TString_const` | `0x1e3760` | `0x1e7630` | `_Z20Vx2_xajLEdE7Bm2aaHDBRK10C8THgaTQxF` | 0x90-byte LCG allocation |
| `MRandomR250_initObject_int` | `0x1e39d8` | `0x1e78a8` | `_ZN10ZwL1xarB5e10j9gLgaw2nIEi` | R250 property and vtable setup |
| `MRandomR250_MRandomR250_TString_const` | `0x1e3a18` | `0x1e78e8` | `_ZN10ZwL1xarB5eC1ERK10C8THgaTQxF` | R250 constructor order |
| `MRandomR250_create_TString_const` | `0x1e3a68` | `0x1e7938` | `_Z20ZwL1xarB5eE7Bm2aaHDBRK10C8THgaTQxF` | 0x478-byte R250 allocation |
| `MRandomGeneratorProperties_MRandomGeneratorProperties` | `0x1e3cb8` | `0x1e7b88` | `_ZN20o3AZxayNqcPropertiesD2Ev` | base-property destructor |
| `MRandomLCGProperties_MRandomLCGProperties` | `0x1e3cdc` | `0x1e7bac` | `_ZN20Vx2_xajLEdPropertiesD1Ev` | LCG-property destructor |
| `MRandomR250Properties_MRandomR250Properties` | `0x1e3d00` | `0x1e7bd0` | `_ZN20ZwL1xarB5ePropertiesD1Ev` | R250-property destructor |
| `MRandomLCG_MRandomLCG` | `0x1e3de4` | `0x1e7cb4` | `_ZN10Vx2_xajLEdD2Ev` | LCG object destructor |
| `MRandomR250_MRandomR250` | `0x1e3e28` | `0x1e7cf8` | `_ZN10ZwL1xarB5eD2Ev` | R250 object destructor |

The remaining property and deleting-destructor thunks are recorded in the
machine-readable artifact. The class-local order distinguishes them even
where the short thunk shapes are shared with many unrelated property classes.

The source static initializer allocates an LCG object with size `0x90`, stores
it in `gRandGen`, and removes it from the garbage collector. Spectron does the
same with `Vx2_xajLEd`, target global `Lry_xa0Aed`, and the
`NgNBgaN3oA::nrLqgaDw7q` helper. This resolved the only row in the block that
had previously been left as a medium-confidence semantic match.

All 29 rows match normalized shape. Eight match every recorded metric, while
21 differ only in `register_detail_hash`. The target ABI names and direct-call
names are retained in the evidence rows because the target rebuilds the
`TStaticVar`, string-wrapper, property-base, and allocator symbols under new
names.

The aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v215.i64`.
The database contains 11,694 functions, 3,641 high-confidence semantic
labels, and 1,198 default `sub_` names. Its SHA-256 is
`76c43334d5e5afae29a5dc51067056ebe0118bbae6366fd64908c62d317b9186`. The
machine-readable record is
`artifacts/spectron_mrandom_family_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_mrandom_anchors.py`. No APK or native
library was modified.

## Spectron residual TStringList methods

The v216 pass resolves the four remaining reviewed methods from the source
`TStringList` implementation. The target block is the obfuscated
`vuuHgangcF` class, which stores rebuilt `CanTfaz6bZ` entries and exposes
`C8THgaTQxF` string-wrapper conversions.

| Source role | Source | Spectron target | Target ABI name | Context |
| --- | ---: | ---: | --- | --- |
| `TStringList_TStringList__2` | `0xf5334` | `0xf6b34` | `_ZN10vuuHgangcFD0Ev` | deleting destructor wrapper |
| `TStringList_Remove_TString_const` | `0xf5708` | `0xf6f08` | `_ZN10vuuHgangcF6RemoveERK10CanTfaz6bZ` | repeated-value removal |
| `TStringList_indexOfIgnoreCase_TString_const` | `0xf5750` | `0xf6f9c` | `_ZNK10vuuHgangcF10W2tZ2afUk7ERK10C8THgaTQxF` | case-insensitive list scan |
| `TStringList_operator_index_int` | `0xf5df8` | `0xf7670` | `_ZNK10vuuHgangcFixEi` | compiler-mangled `operator[]` |

The deleting destructor calls the class D2 destructor and then operator delete,
matching the source wrapper. The remove method preserves the source loop that
finds and deletes every occurrence of a value. The indexed-access method keeps
the bounds check, clears the output string, and assigns the selected element.

The case-insensitive lookup is the only layout-change row. The source scans
`TString` entries and calls `equalsIgnoreCase`. The target scans the same list,
converts each `CanTfaz6bZ` entry into `C8THgaTQxF`, calls the target
case-insensitive comparison helper, and clears the temporary wrapper. This
adds conversion and cleanup work, producing a 176-byte, three-call target
body compared with the 140-byte, one-call source body. The matching class
block and preserved return logic make the correspondence safe even though its
normalized shape is not identical.

Three rows match every recorded feature metric and all four are high
confidence. The aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v216.i64`.
The machine-readable record is
`artifacts/spectron_tstringlist_residual_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tstringlist_residual_anchors.py`. The
v216 database SHA-256 is
`ab792c07ded18a61682da7a191aefd1fc9d7714f480e70685ca2386ff42089f1`. No APK
or native library was modified.

## Spectron server-object lifecycle blocks

The v217 pass resolves 49 residual methods from seven adjacent server-object
classes. The target class names are `Dq2rua2Ece` for `TExplosion`,
`irqhGaERgb` for `TServerBomb`, `dJ10YaC3tX` for `TServerChest`,
`k1h4JaIMdn` for `TServerExtra`, `gId5RaV8_6` for `TServerFlying`,
`X0HXmbuEQV` for `TServerLeap`, and `C2t_vaQTax` for `TServerSign`.
The property classes use the same target prefixes with a `Properties` suffix.

| Source role | Source | Spectron target | Target ABI name | Target class |
| --- | ---: | ---: | --- | --- |
| `TExplosion_getPower` | `0x23c850` | `0x246700` | `sub_246700` | `Dq2rua2Ece` |
| `TExplosion_getTime` | `0x23c858` | `0x246708` | `sub_246708` | `Dq2rua2Ece` |
| `TExplosion_initStaticScriptVars_void` | `0x23cda4` | `0x246cbc` | `_Z10jt7uualUNgv` | `Dq2rua2Ece` |
| `TExplosionProperties_TExplosionProperties` | `0x23cdd4` | `0x246cec` | `_ZN20Dq2rua2EcePropertiesD2Ev` | `Dq2rua2EceProperties` |
| `TExplosionProperties_TExplosionProperties__2` | `0x23cdf8` | `0x246d10` | `_ZN20Dq2rua2EcePropertiesD0Ev` | `Dq2rua2EceProperties` |
| `TExplosion_TExplosion` | `0x23ce38` | `0x246d50` | `_ZN10Dq2rua2EceD1Ev` | `Dq2rua2Ece` |
| `TExplosion_TExplosion__2` | `0x23ce4c` | `0x246d64` | `_ZN10Dq2rua2EceD0Ev` | `Dq2rua2Ece` |
| `TServerBomb_getPower` | `0x23ce80` | `0x246d98` | `sub_246D98` | `irqhGaERgb` |
| `TServerBomb_TServerBomb_TServerLevel` | `0x23d27c` | `0x247194` | `_ZN10irqhGaERgbC1EP10zF9VgaBKxR` | `irqhGaERgb` |
| `TServerBomb_initStaticVars_void` | `0x23d2cc` | `0x2471e4` | `_Z10DsHgGaPaFav` | `irqhGaERgb` |
| `TServerBomb_initStaticScriptVars_void` | `0x23d2f8` | `0x247210` | `_Z10IBCgGan5Aav` | `irqhGaERgb` |
| `TServerBombProperties_TServerBombProperties` | `0x23d328` | `0x247240` | `_ZN20irqhGaERgbPropertiesD2Ev` | `irqhGaERgbProperties` |
| `TServerBombProperties_TServerBombProperties__2` | `0x23d34c` | `0x247264` | `_ZN20irqhGaERgbPropertiesD0Ev` | `irqhGaERgbProperties` |
| `TServerBomb_TServerBomb` | `0x23d38c` | `0x2472a4` | `_ZN10irqhGaERgbD1Ev` | `irqhGaERgb` |
| `TServerBomb_TServerBomb__2` | `0x23d3c0` | `0x2472d8` | `_ZN10irqhGaERgbD0Ev` | `irqhGaERgb` |
| `TServerChest_getIsOpen` | `0x23e184` | `0x24810c` | `sub_24810C` | `dJ10YaC3tX` |
| `TServerChest_getOrderPoint_void` | `0x23e18c` | `0x248114` | `_ZN10dJ10YaC3tX10JhjWgazQFREv` | `dJ10YaC3tX` |
| `TServerChest_initStaticScriptVars_void` | `0x23e5e4` | `0x24856c` | `_Z10O7rR2aehA0v` | `dJ10YaC3tX` |
| `TServerChestProperties_TServerChestProperties` | `0x23e614` | `0x24859c` | `_ZN20dJ10YaC3tXPropertiesD1Ev` | `dJ10YaC3tXProperties` |
| `TServerChestProperties_TServerChestProperties__2` | `0x23e638` | `0x2485c0` | `_ZN20dJ10YaC3tXPropertiesD0Ev` | `dJ10YaC3tXProperties` |
| `TServerChest_TServerChest` | `0x23e678` | `0x248600` | `_ZN10dJ10YaC3tXD2Ev` | `dJ10YaC3tX` |
| `TServerChest_TServerChest__2` | `0x23e6ac` | `0x248634` | `_ZN10dJ10YaC3tXD0Ev` | `dJ10YaC3tX` |
| `TServerExtra_getTime` | `0x23e6e8` | `0x248670` | `sub_248670` | `k1h4JaIMdn` |
| `TServerExtra_TServerExtra_TServerLevel` | `0x23ea7c` | `0x248a04` | `_ZN10k1h4JaIMdnC1EP10zF9VgaBKxR` | `k1h4JaIMdn` |
| `TServerExtra_initStaticScriptVars_void` | `0x23eacc` | `0x248a54` | `_Z10Xtw3JaTWzmv` | `k1h4JaIMdn` |
| `TServerExtraProperties_TServerExtraProperties` | `0x23eafc` | `0x248a84` | `_ZN20k1h4JaIMdnPropertiesD1Ev` | `k1h4JaIMdnProperties` |
| `TServerExtraProperties_TServerExtraProperties__2` | `0x23eb20` | `0x248aa8` | `_ZN20k1h4JaIMdnPropertiesD0Ev` | `k1h4JaIMdnProperties` |
| `TServerExtra_TServerExtra` | `0x23eb60` | `0x248ae8` | `_ZN10k1h4JaIMdnD2Ev` | `k1h4JaIMdn` |
| `TServerExtra_TServerExtra__2` | `0x23eb94` | `0x248b1c` | `_ZN10k1h4JaIMdnD0Ev` | `k1h4JaIMdn` |
| `TServerFlying_TServerFlying_TServerLevel` | `0x23ee64` | `0x248dec` | `_ZN10gId5RaV8_6C2EP10zF9VgaBKxR` | `gId5RaV8_6` |
| `TServerFlying_initStaticScriptVars_void` | `0x23fb68` | `0x249b10` | `_Z10Lm_Q2aU4b0v` | `gId5RaV8_6` |
| `TServerFlyingProperties_TServerFlyingProperties` | `0x23fb98` | `0x249b40` | `_ZN20gId5RaV8_6PropertiesD1Ev` | `gId5RaV8_6Properties` |
| `TServerFlyingProperties_TServerFlyingProperties__2` | `0x23fbbc` | `0x249b64` | `_ZN20gId5RaV8_6PropertiesD0Ev` | `gId5RaV8_6Properties` |
| `TServerFlying_TServerFlying` | `0x23fbfc` | `0x249ba4` | `_ZN10gId5RaV8_6D2Ev` | `gId5RaV8_6` |
| `TServerFlying_TServerFlying__2` | `0x23fc10` | `0x249bb8` | `_ZN10gId5RaV8_6D0Ev` | `gId5RaV8_6` |
| `TServerLeap_getOrderPoint_void` | `0x23fc40` | `0x249be8` | `_ZN10X0HXmbuEQV10JhjWgazQFREv` | `X0HXmbuEQV` |
| `TServerLeap_TServerLeap_TServerLevel` | `0x23fe70` | `0x249e18` | `_ZN10X0HXmbuEQVC2EP10zF9VgaBKxR` | `X0HXmbuEQV` |
| `TServerLeap_initStaticScriptVars_void` | `0x23fee4` | `0x249e8c` | `_Z10fz9Q2aeFk0v` | `X0HXmbuEQV` |
| `TServerLeapProperties_TServerLeapProperties` | `0x23ff14` | `0x249ebc` | `_ZN20X0HXmbuEQVPropertiesD1Ev` | `X0HXmbuEQVProperties` |
| `TServerLeapProperties_TServerLeapProperties__2` | `0x23ff38` | `0x249ee0` | `_ZN20X0HXmbuEQVPropertiesD0Ev` | `X0HXmbuEQVProperties` |
| `TServerLeap_TServerLeap` | `0x23ff78` | `0x249f20` | `_ZN10X0HXmbuEQVD1Ev` | `X0HXmbuEQV` |
| `TServerLeap_TServerLeap__2` | `0x23ff8c` | `0x249f34` | `_ZN10X0HXmbuEQVD0Ev` | `X0HXmbuEQV` |
| `TServerSign_setText` | `0x23ffbc` | `0x249f64` | `sub_249F64` | `C2t_vaQTax` |
| `TServerSign_getText` | `0x23ffc4` | `0x249f6c` | `sub_249F6C` | `C2t_vaQTax` |
| `TServerSign_TServerSign_TServerLevel` | `0x240090` | `0x24a038` | `_ZN10C2t_vaQTaxC1EP10zF9VgaBKxR` | `C2t_vaQTax` |
| `TServerSign_initStaticScriptVars_void` | `0x2400e0` | `0x24a088` | `_Z10yHC_vamaixv` | `C2t_vaQTax` |
| `TServerSignProperties_TServerSignProperties` | `0x240110` | `0x24a0b8` | `_ZN20C2t_vaQTaxPropertiesD2Ev` | `C2t_vaQTaxProperties` |
| `TServerSignProperties_TServerSignProperties__2` | `0x240134` | `0x24a0dc` | `_ZN20C2t_vaQTaxPropertiesD0Ev` | `C2t_vaQTaxProperties` |
| `TServerSign_TServerSign` | `0x240174` | `0x24a11c` | `_ZN10C2t_vaQTaxD1Ev` | `C2t_vaQTax` |

All 49 rows match normalized shape. Nine also match every recorded feature
metric. The remaining 40 differ only in `register_detail_hash`, which reflects
register allocation changes in the target build. Seven target getter rows had
default `sub_` names and received the same `v18_` analysis-label treatment as
the ABI-named rows.

The level-bound constructors preserve the common base-object initialization,
receiver flags, and class property pointer. The property destructor pairs
match the source D2 or deleting-destructor roles, and the object destructor
pairs match the target D1, D2, and D0 ABI variants. The static script-variable
initializers sit immediately before each corresponding property-destructor
block, which provides useful context for otherwise short allocator wrappers.

The aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v217.i64`.
The database contains 11,694 functions, 3,641 high-confidence semantic
labels, and 1,191 default `sub_` names. Its SHA-256 is
`f6a40e8f1849fa008b64af1cdf31a47375ae521a6edcb8afc333af9fa00a9840`. The
machine-readable record is
`artifacts/spectron_server_object_lifecycle_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_server_object_lifecycle_anchors.py`. No
APK or native library was modified.

## Spectron GuiMLTextCtrl residual methods

The v218 pass resolves the remaining named `GuiMLTextCtrl` rows that were left
outside the earlier GUI and HTML passes. The source block runs from
`0x1bc6fc` through the property thunks at `0x1bfcf0`. The target code sits in
the obfuscated `GbMhIaz9yS` class block from `0x1c0028` through `0x1c35fc`,
with the target property destructor pair at `0x1c4700` and `0x1c4724`.

The first group is a particularly clean translation. These compact methods
read or write the same receiver fields, or delegate to the corresponding
HTML-page operation through the target `AS80gaE4zW` class.

| Source role | Source | Spectron target | Target ABI name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `GuiMLTextCtrl_get_htmllinks` | `0x1bc6fc` | `0x1c0028` | `sub_1C0028` | exact field getter |
| `GuiMLTextCtrl_set_htmllinks` | `0x1bc704` | `0x1c0030` | `sub_1C0030` | exact field setter |
| `GuiMLTextCtrl_get_alpha` | `0x1bc70c` | `0x1c0038` | `sub_1C0038` | exact page-property getter |
| `GuiMLTextCtrl_get_cursorposition` | `0x1bc718` | `0x1c0044` | `sub_1C0044` | exact field getter |
| `GuiMLTextCtrl_set_cursorposition` | `0x1bc720` | `0x1c004c` | `sub_1C004C` | exact virtual setter |
| `GuiMLTextCtrl_get_maxchars` | `0x1bc740` | `0x1c006c` | `sub_1C006C` | exact field getter |
| `GuiMLTextCtrl_set_maxchars` | `0x1bc748` | `0x1c0074` | `sub_1C0074` | exact field setter |
| `GuiMLTextCtrl_get_wordwrap` | `0x1bc750` | `0x1c007c` | `sub_1C007C` | exact page-property getter |
| `GuiMLTextCtrl_get_parsetags` | `0x1bc794` | `0x1c00c0` | `sub_1C00C0` | exact field getter |
| `GuiMLTextCtrl_script_reflow` | `0x1bc79c` | `0x1c00c8` | `sub_1C00C8` | exact virtual dispatch |
| `GuiMLTextCtrl_set_wordwrap` | `0x1bc818` | `0x1c0144` | `sub_1C0144` | exact page-property setter |
| `GuiMLTextCtrl_set_urlbase` | `0x1bc820` | `0x1c014c` | `sub_1C014C` | exact page-property setter |
| `GuiMLTextCtrl_get_urlbase` | `0x1bc828` | `0x1c0154` | `sub_1C0154` | exact page-property getter |
| `GuiMLTextCtrl_set_htmlcompatibility` | `0x1bc8d8` | `0x1c0204` | `sub_1C0204` | exact page-property setter |
| `GuiMLTextCtrl_get_htmlcompatibility` | `0x1bc8e0` | `0x1c020c` | `sub_1C020C` | exact page-property getter |
| `GuiMLTextCtrl_get_allowedtags` | `0x1bc8e8` | `0x1c0214` | `sub_1C0214` | exact list serializer |
| `GuiMLTextCtrl_set_deniedsound` | `0x1bc90c` | `0x1c0238` | `sub_1C0238` | exact string assignment |
| `GuiMLTextCtrl_get_deniedsound` | `0x1bc914` | `0x1c0240` | `sub_1C0240` | exact string copy |
| `GuiMLTextCtrl_set_alpha` | `0x1bc944` | `0x1c0270` | `sub_1C0270` | exact page-property setter |

The rest of the block contains the factory, script bridge, layout, input, and
lifecycle rows.

| Source role | Source | Spectron target | Target ABI name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `GuiMLTextCtrl_GuiMLTextCtrl__2` | `0x1bc9e0` | `0x1c030c` | `_ZN10GbMhIaz9ySD0Ev` | exact deleting destructor |
| `GuiMLTextCtrl_onRightMouseDown_GuiEvent_const` | `0x1bcc04` | `0x1c0530` | `_ZN10GbMhIaz9yS10jAiwga8eNvERK10cXoLgatBuI` | reviewed layout change |
| `GuiMLTextCtrl_create_TString_const` | `0x1bcec0` | `0x1c0824` | `_Z20GbMhIaz9ySE7Bm2aaHDBRK10C8THgaTQxF` | exact factory wrapper |
| `GuiMLTextCtrl_getNumChars_void` | `0x1bcf60` | `0x1c08c4` | `_ZNK10GbMhIaz9yS10mK1ILaB4uLEv` | exact count getter |
| `GuiMLTextCtrl_updateCursorLine_void` | `0x1bd48c` | `0x1c0df0` | `_ZN10GbMhIaz9yS10c9LILap7gLEv` | reviewed layout change |
| `GuiMLTextCtrl_script_getline` | `0x1bd6e8` | `0x1c1084` | `sub_1C1084` | exact script wrapper |
| `GuiMLTextCtrl_script_getlines` | `0x1bd7c8` | `0x1c1164` | `sub_1C1164` | exact script wrapper |
| `GuiMLTextCtrl_isSelectionActive_void` | `0x1bd8cc` | `0x1c1268` | `_ZNK10GbMhIaz9yS10IJUMLaclLOEv` | exact field getter |
| `GuiMLTextCtrl_script_findtext` | `0x1bdf1c` | `0x1c18b8` | `sub_1C18B8` | exact script wrapper |
| `GuiMLTextCtrl_set_plaintext` | `0x1be504` | `0x1c1ea0` | `sub_1C1EA0` | normalized-shape match |
| `GuiMLTextCtrl_script_setlines` | `0x1be52c` | `0x1c1ec8` | `sub_1C1EC8` | reviewed wrapper layout change |
| `GuiMLTextCtrl_reflowResize_bool` | `0x1be758` | `0x1c210c` | `_ZN10GbMhIaz9yS10MeKxLabw_BEb` | reviewed layout change |
| `GuiMLTextCtrl_set_allowedtags` | `0x1bed78` | `0x1c2764` | `sub_1C2764` | reviewed wrapper layout change |
| `GuiMLTextCtrl_set_disallowedtags` | `0x1bef2c` | `0x1c291c` | `sub_1C291C` | reviewed wrapper layout change |
| `GuiMLTextCtrl_onMouseDown_GuiEvent_const` | `0x1bf0e4` | `0x1c2ad8` | `_ZN10GbMhIaz9yS10q2hwgaKNMvERK10cXoLgatBuI` | reviewed layout change |
| `GuiMLTextCtrl_onMouseDragged_GuiEvent_const` | `0x1bf4b0` | `0x1c2ee0` | `_ZN10GbMhIaz9yS10umViIaxSwTERK10cXoLgatBuI` | reviewed layout change |
| `GuiMLTextCtrl_onMouseUp_GuiEvent_const` | `0x1bf6f4` | `0x1c3124` | `_ZN10GbMhIaz9yS10LcTxgao36wERK10cXoLgatBuI` | reviewed layout change |
| `GuiMLTextCtrl_onStyleUpdated_void` | `0x1bfb0c` | `0x1c3578` | `_ZN10GbMhIaz9yS10OIFwLasI5AEv` | exact style hook |
| `GuiMLTextCtrlProperties_GuiMLTextCtrlProperties` | `0x1bfc94` | `0x1c4700` | `_ZN20GbMhIaz9ySPropertiesD1Ev` | normalized-shape destructor |
| `GuiMLTextCtrlProperties_GuiMLTextCtrlProperties__2` | `0x1bfcb8` | `0x1c4724` | `_ZN20GbMhIaz9ySPropertiesD0Ev` | normalized-shape deleting destructor |

The first nineteen rows are complete feature matches. The deleting
destructor, factory, character-count getter, line wrappers, selection getter,
find-text wrapper, and style hook add more complete matches for a total of 27.
Thirty rows retain normalized shape. The twelve rows with a different
`register_detail_hash` reflect target register allocation or the larger
handlers, not a different source role. Nine rows are marked as layout changes:
the right-click and mouse handlers, cursor-line update, line-list setter,
reflow-resize path, and the two tag-list string wrappers. These target bodies
preserve the source operation while making the rebuilt string and base-control
calls explicit.

The event handlers are useful for later GUI debugging. The target mouse-down
body still computes local coordinates, finds a text atom or bitmap, updates
the selection range, handles double and triple click selection, locks the
mouse, and invalidates the control. The drag body retains link-hover handling,
scroll-region autoscroll, and selection extension. The mouse-up body retains
mouse unlock, text selection, and tag activation. The right-click handler
keeps the `onRightSelectTag` event path. Their size changes are therefore
documented as build differences rather than used as automatic fingerprint
matches.

The line-list wrappers explain another useful target-build difference. The
source uses `TString`; the target converts through `CanTfaz6bZ` and
`C8THgaTQxF`, with explicit temporary cleanup. The target reflow path also
uses the rebuilt `AS80gaE4zW` page and scroll-control helpers. The source and
target still read the same cursor, line, selection, and page fields. The two
property destructor rows match the source D1 and deleting-destructor roles,
with only register-detail allocation differing.

All 39 rows are high-confidence reviewed anchors. Twenty-six target functions
initially carried default `sub_` names. The aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v218.i64`,
which contains 11,694 functions, 3,641 high-confidence semantic labels, and
1,165 remaining default `sub_` names. The v218 database SHA-256 is
`d82c297a781db70c75d56b9dad679db224127653c55a5c312542ab698e5b53b5`.
The machine-readable record is
`artifacts/spectron_gui_ml_text_residual_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_gui_ml_text_residual_anchors.py`. No APK
or native library was modified.

## Spectron residual GUI text-list property block

The v219 pass names the next residual run in the target's GUI text-list
property tables. This is a useful example of where stripped code can still be
translated safely. The source table and target table keep the same order, the
target class block is identified by the surrounding `RZNxgaOF2w` and
`u0eyga1eqx` methods, and every decompiled target body performs the same field
operation as its 1.8 counterpart.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiTextListEntry_get_active` | `0x1dc82c` | `0x1e05c8` | `sub_1E05C8` | byte at `+140` |
| `GuiTextListEntry_set_active` | `0x1dc834` | `0x1e05d0` | `sub_1E05D0` | byte at `+140` |
| `GuiTextListEntry_get_flickering` | `0x1dc83c` | `0x1e05d8` | `sub_1E05D8` | byte at `+141` |
| `GuiTextListEntry_set_flickering` | `0x1dc844` | `0x1e05e0` | `sub_1E05E0` | byte at `+141` |
| `GuiTextListEntry_get_height` | `0x1dc86c` | `0x1e0608` | `sub_1E0608` | integer at `+196` |
| `GuiTextListEntry_get_id` | `0x1dc874` | `0x1e0610` | `sub_1E0610` | integer at `+136` |
| `GuiTextListEntry_set_id` | `0x1dc87c` | `0x1e0618` | `sub_1E0618` | integer at `+136` |
| `GuiTextListEntry_get_image` | `0x1dc884` | `0x1e0620` | `sub_1E0620` | integer at `+176` |
| `GuiTextListEntry_set_image` | `0x1dc88c` | `0x1e0628` | `sub_1E0628` | integer at `+176` |
| `GuiTextListEntry_get_sortgroup` | `0x1dc8a8` | `0x1e0644` | `sub_1E0644` | integer at `+216` |
| `GuiTextListEntry_set_sortgroup` | `0x1dc8b0` | `0x1e064c` | `sub_1E064C` | integer at `+216` |
| `GuiTextListEntry_get_sortvalue` | `0x1dc8b8` | `0x1e0654` | `sub_1E0654` | integer at `+220` |
| `GuiTextListEntry_set_sortvalue` | `0x1dc8c0` | `0x1e065c` | `sub_1E065C` | integer at `+220` |
| `GuiTextListEntry_get_selectedimage` | `0x1dc8c8` | `0x1e0664` | `sub_1E0664` | integer at `+180` |
| `GuiTextListEntry_set_selectedimage` | `0x1dc8d0` | `0x1e066c` | `sub_1E066C` | integer at `+180` |
| `GuiTextListEntry_get_useownprofile` | `0x1dc8d8` | `0x1e0674` | `sub_1E0674` | pointer presence at `+208` |
| `GuiTextListEntry_get_width` | `0x1dc8e8` | `0x1e0684` | `sub_1E0684` | integer at `+192` |
| `GuiTextListEntry_get_x` | `0x1dc8f0` | `0x1e068c` | `sub_1E068C` | integer at `+184` |
| `GuiTextListEntry_get_y` | `0x1dc8f8` | `0x1e0694` | `sub_1E0694` | integer at `+188` |
| `GuiTextListCtrl_get_clipcolumntext` | `0x1dc900` | `0x1e069c` | `sub_1E069C` | byte at `+531` |
| `GuiTextListCtrl_set_clipcolumntext` | `0x1dc908` | `0x1e06a4` | `sub_1E06A4` | byte at `+531` |
| `GuiTextListCtrl_get_enumerate` | `0x1dc910` | `0x1e06ac` | `sub_1E06AC` | byte at `+528` |
| `GuiTextListCtrl_set_enumerate` | `0x1dc918` | `0x1e06b4` | `sub_1E06B4` | byte at `+528` |
| `GuiTextListCtrl_get_fitparentwidth` | `0x1dc920` | `0x1e06bc` | `sub_1E06BC` | byte at `+530` |
| `GuiTextListCtrl_set_fitparentwidth` | `0x1dc928` | `0x1e06c4` | `sub_1E06C4` | byte at `+530` |
| `GuiTextListCtrl_get_iconheight` | `0x1dc930` | `0x1e06cc` | `sub_1E06CC` | integer at `+536` |
| `GuiTextListCtrl_get_iconwidth` | `0x1dc938` | `0x1e06d4` | `sub_1E06D4` | integer at `+532` |
| `GuiTextListCtrl_get_resizecell` | `0x1dc940` | `0x1e06dc` | `sub_1E06DC` | byte at `+529` |
| `GuiTextListCtrl_set_resizecell` | `0x1dc948` | `0x1e06e4` | `sub_1E06E4` | byte at `+529` |
| `GuiTextListCtrl_get_sortcolumn` | `0x1dc950` | `0x1e06ec` | `sub_1E06EC` | integer presence at `+552` |

The already translated neighbors `get_flickertime`, `set_flickertime`,
`get_profile`, and `set_sortcolumn` were used as additional block anchors but
are not counted again here. The 30 new rows match all recorded feature
metrics, including normalized shape and register detail. Each target began
with a default `sub_` name. The aliases reopened with zero failures in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v219.i64`,
which contains 11,694 functions and 1,135 remaining default `sub_` names. Its
SHA-256 is
`bf219383ca3b9d99ca0fc8133b61c8204263458dc916f3f0cf846e41f9383097`.

The machine-readable record is
`artifacts/spectron_gui_text_list_entry_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_text_list_entry_property_anchors.py`. The pass
was read-only with respect to the APK and native library, and did not contact
any network service. The v219 database identity is also recorded in
`artifacts/spectron_translation_checkpoint_20260828.json`, generated by
`tools/extend_spectron_translation_checkpoint.py`.

## Spectron adjacent GUI text-list methods

The v220 pass continues directly after the property accessors. These methods
are still in the same obfuscated `RZNxgaOF2w` and `u0eyga1eqx` class families.
The target property or method table provides the pointer reference, and the
body confirms the operation. The target's rebuilt `C8THgaTQxF` string wrapper
explains the register-detail differences in the sort methods without changing
their role.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiTextListCtrl_get_sortorder` | `0x1dca48` | `0x1e07e4` | `sub_1E07E4` | string from index at `+544` |
| `GuiTextListCtrl_get_sortmode` | `0x1dca84` | `0x1e0820` | `sub_1E0820` | string from index at `+540` |
| `GuiTextListCtrl_get_groupsortorder` | `0x1dcac0` | `0x1e085c` | `sub_1E085C` | string from index at `+548` |
| `GuiTextListEntry_set_hint` | `0x1dcb08` | `0x1e08a4` | `sub_1E08A4` | assignment at `+128` |
| `GuiTextListEntry_get_hint` | `0x1dcb5c` | `0x1e08f8` | `sub_1E08F8` | copy from `+128` |
| `GuiTextListEntry_get_position` | `0x1dcb8c` | `0x1e0928` | `sub_1E0928` | TPoint from `+184` |
| `GuiTextListEntry_get_extent` | `0x1dcbb0` | `0x1e094c` | `sub_1E094C` | TPoint from `+192` |
| `GuiTextListCtrl_set_sortorder` | `0x1dcc68` | `0x1e0a04` | `sub_1E0A04` | parse into `+544` |
| `GuiTextListCtrl_set_groupsortorder` | `0x1dcdb4` | `0x1e0b50` | `sub_1E0B50` | parse into `+548` |
| `GuiTextListEntry_set_profile` | `0x1dd94c` | `0x1e16e8` | `sub_1E16E8` | dynamic cast and assignment |

Four rows match the complete recorded feature set. The other six preserve
normalized shape and differ only in register-detail or target wrapper names.
All ten targets initially had default `sub_` names, and all ten aliases
reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v220.i64`.
The database contains 11,694 functions and 1,125 remaining default `sub_`
names. Its SHA-256 is
`8ed23c3f19d77413dd044e64b810352c66dc76660e34b7c205d9648a82edd09f`.

The machine-readable record is
`artifacts/spectron_gui_text_list_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_text_list_residual_anchors.py`.
The v220 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v220.json`. This pass
changed only the disposable IDA analysis copy and made no network request.

## Spectron residual drawing-panel and ShowImg properties

The v221 pass moved to two adjacent GUI property blocks that still had
default names in the target IDA database. The source and target property
tables, class-local order, and decompiled bodies all agree on these roles.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiDrawingPanel_get_partx` | `0x1e0030` | `0x1e3f24` | `sub_1E3F24` | panel field at `+172` |
| `GuiDrawingPanel_get_party` | `0x1e003c` | `0x1e3f30` | `sub_1E3F30` | panel field at `+176` |
| `GuiDrawingPanel_get_partw` | `0x1e0048` | `0x1e3f3c` | `sub_1E3F3C` | panel field at `+180` |
| `GuiDrawingPanel_get_parth` | `0x1e0054` | `0x1e3f48` | `sub_1E3F48` | panel field at `+184` |
| `GuiDrawingPanel_get_enablecache` | `0x1e0060` | `0x1e3f54` | `sub_1E3F54` | cache flag at `+140` |
| `GuiDrawingPanel_get_availablefilters` | `0x1e0090` | `0x1e3f84` | `sub_1E3F84` | filter-name list construction |
| `GuiShowImgCtrl_get_offsetx` | `0x1e0e48` | `0x1e4d3c` | `sub_1E4D3C` | control field at `+472` |
| `GuiShowImgCtrl_get_offsety` | `0x1e0e50` | `0x1e4d44` | `sub_1E4D44` | control field at `+476` |
| `GuiShowImgCtrl_set_layer` | `0x1e0e64` | `0x1e4d58` | `sub_1E4D58` | forwards to owned image |
| `GuiShowImgCtrl_get_layer` | `0x1e0e6c` | `0x1e4d60` | `sub_1E4D60` | reads owned image layer |
| `GuiShowImgCtrl_get_dir` | `0x1e0e74` | `0x1e4d68` | `sub_1E4D68` | particle direction field |
| `GuiShowImgCtrl_get_ani` | `0x1e0e80` | `0x1e4d74` | `sub_1E4D74` | returns image animation |
| `GuiShowImgCtrl_set_dir` | `0x1e1088` | `0x1e4f7c` | `sub_1E4F7C` | direction plus player-look reset |
| `GuiShowImgCtrl_set_ani` | `0x1e10d0` | `0x1e4fc4` | `sub_1E4FC4` | animation plus player-look reset |
| `GuiShowImgCtrl_set_offsety` | `0x1e1564` | `0x1e5434` | `sub_1E5434` | write and image-position refresh |
| `GuiShowImgCtrl_set_offsetx` | `0x1e156c` | `0x1e543c` | `sub_1E543C` | write and image-position refresh |

All 16 rows match the normalized ARM64 feature fields. Fifteen match the
complete recorded metric set. The one metric difference is retained in the
machine-readable record rather than being hidden by the alias. The v221
copy has 11,694 functions and 1,109 remaining default `sub_` names, and all
16 aliases reopened with zero failures.

The two nearby target helpers at `0x1e3f60` and `0x1e4d4c` clear target-only
static strings during drawing-panel and ShowImg rendering. They are recorded
as reviewed target-only rows and remain unaliased because no 1.8 counterpart
was demonstrated. The evidence and input hashes are in
`artifacts/spectron_gui_drawing_showimg_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_residual_property_anchors.py`. The v221 database
identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v221.json`.

This pass changed only the disposable IDA database and performed no DNS,
HTTP, or TLS operation.

## Spectron residual GuiBrowserCtrl getters

The v222 pass resolves the three small property getters that remained
unnamed in the target `VGEwBaTQ4a` class block. The target property table
keeps the same allow-zoom, URL, and text entries as the source table, and the
decompiled bodies read the same receiver fields.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiBrowserCtrl_get_allowzoom` | `0x1e1914` | `0x1e57e4` | `sub_1E57E4` | byte at `+472` |
| `GuiBrowserCtrl_get_url` | `0x1e191c` | `0x1e57ec` | `sub_1E57EC` | string copy from `+464` |
| `GuiBrowserCtrl_get_text` | `0x1e194c` | `0x1e581c` | `sub_1E581C` | string copy from `+456` |

All three rows match normalized shape and the complete recorded metric set.
They reopened with zero failures in the v222 disposable database, which has
11,694 functions and 1,106 remaining default `sub_` names. The evidence and
input hashes are in
`artifacts/spectron_gui_browser_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_browser_property_anchors.py`. The v222 database
identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v222.json`.

This pass changed only the disposable IDA database and performed no DNS,
HTTP, or TLS operation.

## Spectron residual GuiContextMenuCtrl callbacks

The v223 pass resolves five default-named callbacks in the target
`c3fygag7qx` context-menu block. Their property or method table entries line
up with the source, and each decompiled body preserves the same receiver
field access or virtual close dispatch.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiContextMenuCtrl_get_maxpopupheight` | `0x1d7cac` | `0x1dc974` | `sub_1DC974` | field at `+480` |
| `GuiContextMenuCtrl_set_maxpopupheight` | `0x1d7cb4` | `0x1dc97c` | `sub_1DC97C` | field at `+480` |
| `GuiContextMenuCtrl_script_close` | `0x1d7cbc` | `0x1dc984` | `sub_1DC984` | virtual slot `888` |
| `GuiContextMenuCtrl_script_isopen` | `0x1d7cdc` | `0x1dc9a4` | `sub_1DC9A4` | byte at `+460` |
| `GuiContextMenuCtrl_get_width` | `0x1d7ce4` | `0x1dc9ac` | `sub_1DC9AC` | owned-control field at `+352` |

All five rows match normalized shape and the complete recorded metric set.
They reopened with zero failures in the v223 disposable database, which has
11,694 functions and 1,101 remaining default `sub_` names. The evidence and
input hashes are in
`artifacts/spectron_gui_context_menu_property_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_context_menu_property_anchors.py`. The v223
database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v223.json`.

This pass changed only the disposable IDA database and performed no DNS,
HTTP, or TLS operation.

## Spectron residual array and popup GUI callbacks

The v224 pass covers a small callback block spanning `GuiArrayCtrl`,
`GuiContextMenuCtrl`, and `GuiPopUpMenuCtrl`. Five rows are exact feature
matches. The rows lookup is still a high-confidence semantic match, but the
target's rebuilt string and hash-list helpers change its normalized
instruction shape, so that difference is recorded explicitly.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiArrayCtrl_get_allowmultipleselections` | `0x1d5f04` | `0x1dab5c` | `sub_1DAB5C` | byte at `+480` |
| `GuiContextMenuCtrl_get_rows` | `0x1d85ac` | `0x1dd334` | `sub_1DD334` | `rows` lookup through owned hash list |
| `GuiPopUpMenuCtrl_script_forceonaction` | `0x1d9104` | `0x1dde40` | `sub_1DDE40` | virtual slot `832` |
| `GuiPopUpMenuCtrl_script_forceclose` | `0x1d9124` | `0x1dde60` | `sub_1DDE60` | virtual slot `904` |
| `GuiPopUpMenuCtrl_script_rowcount` | `0x1d91e4` | `0x1ddf20` | `sub_1DDF20` | embedded text-list count |
| `GuiPopUpMenuCtrl_script_getselected` | `0x1d91f0` | `0x1ddf2c` | `sub_1DDF2C` | embedded text-list selected ID |

All six targets initially had default `sub_` names. Five match normalized
shape and the complete recorded metric set. The rows lookup preserves the
same `rows` hash lookup and temporary-string cleanup, so it is retained as a
high-confidence alias even though its target wrapper sequence is different.
All six names reopened with zero failures in the v224 disposable database,
which has 11,694 functions and 1,095 remaining default `sub_` names.

The target helper at `0x1dded4` clears a target-only temporary string during
`GuiPopUpMenuCtrl_setIconSize`. It is recorded as target-only and remains
unaliased because no 1.8 source counterpart was demonstrated. The evidence
and input hashes are in
`artifacts/spectron_gui_array_popup_residual_manual_translation_anchors_20260828.json`,
generated by
`tools/generate_spectron_gui_array_popup_residual_anchors.py`. The v224
database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v224.json`.

This pass changed only the disposable IDA database and performed no DNS,
HTTP, or TLS operation.

## Spectron residual TClient script-property callbacks

The v230 pass resolves five high-confidence callbacks from the decoded TClient
script-property table. The target functions are in the obfuscated callback
families shown below, and the table names identify their 2.2 roles directly.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TClient_setBigFileSizeAndContinue` | `0x1eaff8` | `0x1ef660` | `sub_1EF660` | `tclient_downloadsetsize` at `0x397b90` |
| `TGUIScriptLoader_finishServerListConnect` | `0x1eb4c0` | `0x1efb64` | `sub_1EFB64` | `tclient_setserverlisterconnect` at `0x397830` |
| `TClient_setPlayerFlagValueNullName` | `0x1eb890` | `0x1eff68` | `sub_1EFF68` | `tclient_unsetflagdata` at `0x3979e0` |
| `TClient_setPlayerFlagValueEmptyName` | `0x1eb898` | `0x1eff70` | `sub_1EFF70` | `tclient_setflagdata` at `0x3979b0` |
| `TClient_addWeaponForActivePlayer` | `0x1eb8bc` | `0x1eff94` | `sub_1EFF94` | `tclient_setweapon` at `0x3978f0` |

The corresponding source records are `0x384b30`, `0x3847d0`, `0x384980`,
`0x384950`, and `0x384890`. The target table keeps the same named property
roles while the function bodies use rebuilt helper classes. The download-size
callback stores the big-file size and advances download processing. The
server-list callback hides the connecting window, invokes
`onServerListerConnect`, and sets the reconnect state. The flag wrappers retain
their null-name and empty-name distinction, while the weapon wrapper checks
for an active player before forwarding both weapon strings.

The two flag rows match the complete feature set. The download-size and
server-list rows preserve their semantics but have explicit wrapper-layout
differences. The weapon row keeps normalized shape and differs only in
register-detail allocation. This is a high-confidence semantic translation,
with the metric differences retained in the machine-readable artifact.

The aliases reopened with zero failures in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v230.i64`,
which has 11,694 functions and 1,079 remaining default `sub_` names. Its
SHA-256 is
`220e9fe71bb8e93472ed7892b4b16363559e1d24a3733bb876fd6abb393023ba`.
The evidence and input hashes are in
`artifacts/spectron_tclient_script_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tclient_script_property_anchors.py`.
The database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v230.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron TPlayer findweapon callbacks

The v251 pass resolves both source `findweapon` callbacks. The first is a
property callback, and the second is the callback installed by the static
player initialization path.

| 1.8 callback | Source | Spectron target | Source record | Target record | Context |
| --- | ---: | ---: | ---: | ---: | --- |
| `TPlayerProperties_script_findweapon` | `0x16ca18` | `0x1705f0` | `0x37bce8` | `0x38ed18` | player object plus weapon name |
| `TPlayer_script_findweapon` | `0x16db28` | `0x171728` | `0x37bdd8` | `0x38ee38` | active player plus weapon name |

The two source callbacks share the same weapon-list search idea but not the
same calling context. The property callback searches the supplied player;
the static callback resolves the active player and handles a null active
player. Spectron keeps separate callbacks and uses an explicit temporary
string comparison plus the relocated player collection field at +2640. Both
target bodies are larger than their 1.8 counterparts because of those rebuilt
helpers. They are high-confidence semantic matches, but neither is a
normalized or complete metric match.

The evidence is
`artifacts/spectron_tplayer_findweapon_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tplayer_findweapon_anchors.py`. The v251
checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v251.json`, with 11,696
functions, 814 remaining default `sub_` names, and database SHA-256
`7ab7b98f01f2a4e5241187e1f5864006a7b8b21f6fa163e61fc3c76081a65e9c`. A clean
serial reopen verified both names with zero failures. No network endpoint was
contacted.

## Spectron short residual property aliases

The v262 pass translates six callbacks from three short residual property
runs: `GuiButtonCtrl.stylesection` at source `0x3804f0` and target `0x393550`,
`TScriptProperty.scriptlogwritetoreadonly` at source `0x387d90` and target
`0x39aee0`, and `TTiles.waterheight` at source `0x387e78` and target
`0x39afc8`. Each record is 0x30 bytes, with getter and setter pointers at
offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiButtonCtrl_get_stylesection` | `0x1adfe8` | `0x1b21a8` | `stylesection` | `0x3804f0` | `0x393550` | getter |
| `GuiButtonCtrl_set_stylesection` | `0x1adfe0` | `0x1b21a0` | `stylesection` | `0x3804f0` | `0x393550` | setter |
| `TScriptProperty_get_scriptlogwritetoreadonly` | `0x224540` | `0x22cba0` | `scriptlogwritetoreadonly` | `0x387d90` | `0x39aee0` | getter |
| `TScriptProperty_set_scriptlogwritetoreadonly` | `0x224550` | `0x22cbb0` | `scriptlogwritetoreadonly` | `0x387d90` | `0x39aee0` | setter |
| `TTiles_get_waterheight` | `0x22f2bc` | `0x238eb0` | `waterheight` | `0x387e78` | `0x39afc8` | getter |
| `TTiles_set_waterheight` | `0x22f2cc` | `0x238ec0` | `waterheight` | `0x387e78` | `0x39afc8` | setter |

The target preserves the source string, flag, and static-double operations.
All six callbacks began as default `sub_` names. Their normalized ARM64
shapes match. The style-section pair matches the full metric set, and the
script-log and water-height pairs differ only in register-detail hashes.

The evidence is
`artifacts/spectron_residual_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_residual_property_anchors.py`. Its
SHA-256 is
`bb3e744e452f93591ae6d6c5630886a42e43cbbee7b72502e24680c32a131fce`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v262.i64`, with 11,696 functions and
737 remaining default `sub_` names. The database SHA-256 is
`6ec4091d8781101661216a2b99f6414cc3f5a07c556185eb40de2e203351d67e`.
The v262 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v262.json`. A clean serial
reopen verified all six names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron TBodyPanel bodycacheperplayer alias

The v261 pass translates the last unnamed callback in the server and player
property block. The source `TBodyPanel` row is at `0x38af98` and the
corresponding Spectron row is at `0x39e0e8`. The property records are 0x30
bytes, with the getter pointer at offset `0x10`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `TBodyPanel_get_bodycacheperplayer` | `0x23bf5c` | `0x245e0c` | `bodycacheperplayer` | `0x38af98` | `0x39e0e8` | getter |

Both implementations return the panels-per-player static integer. The target
preserves normalized ARM64 shape and differs only in register-detail hash. The
property row resolves the final default callback in this server and player
block.

The evidence is
`artifacts/spectron_tbodypanel_bodycacheperplayer_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_tbodypanel_bodycacheperplayer_anchor.py`.
Its SHA-256 is
`0ff2947f62774d86e53cdb489124917118870b9047d96ba8a1e2ea67a17d96a3`.
The alias is materialized in
`analysis/spectron_libqplay_translated_v261.i64`, with 11,696 functions and
743 remaining default `sub_` names. The database SHA-256 is
`d2f88d291451b82578968bff85c7018fdba2d2c0a18ec256ac7b3368d73e77de`.
The v261 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v261.json`. A clean serial
reopen verified the name with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron TGraalVar property residual aliases

The v260 pass translates four residual callbacks from the `TGraalVar`
property table. The source table is at `0x387340` and the corresponding
Spectron table is at `0x39a460`. Each record is 0x30 bytes, with getter and
setter pointers at offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `TGraalVar_set_name` | `0x20d388` | `0x21376c` | `name` | `0x387340` | `0x39a460` | setter |
| `TGraalVar_get_ispaused` | `0x20d22c` | `0x2135ec` | `ispaused` | `0x3873a0` | `0x39a4c0` | getter |
| `TGraalVar_set_ispaused` | `0x20d24c` | `0x21360c` | `ispaused` | `0x3873a0` | `0x39a4c0` | setter |
| `TGraalVar_get_joinedclasses` | `0x210068` | `0x21675c` | `joinedclasses` | `0x3873d0` | `0x39a4f0` | getter |

The name setter preserves its guard before assigning +8. The pause pair uses
virtual slots 152 and 160. The joined-classes getter performs the same hash
lookup and array-string refresh as the source. The property table resolves
two broad-map ambiguities and two unmatched source functions. The pause pair
matches completely. The name setter and joined-classes getter have explicit
rebuilt-wrapper shape differences, rather than being treated as exact body
matches.

The evidence is
`artifacts/spectron_tgraalvar_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tgraalvar_property_residual_anchors.py`.
Its SHA-256 is
`8740e2bc323e4e632f1f639053179eda090d5a715badda2dae415ffc326aec0d`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v260.i64`, with 11,696 functions and
744 remaining default `sub_` names. The database SHA-256 is
`a8d0c87f225ba9cd5490e7616ea05d983d48c80b8ef07ec7a8da2b91e675e944`.
The v260 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v260.json`. A clean serial
reopen verified all four names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron GuiTextEditCtrl property aliases

The v259 pass translates nine residual callbacks from the `GuiTextEditCtrl`
property table. The source table is at `0x3821e0` and the corresponding
Spectron table is at `0x395240`. Each record is 0x30 bytes, with getter and
setter pointers at offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiTextEditCtrl_get_deniedsound` | `0x1c69f0` | `0x1cb4fc` | `deniedsound` | `0x3821e0` | `0x395240` | getter |
| `GuiTextEditCtrl_set_deniedsound` | `0x1c69e8` | `0x1cb4f4` | `deniedsound` | `0x3821e0` | `0x395240` | setter |
| `GuiTextEditCtrl_get_historysize` | `0x1c696c` | `0x1cb478` | `historysize` | `0x382210` | `0x395270` | getter |
| `GuiTextEditCtrl_get_inputtype` | `0x1c6e50` | `0x1cb95c` | `inputtype` | `0x382240` | `0x3952a0` | getter |
| `GuiTextEditCtrl_get_showcursor` | `0x1c6974` | `0x1cb480` | `showcursor` | `0x3822a0` | `0x395300` | getter |
| `GuiTextEditCtrl_set_showcursor` | `0x1c697c` | `0x1cb488` | `showcursor` | `0x3822a0` | `0x395300` | setter |
| `GuiTextEditCtrl_get_tabcomplete` | `0x1c6984` | `0x1cb490` | `tabcomplete` | `0x3822d0` | `0x395330` | getter |
| `GuiTextEditCtrl_set_tabcomplete` | `0x1c698c` | `0x1cb498` | `tabcomplete` | `0x3822d0` | `0x395330` | setter |
| `GuiTextEditCtrl_get_text` | `0x1c6994` | `0x1cb4a0` | `text` | `0x382300` | `0x395360` | getter |

The target preserves the source behavior: string access at +576, history-size
access at +584, input-type forwarding, cursor and tab-completion byte access
at +589 and +588, and text getter virtual dispatch. All nine target callbacks
began as default `sub_` names. Their decoded rows, roles, pseudocode, and
complete ARM64 feature records agree. Every row has an exact normalized shape
and full metric match.

The evidence is
`artifacts/spectron_guitexteditctrl_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guitexteditctrl_property_anchors.py`. Its
SHA-256 is
`48bbaf748d8305f5054fbc9ace999e5f0f3cf3c6b7318019c5d9804c6fcefce1`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v259.i64`, with 11,696 functions and
748 remaining default `sub_` names. The database SHA-256 is
`9b5a46e16dbf912a7e67583b8f626f52878bcbb30225e3674793d3b8ef5114d9`.
The v259 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v259.json`. A clean serial
reopen verified all nine names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron GuiStretchCtrl property aliases

The v258 pass translates seven residual callbacks from the `GuiStretchCtrl`
property block and its inherited `GuiTextCtrl` rows. The source block begins
at `0x382090` and the corresponding Spectron block begins at `0x3950f0`. The
records use the standard 0x30-byte layout, with getter and setter pointers at
offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiStretchCtrl_get_clientextent` | `0x1c522c` | `0x1c9d08` | `clientextent` | `0x382090` | `0x3950f0` | getter |
| `GuiStretchCtrl_get_clientheight` | `0x1c5118` | `0x1c9bf4` | `clientheight` | `0x3820c0` | `0x395120` | getter |
| `GuiStretchCtrl_get_clientwidth` | `0x1c5164` | `0x1c9c40` | `clientwidth` | `0x3820f0` | `0x395150` | getter |
| `GuiTextCtrl_get_maxchars` | `0x1c5bfc` | `0x1ca6d8` | `maxchars` | `0x382120` | `0x395180` | getter |
| `GuiTextCtrl_set_maxchars` | `0x1c5c04` | `0x1ca6e0` | `maxchars` | `0x382120` | `0x395180` | setter |
| `GuiTextCtrl_get_text` | `0x1c5c0c` | `0x1ca6e8` | `text` | `0x382150` | `0x3951b0` | getter |
| `GuiTextCtrl_set_text` | `0x1c5c34` | `0x1ca710` | `text` | `0x382150` | `0x3951b0` | setter |

The target preserves the source field and virtual-slot behavior: point access
at +384, integer access at +388 and +464, and the text getter or setter slots.
All seven target callbacks began as default `sub_` names. Their decoded rows,
inheritance-aware source names, pseudocode, and complete ARM64 feature records
agree. Every row has an exact normalized shape and full metric match.

The evidence is
`artifacts/spectron_guistretchctrl_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guistretchctrl_property_anchors.py`. Its
SHA-256 is
`4828b7c6dd83462eac2cc589573f59cb4922ac165b7f3a2f6c025ad0da9acd29`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v258.i64`, with 11,696 functions and
757 remaining default `sub_` names. The database SHA-256 is
`7e7aa1628bd8f9123540346c06455d7b2e1aca803092f4ba3466cd4974f2bbd8`.
The v258 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v258.json`. A clean serial
reopen verified all seven names with zero failures. No APK or native library
was modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron GuiScrollCtrl property aliases

The v257 pass translates 11 residual callbacks from the `GuiScrollCtrl`
property table. The source table is at `0x381df0` and the corresponding
Spectron table is at `0x394e50`. Each record is 0x30 bytes, with getter and
setter pointers at offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiScrollCtrl_get_childmargin` | `0x1c009c` | `0x1c4b08` | `childmargin` | `0x381df0` | `0x394e50` | getter |
| `GuiScrollCtrl_get_constantthumbheight` | `0x1bffc4` | `0x1c4a30` | `constantthumbheight` | `0x381e20` | `0x394e80` | getter |
| `GuiScrollCtrl_set_constantthumbheight` | `0x1bffcc` | `0x1c4a38` | `constantthumbheight` | `0x381e20` | `0x394e80` | setter |
| `GuiScrollCtrl_get_hscrollbar` | `0x1c004c` | `0x1c4ab8` | `hscrollbar` | `0x381e50` | `0x394eb0` | getter |
| `GuiScrollCtrl_get_scrollpos` | `0x1c00c0` | `0x1c4b2c` | `scrollpos` | `0x381e80` | `0x394ee0` | getter |
| `GuiScrollCtrl_get_tile` | `0x1bffd4` | `0x1c4a40` | `tile` | `0x381eb0` | `0x394f10` | getter |
| `GuiScrollCtrl_set_tile` | `0x1bffdc` | `0x1c4a48` | `tile` | `0x381eb0` | `0x394f10` | setter |
| `GuiScrollCtrl_get_vscrollbar` | `0x1c000c` | `0x1c4a78` | `vscrollbar` | `0x381ee0` | `0x394f40` | getter |
| `GuiScrollCtrl_get_wheelscrolllines` | `0x1bffe4` | `0x1c4a50` | `wheelscrolllines` | `0x381f10` | `0x394f70` | getter |
| `GuiScrollCtrl_get_willfirstrespond` | `0x1bfffc` | `0x1c4a68` | `willfirstrespond` | `0x381f40` | `0x394fa0` | getter |
| `GuiScrollCtrl_set_willfirstrespond` | `0x1c0004` | `0x1c4a70` | `willfirstrespond` | `0x381f40` | `0x394fa0` | setter |

The target preserves the source field behavior: point conversion for child
margin and scroll position, byte access for constant thumb height and tile,
name-table lookup for the two scrollbar modes, integer access for
wheel-scroll lines, and byte access for first-responder state. All 11 target
callbacks began as default `sub_` names. Their normalized ARM64 shapes match,
and nine have complete metric matches. The only remaining differences are
register-detail hashes in the two scrollbar getters.

The evidence is
`artifacts/spectron_guiscrollctrl_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guiscrollctrl_property_anchors.py`. Its
SHA-256 is
`1bbb639528ac2344e83a74478d3cf8b9c44563f2ab5d04157f3c5d76fc0954d9`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v257.i64`, with 11,696 functions and
764 remaining default `sub_` names. The database SHA-256 is
`91201c29da6a4798a7f1918c2f11fa848cb66848615079beaaf29d04b022d82e`.
The v257 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v257.json`. A clean serial
reopen verified all 11 names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron GuiGraalCtrl isrendering property aliases

The v256 pass translates the two remaining callbacks for the `isrendering`
property. The source `GuiGraalCtrl` row is at `0x3816d0` and the corresponding
Spectron row is at `0x394730`. The records use the standard 0x30-byte layout,
with getter and setter pointers at offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiGraalCtrl_get_isrendering` | `0x1bbe80` | `0x1bf7ac` | `isrendering` | `0x3816d0` | `0x394730` | getter |
| `GuiGraalCtrl_set_isrendering` | `0x1bbe88` | `0x1bf7b4` | `isrendering` | `0x3816d0` | `0x394730` | setter |

The getter reads the flag byte at +456 and the setter writes the same byte.
Both selected target callbacks began as default `sub_` names. Their table
rows, roles, pseudocode, and complete ARM64 feature records agree, with exact
normalized and full metric matches and no layout or register-detail
difference.

The evidence is
`artifacts/spectron_guigraalctrl_isrendering_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guigraalctrl_isrendering_anchors.py`. Its
SHA-256 is
`bacbb0481379faab4134a7ff22007ff30a6b6215305531d84b8337f91da01578`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v256.i64`, with 11,696 functions and
775 remaining default `sub_` names. The database SHA-256 is
`51cc802c6c5ae38aa70bf09119f3caef12fe4e6907403d9a54211e79e110731c`.
The v256 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v256.json`. A clean serial
reopen verified both names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron GuiControl property tail aliases

The v255 pass translates four residual callbacks from the tail of the
`GuiControl` property table. The source table is at `0x3806a0` and the
corresponding Spectron table is at `0x393700`. Each table uses 0x30-byte
records, with getter and setter pointers at record offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiControl_getCursor` | `0x1ba398` | `0x1becbc` | `cursor` | `0x3809d0` | `0x393a30` | getter |
| `GuiControl_setFlickering` | `0x1b7450` | `0x1bbc10` | `flickering` | `0x380af0` | `0x393b50` | setter |
| `GuiControl_setIsInAnimation` | `0x1b7a34` | `0x1bc254` | `isinanimation` | `0x380c70` | `0x393cd0` | setter |
| `GuiControl_setIsInOutAnimation` | `0x1b7b64` | `0x1bc384` | `isininoutanimation` | `0x380ca0` | `0x393d00` | setter |

The cursor getter forwards the control cursor string. The flickering setter
updates the byte at +408 and invalidates the rectangle only when the value
changes. The ordinary-animation and in-or-out-animation setters stop their
respective animation groups when the incoming flag is false. These operations
and the source field offsets are preserved in the target pseudocode.

All four selected target callbacks began as default `sub_` names. Their
decoded property rows, getter or setter roles, pseudocode, and complete ARM64
feature records agree. Every row has an exact normalized shape and full metric
match, with no layout or register-detail difference.

The evidence is
`artifacts/spectron_guicontrol_property_tail_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_guicontrol_property_tail_anchors.py`. Its
SHA-256 is
`79289bc7d611ba4cb806e27c9e5c2afe3e9714aa07a57543cc859cf0ae279d3c`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v255.i64`, with 11,696 functions and
777 remaining default `sub_` names. The database SHA-256 is
`41201714ed45c2e165f0199268d1863fb6d7895f8067678c6614fc786c5254b6`.
The v255 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v255.json`. A clean serial
reopen verified all four names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron GuiBitmapButtonCtrl and GuiButtonBaseCtrl residual property aliases

The v254 pass translates 11 residual callbacks from two related GUI button
property blocks. The source `GuiBitmapButtonCtrl` rows are at
`0x380190`, `0x3801c0`, and `0x3801f0`, with corresponding Spectron rows at
`0x3931f0`, `0x393220`, and `0x393250`. The source `GuiButtonBaseCtrl` table is
at `0x3803a0`; the target table is at `0x393400`. All records are 0x30 bytes,
with getter and setter pointers at offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiBitmapButtonCtrl_get_mouseoverbitmap` | `0x1abf1c` | `0x1b00dc` | `mouseoverbitmap` | `0x380190` | `0x3931f0` | getter |
| `GuiBitmapButtonCtrl_get_normalbitmap` | `0x1abeec` | `0x1b00ac` | `normalbitmap` | `0x3801c0` | `0x393220` | getter |
| `GuiBitmapButtonCtrl_get_pressedbitmap` | `0x1abebc` | `0x1b007c` | `pressedbitmap` | `0x3801f0` | `0x393250` | getter |
| `GuiBitmapButtonCtrl_set_mouseoverbitmap` | `0x1ac6c4` | `0x1b0884` | `mouseoverbitmap` | `0x380190` | `0x3931f0` | setter |
| `GuiBitmapButtonCtrl_set_normalbitmap` | `0x1ac6bc` | `0x1b087c` | `normalbitmap` | `0x3801c0` | `0x393220` | setter |
| `GuiBitmapButtonCtrl_set_pressedbitmap` | `0x1ac6b4` | `0x1b0874` | `pressedbitmap` | `0x3801f0` | `0x393250` | setter |
| `GuiButtonBaseCtrl_get_buttontype` | `0x1ad278` | `0x1b1438` | `buttontype` | `0x3803a0` | `0x393400` | getter |
| `GuiButtonBaseCtrl_set_buttontype` | `0x1ad2b8` | `0x1b1478` | `buttontype` | `0x3803a0` | `0x393400` | setter |
| `GuiButtonBaseCtrl_get_groupnum` | `0x1ad268` | `0x1b1428` | `groupnum` | `0x380400` | `0x393460` | getter |
| `GuiButtonBaseCtrl_set_groupnum` | `0x1ad270` | `0x1b1430` | `groupnum` | `0x380400` | `0x393460` | setter |
| `GuiButtonBaseCtrl_get_text` | `0x1ad53c` | `0x1b16fc` | `text` | `0x380430` | `0x393490` | getter |

The bitmap-button getters copy the mouse-over, normal, and pressed strings
from +504, +488, and +520. Their setters pass mode values 1, 0, and 2 to the
shared bitmap assignment routine. The button-type getter indexes a name list
using +468, while its setter scans that list and stores the matching index.
The group-number pair reads and writes +472, and the text getter forwards to
the button control's text accessor. The target uses obfuscated string and
comparison helpers, but the pseudocode preserves these operations and field
offsets. The checked pair and the text setter already had target ABI names and
are not duplicated here.

All 11 selected target callbacks began as default `sub_` names. They all match
normalized ARM64 instruction shape and have no layout change. Nine match the
complete recorded metric set. The two button-type rows differ only in
register-detail hashes caused by target register allocation.

The machine-readable evidence is
`artifacts/spectron_gui_bitmap_button_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_bitmap_button_property_anchors.py`.
Its SHA-256 is
`3667221c20d23e527d2972177b7d9dbf62dc393c4b82717319dbaad53176fbd4`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v254.i64`, which contains 11,696
functions and 781 remaining default `sub_` names. The database SHA-256 is
`078918adcdeadc3fa6a894d07e0f9b1929dacaeb2043de3f9952ed8e2f9289e8`.
The v254 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v254.json`. A clean serial
reopen verified all 11 names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron GuiBitmapCtrl residual property aliases

The v253 pass translates the remaining default callbacks in the
`GuiBitmapCtrl` property table. The source table is at `0x380250`, the
Spectron table is at `0x3932b0`, and both use 0x30-byte records with getter and
setter pointers at record offsets `0x10` and `0x18`.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `GuiBitmapCtrl_get_bitmap` | `0x1aca14` | `0x1b0bd4` | `bitmap` | `0x380250` | `0x3932b0` | getter |
| `GuiBitmapCtrl_get_bitmaprectangle` | `0x1ac9f0` | `0x1b0bb0` | `bitmaprectangle` | `0x380280` | `0x3932e0` | getter |
| `GuiBitmapCtrl_get_fullbitmap` | `0x1ac998` | `0x1b0b58` | `fullbitmap` | `0x3802b0` | `0x393310` | getter |
| `GuiBitmapCtrl_set_fullbitmap` | `0x1ac9a0` | `0x1b0b60` | `fullbitmap` | `0x3802b0` | `0x393310` | setter |
| `GuiBitmapCtrl_get_tile` | `0x1ac9a8` | `0x1b0b68` | `tile` | `0x3802e0` | `0x393340` | getter |
| `GuiBitmapCtrl_get_tile` | `0x1ac9a8` | `0x1b0b68` | `wrap` | `0x380310` | `0x393370` | getter |

There are six registration rows and five distinct target functions. The
`tile` and `wrap` rows share one getter in both builds. The bitmap setter,
bitmap-rectangle setter, and shared tile or wrap setter were already named in
the target and are not duplicated here.

The bitmap getter copies the control string at +472. The rectangle getter
converts the rectangle at +484 into the script representation. The
`fullbitmap` getter and setter access the byte at +481, while the shared tile
or wrap getter reads the byte at +480. Spectron replaces the readable helper
names with obfuscated ones, but the decompiled operations and object offsets
remain unchanged.

All five selected target callbacks began as default `sub_` names and match the
complete recorded ARM64 feature metrics. This includes the function sizes,
instruction and control-flow counts, normalized instruction shape, and
register-detail hash. The aliases are therefore supported by both the
registration-table correspondence and exact body structure.

The machine-readable evidence is
`artifacts/spectron_gui_bitmap_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_bitmap_property_anchors.py`. Its
SHA-256 is
`97f715852440abf89f99ebf0887313a60aef15e26037045859cfc3f9718cafe1`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v253.i64`, which contains 11,696
functions and 792 remaining default `sub_` names. The database SHA-256 is
`924bca24389cf9c6f8d07ade1f6a7b31726c8bc7991f7fdbacf6e94967a5028c`.
The v253 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v253.json`. A clean serial
reopen verified all five names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron TGUIAnimation residual property aliases

The v252 pass translates the remaining default callbacks in the
`TGUIAnimationProperties` table. The source table is at `0x3823c0`, the
Spectron table is at `0x395420`, and both use 0x30-byte records. Getter and
setter pointers are stored at record offsets `0x10` and `0x18` respectively.
Table order and decoded property names provide the primary correspondence,
with pseudocode and the complete ARM64 feature metrics as independent checks.

| 1.8 callback | Source | Spectron target | Property | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `TGUIAnimation_get_currenttime` | `0x1c9718` | `0x1ce298` | `currenttime` | `0x3823c0` | `0x395420` | getter |
| `TGUIAnimation_set_currenttime` | `0x1c9720` | `0x1ce2a0` | `currenttime` | `0x3823c0` | `0x395420` | setter |
| `TGUIAnimation_get_amplitude` | `0x1c9708` | `0x1ce288` | `amplitude` | `0x382420` | `0x395480` | getter |
| `TGUIAnimation_set_amplitude` | `0x1c9710` | `0x1ce290` | `amplitude` | `0x382420` | `0x395480` | setter |
| `TGUIAnimation_get_bounds` | `0x1c9f00` | `0x1cea80` | `bounds` | `0x382450` | `0x3954b0` | getter |
| `TGUIAnimation_set_bounds` | `0x1c9fd0` | `0x1ceb50` | `bounds` | `0x382450` | `0x3954b0` | setter |
| `TGUIAnimation_get_delay` | `0x1c9728` | `0x1ce2a8` | `delay` | `0x382480` | `0x3954e0` | getter |
| `TGUIAnimation_set_delay` | `0x1c9730` | `0x1ce2b0` | `delay` | `0x382480` | `0x3954e0` | setter |
| `TGUIAnimation_get_duration` | `0x1c9738` | `0x1ce2b8` | `duration` | `0x3824b0` | `0x395510` | getter |
| `TGUIAnimation_set_duration` | `0x1c9740` | `0x1ce2c0` | `duration` | `0x3824b0` | `0x395510` | setter |
| `TGUIAnimation_get_interval` | `0x1c9748` | `0x1ce2c8` | `interval` | `0x3824e0` | `0x395540` | getter |
| `TGUIAnimation_set_interval` | `0x1c9750` | `0x1ce2d0` | `interval` | `0x3824e0` | `0x395540` | setter |
| `TGUIAnimation_get_sound` | `0x1c9780` | `0x1ce300` | `sound` | `0x382540` | `0x3955a0` | getter |
| `TGUIAnimation_get_tabfirstonshow` | `0x1c9770` | `0x1ce2f0` | `tabfirstonshow` | `0x382570` | `0x3955d0` | getter |
| `TGUIAnimation_set_tabfirstonshow` | `0x1c9778` | `0x1ce2f8` | `tabfirstonshow` | `0x382570` | `0x3955d0` | setter |
| `TGUIAnimation_get_timing` | `0x1c9bc4` | `0x1ce744` | `timing` | `0x3825a0` | `0x395600` | getter |
| `TGUIAnimation_get_transition` | `0x1c9b1c` | `0x1ce69c` | `transition` | `0x3825d0` | `0x395630` | getter |

The twelve decoded property names appear in the same order in both builds:
`currenttime`, `alpha`, `amplitude`, `bounds`, `delay`, `duration`, `interval`,
`rotation`, `sound`, `tabfirstonshow`, `timing`, and `transition`. The target
alpha and rotation getters and the sound setter were already named. The alpha,
rotation, timing, and transition setters retain target ABI jump labels and are
not duplicated in this source-to-target alias set. The 17 rows above are the
callbacks that were still default `sub_` names.

The scalar wrappers read or write the same animation state represented by the
source pseudocode. The float fields are current time at +120, delay at +136,
duration at +140, amplitude at +144, and interval at +148. The tab-first-on-
show flag is at +152 and the sound string is at +168. The bounds getter wraps
the rectangle returned by `getBounds`; the setter parses a script rectangle and
forwards it to `setBounds`. Timing and transition return their string wrappers.
The target uses obfuscated helper names, but the operations and table roles
remain clear.

All 17 rows are high-confidence semantic matches. They all match normalized
instruction shape and the complete recorded metric set. No target layout or
register-detail difference was observed in this group. The target callbacks
were all default names before the pass.

The machine-readable evidence is
`artifacts/spectron_tgui_animation_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tgui_animation_property_residual_anchors.py`.
Its SHA-256 is
`37c44d57508bd75d7fdca5116a3d3718fe93478fff7e58dc837dd20bcdab9d9c`.
The aliases are materialized in
`analysis/spectron_libqplay_translated_v252.i64`, which contains 11,696
functions and 797 remaining default `sub_` names. The database SHA-256 is
`90a0d433ed61969714d1c853823693ce4286e2d785e159535e7f68e06548af4b`.
The v252 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v252.json`. A clean serial
reopen verified all 17 names with zero failures. No APK or native library was
modified, and no DNS, HTTP, or TLS operation was performed.

## Spectron TDrawingPanel property and script residual aliases

The v250 pass translates the remaining unnamed callbacks from the source
`TDrawingPanel` property table at `0x377d38` and its `drawimagestretched`
function-table row. The target `.data` property copy starts at `0x38ad48`, and
the target function-table copy starts at `0x38af58`.

| 1.8 callback | Source | Spectron target | Script name | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `TDrawingPanel_get_height` | `0x117850` | `0x11a2b0` | `height` | `0x377d38` | `0x38ad48` | getter |
| `TDrawingPanel_get_height` | `0x117850` | `0x11a2b0` | `parth` | `0x377e28` | `0x38ae38` | getter |
| `TDrawingPanel_get_isclear` | `0x117830` | `0x11a290` | `isclear` | `0x377d68` | `0x38ad78` | getter |
| `TDrawingPanel_get_partx` | `0x117838` | `0x11a298` | `partx` | `0x377d98` | `0x38ada8` | getter |
| `TDrawingPanel_get_party` | `0x117840` | `0x11a2a0` | `party` | `0x377dc8` | `0x38add8` | getter |
| `TDrawingPanel_get_partw` | `0x117848` | `0x11a2a8` | `partw` | `0x377df8` | `0x38ae08` | getter |
| `TDrawingPanel_get_partw` | `0x117848` | `0x11a2a8` | `width` | `0x377eb8` | `0x38aec8` | getter |
| `TDrawingPanel_set_profile` | `0x11a358` | `0x11ce58` | `profile` | `0x377e58` | `0x38ae68` | setter |
| `TDrawingPanel_get_useownprofile` | `0x117858` | `0x11a2b8` | `useownprofile` | `0x377e88` | `0x38ae98` | getter |
| `TDrawingPanel_get_availablefilters` | `0x117868` | `0x11a2c8` | `availablefilters` | `0x377ee8` | `0x38aef8` | getter |
| `TDrawingPanel_get_enablecache` | `0x117828` | `0x11a288` | `enablecache` | `0x377f18` | `0x38af28` | getter |
| `TDrawingPanel_script_drawimagestretched` | `0x1182dc` | `0x11ad8c` | `drawimagestretched` | `0x377fd8` | `0x38afe8` | callback |

There are 12 residual registration rows and 10 distinct target callbacks.
The `height` getter is intentionally shared by `height` and `parth`, and the
`partw` getter is shared by `partw` and `width`. The profile getter,
`useownprofile` setter, and `enablecache` setter were already named in the
target and were not renamed a second time.

The scalar getters preserve their source fields and roles. The profile setter
still casts the script value to a `GuiControlProfile`, the filter getter still
turns the panel filter-name list into a script value, and the stretched-image
wrapper forwards the same ten arguments to the drawing implementation. All
10 anchors match normalized instruction shape. Eight match the complete
feature metrics; the profile and filter-list wrappers differ only in target
register allocation.

The evidence is
`artifacts/spectron_drawing_panel_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_drawing_panel_property_residual_anchors.py`.
The v250 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v250.json`, with 11,696
functions, 816 remaining default `sub_` names, and database SHA-256
`d9fa44a190b1b5014dd9e56651fd416c0e1923cba4e2cd8e361314a9ba7a046f`. A clean
serial reopen verified all 10 names with zero failures. No network endpoint
was contacted.

## Spectron residual TGaniObject and TGaniParam property aliases

The v249 pass translates the remaining callbacks in the main animation
property table. The source `TGaniObjectProperties` table starts at `0x37a5b0`
and the corresponding Spectron `.data` copy starts at `0x38d5d0`. Table-local
order, decoded property names, getter or setter roles, pseudocode, and ARM64
feature metrics all contribute to the correspondence.

| 1.8 callback | Source | Spectron target | Script name | Source record | Target record | Role |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `TGaniObject_getField280` | `0x15d4d0` | `0x160560` | `ani` | `0x37a5b0` | `0x38d5d0` | getter |
| `TGaniParam_getStringField304` | `0x15da98` | `0x160cf0` | `aniparams` | `0x37a5e0` | `0x38d600` | getter |
| `TGaniObject_getField292` | `0x15d4d8` | `0x160568` | `anistep` | `0x37a610` | `0x38d630` | getter |
| `TGaniObject_getChildField748` | `0x15d4e0` | `0x160570` | `attachid` | `0x37a640` | `0x38d660` | getter |
| `TGaniObject_getChildVisibilityInverted` | `0x15d4f8` | `0x160588` | `attachtype` | `0x37a670` | `0x38d690` | getter |
| `TGaniObject_getChildField144` | `0x15d514` | `0x1605a4` | `attachedtoobject` | `0x37a6a0` | `0x38d6c0` | getter |
| `TGaniObject_getField320` | `0x15d51c` | `0x1605ac` | `attr` | `0x37a6d0` | `0x38d6f0` | getter |
| `TGaniParam_getStringField376` | `0x15da68` | `0x160cc0` | `body` | `0x37a700` | `0x38d720` | getter |
| `TGaniParam_getStringField376` | `0x15da68` | `0x160cc0` | `bodyimg` | `0x37a730` | `0x38d750` | getter |
| `TGaniObject_getField448` | `0x15d524` | `0x1605b4` | `colors` | `0x37a760` | `0x38d780` | getter |
| `TGaniObject_callVirtual504` | `0x15d52c` | `0x1605bc` | `dir` | `0x37a790` | `0x38d7b0` | getter |
| `TGaniObject_getField576` | `0x15d590` | `0x160620` | `gmap` | `0x37a7c0` | `0x38d7e0` | getter |
| `TGaniParam_getStringField384` | `0x15da38` | `0x160c90` | `head` | `0x37a7f0` | `0x38d810` | getter |
| `TGaniParam_getStringField384` | `0x15da38` | `0x160c90` | `headimg` | `0x37a820` | `0x38d840` | getter |
| `TGaniParam_getStringField392` | `0x15da08` | `0x160c60` | `shield` | `0x37a880` | `0x38d8a0` | getter |
| `TGaniParam_getStringField400` | `0x15d9d8` | `0x160c30` | `sword` | `0x37a8b0` | `0x38d8d0` | getter |
| `TGaniObject_getFloatField460` | `0x15d598` | `0x160628` | `rotation` | `0x37a8e0` | `0x38d900` | getter |
| `TGaniObject_setFloatField460` | `0x15d5a0` | `0x160630` | `rotation` | `0x37a8e0` | `0x38d900` | setter |
| `TGaniParam_getPointField476` | `0x15db90` | `0x160c0c` | `rotationcenter` | `0x37a910` | `0x38d930` | getter |
| `TGaniParam_setPointField476` | `0x15db60` | `0x160be0` | `rotationcenter` | `0x37a910` | `0x38d930` | setter |
| `TGaniObject_getFloatField464` | `0x15d5a8` | `0x160638` | `stretchx` | `0x37a940` | `0x38d960` | getter |
| `TGaniObject_setFloatField464` | `0x15d5b0` | `0x160640` | `stretchx` | `0x37a940` | `0x38d960` | setter |
| `TGaniObject_getFloatField468` | `0x15d5b8` | `0x160648` | `stretchy` | `0x37a970` | `0x38d990` | getter |
| `TGaniObject_setFloatField468` | `0x15d5c0` | `0x160650` | `stretchy` | `0x37a970` | `0x38d990` | setter |
| `TGaniObject_getByteField472` | `0x15d5c8` | `0x160658` | `useowncenter` | `0x37a9a0` | `0x38d9c0` | getter |
| `TGaniObject_setByteField472` | `0x15d5d0` | `0x160660` | `useowncenter` | `0x37a9a0` | `0x38d9c0` | setter |
| `TGaniObject_getFloatField456` | `0x15d5d8` | `0x160668` | `zoom` | `0x37a9d0` | `0x38d9f0` | getter |
| `TGaniObject_setFloatField456` | `0x15d5e0` | `0x161530` | `zoom` | `0x37a9d0` | `0x38d9f0` | setter |
| `TGaniObject_getFloatField484` | `0x15d638` | `0x160708` | `red` | `0x37aa00` | `0x38da20` | getter |
| `TGaniObject_setFloatField484Clamped` | `0x15d640` | `0x160710` | `red` | `0x37aa00` | `0x38da20` | setter |
| `TGaniObject_getFloatField488` | `0x15d66c` | `0x16073c` | `green` | `0x37aa30` | `0x38da50` | getter |
| `TGaniObject_setFloatField488Clamped` | `0x15d674` | `0x160744` | `green` | `0x37aa30` | `0x38da50` | setter |
| `TGaniObject_getFloatField492` | `0x15d6a0` | `0x160770` | `blue` | `0x37aa60` | `0x38da80` | getter |
| `TGaniObject_setFloatField492Clamped` | `0x15d6a8` | `0x160778` | `blue` | `0x37aa60` | `0x38da80` | setter |
| `TGaniObject_getFloatField496` | `0x15d6d4` | `0x1607a4` | `alpha` | `0x37aa90` | `0x38dab0` | getter |
| `TGaniObject_setFloatField496Clamped` | `0x15d6dc` | `0x1607ac` | `alpha` | `0x37aa90` | `0x38dab0` | setter |
| `TGaniObject_getByteField500` | `0x15d61c` | `0x1606ec` | `mode` | `0x37aac0` | `0x38dae0` | getter |

This residual group contains 30 registration rows and 29 distinct target
callbacks. `head` and `headimg` intentionally share the getter at `0x160c90`,
matching the shared source getter at `0x15da38`. The existing v238 aliases for
`body`, `bodyimg`, and `enableganimoviereposition` are left intact and are
not renamed again here.

Eight callback anchors match the complete feature metrics. Eighteen more
match normalized instruction shape and differ only in register-detail
allocation. Three rows have larger shape changes: the rotation-center setter
is shorter in Spectron, and the zoom getter and setter implement an encoded
backing allocation rather than the direct 1.8 float field. The source and
target tables still provide a strong semantic anchor for those three cases.
The target object also moves the apparent rotation, stretch, center, and color
fields, so the old field-offset names are descriptive source aliases, not
claims that the target uses identical offsets.

The aliases are documented by
`artifacts/spectron_gani_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gani_property_residual_anchors.py`. The
v249 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v249.json`, with 11,696
functions, 826 remaining default `sub_` names, and database SHA-256
`50377973defadbbf25181fdad93a1fcc4a06480f20bcdbd180dd9a63dc27defa`. A clean
serial reopen verified all 29 renamed callbacks with zero failures. No
network endpoint was contacted.

## Spectron TPlayer property aliases

The v248 pass translates the residual main `TPlayer` property table. The
source table starts at `0x37b508`, the target table copy starts at `0x38e538`,
and records are 0x30 bytes apart. The target preserves the property order and
getter or setter roles, so the table gives stronger evidence than address
proximity alone.

| 1.8 callback | Source | Spectron target | Script name | Target record | Role |
| --- | ---: | ---: | --- | ---: | --- |
| `TPlayer_get_alliedguilds` | `0x16c9f4` | `0x1705cc` | `alliedguilds` | `0x38e538` | getter |
| `TPlayer_set_alliedguilds` | `0x16c9ec` | `0x1705c4` | `alliedguilds` | `0x38e538` | setter |
| `TPlayer_get_ap` | `0x16c1e8` | `0x16fda0` | `ap` | `0x38e568` | getter |
| `TPlayer_get_chat` | `0x16c844` | `0x1703bc` | `chat` | `0x38e598` | getter |
| `TPlayer_get_defaultwalkspeed` | `0x16c268` | `0x16fe20` | `defaultwalkspeed` | `0x38e5c8` | getter |
| `TPlayer_get_diagonalwalkspeed` | `0x16c2b0` | `0x16fe68` | `diagonalwalkspeed` | `0x38e5f8` | getter |
| `TPlayer_get_hearts` | `0x16c2f8` | `0x16feb0` | `hearts` | `0x38e658` | getter |
| `TPlayer_get_horseimg` | `0x16c814` | `0x17038c` | `horseimg` | `0x38e688` | getter |
| `TPlayer_get_hearts` | `0x16c2f8` | `0x16feb0` | `hp` | `0x38e6e8` | getter |
| `TPlayer_get_hurt` | `0x16c3f8` | `0x16ffb0` | `hurt` | `0x38e718` | getter |
| `TPlayer_get_hurtdx` | `0x16c370` | `0x16ff28` | `hurtdx` | `0x38e748` | getter |
| `TPlayer_get_hurtdy` | `0x16c378` | `0x16ff30` | `hurtdy` | `0x38e778` | getter |
| `TPlayer_get_hurted` | `0x16c380` | `0x16ff38` | `hurted` | `0x38e7a8` | getter |
| `TPlayer_get_hurtpower` | `0x16c470` | `0x170028` | `hurtpower` | `0x38e7d8` | getter |
| `TPlayer_get_isfemale` | `0x16c478` | `0x170030` | `isfemale` | `0x38e808` | getter |
| `TPlayer_get_isinvincible` | `0x16c484` | `0x17003c` | `isinvincible` | `0x38e838` | getter |
| `TPlayer_set_isinvincible` | `0x16cdec` | `0x170a58` | `isinvincible` | `0x38e838` | setter |
| `TPlayer_get_isinvincible2` | `0x16c4ac` | `0x170064` | `isinvincible2` | `0x38e868` | getter |
| `TPlayer_set_isinvincible2` | `0x16ce58` | `0x1709ec` | `isinvincible2` | `0x38e868` | setter |
| `TPlayer_get_ismale` | `0x16c4d4` | `0x17008c` | `ismale` | `0x38e898` | getter |
| `TPlayer_get_letters` | `0x16c7e4` | `0x17035c` | `letters` | `0x38e8f8` | getter |
| `TPlayer_set_letters` | `0x16c77c` | `0x170354` | `letters` | `0x38e8f8` | setter |
| `TPlayer_get_nick` | `0x16c874` | `0x1703ec` | `nick` | `0x38e958` | getter |
| `TPlayer_get_onhorse` | `0x16c584` | `0x17013c` | `onhorse` | `0x38e988` | getter |
| `TPlayer_get_shield` | `0x16c7b4` | `0x1704b4` | `shield` | `0x38ea48` | getter |
| `TPlayer_get_shield` | `0x16c7b4` | `0x1704b4` | `shieldimg` | `0x38ea78` | getter |
| `TPlayer_get_sword` | `0x16c784` | `0x170484` | `sword` | `0x38eb08` | getter |
| `TPlayer_get_sword` | `0x16c784` | `0x170484` | `swordimg` | `0x38eb38` | getter |
| `TPlayer_get_zoomfactor` | `0x16c68c` | `0x170244` | `zoomfactor` | `0x38eb68` | getter |
| `TPlayer_get_weapons` | `0x16c6c0` | `0x170278` | `weapons` | `0x38ebc8` | getter |

The 30 rows resolve to 27 target callbacks. The repeated callbacks are
intentional table aliases for `hearts` or `hp`, `shield` or `shieldimg`, and
`sword` or `swordimg`. The pass records all rows rather than collapsing them,
which keeps the script-visible names and registration records explicit.

All rows match normalized instruction shape. Seven rows match the complete
recorded feature metrics, covering chat, horse image, on-horse state, and the
two pairs of shared shield and sword registrations. The other 23 rows differ
only in register-detail allocation. There are no layout changes. The target
callbacks were all default `sub_` names before the pass, and a clean serial
reopen verified all 30 aliases with zero failures.

The machine-readable evidence is
`artifacts/spectron_player_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_player_property_anchors.py`. The v248
database checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v248.json`, with 11,696
functions, 855 remaining default `sub_` names, and database SHA-256
`780a8ac4584699546ef14a692bd520f13389f5c3918f45b37e33256718028165`. This
was an offline comparison and did not contact any endpoint.

## Spectron TTilesLayer property aliases

The v247 pass completes the residual `TTilesLayer` property table. The source
table starts at `0x37fb00`, the target table starts at `0x392b60`, and the
target retains the same property order and getter or setter roles.

| 1.8 callback | Source | Spectron target | Script name | Target record | Role |
| --- | ---: | ---: | --- | ---: | --- |
| `TTilesLayer_getAlpha` | `0x19f8b0` | `0x1a4580` | `alpha` | `0x392b60` | getter |
| `TTilesLayer_setAlpha` | `0x19f8b8` | `0x1a4588` | `alpha` | `0x392b60` | setter |
| `TTilesLayer_getBlue` | `0x19f8c0` | `0x1a4590` | `blue` | `0x392b90` | getter |
| `TTilesLayer_setBlue` | `0x19f8c8` | `0x1a4598` | `blue` | `0x392b90` | setter |
| `TTilesLayer_getGreen` | `0x19f8d0` | `0x1a45a0` | `green` | `0x392bc0` | getter |
| `TTilesLayer_setGreen` | `0x19f8d8` | `0x1a45a8` | `green` | `0x392bc0` | setter |
| `TTilesLayer_getLayerIndex` | `0x19f8e0` | `0x1a45b0` | `layerindex` | `0x392bf0` | getter |
| `TTilesLayer_getOffset` | `0x19fbcc` | `0x1a48a4` | `offset` | `0x392c20` | getter |
| `TTilesLayer_setOffset` | `0x19fb98` | `0x1a4870` | `offset` | `0x392c20` | setter |
| `TTilesLayer_getRed` | `0x19f8e8` | `0x1a45b8` | `red` | `0x392c50` | getter |
| `TTilesLayer_setRed` | `0x19f8f0` | `0x1a45c0` | `red` | `0x392c50` | setter |
| `TTilesLayer_getX` | `0x19f8f8` | `0x1a45c8` | `x` | `0x392c80` | getter |
| `TTilesLayer_setX` | `0x19f900` | `0x1a45d0` | `x` | `0x392c80` | setter |
| `TTilesLayer_getY` | `0x19f908` | `0x1a45d8` | `y` | `0x392cb0` | getter |
| `TTilesLayer_setY` | `0x19f910` | `0x1a45e0` | `y` | `0x392cb0` | setter |
| `TTilesLayer_getZ` | `0x19f918` | `0x1a45e8` | `z` | `0x392ce0` | getter |
| `TTilesLayer_setZ` | `0x19f920` | `0x1a45f0` | `z` | `0x392ce0` | setter |

The table covers color channels, layer index, offset, and three coordinates.
All 17 target callbacks were default `sub_` functions before application and
match the complete recorded ARM64 feature set. The mapping also corrects the
earlier loose source-address grouping for the red and coordinate rows. The
aliases reopened with zero failures in
`analysis/spectron_libqplay_translated_v247.i64`, which has 11,696 functions
and 882 remaining default `sub_` names. The evidence is in
`artifacts/spectron_tiles_layer_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tiles_layer_property_anchors.py`.
This was an offline IDA pass with no DNS, HTTP, TLS, APK, or native-library
operation.

## Spectron TServerNPC showimg callbacks

The v246 pass translates the two larger image-display callbacks in the
`TServerNPC` script-function table. The source table starts at `0x37c308` and
the target table starts at `0x38f368`; callback pointers are stored at
`+0x18`.

| 1.8 callback | Source | Spectron target | Script name | Target record | Arguments |
| --- | ---: | ---: | --- | ---: | --- |
| `TServerNPC_script_showImg` | `0x182f44` | `0x1875a0` | `showimg` | `0x38fba8` | image index, image string, X, Y |
| `TServerNPC_script_showImg2` | `0x182c84` | `0x18742c` | `showimg2` | `0x38fbd8` | image index, image string, X, Y, Z |

The source and target bodies keep the same image-list lookup and allocation
path, image-part reset, image assignment, coordinate updates, and final
refresh calls. `showimg2` adds the Z-coordinate write in both builds. Spectron
uses an explicit temporary string assignment and cleanup around the image
argument, expanding each body from 344 to 372 bytes. That target-version
detail explains the shape differences, so the aliases are semantic table
anchors rather than byte-identical claims.

The two target functions were default `sub_` names before application and
reopened with zero failures in
`analysis/spectron_libqplay_translated_v246.i64`, which has 11,696 functions
and 899 remaining default `sub_` names. The evidence is in
`artifacts/spectron_server_npc_showimg_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_server_npc_showimg_anchors.py`.
This was an offline IDA pass with no DNS, HTTP, TLS, APK, or native-library
operation.

## Spectron TServerNPC script callbacks

The v245 pass translates seven compact callbacks from the `TServerNPC`
script-function table. The source table starts at `0x37c308` and the target
table starts at `0x38f368`; callback pointers are stored at record offset
`+0x18`.

| 1.8 callback | Source | Spectron target | Script name | Target record |
| --- | ---: | ---: | --- | ---: |
| `TServerNPC_script_canBeCarried` | `0x1809e0` | `0x184f48` | `canbecarried` | `0x38f3f8` |
| `TServerNPC_script_cannotBeCarried` | `0x1809ec` | `0x184f54` | `cannotbecarried` | `0x38f428` |
| `TServerNPC_script_canBePushed` | `0x1809f4` | `0x184f5c` | `canbepushed` | `0x38f458` |
| `TServerNPC_script_cannotBePushed` | `0x180a00` | `0x184f68` | `cannotbepushed` | `0x38f488` |
| `TServerNPC_script_canBePulled` | `0x180a08` | `0x184f70` | `canbepulled` | `0x38f4b8` |
| `TServerNPC_script_cannotBePulled` | `0x180a14` | `0x184f7c` | `cannotbepulled` | `0x38f4e8` |
| `TServerNPC_script_timeEverywhere` | `0x180aa8` | `0x185010` | `timereverywhere` | `0x38fd58` |

The seven callbacks expose NPC carry, push, pull, and timer policy. Their
clear-text table names and direct pointers agree across builds, and all seven
target bodies preserve normalized ARM64 shape. The only recorded difference
is register-detail allocation. The aliases reopened with zero failures in
`analysis/spectron_libqplay_translated_v245.i64`, which has 11,696 functions
and 901 remaining default `sub_` names. The evidence is in
`artifacts/spectron_server_npc_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_server_npc_script_anchors.py`.
This was an offline IDA pass with no DNS, HTTP, TLS, APK, or native-library
operation.

## Spectron TServerNPC property aliases

The v244 pass translates six residual callbacks from the `TServerNPC` property
table at source `0x37be28` and target `0x38ee88`. The target retains the same
clear-text registrations for horse and NPC images, `peltwithnpc`, and the X/Y
coordinate setters.

| 1.8 callback | Source | Spectron target | Script name | Role |
| --- | ---: | ---: | --- | ---: |
| `TServerNPC_getHorseImg` | `0x180af8` | `0x185060` | `horseimg` | getter |
| `TServerNPC_setHorseImg` | `0x180ad4` | `0x18503c` | `horseimg` | setter |
| `TServerNPC_getImage` | `0x180b28` | `0x185090` | `image` | getter |
| `TServerNPC_getPeltWithNPC` | `0x180c80` | `0x1851e8` | `peltwithnpc` | getter |
| `TServerNPC_setX` | `0x186bd0` | `0x18b348` | `x` | setter |
| `TServerNPC_setY` | `0x186b68` | `0x18b2e0` | `y` | setter |

All six rows match normalized ARM64 instruction shape. The horse-image getter
and setter also match the complete recorded metric set. The other four rows
retain a register-detail difference only. No size, control-flow, or layout
mismatch was found. The larger NPC function table remains a separate review
target because its wrappers contain more varied logic. The aliases reopened
with zero failures in
`analysis/spectron_libqplay_translated_v244.i64`, which has 11,696 functions
and 908 remaining default `sub_` names. The evidence is in
`artifacts/spectron_server_npc_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_server_npc_property_anchors.py`.
This was an offline IDA pass with no DNS, HTTP, TLS, APK, or native-library
operation.

## Spectron TPlayer and TTranslations property aliases

The v243 pass translates nine residual callbacks from the auxiliary `TPlayer`
and `TTranslations` property tables. The source and target table copies retain
the same clear-text property names and callback roles, making the mapping
stronger than a size-only comparison.

| 1.8 callback | Source | Spectron target | Script name | Target table | Role |
| --- | ---: | ---: | --- | ---: | --- |
| `TPlayer_get_selectedlistplayers` | `0x16c6c8` | `0x170280` | `selectedlistplayers` | `0x38ed48` | getter |
| `TPlayer_get_disableapnoheal` | `0x16c1a8` | `0x16fd60` | `disableapnoheal` | `0x38ed48` | getter |
| `TPlayer_set_disableapnoheal` | `0x16c1b8` | `0x16fd70` | `disableapnoheal` | `0x38ed48` | setter |
| `TPlayer_get_disableapsaint` | `0x16c1c8` | `0x16fd80` | `disableapsaint` | `0x38ed48` | getter |
| `TPlayer_set_disableapsaint` | `0x16c1d8` | `0x16fd90` | `disableapsaint` | `0x38ed48` | setter |
| `TPlayer_get_disablenpchits` | `0x16c188` | `0x16fd40` | `disablenpchits` | `0x38ed48` | getter |
| `TPlayer_set_disablenpchits` | `0x16c198` | `0x16fd50` | `disablenpchits` | `0x38ed48` | setter |
| `TTranslations_get_pref__graal__language` | `0x191154` | `0x195bf4` | `pref::graal::language` | `0x390970` | getter |
| `TTranslations_get_installedlanguages` | `0x19118c` | `0x195c2c` | `installedlanguages` | `0x390970` | getter |

These nine rows all match normalized ARM64 instruction shape. The only
recorded difference is register-detail allocation, which is consistent with
the target's rebuilt global and string wrappers. The aliases reopened with
zero failures in
`analysis/spectron_libqplay_translated_v243.i64`, which has 11,696 functions
and 914 remaining default `sub_` names. The evidence is in
`artifacts/spectron_player_translation_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_player_translation_property_anchors.py`.
This was an offline IDA pass with no DNS, HTTP, TLS, APK, or native-library
operation.

## Spectron small world-object property aliases

The v242 pass translates 22 residual callbacks from five small property-table
families. The target `.data` table copies retain the original script-property
names and callback order, so these are direct table correspondences rather
than guesses based only on nearby addresses.

| 1.8 callback | Source | Spectron target | Script name | Target table | Role |
| --- | ---: | ---: | --- | ---: | --- |
| `TBitmap_get_jpegquality` | `0x150e80` | `0x153ca8` | `jpegquality` | `0x38b278` | getter |
| `TBitmap_set_jpegquality` | `0x150e90` | `0x153cb8` | `jpegquality` | `0x38b278` | setter |
| `TServerWeapon_getIsWeapon` | `0x190c68` | `0x1956a4` | `isweapon` | `0x390940` | getter |
| `TProjectile_getX` | `0x19eb88` | `0x1a3860` | `x` | `0x392738` | getter |
| `TProjectile_getY` | `0x19ebbc` | `0x1a3894` | `y` | `0x392738` | getter |
| `TProjectile_getZ` | `0x19ebf0` | `0x1a38c8` | `z` | `0x392738` | getter |
| `TProjectile_getAngle` | `0x19ec10` | `0x1a38e8` | `angle` | `0x392738` | getter |
| `TProjectile_getSpeed` | `0x19ec18` | `0x1a38f0` | `speed` | `0x392738` | getter |
| `TProjectile_getZSpeed` | `0x19ec20` | `0x1a38f8` | `zspeed` | `0x392738` | getter |
| `TProjectile_getHoriz` | `0x19ec28` | `0x1a3900` | `horiz` | `0x392738` | getter |
| `TProjectile_getFromPlayer` | `0x19ec30` | `0x1a3908` | `fromplayer` | `0x392738` | getter |
| `TProjectile_getFromPlayerId` | `0x19ec38` | `0x1a3910` | `fromplayerid` | `0x392738` | getter |
| `TProjectile_getParams` | `0x19ec40` | `0x1a3918` | `params` | `0x392738` | getter |
| `TProjectile_get_disableactionprojectile` | `0x19eb48` | `0x1a3820` | `disableactionprojectile` | `0x392918` | getter |
| `TProjectile_set_disableactionprojectile` | `0x19eb58` | `0x1a3830` | `disableactionprojectile` | `0x392918` | setter |
| `TProjectile_get_disableactionprojectile2` | `0x19eb68` | `0x1a3840` | `disableactionprojectile2` | `0x392918` | getter |
| `TProjectile_set_disableactionprojectile2` | `0x19eb78` | `0x1a3850` | `disableactionprojectile2` | `0x392918` | setter |
| `TServerLevelLink_getHeight` | `0x19f890` | `0x1a4560` | `height` | `0x392a10` | getter |
| `TServerLevelLink_getWidth` | `0x19f898` | `0x1a4568` | `width` | `0x392a10` | getter |
| `TServerLevelLink_getX` | `0x19f8a0` | `0x1a4570` | `x` | `0x392a10` | getter |
| `TServerLevelLink_getY` | `0x19f8a8` | `0x1a4578` | `y` | `0x392a10` | getter |
| `TServerLevel_get_preloadleveldefaulttile` | `0x19f928` | `0x1a45f8` | `preloadleveldefaulttile` | `0x3931c0` | getter |

The projectile rows are split across its ordinary property table and its
additional action-projectile table. That split is preserved in Spectron. The
level-link dimensions and coordinates remain a compact scalar block, while
the server-level preload callback stays in the adjacent level registration
table. This combination of table membership, decoded property name, callback
role, and function shape is the basis for each alias.

All 22 rows match normalized instruction shape. Eight match the complete
recorded feature set, and the other 14 differ only in register-detail hashes.
There are no control-flow or layout mismatches in this batch. The target
functions were default `sub_` names before application and now use the
`v18_` prefix. The evidence is in
`artifacts/spectron_world_object_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_world_object_property_anchors.py`. The
aliases were reopened successfully in
`analysis/spectron_libqplay_translated_v242.i64`, whose SHA-256 is
`6d8eb4e0dcacddce087564e3f14a7b355472cebac32f6854c007e98c740f5f44`.
This was an offline IDA pass with no DNS, HTTP, TLS, APK, or native-library
operation.

## Spectron TParticleEmitter GS2 modifier callbacks

The v241 pass resolves the three remaining default callbacks in the
`TParticleEmitter` script-function table. The source table starts at
`0x38ae10`, the canonical Spectron table starts at `0x39df60`, and the callback
pointer is stored at record offset `+0x18`.

| 1.8 callback | Source | Spectron target | Script name | Target record |
| --- | ---: | ---: | --- | ---: |
| `TParticleEmitter_script_addglobalmodifier` | `0x239414` | `0x2432b4` | `addglobalmodifier` | `0x39df60` |
| `TParticleEmitter_script_addlocalmodifier` | `0x239500` | `0x2433a0` | `addlocalmodifier` | `0x39df90` |
| `TParticleEmitter_script_addemitmodifier` | `0x2395ec` | `0x24348c` | `addemitmodifier` | `0x39dfc0` |

The wrappers parse their script arguments and dispatch to the corresponding
global, local, or template modifier path. All three rows match the complete
feature record, including control flow and register detail. They were default
`sub_` functions before the pass and reopened with zero rename failures.

The aliases are materialized in
`analysis/spectron_libqplay_translated_v241.i64`. The evidence is in
`artifacts/spectron_particle_emitter_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_particle_emitter_script_anchors.py`, and
the database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v241.json`. No DNS, HTTP,
TLS, APK, or native-library operation was part of this pass.

## Spectron TParticleEmitter property aliases

The v240 pass resolves the remaining default callbacks in the
`TParticleEmitterProperties` table. The source table is at `0x38a8d0` and the
canonical Spectron table is at `0x39da20`. The records are 0x30 bytes each and
retain the same decoded property order. Direct table pointers and complete
feature equality make this one of the cleanest residual translations.

| 1.8 callback | Source | Spectron target | Script name | Target record | Role |
| --- | ---: | ---: | --- | ---: | --- |
| `TParticleEmitter_get_attachposition` | `0x238188` | `0x242028` | `attachposition` | `0x39da20` | getter |
| `TParticleEmitter_set_attachposition` | `0x238190` | `0x242030` | `attachposition` | `0x39da20` | setter |
| `TParticleEmitter_get_autorotation` | `0x238198` | `0x242038` | `autorotation` | `0x39da50` | getter |
| `TParticleEmitter_set_autorotation` | `0x2381a0` | `0x242040` | `autorotation` | `0x39da50` | setter |
| `TParticleEmitter_get_checkbelowterrain` | `0x2381a8` | `0x242048` | `checkbelowterrain` | `0x39da80` | getter |
| `TParticleEmitter_set_checkbelowterrain` | `0x2381b0` | `0x242050` | `checkbelowterrain` | `0x39da80` | setter |
| `TParticleEmitter_get_clippingbox` | `0x2385b8` | `0x242458` | `clippingbox` | `0x39dab0` | getter |
| `TParticleEmitter_get_cliptoscreen` | `0x2381b8` | `0x242058` | `cliptoscreen` | `0x39dae0` | getter |
| `TParticleEmitter_set_cliptoscreen` | `0x2381c0` | `0x242060` | `cliptoscreen` | `0x39dae0` | setter |
| `TParticleEmitter_get_continueafterdestroy` | `0x2381c8` | `0x242068` | `continueafterdestroy` | `0x39db10` | getter |
| `TParticleEmitter_set_continueafterdestroy` | `0x2381d0` | `0x242070` | `continueafterdestroy` | `0x39db10` | setter |
| `TParticleEmitter_get_currentparticlecount` | `0x2381d8` | `0x242078` | `currentparticlecount` | `0x39db40` | getter |
| `TParticleEmitter_get_delaymax` | `0x2381e0` | `0x242080` | `delaymax` | `0x39db70` | getter |
| `TParticleEmitter_get_delaymin` | `0x238210` | `0x2420b0` | `delaymin` | `0x39dba0` | getter |
| `TParticleEmitter_get_emissionoffset` | `0x238548` | `0x2423e8` | `emissionoffset` | `0x39dc30` | getter |
| `TParticleEmitter_set_emissionoffset` | `0x238514` | `0x2423b4` | `emissionoffset` | `0x39dc30` | setter |
| `TParticleEmitter_get_emitatterrainheight` | `0x238240` | `0x2420e0` | `emitatterrainheight` | `0x39dc60` | getter |
| `TParticleEmitter_set_emitatterrainheight` | `0x238248` | `0x2420e8` | `emitatterrainheight` | `0x39dc60` | setter |
| `TParticleEmitter_get_emitautomatically` | `0x238250` | `0x2420f0` | `emitautomatically` | `0x39dc90` | getter |
| `TParticleEmitter_set_emitautomatically` | `0x238258` | `0x2420f8` | `emitautomatically` | `0x39dc90` | setter |
| `TParticleEmitter_get_emittedparticles` | `0x238260` | `0x242100` | `emittedparticles` | `0x39dcc0` | getter |
| `TParticleEmitter_get_firstinfront` | `0x238268` | `0x242108` | `firstinfront` | `0x39dcf0` | getter |
| `TParticleEmitter_set_firstinfront` | `0x238270` | `0x242110` | `firstinfront` | `0x39dcf0` | setter |
| `TParticleEmitter_get_forceaboveterrain` | `0x238278` | `0x242118` | `forceaboveterrain` | `0x39dd20` | getter |
| `TParticleEmitter_set_forceaboveterrain` | `0x238280` | `0x242120` | `forceaboveterrain` | `0x39dd20` | setter |
| `TParticleEmitter_get_isfrozen` | `0x238288` | `0x242128` | `isfrozen` | `0x39dd50` | getter |
| `TParticleEmitter_get_maxparticles` | `0x238290` | `0x242130` | `maxparticles` | `0x39dd80` | getter |
| `TParticleEmitter_get_movementfactor` | `0x238298` | `0x242138` | `movementfactor` | `0x39ddb0` | getter |
| `TParticleEmitter_set_movementfactor` | `0x2382a0` | `0x242140` | `movementfactor` | `0x39ddb0` | setter |
| `TParticleEmitter_get_noclipping` | `0x2382a8` | `0x242148` | `noclipping` | `0x39dde0` | getter |
| `TParticleEmitter_set_noclipping` | `0x2382b0` | `0x242150` | `noclipping` | `0x39dde0` | setter |
| `TParticleEmitter_get_nrofparticles` | `0x2382b8` | `0x242158` | `nrofparticles` | `0x39de10` | getter |
| `TParticleEmitter_get_particle` | `0x23841c` | `0x2422bc` | `particle` | `0x39de40` | getter |
| `TParticleEmitter_get_particletypes` | `0x2382c0` | `0x242160` | `particletypes` | `0x39de70` | getter |
| `TParticleEmitter_get_showonground` | `0x2382cc` | `0x24216c` | `showonground` | `0x39dea0` | getter |
| `TParticleEmitter_set_showonground` | `0x2382d4` | `0x242174` | `showonground` | `0x39dea0` | setter |
| `TParticleEmitter_get_showontop` | `0x2382dc` | `0x24217c` | `showontop` | `0x39ded0` | getter |
| `TParticleEmitter_set_showontop` | `0x2382e4` | `0x242184` | `showontop` | `0x39ded0` | setter |
| `TParticleEmitter_get_switchyandzaxis` | `0x2382ec` | `0x24218c` | `switchyandzaxis` | `0x39df00` | getter |
| `TParticleEmitter_set_switchyandzaxis` | `0x2382f4` | `0x242194` | `switchyandzaxis` | `0x39df00` | setter |
| `TParticleEmitter_get_wraptoclippingbox` | `0x2382fc` | `0x24219c` | `wraptoclippingbox` | `0x39df30` | getter |
| `TParticleEmitter_set_wraptoclippingbox` | `0x238304` | `0x2421a4` | `wraptoclippingbox` | `0x39df30` | setter |

The table accounts for 26 getters and 16 setters that were still default
functions. The already-translated entries are the `clippingbox`, `delaymax`,
and `delaymin` setters, the `dropemitter` and `dropwateremitter` getters, and
the bounded setters for `isfrozen`, `maxparticles`, `nrofparticles`, and
`particletypes`. The target property table therefore remains fully accounted
for without renaming a callback twice.

The getter and setter bodies are direct field accessors except for the point or
box object wrappers and the indexed `particle` lookup. Source and target
pseudocode preserve those operations. All 42 selected rows match the complete
feature record, including size, instruction count, control-flow shape, calls,
and register detail.

The aliases are materialized in
`analysis/spectron_libqplay_translated_v240.i64`. The machine-readable record
is `artifacts/spectron_particle_emitter_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_particle_emitter_property_anchors.py`.
The v240 checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v240.json`. The clean
reopen verified all 42 names. No DNS, HTTP, TLS, APK, or native-library
operation was part of this pass.

## Spectron TOptions preference property aliases

The v239 pass resolves 30 residual callbacks from the `TOptions` static
property table. The source table starts at `0x37b148`, while the canonical
Spectron table starts at `0x38e168`. The table names, source getter or setter
roles, and matching decompiled global accesses provide the mapping even though
the target's C++ names are obfuscated.

| 1.8 callback | Source | Spectron target | Script name | Target record | Role |
| --- | ---: | ---: | --- | ---: | --- |
| `TOptions_get_graalplugincookie` | `0x16a4b8` | `0x16df10` | `graalplugincookie` | `0x38e168` | getter |
| `TOptions_get_isgraalplugin` | `0x16a26c` | `0x16dcc4` | `isgraalplugin` | `0x38e198` | getter |
| `TOptions_get_pref__graal__dontsavepasswords` | `0x16a27c` | `0x16dcd4` | `$pref::graal::dontsavepasswords` | `0x38e1c8` | getter |
| `TOptions_set_pref__graal__dontsavepasswords` | `0x16a28c` | `0x16dce4` | `$pref::graal::dontsavepasswords` | `0x38e1c8` | setter |
| `TOptions_get_pref__graal__limitnicknames` | `0x16a29c` | `0x16dcf4` | `$pref::graal::limitnicknames` | `0x38e1f8` | getter |
| `TOptions_set_pref__graal__limitnicknames` | `0x16a2ac` | `0x16dd04` | `$pref::graal::limitnicknames` | `0x38e1f8` | setter |
| `TOptions_get_pref__graal__nicknamelimit` | `0x16a2bc` | `0x16dd14` | `$pref::graal::nicknamelimit` | `0x38e228` | getter |
| `TOptions_set_pref__graal__nicknamelimit` | `0x16a2cc` | `0x16dd24` | `$pref::graal::nicknamelimit` | `0x38e228` | setter |
| `TOptions_get_drawallinsidenpcs` | `0x16a2dc` | `0x16dd34` | `drawallinsidenpcs` | `0x38e258` | getter |
| `TOptions_set_drawallinsidenpcs` | `0x16a2ec` | `0x16dd44` | `drawallinsidenpcs` | `0x38e258` | setter |
| `TOptions_get_lighteffectsenabled` | `0x16a2fc` | `0x16dd54` | `lighteffectsenabled` | `0x38e288` | getter |
| `TOptions_set_lighteffectsenabled` | `0x16a30c` | `0x16dd64` | `lighteffectsenabled` | `0x38e288` | setter |
| `TOptions_get_weathereffectsenabled` | `0x16a31c` | `0x16dd74` | `weathereffectsenabled` | `0x38e2b8` | getter |
| `TOptions_set_weathereffectsenabled` | `0x16a32c` | `0x16dd84` | `weathereffectsenabled` | `0x38e2b8` | setter |
| `TOptions_get_particleeffectsenabled` | `0x16a33c` | `0x16dd94` | `particleeffectsenabled` | `0x38e2e8` | getter |
| `TOptions_set_particleeffectsenabled` | `0x16a34c` | `0x16dda4` | `particleeffectsenabled` | `0x38e2e8` | setter |
| `TOptions_get_pref__audio__reversestereo` | `0x16a35c` | `0x16ddb4` | `$pref::audio::reversestereo` | `0x38e318` | getter |
| `TOptions_set_pref__audio__reversestereo` | `0x16a36c` | `0x16ddc4` | `$pref::audio::reversestereo` | `0x38e318` | setter |
| `TOptions_get_pref__audio__midivolume` | `0x16a37c` | `0x16ddd4` | `$pref::audio::midivolume` | `0x38e348` | getter |
| `TOptions_set_pref__audio__midivolume` | `0x16a38c` | `0x16dde4` | `$pref::audio::midivolume` | `0x38e348` | setter |
| `TOptions_get_pref__audio__mp3volume` | `0x16a39c` | `0x16ddf4` | `$pref::audio::mp3volume` | `0x38e378` | getter |
| `TOptions_set_pref__audio__mp3volume` | `0x16a3ac` | `0x16de04` | `$pref::audio::mp3volume` | `0x38e378` | setter |
| `TOptions_get_pref__audio__radiovolume` | `0x16a3bc` | `0x16de14` | `$pref::audio::radiovolume` | `0x38e3a8` | getter |
| `TOptions_set_pref__audio__radiovolume` | `0x16a3cc` | `0x16de24` | `$pref::audio::radiovolume` | `0x38e3a8` | setter |
| `TOptions_get_pref__audio__sfxvolume` | `0x16a3dc` | `0x16de34` | `$pref::audio::sfxvolume` | `0x38e3d8` | getter |
| `TOptions_set_pref__audio__sfxvolume` | `0x16a3ec` | `0x16de44` | `$pref::audio::sfxvolume` | `0x38e3d8` | setter |
| `TOptions_get_pref__video__defaultguistyle` | `0x16a480` | `0x16ded8` | `$pref::video::defaultguistyle` | `0x38e408` | getter |
| `TOptions_get_pref__video__externalguistyle` | `0x16a448` | `0x16dea0` | `$pref::video::externalguistyle` | `0x38e438` | getter |
| `TOptions_get_pref__video__screenshotformat` | `0x16a410` | `0x16de68` | `$pref::video::screenshotformat` | `0x38e468` | getter |
| `TOptions_set_pref__video__screenshotformat` | `0x16a3fc` | `0x16de54` | `$pref::video::screenshotformat` | `0x38e468` | setter |

The first two rows expose plugin state. The Graal preference rows cover the
password-save switch, nickname validation, and nickname length. The rendering
rows cover NPC drawing, light, weather, and particles. The audio rows cover
reverse stereo and MIDI, MP3, radio, and SFX volume. The final rows copy or
store the default GUI style, external GUI style, and screenshot format strings.

The target setters for `defaultguistyle` and `externalguistyle` were already
translated in the earlier v100 options pass at `0x16e03c` and `0x16df48`, so
they are not duplicated in this batch. The remaining 30 target callbacks all
started with default `sub_` names. Their normalized ARM64 instruction shape
matches the source rows, while the register-detail hash differs in each case
because the target uses rebuilt string and global-access helpers. This is a
translation record, not a claim that the two binaries are byte-identical.

The aliases are materialized in
`analysis/spectron_libqplay_translated_v239.i64`. The machine-readable record
is `artifacts/spectron_options_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_options_property_anchors.py`. The v239
checkpoint is `artifacts/spectron_translation_checkpoint_20260828_v239.json`.
The clean reopen verified all 30 names. No DNS, HTTP, TLS, APK, or native
library operation was part of this pass.

## Spectron TGaniObject and TGaniParam property aliases

The v238 pass resolves eight residual target callbacks from the animation
property tables. The source table begins at `0x37a5b0`. Spectron adds an
`adventure_getbuildtime` row before the corresponding block, so its `ani` row
begins at `0x38d5d0` and the selected rows follow from there.

| 1.8 callback | Source | Spectron target | Script name | Target record |
| --- | ---: | ---: | --- | ---: |
| `TGaniParam_getStringField304` | `0x15da98` | `0x160cf0` | `aniparams` | `0x38d600` |
| `TGaniObject_getField292` | `0x15d4d8` | `0x160568` | `anistep` | `0x38d630` |
| `TGaniObject_getField320` | `0x15d51c` | `0x1605ac` | `attr` | `0x38d6f0` |
| `TGaniParam_getStringField376` | `0x15da68` | `0x160cc0` | `body` | `0x38d720` |
| `TGaniObject_getField448` | `0x15d524` | `0x1605b4` | `colors` | `0x38d780` |
| `TGaniObject_getField576` | `0x15d590` | `0x160620` | `gmap` | `0x38d7e0` |
| `TGaniObject_getEnableMovieReposition` | `0x15d4b0` | `0x160540` | `enableganimoviereposition` | `0x38db70` |
| `TGaniObject_setEnableMovieReposition` | `0x15d4c0` | `0x160550` | `enableganimoviereposition` | `0x38db70` |

The `body` getter is also registered under `bodyimg` in both builds and points
to the same function. Its setter was already translated. The other rows are
direct field copies, and the movie-reposition pair reads and writes a single
global flag. Five rows match the complete feature metrics, one has only a
register-detail difference, and the two global wrappers use a different
target instruction form while preserving the same operation.

The aliases are materialized in
`analysis/spectron_libqplay_translated_v238.i64`. The machine-readable record
is `artifacts/spectron_gani_property_manual_translation_anchors_20260828.json`,
and the persisted checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v238.json`. The clean
reopen verified all eight names. No network operation was part of this pass.

## Spectron TLevelObject property aliases

The v237 pass resolves the target's remaining level-object property callbacks
and materializes the missing `z` getter boundary. The source property table is
at `0x37b048`; the canonical target `.data` copy starts at `0x38e068`.

| 1.8 callback | Source | Spectron target | Script name | Target record |
| --- | ---: | ---: | --- | ---: |
| `TLevelObject_getLevel` | `0x1698b0` | `0x16d308` | `level` | `0x38e068` |
| `TLevelObject_getX` | `0x1698b8` | `0x16d310` | `x` | `0x38e098` |
| `TLevelObject_setX` | `0x1698ec` | `0x16d344` | `x` | `0x38e098` |
| `TLevelObject_getY` | `0x169960` | `0x16d3b8` | `y` | `0x38e0c8` |
| `TLevelObject_setY` | `0x169994` | `0x16d3ec` | `y` | `0x38e0c8` |
| `TLevelObject_getZ` | `0x169a08-0x169a28` | `0x16d460-0x16d480` | `z` | `0x38e0f8` |
| `TLevelObject_getLayer` | `0x169a28` | `0x16d480` | `layer` | `0x38e128` |

The level getter returns the owning level. The x and y accessors preserve the
64-pixels-per-tile conversion, ordinary-object clamping, and vtable position
dispatch. The layer getter keeps the source mapping from internal layer values
to script-visible values. The target's `TLevelObject_setZ` callback was already
translated in an earlier pass and sits immediately after the recovered getter.

IDA had no function boundary for the target z callback in v236. The property
row points directly to `0x16d460`, where the raw code contains eight complete
instructions and returns at `0x16d47c`. The next known function starts at
`0x16d480`, establishing the reviewed range. Once materialized, the target
feature export matched all source metrics for this getter. The other six rows
also match every recorded feature field, giving seven complete metric matches
in total.

The aliases are materialized in
`analysis/spectron_libqplay_translated_v237.i64`. The machine-readable anchor
record is
`artifacts/spectron_level_object_property_manual_translation_anchors_20260828.json`,
and the persisted checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v237.json`. The clean
reopen verified all seven names and the recovered boundary. No network
operation was part of this pass.

## Spectron identification, time, file, and input callback aliases

The v236 pass uses decoded registration rows to translate 22 target callbacks
that IDA initially displayed as `sub_` functions. The address pairs below are
semantic correspondences between the 1.8 IDB and the stripped Spectron target.
The target records are from the `.data` copy of the script tables. A duplicate
`.data.rel.ro` copy exists, but it is not used as the canonical target address
in this archive.

| 1.8 callback | Source | Spectron target | Script name | Target table record |
| --- | ---: | ---: | --- | ---: |
| `TIdentification_script_getOSID` | `0xec6d8` | `0xed694` | `adventure_getosid` | `0x3898d8` |
| `TIdentification_script_getNetworkID` | `0xec270` | `0xed0b8` | `adventure_getnetworkid` | `0x389908` |
| `TIdentification_script_getSystemID` | `0xec7ac` | `0xed77c` | `adventure_getsystemid` | `0x389938` |
| `TTime_script_adventure_getframetick` | `0xf6e58` | `0xf87d0` | `adventure_getframetick` | `0x3899f8` |
| `TTime_script_adventure_setframetick` | `0xf6e68` | `0xf87e0` | `adventure_setframetick` | `0x389a28` |
| `TFileScripting_script_getScriptAccessFile` | `0xfc880` | `0xfee28` | `getscriptaccessfile` | `0x389be0` |
| `TFileScripting_script_escapeFilename` | `0xfbba4` | `0xfe124` | `escapefilename` | `0x389c40` |
| `TFileScripting_script_removeEscapesFromFilename` | `0xfbeec` | `0xfe46c` | `removeescapesfromfilename` | `0x389c70` |
| `TFileScripting_script_freeAllResources` | `0xfbe68` | `0xfe3e8` | `freeallresources` | `0x389d00` |
| `TFileScripting_script_findFiles` | `0xfbe20` | `0xfe3a0` | `findfiles` | `0x389d30` |
| `TFileScripting_script_extractFileExt` | `0xfbb84` | `0xfe104` | `extractfileext` | `0x389d60` |
| `TFileScripting_script_getExtension` | `0xfbb64` | `0xfe0e4` | `getextension` | `0x389d90` |
| `TFileScripting_script_setFileModTime` | `0xfc540` | `0xfeac0` | `adventure_setfilemodtime` | `0x389e20` |
| `TFileScripting_script_extractFileBase` | `0xfbc5c` | `0xfe1dc` | `extractfilebase` | `0x38a000` |
| `TFileScripting_script_extractFilename` | `0xfbb44` | `0xfe0c4` | `extractfilename` | `0x38a030` |
| `TFileScripting_script_extractFilepath` | `0xfbb24` | `0xfe0a4` | `extractfilepath` | `0x38a060` |
| `TControlBinding_getAction` | `0x168b10` | `0x16c4e8` | `action` | `0x38deb8` |
| `TControlBinding_getKeycode` | `0x168b18` | `0x16c4f0` | `keycode` | `0x38dee8` |
| `TControlBinding_getKeytext` | `0x168e40` | `0x16c840` | `keytext` | `0x38df18` |
| `TControlBinding_getSlot` | `0x168b20` | `0x16c4f8` | `slot` | `0x38df48` |
| `TInput_getHardwareKeyboardEnabled` | `0x168af0` | `0x16c4c8` | `enablehardwarekeyboard` | `0x38df78` |
| `TInput_setHardwareKeyboardEnabled` | `0x168b00` | `0x16c4d8` | `enablehardwarekeyboard` | `0x38df78` |

The identification callbacks call the corresponding native ID methods. The
time callbacks access one global frame-tick value. The target getter is also
registered as `getframetick`, matching the source's second `getFrameTick` row;
the duplicate registration points to the same callback in each build.

The file callbacks preserve the old wrapper roles. They resolve script-access
paths, escape and unescape filenames, clean resources, enumerate files, split
path components, and update UTC modification times. The target
`setFileModTime` implementation is expanded from 324 to 364 bytes, but both
decompilations choose between an explicit filesystem path and a packaged level
resource before applying the timestamp. It remains a high-confidence semantic
anchor, with its metric differences visible in the JSON artifact.

The control-binding getters read the action, keycode, key text, and slot
fields. The key-text path calls the native key-description helper. The final
getter and setter access the global hardware-keyboard flag. Across all 22 rows,
21 match the normalized instruction shape and 17 match the complete feature
record. Five have only register-detail changes, and one is the expanded file
timestamp wrapper.

The aliases are materialized in
`analysis/spectron_libqplay_translated_v236.i64`. The machine-readable anchor
record is
`artifacts/spectron_time_files_input_manual_translation_anchors_20260828.json`,
and the persisted checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v236.json`. The clean
reopen verified all 22 names. No network operation was part of this pass.

## Spectron GSFunctionsClient and GuiControl property aliases

The v235 pass adds 12 high-confidence aliases from the decoded GSFunctionsClient
and GuiControl property tables. Each row has a source registration, a target
registration, a direct callback pointer, and matching decompiled behavior.

| 1.8 role | Source | Spectron target | Source table | Target table |
| --- | ---: | ---: | ---: | ---: |
| `GSFunctionsClient_get_carriesbush` | `0x1565ec` | `0x159414` | `0x378388` | `0x38b398` |
| `GSFunctionsClient_get_carriessign` | `0x156640` | `0x159468` | `0x3783b8` | `0x38b3c8` |
| `GSFunctionsClient_get_carriesvase` | `0x156694` | `0x1594bc` | `0x3783e8` | `0x38b3f8` |
| `GSFunctionsClient_get_carriesstone` | `0x1566e8` | `0x159510` | `0x378418` | `0x38b428` |
| `GSFunctionsClient_get_carriesblackstone` | `0x15673c` | `0x159564` | `0x378448` | `0x38b458` |
| `GSFunctionsClient_get_mousescreeny` | `0x1571d8` | `0x15a000` | `0x378958` | `0x38b968` |
| `GSFunctionsClient_get_mousescreenx` | `0x157234` | `0x15a05c` | `0x378928` | `0x38b938` |
| `GSFunctionsClient_set_mousescreeny` | `0x157290` | `0x15a0b8` | `0x378958` | `0x38b968` |
| `GSFunctionsClient_set_mousescreenx` | `0x157304` | `0x15a12c` | `0x378928` | `0x38b938` |
| `GuiControl_setClientHeight` | `0x1b27cc` | `0x1b6ccc` | `0x3808c8` | `0x393910` |
| `GuiControl_setClientWidth` | `0x1b2818` | `0x1b6d18` | `0x3808f8` | `0x393940` |
| `GuiControl_getIsInAnimation` | `0x1b2944` | `0x1b6e44` | `0x380c80` | `0x393cd0` |

The carried-object rows test the action player's current sprite against the
requested bush, sign, vase, stone, or blackstone object. The mouse getter and
setter pairs use the canvas cursor and active-player origin, so the exposed
values are screen-relative coordinates. The two geometry setters preserve the
source control-bound calculation and virtual layout callback. The animation
getter returns whether the animation object has a positive frame count.

All 12 pairs match normalized instruction shape. The nine GSFunctionsClient
rows differ only in the register-detail hash caused by the target's rebuilt
layout. The three GuiControl rows match the complete recorded feature metrics.
All target functions began as default `sub_` names and reopened with the
reviewed `v18_` aliases.

The v235 database contains 11,695 functions and 1,056 remaining default
`sub_` names. Its SHA-256 is
`b58d447613b039f930e5ecd179a56a0e5ad19958715445f0663272dc830e0719`.
The machine-readable evidence is in
`artifacts/spectron_gsfunctions_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gsfunctions_property_anchors.py`. The
generic apply and reopen helpers are
`tools/ida_apply_spectron_manual_anchors.py` and
`tools/ida_verify_spectron_manual_anchors.py`. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v235.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron tclient_setplayerhurt boundary recovery

The v234 pass recovers a function boundary that IDA had not created for one
target property callback.

| 1.8 role | Source range | Spectron range | Property-table evidence |
| --- | ---: | ---: | --- |
| `TClient_script_tclient_setplayerhurt` | `0x1ed158-0x1ed1e4` | `0x1f1b08-0x1f1b94` | target record `0x398010`, callback pointer `0x398028` |

The target entry checks the active-player singleton, object state, and target
no-hurt byte before returning. Its continuation calls the target no-hurt
helper, preserves the script arguments, and tail-branches to
`v18_TClient_hurtPlayer` at `0x1f1b90`. The next known target function begins
at `0x1f1b94`, so the complete callback range is recovered directly from raw
control flow and table context. The moved target fields account for the
semantic rather than byte-identical comparison.

The materialized target is now named
`v18_TClient_script_tclient_setplayerhurt`. The reopened v234 copy has 11,695
functions and 1,068 remaining default `sub_` names, with SHA-256
`c7dda722fbab84a403ed8ba21351af98dc01e181c640c5048c126b2ff4f669b2`.
The evidence is in
`artifacts/spectron_tclient_playerhurt_property_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_tclient_playerhurt_anchor.py`. The
existing manual-anchor apply and reopen helpers are
`tools/ida_apply_spectron_manual_anchors.py` and
`tools/ida_verify_spectron_manual_anchors.py`. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v234.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron-only property callback labels

The v233 pass gives three callbacks from the target property tables descriptive
names while keeping them outside the 1.8-to-Spectron mapping count. Their
roles are fixed by the decoded property names, table records, direct callback
xrefs, function boundaries, and reviewed target pseudocode.

| Spectron target | Property name | Target label | Target role |
| ---: | --- | --- | --- |
| `0x1f00f8` | `setdebugdatahandlers` | `spectron_setdebugdatahandlers` | bounded copy into `w6qzgacqqy::kr8GxaAIUX` |
| `0x1f0010` | `adventure_setdebugdatahandlersauthorization` | `spectron_adventure_setdebugdatahandlersauthorization` | bounded copy into `w6qzgacqqy::nz6Gxas8SX` |
| `0x1f2160` | `tclient_setotherplayerprops` | `spectron_tclient_setotherplayerprops_adapter` | positive-result ABI adapter |

The first callback is registered at `0x398670` and the second at `0x3986a0`.
Their callback xrefs are `0x398688` and `0x3986b8`. Each clears a 1024-byte
global and copies no more than 256 integer values from the array-like script
argument. The third callback is registered at `0x398430`, with callback xref
`0x398448`. It checks the result value and forwards to the already translated
`v18_TClient_updateGlobalPlayer` implementation.

These rows have no demonstrated 1.8 source registration. The `spectron_`
prefix records that boundary directly, while the existing `v18_` prefix stays
reserved for reviewed cross-build correspondences. The target-only artifact
records three high-confidence labels, zero source counterparts, two debug
handler callbacks, and one ABI adapter.

The labels reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v233.i64`.
The copy has 11,694 functions and 1,068 remaining default `sub_` names, with
SHA-256
`21fa935e68dd605c0549656df3a3b832d0c91e080b7d703b2042132ba078ddd6`.
The evidence is in
`artifacts/spectron_target_only_callback_labels_20260828.json`, generated by
`tools/generate_spectron_target_only_labels.py`. The IDA apply and reopen
helpers are `tools/ida_apply_spectron_target_only_labels.py` and
`tools/ida_verify_spectron_target_only_labels.py`. The checkpoint is
`artifacts/spectron_translation_checkpoint_20260828_v233.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron TClient inbound handler correction and aliases

The v232 pass revisits the 85-entry inbound handler table because a prior
feature-only match landed on the wrong class. The source table begins at
`0x369960`, the target table at `0x37c730`, and both use eight-byte function
pointers. Two target slots were still default-named:

| Handler index | 1.8 role | Source | Spectron target | Target table record | Target name before alias |
| ---: | --- | ---: | ---: | ---: | --- |
| 10 | `TClient_handleServerLoginPacket` | `0x1edf04` | `0x1f37e0` | `0x37c780` | `sub_1F37E0` |
| 48 | `TClient_processServerModifies` | `0x1eab78` | `0x1eefa0` | `0x37c8b0` | `sub_1EEFA0` |

The slot-10 target checks for a non-empty packet, subtracts 32 from byte one,
stores the server signature, and invokes `onServerLogin`. The target body is
larger than the source because the rebuilt `C8THgaTQxF` and event wrappers are
expanded, but the table index and event string remove the ambiguity. The
slot-48 target clears the leader state, checks the active player's pending
server-level transition, and chooses between entering that level and applying
server modifications in place. It then clears the pending transition field.
The target preserves the operation while expanding the source body from 184
to 252 bytes.

This pass also corrects the earlier v6 assignment of
`TClient_processServerModifies` to `0xecba0`. That address retains the export
`_ZN10yL3_IaDMFt10XEm8Ta8FEQEP10vuuHgangcFRK10C8THgaTQxF`, and its pseudocode
iterates the `yL3_IaDMFt` hash-container object. It is not a TClient packet
handler. The v232 copy restores that dynamic name and places
`v18_TClient_processServerModifies` at the actual slot-48 target
`0x1eefa0`.

The aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v232.i64`.
The copy has 11,694 functions and 1,071 remaining default `sub_` names, with
SHA-256
`51b76f3945f282bc62c1fb72a5749115315db1e6d5fac5e04ef4208c816a3bf6`.
The machine-readable evidence is in
`artifacts/spectron_tclient_handler_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_tclient_handler_anchors.py`. The name
correction helper is `tools/ida_apply_spectron_name_corrections.py`, and the
checkpoint is `artifacts/spectron_translation_checkpoint_20260828_v232.json`.
No APK or native library was modified.

## Spectron residual file, cache, and password properties

The v231 pass resolves six default-named callbacks from three related script
property tables. The decoded names, table records, and decompiled bodies all
agree on the roles below.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TClient_getGraalPassword` | `0x1eb93c` | `0x1f01e4` | `sub_1F01E4` | `getpassword` at `0x397530` |
| `TCachedStream_get_minfilecachesize` | `0x1fa4fc` | `0x1ffcac` | `sub_1FFCAC` | `minfilecachesize` at `0x3986d8` |
| `TCachedStream_get_maxramcachesize` | `0x1fa524` | `0x1ffcd4` | `sub_1FFCD4` | `maxramcachesize` at `0x398708` |
| `TFileDownload_script_getlastfilerequesttime` | `0x1fbb08` | `0x201400` | `sub_201400` | `getlastfilerequesttime` at `0x398858` |
| `TFileDownload_script_getlastfiledownloadtime` | `0x1fbb18` | `0x201410` | `sub_201410` | `getlastfiledownloadtime` at `0x398888` |
| `TFileDownload_get_lastdownloadfile` | `0x1fbb28` | `0x201420` | `sub_201420` | `lastdownloadfile` at `0x398768` |

The password callback calls the target options accessor, matching the source
callback's call to `TOptions_getGraalPassWord`. The two cache getters return
the target's minimum file-cache and maximum RAM-cache globals. The timestamp
callbacks read the corresponding request and download time fields, and the
last-download getter copies the stored filename into the script return value.
The target global names are obfuscated, but the property table and operation
remain direct evidence rather than an address-only guess.

All six rows match the normalized feature fields. The password callback also
matches every recorded metric. The other five rows differ only in
`register_detail_hash`, which reflects target global layout and register
allocation. There are no normalized layout changes in this group. All six
aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v231.i64`,
which has 11,694 functions and 1,073 remaining default `sub_` names. The
database SHA-256 is
`329596637abe0446019eb80c952e4536157bed027dce3c5f40fc6b8a68cf2fa2`.

Three nearby rows are intentionally kept separate from the source mappings.
`sub_1F00F8` handles the target-only `setdebugdatahandlers` property,
`sub_1F0010` handles target-only
`adventure_setdebugdatahandlersauthorization`, and `sub_1F2160` is a small
wrapper for the already translated target body of
`v18_TClient_updateGlobalPlayer`. The source table does not contain separate
callbacks for those target wrapper or debug-handler entries, so they are not
counted as additional 1.8 translations. The v233 pass gives these rows
descriptive `spectron_` labels in a separate target-only artifact.

The machine-readable evidence and input hashes are in
`artifacts/spectron_file_cache_property_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_file_cache_property_anchors.py`. The
v231 database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v231.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron residual drawing-panel script callbacks

The v229 pass resolves three exact script callbacks in the obfuscated
`V8fxgahcBw` drawing-panel class family. The decoded target registration table
provides a direct name anchor, and the tiny target bodies forward to the same
`TDrawingPanel` operations as the source.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiDrawingPanel_script_setdrawpalette` | `0x1e00e4` | `0x1e3fd8` | `sub_1E3FD8` | `setdrawpalette` record at `0x3970d0` |
| `GuiDrawingPanel_script_maskimage` | `0x1e00ec` | `0x1e3fe0` | `sub_1E3FE0` | `maskimage` record at `0x3970a0` |
| `GuiDrawingPanel_script_filterrectangle` | `0x1e00f4` | `0x1e3fe8` | `sub_1E3FE8` | `filterrectangle` record at `0x397070` |

The corresponding source registration records are `0x384070`, `0x384040`,
and `0x384010`. The target table reverses the local order, but the decoded
callback names and pointers identify each row. The target forwards through the
embedded panel at `this + 464`: palette selection calls
`TDrawingPanel_setDrawPaletteNamed`, masking calls
`TDrawingPanel_maskImage_Impl`, and filtering calls
`TDrawingPanel_filterRectangle_Impl`. All three rows match the complete
recorded feature set, including normalized opcode shape, register detail, and
overall shape.

The aliases reopened with zero failures in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v229.i64`,
which has 11,694 functions and 1,084 remaining default `sub_` names. Its
SHA-256 is
`a2f715b293c1bd6bd0a29d8299ad6d492af6e23a8459b549486de756dcab79c8`.
The evidence and input hashes are in
`artifacts/spectron_gui_drawing_panel_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_drawing_panel_script_anchors.py`.
The database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v229.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron residual MRandomGenerator property callbacks

The v228 pass resolves four exact property and script callbacks in the
obfuscated `o3AZxayNqc` random-generator class family. The source and target
registration records provide a second anchor beyond function shape.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `MRandomGenerator_get_seed` | `0x1e3220` | `0x1e70f0` | `sub_1E70F0` | seed property getter at `0x397288` |
| `MRandomGenerator_set_seed` | `0x1e3228` | `0x1e70f8` | `sub_1E70F8` | seed property setter at `0x397288` |
| `MRandomGenerator_script_randint` | `0x1e3248` | `0x1e7118` | `sub_1E7118` | `randint` callback at `0x3972e8` |
| `MRandomGenerator_script_randfloat` | `0x1e3268` | `0x1e7138` | `sub_1E7138` | `randfloat` callback at `0x3972b8` |

The source seed record is at `0x384228`, with the getter and setter pointers
inside that record. The source `randfloat` and `randint` records are at
`0x384258` and `0x384288`; their target records are at `0x3972b8` and
`0x3972e8`. The decompiled bodies preserve the seed field operations and the
virtual random-number dispatch. Every row matches the complete recorded
feature set, including normalized opcode shape, register detail, and overall
shape. These are exact feature-level correspondences.

The aliases reopened with zero failures in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v228.i64`,
which has 11,694 functions and 1,087 remaining default `sub_` names. Its
SHA-256 is
`eeea668d6fa3eb549c41b9dbec001b5c6a7c7e0a44c17a14faea45664004b06b`.
The evidence and input hashes are in
`artifacts/spectron_mrandom_property_residual_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_mrandom_property_residual_anchors.py`.
The database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v228.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron residual text-list selection script methods

The v227 pass resolves two residual script callbacks in the obfuscated
`s_YwgafWlw` text-list class family. The source `setselectedrows` and
`setselectedbyids` methods map to the target entries registered under those
same decoded script names.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiTextListCtrl_script_setselectedrows` | `0x1df918` | `0x1e3794` | `sub_1E3794` | comma-list selection and multi-select reset |
| `GuiTextListCtrl_script_setselectedbyids` | `0x1dfa48` | `0x1e38c8` | `sub_1E38C8` | comma-list ID lookup and invalid-ID handling |

The target script table records are `0x396cb0` for `setselectedrows` and
`0x396c20` for `setselectedbyids`. The source records are `0x383c50` and
`0x383bc0`. The target table order differs, but the decoded names and
decompiled bodies agree. Both targets parse comma-separated integers, reset on
an empty list, select one item when multiple selection is disabled, and clear
and rebuild the selection when it is enabled. The ID-based method still
resolves each ID through the text-list lookup and skips invalid results.

Each target adds one wrapper instruction while retaining the source block,
branch, call, and return counts. Both rows are therefore high-confidence
semantic correspondences with explicit layout-change records, not exact
instruction matches. The aliases reopened with zero failures in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v227.i64`,
which has 11,694 functions and 1,091 remaining default `sub_` names. Its
SHA-256 is
`150ad989b94e83ebcd6287aeb935961c0b4081c99856a59ce4d789ce1d275276`.
The evidence and input hashes are in
`artifacts/spectron_gui_text_list_selection_script_manual_translation_anchors_20260828.json`,
generated by `tools/generate_spectron_gui_text_list_selection_script_anchors.py`.
The database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v227.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron residual GuiProgressCtrl progress getter

The v226 pass resolves one residual `GuiProgressCtrl_get_progress` getter. The
source starts at `0x1dbfa0`, while the target starts at `0x1dfd3c` in the
obfuscated `EYKlVaL7UR` class. The source and target property records are at
`0x383078` and `0x3960d8`, and their getter pointers are at `0x383088` and
`0x3960e8`.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiProgressCtrl_get_progress` | `0x1dbfa0` | `0x1dfd3c` | `sub_1DFD3C` | returns float at receiver offset `+456` |

Both decompiled bodies load the same progress float from `this + 456` and
return it. All recorded normalized and complete feature metrics match. The
alias reopened with zero failures in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v226.i64`,
which has 11,694 functions and 1,093 remaining default `sub_` names. Its
SHA-256 is
`ae8ab50751ac9f82e108fff9de5ae0274b857c44db27522821ac7c5cdefad45a`.
The evidence and input hashes are in
`artifacts/spectron_gui_progress_getter_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_gui_progress_getter_anchor.py`. The
database identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v226.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron residual popup rows accessor

The v225 pass resolves one residual `GuiPopUpMenuCtrl_get_rows` property
accessor. The source starts at `0x1d9404`, while the target starts at
`0x1de3c4` in the obfuscated `SyVo2a61z` class. The source and target popup
property tables point at these functions through `0x382ed8` and `0x395f38`.

| Source role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `GuiPopUpMenuCtrl_get_rows` | `0x1d9404` | `0x1de3c4` | `sub_1DE3C4` | `rows` hash lookup through owned profile list |

IDA pseudocode shows the same sequence in both builds: obtain the owned
profile hash list, build the literal `rows` key, compute its hash, retrieve the
object, clear the temporary string, and return the result. Spectron replaces
the source string and hash-list helpers with `C8THgaTQxF` and `KKhLga4xoI`.
The body is therefore a high-confidence semantic match with an explicit
normalized-shape difference, not an exact instruction match.

The alias reopened with zero failures in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v225.i64`.
The database contains 11,694 functions and 1,094 remaining default `sub_`
names. Its SHA-256 is
`a6626fec1ef58be22f30e2f23c83ce2573602b556c1f140c9da1530f19aa9f1b`.
The evidence and input hashes are in
`artifacts/spectron_gui_popup_rows_manual_translation_anchor_20260828.json`,
generated by `tools/generate_spectron_gui_popup_rows_anchor.py`. The database
identity is recorded in
`artifacts/spectron_translation_checkpoint_20260828_v225.json`.

This pass changed only the disposable IDA database and performed no DNS, HTTP,
or TLS operation.

## Spectron THTMLPage method family

The v208 pass resolves eight small methods that the ordinary semantic matcher
intentionally skipped because each is shorter than 32 bytes. The pairing is
especially strong because every target name belongs to the same obfuscated
`AS80gaE4zW` class family, all normalized feature fields match exactly, and
the decompiled bodies write the same receiver fields.

| Source role | Source | Spectron target | Target name before alias | Source table | Target table |
| --- | ---: | ---: | --- | ---: | ---: |
| `THTMLPage_clearFontPointers_void` | `0x1cf818` | `0x1d446c` | `_ZN10AS80gaE4zW10pMwQgakbOMEv` | `0x36ff60` | `0x383e08` |
| `THTMLPage_setDirty_void` | `0x1d037c` | `0x1d4fd0` | `_ZN10AS80gaE4zW10FOVQgamf8MEv` | `0x373df8` | `0x384298` |
| `THTMLPage_setWordWrap_bool` | `0x1d03c0` | `0x1d5014` | `_ZN10AS80gaE4zW10ZMSSgaUHMOEb` | `0x370a80` | `0x3854b0` |
| `THTMLPage_setParseTags_bool_TStringList` | `0x1d03f4` | `0x1d5048` | `_ZN10AS80gaE4zW10wEiPgaIiMLEbP10vuuHgangcF` | `0x371ff0` | `0x383ea8` |
| `THTMLPage_setSelection_bool_uint_uint` | `0x1d043c` | `0x1d5090` | `_ZN10AS80gaE4zW10F1pSga8voOEbjj` | `0x370bd8` | `0x3845b8` |
| `THTMLPage_initURLs_void` | `0x1d1280` | `0x1d5ed4` | `_ZN10AS80gaE4zW10TdfRgasqpNEv` | `0x36ed68` | `0x382c18` |
| `THTMLPage_setTabStop_int_int` | `0x1d1324` | `0x1d5f78` | `_ZN10AS80gaE4zW10BPX6ga8Ws0Eii` | `0x371fe8` | `0x385690` |
| `THTMLPage_initLines_void` | `0x1d1d9c` | `0x1d69f0` | `_ZN10AS80gaE4zW10In6QgaHZhNEv` | `0x36f2b0` | `0x384300` |

The cleanup method walks the font list at `+200`, clears each cached pointer
at `+136`, and follows the link at `+152`. The dirty setter updates `+360`.
Word wrap uses `+256` and calls the target dirty helper only after a change.
Parse-tags writes the flag at `+257` and its list pointer at `+264` before
marking the page dirty. Selection writes the enabled byte and the two indices
at `+296`, `+300`, and `+304`.

The URL initializer clears fields at `+112`, `+128`, and `+368`. The tab-stop
helper operates on the list at `+152`, while line initialization clears `+336`
and points the cursor at that field through `+88`. These repeated offsets are
independent of the obfuscated method spellings and agree in both builds.

The applied aliases use the normal `v18_` prefix. They reopened successfully
in `analysis/spectron_libqplay_translated_v208.i64`. The database contains
11,694 functions, 3,641 high-confidence semantic labels, and 1,217 default
`sub_` names. Its SHA-256 is
`8fdd5acca704b5ca0e4bdd54747a60ce132ddb671fa493f4b4ffe8e2e88906a8`.
The machine-readable record is
`artifacts/spectron_html_page_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_html_page_anchors.py`. No APK or native
library was modified.

## Spectron Java sound D1 destructor

The v207 pass resolves the complete D1 destructor for the Java sound-player
class. The source entry is constructor-shaped in IDA, but its alternative ABI
name and body identify it as a complete destructor that does not free the
object.

| Source role | Source | Spectron target | Target name before alias | Source table | Target table | Classification |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `TSoundPlayerJava_TSoundPlayerJava` | `0xe35c8` | `0xe417c` | `_ZN10ohGYZakbFKD1Ev` | `0x35ed80` | `0x371b00` | register-detail difference |

The source body installs the `TSoundPlayerJava` vtable and clears the embedded
`TString` at object offset `+16`. It does not call `operator delete`, so it is
the complete D1 destructor. Spectron's `ohGYZakbFKD1Ev` body performs the
same vtable installation and clears the corresponding `C8THgaTQxF` field at
`+16`, also without deleting the object.

The target D1 wrapper at `0xe417c` is immediately followed by the D0 wrapper
at `0xe4190`, which was translated in v204. That adjacency mirrors the source
D1 and D0 pair at `0xe35c8` and `0xe360c`. Both rows are 20 bytes, have two
basic blocks, five instructions, one branch, and no direct-call or string
references. All normalized shape fields match. Only register detail differs,
which is consistent with register allocation in the rebuilt target.

The applied alias is `v18_TSoundPlayerJava_TSoundPlayerJava`. It reopened
successfully in `analysis/spectron_libqplay_translated_v207.i64`. The full
semantic reopen check reports zero failures across 11,694 functions, with
3,641 high-confidence labels and 1,217 default `sub_` names. The v207 database
SHA-256 is
`dff2f079771c58100c2dd745f48dbecdde881f461598021b890b67e2fa0665f9`.

The machine-readable record is
`artifacts/spectron_sound_java_d1_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_sound_java_d1_anchor.py`. The alias only
changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron TSounds tail methods

The v206 pass resolves three methods at the end of the source `TSounds`
cluster. The stop-SFX wrapper and script pitch bridge are exact normalized
ARM64 matches. The static initializer is a layout-change match because the
target's second helper object grew from 0x18 to 0x20 bytes.

| Source role | Source | Spectron target | Target name before alias | Registration or callback evidence | Classification |
| --- | ---: | ---: | --- | --- | --- |
| `TSounds_stopSFX_TString_const` | `0xe0ea4` | `0xe1a78` | `_ZN10IUKzgam4Gy10jIWZZaS_ILERK10C8THgaTQxF` | `0x376120` to `0x389120` | exact feature match |
| `TSounds_script_setSoundPitch` | `0xe2a7c` | `0xe366c` | `sub_E366C` | `0x376450` to `0x389450` | exact feature match |
| `TSounds_initStaticVars_void` | `0xe2a88` | `0xe3678` | `_Z10WACL2aR4FWv` | static refs `0x2f8c0`, `0x374108` to `0x1daa8`, `0x383a50` | layout change |

The stop-SFX source body calls `TSounds_getSoundEffect_TString_const` and,
when an object is returned, dispatches its virtual stop method at offset
`+112`. Spectron's `IUKzgam4Gy::jIWZZaS_IL` calls the corresponding reviewed
`IUKzgam4Gy::adFVZaKh7H` lookup and uses the same `+112` slot. The complete
normalized feature record matches, including register detail. This row
upgrades the existing medium-confidence semantic candidate with its
sound-effect class, callback-table, and virtual-slot evidence.

The script pitch bridge is a 12-byte, three-instruction wrapper with two
basic blocks. Both versions read the double payload from the script value and
forward it to the native set-pitch method. Source callback reference `0x376450`
and target reference `0x389450` identify the corresponding script entry. The
target body sits directly before the static initializer, just as the source
bridge sits directly before `TSounds_initStaticVars_void`.

The source static initializer allocates a `0x28`-byte `THashList`, constructs
it, stores the sound-effects cache pointer, then allocates a `0x18`-byte
`TStringList`, constructs it, and stores the disabled-sound-effects pointer.
The target function has the same 76-byte, 19-instruction, one-block, four-call
shape and the same class-local order. Its first object is the `0x28`-byte
`KKhLga4xoI` stored in `IUKzgam4Gy::fqEVZaFC6H`. The second is a `vuuHgangcF`
object allocated at `0x20` bytes and stored in `IUKzgam4Gy::mDUVZaIfkI`.
That changed helper type explains the opcode, register, and overall-shape
fingerprint differences without changing the initializer's role or order.

The applied aliases are `v18_TSounds_stopSFX_TString_const`,
`v18_TSounds_script_setSoundPitch`, and `v18_TSounds_initStaticVars_void`.
All three reopened successfully in
`analysis/spectron_libqplay_translated_v206.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,217 default `sub_` names. The v206 database
SHA-256 is
`f909721bba6d7d22b56727328f18382f71d57ce3d539686d450e6d910fa5aabd`.

The machine-readable record is
`artifacts/spectron_sounds_tail_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_sounds_tail_anchors.py`. The aliases
only change the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron Java sound deleting destructors

The v204 pass resolves the two constructor-shaped `__2` entries at the ends
of the Java sound class blocks. In this IDA database those names describe
deleting destructors, not constructors. Each body calls the complete class
destructor and then `operator delete`.

| 1.8 role | Source | Spectron target | Target ABI name | Source table | Target table | Classification |
| --- | ---: | ---: | --- | ---: | ---: | --- |
| `TSoundEffectJava_TSoundEffectJava__2` | `0xe2c14` | `0xe3804` | `_ZN10QPh5pbnC3yD0Ev` | `0x35ee28` | `0x371ba8` | exact feature match |
| `TSoundPlayerJava_TSoundPlayerJava__2` | `0xe360c` | `0xe4190` | `_ZN10ohGYZakbFKD0Ev` | `0x35ed88` | `0x371b08` | register-detail difference |

The sound-effect source and target wrappers are both 32 bytes, with two
basic blocks, two branches, one destructor call, and the same normalized
fingerprints. The sound-player wrappers are both 48 bytes with two blocks,
two branches, and one cleanup call. Their normalized shape also matches;
only the register-detail fingerprint changes, which is consistent with the
rebuilt target's register allocation. The target classes are independently
established by the adjacent constructors and the Java sound method blocks.

The source names retain the original IDA spelling in the aliases, while the
artifact records the lifecycle role explicitly. The sound-player row was
already present as a medium-confidence feature candidate. The new review
adds its D0 ABI, method-table slot, and pseudocode evidence before persisting
the alias. Both aliases reopened successfully in
`analysis/spectron_libqplay_translated_v204.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,218 default `sub_` names. The v204 database
SHA-256 is
`34e94dad94d50d81664f109b3831cc29528d1a64c0ac0a8f1dd18a90c6d69765`.

The machine-readable record is
`artifacts/spectron_sound_java_destructor_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sound_java_destructor_anchors.py`. The aliases only
change the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron Java sound bridge small methods

The v203 pass resolves seven short methods that sit in the Java sound bridge.
The first two source methods are `TSoundPlayerJava` methods. Their target
counterparts are adjacent methods in Spectron's `ohGYZakbFK` class. The next
five source methods are the compact `TSoundEffectJava` state methods, and
their target counterparts are adjacent methods in `QPh5pbnC3y`.

| 1.8 role | Source | Spectron target | Target name before alias | Source table | Target table |
| --- | ---: | ---: | --- | ---: | ---: |
| `TSoundPlayerJava_stopMidi_void` | `0xe2b58` | `0xe3748` | `_ZN10ohGYZakbFK10xcTMgag3JJEv` | `0x35edc8` | `0x371b48` |
| `TSoundPlayerJava_setMusicVolumeAndPan_int_int` | `0xe2b78` | `0xe3768` | `_ZN10ohGYZakbFK10cqUMgaI4KJEii` | `0x35ede8` | `0x371b68` |
| `TSoundEffectJava_freeResource_void` | `0xe2b98` | `0xe3788` | `_ZN10QPh5pbnC3y10AtwMgawWqJEv` | `0x35ee40` | `0x371bc0` |
| `TSoundEffectJava_load_void` | `0xe2ba0` | `0xe3790` | `_ZN10QPh5pbnC3y4loadEv` | `0x35ee48` | `0x371bc8` |
| `TSoundEffectJava_setVolume_int` | `0xe2ba4` | `0xe3794` | `_ZN10QPh5pbnC3y10uosMgajvnJEi` | `0x35ee70` | `0x371bf0` |
| `TSoundEffectJava_setPan_int` | `0xe2bac` | `0xe379c` | `_ZN10QPh5pbnC3y10spDMga7LwJEi` | `0x35ee78` | `0x371bf8` |
| `TSoundEffectJava_stop_void` | `0xe2bb4` | `0xe37a4` | `_ZN10QPh5pbnC3y10pOFMga6MyJEv` | `0x35ee90` | `0x371c10` |

The source `stopMidi` wrapper dispatches through the sound-player vtable at
offset `+64`, and the target `xcTMgag3JJ` wrapper uses the same receiver
offset. The source volume-and-pan wrapper uses `+96`, and the target
`cqUMgaI4KJ` wrapper does the same. Those two slots distinguish the methods
from other short sound-player wrappers that have similar instruction shapes.

The five `TSoundEffectJava` rows preserve the small object-state operations.
`freeResource` clears the live-resource byte at object offset `+48`, `load` is
a no-op, `setVolume` stores its integer at `+52`, `setPan` stores its integer
at `+56`, and `stop` clears the same live-resource byte at `+48`. Spectron's
five target bodies have the same operations in the same class-local order.

All seven rows match the complete normalized feature record, including
register detail. None has literal string references or direct calls, so the
method-table records and receiver behavior are the important role evidence.
The aliases are `v18_TSoundPlayerJava_stopMidi_void`,
`v18_TSoundPlayerJava_setMusicVolumeAndPan_int_int`,
`v18_TSoundEffectJava_freeResource_void`,
`v18_TSoundEffectJava_load_void`, `v18_TSoundEffectJava_setVolume_int`,
`v18_TSoundEffectJava_setPan_int`, and `v18_TSoundEffectJava_stop_void`.
All seven reopened successfully in
`analysis/spectron_libqplay_translated_v203.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,218 default `sub_` names. The v203 database
SHA-256 is
`c9ef630efa45cf233022f46b3f051702acf07f72d4d49c32b9621f0f7ee289b5`.

The machine-readable record is
`artifacts/spectron_sound_java_small_methods_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_sound_java_small_methods_anchors.py`. The aliases
only change the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron TSoundEffect virtual method block

The v202 pass resolves the complete seven-method `TSoundEffect` interface.
The source methods are contiguous in the `TSoundEffect` method table, and the
Spectron methods are contiguous in the already identified `fEVMgax6LJ`
object's table.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TSoundEffect_hasChannel_void` | `0xe2b24` | `0xe3714` | `_ZN10fEVMgax6LJ10pTqwgajeUvEv` | exact feature match |
| `TSoundEffect_isPlaying_void` | `0xe2b34` | `0xe3724` | `_ZN10fEVMgax6LJ10my_MgaBeQJEv` | exact feature match |
| `TSoundEffect_setVolume_int` | `0xe2b3c` | `0xe372c` | `_ZN10fEVMgax6LJ10uosMgajvnJEi` | exact feature match |
| `TSoundEffect_setPan_int` | `0xe2b40` | `0xe3730` | `_ZN10fEVMgax6LJ10spDMga7LwJEi` | exact feature match |
| `TSoundEffect_setPitch_float` | `0xe2b44` | `0xe3734` | `_ZN10fEVMgax6LJ10ACEMgabNxJEf` | exact feature match |
| `TSoundEffect_set3DPosition_T3DFloatPoint_const_T3DFloatPoint_const_int` | `0xe2b48` | `0xe3738` | `_ZN10fEVMgax6LJ10nQlWHaFZHzERK10V6P7faBscbS2_i` | exact feature match |
| `TSoundEffect_getLength_void` | `0xe2b4c` | `0xe373c` | `_ZN10fEVMgax6LJ10ttTHEavhxREv` | exact feature match |

The source method-table records begin at `0x35ec60` and continue through
`0x35ec98`; the target records begin at `0x3719e0` and continue through
`0x371a18`. The `hasChannel` method tests the stored channel index, the
`isPlaying` method returns the base implementation's false value, the three
setters are no-ops in this base class, `set3DPosition` is also a no-op, and
`getLength` returns `-1.0`. Spectron's pseudocode has the same behavior for
each corresponding method.

The constructor and cache-lookup anchors already tie `fEVMgax6LJ` to the
source `TSoundEffect` object. This table provides an independent interface-
level check, and every size, instruction, block, branch, call, return,
mnemonic, opcode, register, overall-shape, and string-reference fingerprint
matches exactly. The reviewed aliases are
`v18_TSoundEffect_hasChannel_void`, `v18_TSoundEffect_isPlaying_void`,
`v18_TSoundEffect_setVolume_int`, `v18_TSoundEffect_setPan_int`,
`v18_TSoundEffect_setPitch_float`,
`v18_TSoundEffect_set3DPosition_T3DFloatPoint_const_T3DFloatPoint_const_int`,
and `v18_TSoundEffect_getLength_void`. All seven reopened successfully in
`analysis/spectron_libqplay_translated_v202.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,218 default `sub_` names. The v202 database
SHA-256 is
`87fb8ed432789f0f729d645c34fb11b6d3bfe55ebdcc96705d7beaa865c9b77d`.

The machine-readable record is
`artifacts/spectron_tsound_effect_methods_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tsound_effect_methods_anchors.py`. The
aliases only change the persisted IDA analysis copy. No APK or native library
was modified.

## Spectron THTMLDefinitions default initializer

The v195 pass resolves source `sub_E09F4` to target `sub_E0FC4` by following
the static-initializer slots, the HTML default fields, and both translated
HTML consumers. The target class name is obfuscated as `D2x4gaXfrZ`, but its
fields and surrounding method family line up with the source
`THTMLDefinitions` class.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `THTMLDefinitions` default initializer | `0xe09f4` | `0xe0fc4` | `sub_E0FC4` | exact normalized shape |

The source callback is referenced by static-initializer table slot `0x35d290`.
It stores `defaultbitmapindent = 5` at
`data_THTMLDefinitions_defaultbitmapindent` (`0x38fa90`), clears the
adjacent `dword_38FA94`, and writes the horizontal-line color bytes
`[64, 64, 64, 255]` at `0x38fa88..0x38fa8b`. The color bytes are read by
`THTMLPage_render_TPoint_const` at `0x1d095c`; the indent and adjacent state
are read by `THTMLPage_executeTag_html_tag_THTMLTagName_int` at `0x1d3c88`.

Spectron places the callback in target slot `0x36fae0`. `sub_E0FC4` writes
the same six values at the obfuscated target fields
`D2x4gaXfrZ::xYeSgaycfO` (`0x3a3458`), its three adjacent color bytes,
`D2x4gaXfrZ::yyt3gaHtxY` (`0x3a3460`), and `dword_3A3464`. The corresponding
target consumers are `v18_THTMLPage_render_TPoint_const` at `0x1d55b0` and
`v18_THTMLPage_executeTag_html_tag_THTMLTagName_int` at `0x1d88e0`.

Both rows are 56 bytes and 14 instructions in one basic block, with one
branch, no direct calls, and one return. Their mnemonic, opcode-shape,
register-shape, overall-shape, and string-reference hashes match. The only
recorded difference is `register_detail_hash`; the artifact keeps both
values and compares the normalized shape explicitly instead of hiding that
detail.

The reviewed alias is `v18_THTMLDefinitions_initializeDefaults`. It reopened
successfully in
`analysis/spectron_libqplay_translated_v195.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,224 default `sub_` names. The v195 database
SHA-256 is
`be423f317890860401a1d7570cfeeb5783f45f0e967448656808a51cf76d30c7`.

The machine-readable record is
`artifacts/spectron_thtml_definitions_defaults_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_thtml_definitions_defaults_anchors.py`. The alias
only changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron TGUIRender border-color initializer

The v194 pass resolves source `sub_E0984` to target `sub_E0F0C` by following
the complete color block into the matching `TGUIRender::renderBorder`
consumer. Both callbacks publish five RGBA defaults used by the border-style
branches: white, black, 75% gray, 50% gray, and 25% gray. This consumer link
is stronger than matching the repeated floating-point constants alone.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TGUIRender` border-color initializer | `0xe0984` | `0xe0f0c` | `sub_E0F0C` | color defaults, layout change |

The source callback is referenced by static-initializer table slot `0x35d288`.
It writes twenty floats beginning at `0x38f9e8`, then returns `1.0`. The five
four-component values are white `[1.0, 1.0, 1.0, 1.0]`, black
`[0.0, 0.0, 0.0, 1.0]`, 75% gray `[0.75, 0.75, 0.75, 1.0]`, 50% gray
`[0.5, 0.5, 0.5, 1.0]`, and 25% gray `[0.25, 0.25, 0.25, 1.0]`.
`TGUIRender_renderBorder_TRectangle_const_GuiControlProfile` at `0x1cb5e4`
pushes these global colors for its border-style cases.

Spectron keeps the same role in target slot `0x36fad0`. `sub_E0F0C` writes the
same twenty values beginning at `0x3a33a0`, then returns `1.0`.
`v18_TGUIRender_renderBorder_TRectangle_const_GuiControlProfile` at
`0x1d016c` consumes the target block and preserves the four border-style
branches and matching color pushes.

The target also initializes neighboring `qword_3A33C0` as an empty
`CanTfaz6bZ` string. Target `sub_E0070` at `0xe0070`, referenced by cleanup
table slot `0x36feb0`, clears that extra field. This accounts for the target's
larger body. The source row is 112 bytes and 28 instructions in one block,
with one branch, no direct calls, and one return. The target row is 156 bytes
and 38 instructions in one block, with two branches, one direct string
assignment call, and one return.

The alias reopened successfully in
`analysis/spectron_libqplay_translated_v194.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,225 default `sub_` names. The v194 database SHA-256 is
`62b68defbcd16bc235d1c9da05c623f610e1ebea8bda0c473f6260a600f40c27`.

The machine-readable record is
`artifacts/spectron_tgui_render_colors_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tgui_render_colors_anchors.py`. The
alias only changes the persisted IDA analysis copy. No APK or native library
was modified.

## Spectron GuiStretchCtrl mode-table initializer

The v193 pass resolves source `sub_E0960` to target `sub_E0E54` by following
the three mode entries and the surrounding `GuiStretchCtrl` property table.
Both callbacks publish the same ordered `alwaysOn`, `alwaysOff`, and `dynamic`
entries with values zero, one, and two. The nearby property table confirms the
class context and avoids treating the callback as a generic three-entry list.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `GuiStretchCtrl` mode-table initializer | `0xe0960` | `0xe0e54` | `sub_E0E54` | mode table, layout change |

The source callback is referenced by static-initializer table slot `0x35d280`.
It sets `dword_38F8F8` to three, publishes the table at `0x382060` through
`qword_38F900`, and returns the table address. The table entries are
`alwaysOn`, `alwaysOff`, and `dynamic`, with values zero through two. The
following property table begins at `0x382090`; its three decoded properties
are `clientextent`, `clientheight`, and `clientwidth`, registered by
`GuiStretchCtrlProperties_GuiStretchCtrlProperties_void` at `0x1c5470`.

Spectron keeps the same role in target slot `0x36faa8`. `sub_E0E54` sets
`dword_3A3288` to three, publishes the table at `0x3950c0` through
`qword_3A3290`, and returns the table address. The target table preserves all
three names and values. Its property table at `0x3950f0` keeps the same
decoded property order and is registered by
`v18_GuiStretchCtrlProperties_GuiStretchCtrlProperties_void` at `0x1c9f4c`.

The target also initializes neighboring `qword_3A32D8` as an empty
`CanTfaz6bZ` string. Target `sub_E0028` at `0xe0028`, referenced by cleanup
table slot `0x36fe88`, clears that extra field. This accounts for the target's
larger body. The source row is 36 bytes and nine instructions in one block,
with one branch, no direct calls, and one return. The target row is 80 bytes
and 19 instructions in one block, with two branches, one direct string
assignment call, and one return.

The alias reopened successfully in
`analysis/spectron_libqplay_translated_v193.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,226 default `sub_` names. The v193 database SHA-256 is
`fef77c04831227ee44dfe1edf8499744b627851daa651b5b1d77f8d92ea920c7`.

The machine-readable record is
`artifacts/spectron_gui_stretch_modes_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_gui_stretch_modes_anchors.py`. The alias
only changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron GuiGraalCtrl alignment-table initializer

The v192 pass resolves source `sub_E0930` to target `sub_E0DAC` by following
the table contents and the surrounding `GuiGraalCtrl` property metadata. Both
callbacks publish one five-entry horizontal alignment table and one five-entry
vertical alignment table. The function address change by itself would not be
enough because the target GUI static-state block has been rearranged.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `GuiGraalCtrl` alignment-table initializer | `0xe0930` | `0xe0dac` | `sub_E0DAC` | alignment tables, layout change |

The source callback is referenced by static-initializer table slot `0x35d278`.
It sets `dword_38F830` and `dword_38F840` to five, publishes the vertical
table at `0x381680` through `qword_38F838`, publishes the horizontal table at
`0x381630` through `qword_38F848`, and returns the vertical table address. The
horizontal entries are `right`, `width`, `left`, `center`, and `relative`,
with values zero through four. The vertical entries are `bottom`, `height`,
`top`, `center`, and `relative`, again with values zero through four. The
property record at `0x3816d0` is registered by
`GuiGraalCtrlProperties_GuiGraalCtrlProperties_void` at `0x1bbfc8`.

Spectron keeps the same role in target slot `0x36fa88`. `sub_E0DAC` sets
`dword_3A31A0` and `dword_3A31B0` to five, publishes the vertical table at
`0x3946e0` through `qword_3A31A8`, publishes the horizontal table at
`0x394690` through `qword_3A31B8`, and returns the vertical table address. The
tables preserve both label orders and all values. The corresponding property
record is at `0x394730` and is registered by
`v18_GuiGraalCtrlProperties_GuiGraalCtrlProperties_void` at `0x1bf8f4`.

The target also initializes neighboring `qword_3A31D8` as an empty
`CanTfaz6bZ` string. Target `sub_DFFF0` at `0xdfff0`, referenced by cleanup
table slot `0x36fe68`, clears that extra field. This accounts for the target's
larger body. The source row is 48 bytes and 12 instructions in one block,
with one branch, no direct calls, and one return. The target row is 92 bytes
and 22 instructions in one block, with two branches, one direct string
assignment call, and one return.

The alias reopened successfully in
`analysis/spectron_libqplay_translated_v192.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,227 default `sub_` names. The v192 database SHA-256 is
`fa7c62af8d8aa0608d58792573ade2a0de41c373b844b7adf76d9f8e296b9c48`.

The machine-readable record is
`artifacts/spectron_gui_alignment_tables_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_gui_alignment_tables_anchors.py`. The
alias only changes the persisted IDA analysis copy. No APK or native library
was modified.

## Spectron GUI button-type table initializer

The v191 pass resolves source `sub_E090C` to target `sub_E0D10` by following
the `GuiButtonBaseCtrl` property metadata and the table contents rather than
their addresses alone. Both callbacks build the three-entry button-type table
used by the property getter and setter.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `GuiButtonBaseCtrl` button-type initializer | `0xe090c` | `0xe0d10` | `sub_E0D10` | button-type table, layout change |

The source callback is referenced by static-initializer table slot `0x35d270`.
It sets the type count at `dword_38F788` to three, points `qword_38F790` at
the table beginning at `0x3804c0`, and returns the table address. The entries
are ordered `PushButton`, `ToggleButton`, and `RadioButton`, with values 0,
1, and 2. The source property table at `0x3803a0` points to the corresponding
`GuiButtonBaseCtrl` getter and setter.

The target callback is referenced by slot `0x36fa68`. It sets
`dword_3A30D8` to three, points `qword_3A30E0` at `0x393520`, and returns the
same table role. The target table preserves the same three names and values.
Its property table at `0x393400` points to the target property constructor and
the target getter and setter at `0x1b1438` and `0x1b1478`, whose pseudocode
retains the source's count, table stride, and object field offset.

The target also initializes neighboring `qword_3A30E8` as an empty
`CanTfaz6bZ` string. Target `sub_DFFB8` at `0xdffb8`, referenced by cleanup
table slot `0x36fe48`, clears that extra field. The source has no matching
string lifetime in this callback, so the extra assignment accounts for the
larger target body. The source row is 36 bytes and eight instructions in one
block, with one branch, no direct calls, and one return. The target row is 80
bytes and 19 instructions in one block, with two branches, one direct string
assignment call, and one return.

The alias reopened successfully in
`analysis/spectron_libqplay_translated_v191.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,228 default `sub_` names. The v191 database SHA-256 is
`954bce45a8c01d94a27dffcc75d5173798b5637459ad8c0d1358961ce2527f26`.

The machine-readable record is
`artifacts/spectron_gui_button_types_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_gui_button_types_anchors.py`. The alias
only changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron displayed-GIF state initializer

The v190 pass resolves the source `initializeDisplayedGif` callback to the
target `sub_E0B80`. The match is supported by both static-initializer and
cleanup tables, the shared global-pointer indirection, and the same translated
draw-consumer family.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `initializeDisplayedGif` | `0xe08fc` | `0xe0b80` | `sub_E0B80` | displayed-GIF state, layout change |

The source callback stores null through `displayedgif_ptr` at `0x374cd8` into
the shared `displayedgif` state at `0x38ede8`, then returns the state address.
Its static-initializer table slot is `0x35d268`. The corresponding source
cleanup callback is `sub_E05E0` at `0xe05e0`, referenced by cleanup table slot
`0x35d2e0`.

Spectron keeps the same role in `DiZVgajboR` at `0x3a26c8`, reached through
`DiZVgajboR_ptr` at `0x387d08`. The initializer is `sub_E0B80` at `0xe0b80`,
referenced by target slot `0x36f9f8`. The target cleanup callback is
`sub_DFED4` at `0xdfed4`, referenced by `0x36fdd8`. It clears `DiZVgajboR`
and then clears the neighboring `CanTfaz6bZ` object at `qword_3A26A8`.

The target initializer also sets that neighboring string to the empty
`byte_2EA8F0` value. This accounts for the extra assignment call and the
larger body. The source row is 16 bytes and four instructions in one block,
with one branch, no direct calls, and one return. The target row is 60 bytes
and 13 instructions in one block, with two branches, one direct string
assignment call, and one return.

The state correspondence is also visible in the consumers. Both globals are
read by the translated `TPlayer` sprite, status-bar, and draw paths, the
`TServerPlayer` draw paths, and the `TExplosion`, `TServerBomb`,
`TServerCarry`, and `TServerExtra` draw families. That consumer set separates
this callback from nearby static string initializers that have similar target
shapes.

The alias reopened successfully in
`analysis/spectron_libqplay_translated_v190.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,229 default `sub_` names. The v190 database SHA-256 is
`6786c5996c4b41c0f4e1825b7e5df7d4a5ed828f586adca1b1d9592a4ab625ee`.

The machine-readable record is
`artifacts/spectron_displayed_gif_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_displayed_gif_anchors.py`. The alias only
changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron TOptions window-position initializer

The v189 pass resolves the source `TOptions_initializeWindowPosition`
callback to the target `sub_E0B3C` in Spectron's obfuscated `K7FLgag3II`
options class. The static-initializer table references and the two coordinate
stores make this a high-confidence layout-change match.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TOptions_initializeWindowPosition` | `0xe08e4` | `0xe0b3c` | `sub_E0B3C` | window-position defaults, layout change |

The source callback is a small two-coordinate initializer:

```text
data_TOptions_windowpos = -1;
dword_38E0C4 = -1;
return &data_TOptions_windowpos;
```

It is referenced by source static-initializer table slot `0x35d260`, and the
two source fields are at `0x38e0c0` and `0x38e0c4`. The target callback is
referenced by slot `0x36f9f0` and preserves the same two `-1` defaults in
`K7FLgag3II::y3nkMaCRLg` at `0x3a1988` and `dword_3A198C` at `0x3a198c`:

```text
qword_3A1918 = empty CanTfaz6bZ string;
K7FLgag3II::y3nkMaCRLg = -1;
dword_3A198C = -1;
return &K7FLgag3II::y3nkMaCRLg;
```

The target adds initialization for neighboring `qword_3A1918`, a
`CanTfaz6bZ` string cleared by the target `sub_DFEC4` teardown callback. This
accounts for the extra assignment call and the larger body without changing
the coordinate role. The source row is 24 bytes and six instructions in one
block, with one branch, no direct calls, and one return. The target row is 68
bytes and 15 instructions in one block, with two branches, one direct string
assignment call, and one return. The target's options class was already tied
to the translated account, credential, GUI-style, and persistence methods, so
these field names are not inferred from this initializer alone.

The alias reopened successfully in
`analysis/spectron_libqplay_translated_v189.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,230 default `sub_` names. The v189 database SHA-256 is
`fd4a5a88b1d959ab3a3465b4f080355211f7dcb68d53781f41f8f0dcc2ae538b`.

The machine-readable record is
`artifacts/spectron_options_window_position_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_options_window_position_anchors.py`. The alias only
changes the persisted IDA analysis copy. No APK or native library was
modified.

## Spectron current-animation-state cleanup

The v188 pass resolves the source `clearCurAnis` callback to the target
cleanup routine for the shared current-animation state.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `clearCurAnis` | `0xe083c` | `0xdfe08` | `sub_DFE08` | 248-byte state cleanup, layout change |

In 1.8, `clearCurAnis` loads the `curanis` pointer from `0x38d5e8`, writes
zero over all 248 bytes, and returns the pointer. The source callback table
entry is `0x35d250`.

Spectron initializes an equally sized state object at `RGiAvaPk9a` (`0x3a0e80`)
from `sub_E09E0` at `0xe09e0`. Its cleanup callback, `sub_DFE08`, is recorded
in target cleanup table slot `0x36fda0`, while the initializer is in target
table slot `0x36f9c0`.

The target has a more explicit string lifetime. It calls
`C8THgaTQxF::clear` on each of the 31 eight-byte fields from `RGiAvaPk9a`
through `0x3a0f70`, then clears the adjacent `CanTfaz6bZ` object at
`qword_3A0E70`. The target initializer sets that adjacent object to the
empty `byte_2EA8F0` string and zeroes the same 248-byte state extent. The
target animation code references this state from `TGraalAni`, `TPlayer`,
`TServerNPC`, `TServerPlayer`, and `TServerFlying`, which separates this
callback from unrelated static string cleanup.

The source body is 136 bytes and 34 instructions in one block. The target is
76 bytes and 19 instructions across four blocks, with a two-branch string
cleanup loop and a tail branch into `CanTfaz6bZ::clear`. The source uses no
direct calls and vector stores instead. These implementation differences are
expected from the target's C++ string layout and account for the nonmatching
normalized hashes.

The evidence is in
`artifacts/spectron_clear_cur_anis_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_clear_cur_anis_anchors.py`. The alias
reopened successfully in
`analysis/spectron_libqplay_translated_v188.i64`. The full semantic reopen
check reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,231 default `sub_` names. The v188 database
SHA-256 is
`237d2ba156a7aa8ed41d9d6f7a0c1c1f3dbb7b8504762ae8d3d0a399d64f949c`.

## Spectron resource link-list initializer

The v187 pass resolves the resource link-list initializer that was left
unassigned while reviewing the v186 particle-emitter collision. The source
callback creates the two global lists used by resource file links and
resource object links. Spectron keeps the same startup role with obfuscated
class and field names.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TResource_initializeLinkLists` | `0xe070c` | `0xe0564` | `sub_E0564` | exact normalized match |

The source function allocates two 0x28-byte `THashList` objects and calls
the list constructor for each one. It stores the first object in
`TResourceFileLink::links`, stores the second in
`TResourceObjectLink::links`, and returns the second pointer. The target
function allocates the same two object sizes, constructs
`KKhLga4xoI` objects, stores them in
`OOmzgapOmy::IYlQSaJ5EK` and `H4zIGaBY6x::IYlQSaJ5EK`, and returns the
object-link list pointer.

The target fields are independently grounded by the already translated
resource-link methods. `OOmzgapOmy` is the resource-file-link class, based
on its filename constructor and update dispatch method. `H4zIGaBY6x` is
the resource-object-link class, based on its pointer-taking constructor and
link lookup method. The source and target callbacks are referenced from
static-initializer table slots `0x35d218` and `0x36f8d8`.

Both rows are one-block, 76-byte, 19-instruction initializers with five
branches, four calls, one return, and identical complete normalized metrics.
That includes the mnemonic, opcode-shape, register-shape, normalized-shape,
and string-reference hashes. The target was default-named before the alias,
so this pass lowers the persisted default `sub_` count by one.

This target at `0xe0564` was first seen as a possible particle-emitter
initializer because its allocation shape is shared with target
`0x2451f4`. The v186 review resolved `0x2451f4` to the particle
script-property initializer because it constructs
`ULeBJaZ1WYProperties` and `pdnkJaZ8KKProperties`. The class-qualified
static fields and `KKhLga4xoI` constructor calls instead make
`0xe0564` the resource initializer. The written artifact records both
decisions so the collision is not silently revisited.

The evidence is in
`artifacts/spectron_resource_link_lists_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_resource_link_lists_anchors.py`. The alias
reopened successfully in
`analysis/spectron_libqplay_translated_v187.i64`. The full semantic reopen
check still reports zero failures across 11,694 functions, with 3,641
high-confidence labels and 1,232 default `sub_` names. The v187 database
SHA-256 is
`41df8f193e7e69551e85f06e2a01471fc4680d635d6d30eb0fb99efb1c0a3d8e`.
No APK or native code was modified.

## Spectron server-animation anchors

The v59 pass reviewed three remaining unmatched server-animation methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TExplosion_animate_void` | `0x23caec` | `0x24699c` | collision, damage, and PK notification |
| `TServerCarry_animate_void` | `0x23d774` | `0x24768c` | movement, obstacles, damage, and bomb handoff |
| `TServerFlying_animate_void` | `0x23eeb0` | `0x248e38` | projectile, collision, and combat state machine |

`TExplosion_animate` retains active-player and level guards, NPC action 13,
distance checks, direction-dependent damage, the `explosion` label, and the
zero-health PK notification. `TServerCarry_animate` keeps direction-based
movement, adjacent-level transfer, throw-wall and NPC handling, the
`blackstone`, `bush`, `sign`, `stone`, and `vase` sprite families, bush damage,
water leaps, and bomb handoff. `TServerFlying_animate` keeps dominant-direction
selection, four-frame animation, shield interaction, `arrow` damage,
`arrowon.wav`, `bomb.wav`, NPC action 14, wall checks, and overlap scanning.

The target versions have wrapper, direction-table, and object-layout changes.
The explosion and carry methods therefore have expanded block counts, while
the flying method retains the source 106-block shape. These are high-confidence
class-local anchors based on preserved field offsets, distinctive literals,
movement and collision branches, and reviewed pseudocode.

The evidence is in
`artifacts/spectron_server_animation_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_animation_anchors.py`. All three
labels were applied to a copy of v58 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v59.i64`. The database SHA-256 is
`a2f9a22dfe43d846c7a354fc79c7fb44e7727d58610bfb39ebbd26b6c133e95f`.

## Spectron player lifecycle anchors

The v60 pass reviewed two remaining unmatched player lifecycle methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_loadStartLevel_bool` | `0x178160` | `0x17c3e8` | reset state and initial level load |
| `TPlayer_timer_void` | `0x179594` | `0x17d8cc` | periodic update and network-state timer |

`loadStartLevel` retains the reset of player state, the server-privilege and
health decisions, initial animation and spawn-link setup, restart-position
update, and the `Could not find the level` diagnostic in the `levels` category.
`timer` retains encoded-field refresh, action and counter updates, the `stay`
emoticon timeout, server-player and key checks, player and level animation,
map-link and lava handling, client triggers, NPC actions, show-image and board
synchronization, and movement-buffer updates.

Both target methods retain the source 27-block and 148-block control-flow
shapes. The changed field offsets and wrapper calls follow the larger 2.2
player object. The evidence is in
`artifacts/spectron_player_lifecycle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_lifecycle_anchors.py`. Both labels
were applied to a copy of v59 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v60.i64`. The database SHA-256 is
`9254878f5c135452260508068fa54f3ca6821d6cbd506af49dc14fd08bea4ab2`.

## Spectron player emoticon anchors

The v61 pass reviewed two small player coordinate getters that remained
unmatched by the broad semantic matcher.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_getEmoticonX_void` | `0x16fc68` | `0x173b30` | X coordinate and `emoticon_z` adjustment |
| `TPlayer_getEmoticonY_void` | `0x16fd24` | `0x173c0c` | Y coordinate, `emoticon_z`, and active-counter adjustment |

The X getter preserves the inherited base-coordinate call, the shifted player
X field, the `emoticon_z` search, and the plus 2.0 adjustment. The Y getter
preserves the matching Y path, the minus 5.0 adjustment, and the positive
active-counter check that subtracts 1.7. The target adds an explicit wrapper
conversion for the string object and shifts the player and emoticon-object
fields with the larger 2.2 layout, but keeps the source seven-block and
ten-block control-flow shapes.

The evidence is in
`artifacts/spectron_player_emoticon_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_emoticon_anchors.py`. Both labels
were applied to a copy of v60 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v61.i64`. The database SHA-256 is
`cfac89e2ddc58e14b0eac9be2eaf052b8cc1373d47036c33ea96b441544ac079`.

## Spectron player level-entry anchors

The v62 pass reviewed two central player methods that remained unmatched by
the broad semantic matcher.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_enterLevelMain_TString_const_bool` | `0x178558` | `0x17c7f8` | level transition, cleanup, and restart state |
| `TPlayer_enterServerLevel_TString_const_bool` | `0x178a18` | `0x17cd00` | server-level creation and modification handoff |

`enterLevelMain` preserves side-level calculation, changed-map cleanup, stale
object cleanup, map-position and board updates, tile refresh, render-buffer
setup, restart-position resolution, and action-state reset. `enterServerLevel`
preserves server-level creation and loading, client and NPC level globals,
three object-list cleanup passes, server-modification dispatch, attached-player
reset, and the handoff back into main level entry. The target keeps the source
56-block and 32-block shapes, with one extra branch in the first method.

The evidence is in
`artifacts/spectron_player_level_entry_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_level_entry_anchors.py`. Both
labels were applied to a copy of v61 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v62.i64`. The database SHA-256 is
`888c0ef9c1f5f83a45f30a4429a7e2ea7dd8126e04bdf09d50ec08cdfc0a09b3`.

## Spectron player side-level anchors

The v63 pass reviewed four side-level methods used by the player level-entry
path.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_setSideLevels_void` | `0x16e3d0` | `0x1720d0` | grid reset and neighboring level selection |
| `TPlayer_loadSideLevels_void` | `0x16e634` | `0x172404` | level reuse, cleanup, and preload |
| `TPlayer_getSideLevel_int_int` | `0x16e9e8` | `0x1727e0` | bounded coordinate lookup |
| `TPlayer_SideLevelInDirection_int` | `0x16ea50` | `0x172854` | directional occupancy scan |

The target preserves the grid setup, stale-level cleanup, side-level creation,
preload path, coordinate bounds, and directional occupancy behavior. Its grid
is seven by seven instead of three by three, and two target-only boundary
helpers split out arithmetic that was inline in 1.8. Those helpers remain
obfuscated because they do not have direct 1.8 symbol counterparts.

The evidence is in
`artifacts/spectron_player_side_level_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_side_level_anchors.py`. All four
labels were applied to a copy of v62 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v63.i64`. The database SHA-256 is
`9bf7ae63884225e0ef3abab3f9733a1dde9c5c3eae4fdf24b5c83ec41fad076b`.

## Spectron player map-position anchors

The v64 pass reviewed two map-position methods used by the player level-entry
and level-link paths.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_updateMapPos_void` | `0x1720a8` | `0x176068` | active-map refresh and `.gmap` fallback |
| `TPlayer_checkMapPos_bool_bool` | `0x173308` | `0x177308` | map-link detection and translated position |

The target preserves active-map lookup, map-coordinate refresh, nearby-NPC
recalculation, `.gmap` fallback, map-link bounds checks, world-coordinate
translation, and the cached-link or client-send choice. `updateMapPos` has one
fewer target block, while `checkMapPos` retains the exact 17-block shape.

The evidence is in
`artifacts/spectron_player_map_position_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_map_position_anchors.py`. Both
labels were applied to a copy of v63 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v64.i64`. The database SHA-256 is
`f53c37fbdbc66d1774c24ac7fcb30d9a68cb4aca569ac8d7cb81aaf81c12510e`.

## Spectron player link-traversal anchors

The v65 pass reviewed three player methods immediately after the map-position
helpers.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_animateLevel_void` | `0x16f090` | `0x172e78` | profiler scope and side-level animation |
| `TPlayer_testForMapLinks_void` | `0x16f1b8` | `0x17303c` | nearby link detection and packet send |
| `TPlayer_testForLinks_void` | `0x16f338` | `0x1731a8` | edge and object link state machine |

The target preserves the profiler scope, side-level animation, attached-player
and disallowed-link checks, direction and boundary handling, level-object
scans, destination coordinate calculations, and client link notification. The
seven-by-seven grid and rebuilt wrappers account for changed block counts.

The evidence is in
`artifacts/spectron_player_link_traversal_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_link_traversal_anchors.py`. All
three labels were applied to a copy of v64 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v65.i64`. The database SHA-256 is
`0d7f9660341da422888acfc948d0cd6fa2ade6bdbcbbe95d4d5326a39dc7ca44`.

## Spectron player weapon-state anchors

The v66 pass reviewed four player weapon and attribute methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_resetAttributes_void` | `0x1742cc` | `0x1782fc` | full player reset and `letters.png` |
| `TPlayer_deleteSelectedWeapon_void` | `0x1746f0` | `0x178828` | protected weapon check and deletion |
| `TPlayer_setSelectedWeapon_int` | `0x1747b4` | `0x178910` | cyclic selection and name update |
| `TPlayer_getWeapon_TString_const` | `0x175850` | `0x179af8` | weapon-list lookup by name |

The target preserves player reset, weapon cleanup, protected-name handling,
cyclic selection, selected-name update, and weapon lookup. The larger 2.2
player object shifts fields and wrappers, while the small selection and lookup
methods retain their source block counts.

The evidence is in
`artifacts/spectron_player_weapon_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_weapon_state_anchors.py`. All four
labels were applied to a copy of v65 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v66.i64`. The database SHA-256 is
`b17096b3ce92774fdfdf90b2a21c52dad8111ad7d09bd2b705fa0d3371ecd25b`.

## Spectron player visual setter anchors

The v67 pass reviewed five player draw-state and visual setter methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_setDrawRect_void` | `0x16df08` | `0x171bf8` | screen layout and aligned draw rectangle |
| `TPlayer_setHead_TString_const` | `0x17ae84` | `0x17f1c8` | head compare, flag, and inherited setter |
| `TPlayer_setBody_TString_const` | `0x17aec8` | `0x17f238` | body compare, flag, and inherited setter |
| `TPlayer_setSword_TString_const` | `0x19dce8` | `0x1a295c` | normalized sword image update |
| `TPlayer_setShield_TString_const` | `0x19dd4c` | `0x1a29e4` | normalized shield image update |

The target preserves the same screen-layout branches, four-pixel alignment,
head and body comparison plus change-flag behavior, and lower-case sword and
shield updates. The larger 2.2 player object shifts fields and uses rebuilt
string wrappers. The draw-rectangle method keeps fourteen blocks, while the
small setters keep three target blocks.

The evidence is in
`artifacts/spectron_player_visual_setter_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_visual_setter_anchors.py`. All five
labels were applied to a copy of v66 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v67.i64`. The database SHA-256 is
`b35de4695b4ccc607722b5d049df1b3838f20dcd2e010d9bafda5c47ca105b97`.

## Spectron player movement and interaction anchors

The v68 pass reviewed eight player movement, inventory, animation, and hurt
methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_pullStones_void` | `0x197e2c` | `0x19c954` | pulled trigger and client notification |
| `TPlayer_moveStones_void` | `0x1980d0` | `0x19cc50` | pushed trigger and client notification |
| `TPlayer_canJump_void` | `0x198300` | `0x19ced8` | jump tile and wall checks |
| `TPlayer_movementAction_int` | `0x198bb8` | `0x19d7f8` | movement and interaction dispatcher |
| `TPlayer_itemAvailable_int` | `0x19ad78` | `0x19f9a0` | inventory and weapon availability |
| `TPlayer_animateJumping_void` | `0x19bbd8` | `0x1a0844` | directional jump animation |
| `TPlayer_loseItem_int` | `0x19c9e0` | `0x1a1650` | item consumption and downgrade |
| `TPlayer_hurtPlayer_double_double_double_TString_const_TServerPlayer` | `0x19dfa4` | `0x1a2c60` | damage and knockback event |

The target preserves the stone trigger paths, jump tile and wall checks, the
large movement state machine, the item prefix and threshold cases, the weapon
and shield downgrade paths, the directional jump counter, and hurt-event
normalization. The target adds explicit direction switches and rebuilt string,
array, level, and player wrappers, so the large methods change block counts
slightly while retaining their distinctive literals and call relationships.

The evidence is in
`artifacts/spectron_player_movement_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_player_movement_anchors.py`. All eight
labels were applied to a copy of v67 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v68.i64`. The database SHA-256 is
`5daae0f4a60036947f12748aa7b5ef89312b0fe3ac71aa10477d9bfe84f5bf75`.

## Spectron server-player state anchors

The v69 pass reviewed six server-player initialization, level, property,
nickname, and weapon-image methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerPlayer_setHead_TString_const` | `0x18b010` | `0x18f8c0` | conditional head-string update |
| `TServerPlayer_initPlayerVars_void` | `0x18ba6c` | `0x190334` | state initialization and default assets |
| `TServerPlayer_playerEnteredLevel_void` | `0x18ccf8` | `0x1915a8` | level and side-level membership |
| `TServerPlayer_setNick_TString_const` | `0x18dea0` | `0x1927a0` | nickname normalization and events |
| `TServerPlayer_setProperties_TString_const` | `0x18e168` | `0x192ac8` | encoded property parser |
| `TServerPlayer_setWeaponImgs_TString_const` | `0x19004c` | `0x194a54` | encoded weapon-image parser |

The target preserves default state initialization, gmap and regular-level
membership, nickname propagation, the compact property switch, and the full
weapon-image directive parser. It shifts object fields and uses rebuilt
string, list, map, and show-image wrappers. The distinctive default assets,
image and `setani` literals, and the close source and target block counts make
these stable class-local correspondences.

The evidence is in
`artifacts/spectron_server_player_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_player_state_anchors.py`. All six
labels were applied to a copy of v68 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v69.i64`. The database SHA-256 is
`3772800d76e7e1cbc252dc7169a4c15c1ff342dc38bbc8cb43904d2739df360e`.

## Spectron server-NPC state anchors

The v70 pass reviewed seven server-NPC construction, shape, naming, default-
image, movement, and property methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerNPC_script_setShape2` | `0x180f1c` | `0x185484` | shape callback and `shape` variable |
| `TServerNPC_TServerNPC_int` | `0x183cc8` | `0x188340` | constructor and `save` variable |
| `TServerNPC_getLogName_void` | `0x181458` | `0x1859ec` | role-aware log name |
| `TServerNPC_setDefaultImageNames_void` | `0x185fd0` | `0x18a678` | default images and colors |
| `TServerNPC_serverMovedNPC_bool` | `0x186c38` | `0x18b3b0` | movement reset and sound |
| `TServerNPC_setProperties_TString_const` | `0x186d48` | `0x18b4ec` | encoded NPC property parser |
| `TServerNPC_doNPCMove_void` | `0x188260` | `0x18ca28` | NPC move queue and completion |

The target preserves the ten-block shape callback behavior, including the
`shape` script variable and array-length check. The original IDA comment ties
the source callback record at `0x37c908` to `setshape2` in the TServerNPC
script-function table at `0x183c18`. The feature export showed `sub_185484`
because this target function had no retained name, so the callback-table and
behavior evidence is recorded explicitly before applying the v18 role label.

The constructor retains base initialization, NPC vtables, helper allocation,
dimensions, flags, and the `save` variable. The log-name method keeps the
GANI, projectile, weapon, head0, and unknown cases with level, cell, and
coordinate context. Default-image setup retains water-aware animation, the
four image literals, and color defaults. Movement update keeps the legacy
server guard, action-level test, water and gani handling, and optional sound.
The large property parser preserves image, head and body, weapon, GANI,
movement, attachment, map and position, status, event, and hit-detection cases.
The move queue retains the bomy animation branches, position updates, and
`movementfinished` event.

The evidence is in
`artifacts/spectron_server_npc_state_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_npc_state_anchors.py`. All seven
labels were applied to a copy of v69 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v70.i64`. The database SHA-256 is
`c384c10b3a0cdd69925df8017a3a870de64aa4942923d59a12bc88c5bbc690b4`.

## Spectron NPC accessor anchors

The v71 pass reviewed 17 compact server-NPC property accessors that were still
unresolved after the earlier helper pass.

| 1.8 role | Source | Spectron target | Main evidence |
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

The target keeps the same compact class-local sequence and direct behavior. The
hurt setters clamp both axes, the blocking getter inverts its byte, layer keeps
the special normalization cases, and save returns the same logical variable
pointer. The shield and sword wrappers preserve the virtual getter and setter
slots with an eight-byte shift in the rebuilt vtable. The X and Y getters keep
the inherited local-coordinate call plus tile-coordinate contribution, and the
visibility getter reads the shifted logical byte.

The original callback records provide a second identification layer. They name
the properties as hearts and hp, hurtdx, hurtdy, isblocking,
isblockingprojectiles, layer, save, shieldpower, swordpower, x, y, and visible.
All 17 target functions were default-named before the labels were applied, so
the evidence is explicitly behavioral and structural rather than based on a
retained target symbol.

The evidence is in
`artifacts/spectron_npc_accessor_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_npc_accessor_anchors.py`. All 17 labels
were applied to a copy of v70 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v71.i64`. The database SHA-256 is
`307ad12c6bcf4f1aec20e8145daf3b41037a63f5834d84950e7cf399c1859da0`.

## Spectron NPC destructor anchors

The v72 pass reviewed the two server-NPC destructor entry points between the
callback helpers and the role-aware log-name method.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerNPC_TServerNPC` | `0x1811ac` | `0x185730` | complete destructor cleanup |
| `TServerNPC_TServerNPC__2` | `0x181438` | `0x1859cc` | deleting-destructor wrapper |

The large source body is the complete destructor. IDA also shows its D1 ABI
alternative, while the target exposes the matching D2 body and D1 alternative.
The target keeps the same cleanup sequence for script state, helper objects,
global and level membership, local-player weapon references, image resources,
strings, and the server-player base object. Both bodies retain 31 blocks.

The short source wrapper calls the complete destructor and then
`operator delete`. The target D0 wrapper does the same, with the exact two
blocks and 32-byte size. These are ABI and lifecycle correspondences, not
guesses from the obfuscated target class name.

The evidence is in
`artifacts/spectron_npc_destructor_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_npc_destructor_anchors.py`. Both labels
were applied to a copy of v71 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v72.i64`. The database SHA-256 is
`24ea9c5816854de6f8e157439e01f6a556009adf432d26bb8ddbcd429bac87d3`.

## Spectron server-level property anchors

The v73 pass reviewed eight exact server-level and level-link property pairs.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_set_preloadleveldefaulttile` | `0x19f938` | `0x1a4608` | preload tile static setter |
| `TServerLevel_getHeight` | `0x19f948` | `0x1a4618` | active-layer height |
| `TServerLevel_getNoPKZone` | `0x19f978` | `0x1a4648` | no-PK zone byte |
| `TServerLevel_setNoPKZone` | `0x19f980` | `0x1a4650` | no-PK zone store |
| `TServerLevel_getSparringZone` | `0x19f988` | `0x1a4658` | sparring-zone byte |
| `TServerLevel_getTileLayerCount` | `0x19f990` | `0x1a4660` | layer-list count |
| `TServerLevel_getWidth` | `0x19f99c` | `0x1a466c` | active-layer width |
| `TServerLevelLink_getDestLevel` | `0x19faa8` | `0x1a46a0` | destination-level string |

Every source and target body has identical size, instruction count, basic-block
count, mnemonic hash, register-shape hash, and control-flow shape hash. The
target preserves active-layer dimensions, zone bytes, layer-list count, the
preload static setter, and the destination-level string copy.

The paired 1.8 preload getter remains unresolved because the stripped target
region exposes a setter body at `0x1a4608` but no separate corresponding getter
body. This pass intentionally maps only the setter. All eight target functions
were default-named before labeling, so the table comments, callback references,
exact body hashes, and class-local order are the evidence.

The evidence is in
`artifacts/spectron_server_level_property_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_property_anchors.py`. All
eight labels were applied to a copy of v72 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v73.i64`. The database SHA-256 is
`e38d67d4a9920b462b00c851186a19e93f2f4ed9f9abef957272476402ac52e7`.

## Spectron server-level interaction anchors

The v74 pass reviewed five server-level interaction and level-link methods.
The NPC predicate in this neighborhood was already labeled in the earlier
core-helper checkpoint and is not duplicated here.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevelLink_getDestY` | `0x19fcdc` | `0x1a49b4` | player-token-aware destination Y |
| `TServerLevelLink_getDestX` | `0x19fd88` | `0x1a4a60` | player-token-aware destination X |
| `TServerLevel_script_removeExplo` | `0x19ff84` | `0x1a4c5c` | indexed explosion removal |
| `TServerLevel_script_removeBomb` | `0x19ffe8` | `0x1a4cc0` | bomb removal and client packet |
| `TServerLevel_script_removeArrow` | `0x1a00ac` | `0x1a4d84` | indexed arrow removal |

The two destination getters retain the `playerx` and `playery` token checks,
active-player coordinate forwarding, and numeric fallback. The explosion and
arrow methods keep index validation, list deletion, and virtual cleanup. The
bomb method also keeps coordinate extraction and client notification. Four
pairs have identical exported body hashes. The bomb target changes from ten to
eight blocks while preserving the same state transitions with rebuilt wrappers.

The evidence is in
`artifacts/spectron_server_level_interaction_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_interaction_anchors.py`. All
five labels were applied to a copy of v73 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v74.i64`. The database SHA-256 is
`39cf3f36e09056c034713f8384476d269681315df4ee6b6cbe497cb54720113d`.

## Spectron server-level lifecycle helpers

The v75 pass reviewed seven exact server-level lifecycle, script-test, and
animation helper pairs. The NPC-list getter was already labeled in the earlier
core-helper checkpoint and is not repeated here.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_TServerLevel__2` | `0x1a17b8` | `0x1a6468` | deleting-destructor wrapper |
| `TServerLevel_script_tileType` | `0x1a45a8` | `0x1a92c0` | tiletype callback wrapper |
| `TServerLevel_script_testItem` | `0x1a5760` | `0x1aa478` | item collision test wrapper |
| `TServerLevel_script_testExplo` | `0x1a5898` | `0x1aa5b0` | explosion collision test wrapper |
| `TServerLevel_animateCarries_void` | `0x1a6d44` | `0x1aba5c` | carry animation queue |
| `TServerLevel_animateLeaps_void` | `0x1a6dd0` | `0x1abae8` | leap animation queue |
| `TServerLevel_animateFlyingObjects_void` | `0x1a6e5c` | `0x1abb74` | flying-object animation queue |

The target preserves the deleting-destructor wrapper, the three coordinate
script forwards, and the reverse-order animation and cleanup loops for carry,
leap, and flying-object lists. Every pair has identical exported body metrics
and hashes. The script-test targets were default-named before labeling, while
the destructor and animation targets retain ABI or obfuscated names.

The evidence is in
`artifacts/spectron_server_level_lifecycle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_lifecycle_helpers.py`. All
seven labels were applied to a copy of v74 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v75.i64`. The database SHA-256 is
`3aaba8fe22c5f8d92c48e58bcaf0290254b28893e405edf600e9525f00eefe07`.

## Spectron server-level side and flower helpers

The v76 pass reviewed four server-level helper pairs immediately following
the constructor and neighboring level methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_getSideLevelPos_int_int` | `0x1a92a0` | `0x1ae1d8` | cached side-level position lookup |
| `TServerLevel_getSideLevelInDirection_int` | `0x1a93a0` | `0x1ae3ec` | directional side-level lookup |
| `TServerLevel_calcFlowers_void` | `0x1a9480` | `0x1ae584` | empty flower calculation hook |
| `TServerLevel_animateFlowers_void` | `0x1a9484` | `0x1ae588` | empty flower animation hook |

The side-level position target searches the active player's cached grid and
writes the matching coordinates, while the directional target selects a
neighbor from the same cache using the movement vector. Both preserve the
1.8 roles and the class-local order, with the target's seven-by-seven grid
accounting for the changed body sizes. The flower hooks are exact four-byte
no-op matches with identical normalized hashes.

The evidence is in
`artifacts/spectron_server_level_side_helpers_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_side_helpers.py`. All four
labels were applied to a copy of v75 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v76.i64`. The database SHA-256 is
`0be95bd5c5aa4f7e5a6309e85255f798da63ed62363edf843013584579fe3a3e`.

## Spectron server-level construction and storage

The v77 pass reviewed four larger server-level functions with preserved
1.8 lifecycle, persistence, and event-dispatch behavior.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_TServerLevel_TString_const` | `0x1a854c` | `0x1ad294` | constructor and child arrays |
| `TServerLevel_SaveEncrypted_uint` | `0x1a1f50` | `0x1a6c00` | encrypted level serialization |
| `TServerLevel_LoadEncrypted_void` | `0x1aa198` | `0x1af2a0` | encrypted level deserialization |
| `TServerLevel_invokePlayerEnters_TString_const_int_int_int_int` | `0x1a3ee0` | `0x1a8be0` | NPC and baddie enter dispatch |

The constructor preserves the level child arrays and the eleven recognizable
names used by the source. The save and load methods retain the GWEBL001
container header, identity and signature checks, GR-V1 format selection,
multi-layer board handling, object sections, and checksum calculation. The
player-enter method preserves the NPC and baddie scans and coordinate-window
callback tests. These are semantic anchors with changed byte sizes, not byte
identity claims.

The evidence is in
`artifacts/spectron_server_level_storage_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_server_level_storage_anchors.py`. All
four labels were applied to a copy of v76 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v77.i64`. The database SHA-256 is
`ff6ad12749bb2114c4b6701e8c304a43b557d2ae2d8367f1b1e2c15ea8bfa666`.

## Spectron hidden testnpc callback boundary

The v78 pass recovered one function boundary that clean IDA had omitted:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TServerLevel_script_testNPC` | `0x1a4e98` | `0x1a9bb0` to `0x1a9c2c` | exact callback body and NPC index lookup |

The target body sits between the target `isOnNPC` and `getOnNPC` methods. Once
the explicit range was materialized, its pseudocode checked the same action
globals, called the target is-on-NPC method, and returned the matching NPC
list index. All body metrics and normalized hashes match the source exactly.
This row records a boundary recovery as well as a semantic label, so it is
not part of the original clean target function count.

The evidence is in
`artifacts/spectron_hidden_testnpc_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_hidden_testnpc_anchor.py`. The boundary
was materialized with `tools/ida_materialize_spectron_hidden_functions.py`,
then the label was applied to a copy of v77 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v78.i64`. The database SHA-256 is
`07a1209c24090df3908bbb8ec4805cb043d58a7739243a2424f70867e842561c`.

## Spectron level and map lookup anchors

The v79 pass reviewed six helpers that connect level names, map aliases, link
serialization, and GMAP loading:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `getLevel_TString_const` | `0x1a02e4` | `0x1a4fbc` | normalized global level lookup |
| `getLevelPos_TString_const_TStringList` | `0x1a03b4` | `0x1a5094` | normalized list index wrapper |
| `TServerLevelLink_getTStringRepresentation_void` | `0x1a08e8` | `0x1a5580` | link field serialization |
| `checkForNewMap_TPlayer_TString_const` | `0x1a8404` | `0x1ad124` | current-map transition and refresh |
| `LoadGraalMap_TPlayer_TString_const_bool` | `0x1a8e88` | `0x1add28` | `.gmap` load and player refresh |
| `getMap_TString_const_bool` | `0x1a9148` | `0x1ae07c` | map lookup and placeholder creation |

The first lookup keeps the filename normalization, global level-list walk, and
offset-128 name comparison. The level-position helper is a compact target
wrapper that validates the same inputs and calls the obfuscated list index
method. The link serializer keeps the four coordinate fields, both level
fields, space removal, comma-to-period conversion, and prefix construction.

The three map helpers retain the important state transitions. Map selection
searches names and aliases and refreshes loaded levels when the player's map
changes. GMAP loading keeps the `.gmap` rule, 0x198-byte allocation, resource
lookup, global-list insertion, and active-player side-level refresh. Map lookup
keeps the loader fallback and the optional placeholder path with its 999-entry
limit and built-in alias.

The target bodies are semantic matches with changed implementation sizes. The
level-position wrapper is 48 bytes versus 120 in 1.8, and the GMAP loader is
852 bytes versus 704. The remaining targets preserve their source block count.
The evidence is in
`artifacts/spectron_level_map_lookup_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_level_map_lookup_anchors.py`. All six
labels were applied to a copy of v78 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v79.i64`. The database SHA-256 is
`6f60bbda2b7e5f2b5f5c3630611938c113932308d57538120ca9857fd405b85b`.

## Spectron TGaniObject constructor anchor

The v80 pass reviewed the server-level `TGaniObject` constructor:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGaniObject_TGaniObject_TServerLevel` | `0x15e810` | `0x161a24` | animation parameters and color variables |

The target calls the level-object base constructor, initializes the same
animation-object state, creates the show-image and parameter lists, builds the
`attr` variable, inserts the built-in alias, and constructs 30 numbered
parameters. It also creates the `colors` variable and adds five configured
colors plus `black`, then initializes the same scale, font, visibility, sprite,
and lookup fields.

Spectron adds random-seed and encoded-buffer state, so the target is 1836 bytes
and 18 blocks versus 1356 bytes and 11 blocks in 1.8. The shared `attr` and
`black` literals, class-local constructor position, and preserved parameter
loop support a high-confidence semantic match. No byte identity is claimed.
The evidence is in
`artifacts/spectron_gani_constructor_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_gani_constructor_anchor.py`. The label
was applied to a copy of v79 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v80.i64`. The database SHA-256 is
`ec6f4f26293f1025b1e016e0ac5f2ae13ed0f5d3d69d93d5a12be8b02e7993c6`.

## Spectron Gani helper anchors

The v81 pass added two high-confidence helpers from the animation class:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TColorVar_writeString_TString_const` | `0x15dc50` | `0x160dc0` | named-color lookup and integer fallback |
| `TGaniObject_getImageForSprite_TGraalAniSprite_bool` | `0x15de20` | `0x160f8c` | child-Gani walk and type switch |

The color helper resolves a named color, falls back to integer parsing when
needed, and invokes the same virtual setter at slot 192. The sprite helper
retains the child chain, indexed image records, shared image-state fields,
body-name fields, global sprites and tiles filenames, and the optional type 1
current-object update. These are semantic translations supported by direct
Hex-Rays pseudocode, class-local placement, shared field offsets, and the
compact helper roles. Their changed sizes and block counts are recorded in the
artifact, with no byte identity claim.

The evidence is in
`artifacts/spectron_gani_helper_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_helper_anchors.py`. Both labels were
applied to a copy of v80 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v81.i64`. The database SHA-256 is
`bae4704ca2a47e0cbacde2e7c309ae5200e44f0f2c1ea0887dd560518ee2c14e`.

## Spectron Gani runtime anchors

The v82 pass mapped four methods around animation setup and execution:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGaniObject_checkPush2DMatrix_TPlayer` | `0x15fe4c` | `0x16323c` | transformed draw-matrix push |
| `TGaniObject_setGaniParamOrAttr_bool_bool_int_TString_const` | `0x160260` | `0x1636f0` | parameter or attribute write and visibility |
| `TGaniObject_getGaniParamOrAttr_bool_int` | `0x160344` | `0x1637fc` | parameter or attribute read |
| `TGaniObject_startAnimation_TString_const_TString_const_bool` | `0x160534` | `0x163a10` | animation load and child rebuild |

The matrix helper preserves the scale, rotation, identity check, and player
draw-matrix call, with extra target state explaining its larger body. The
parameter setter and getter preserve list selection, index conventions, bounds
checks, virtual slots, and visibility handling. The animation-start body keeps
the name trimming, resource load, owner transitions, bracketed metadata,
comma-separated parameters, child Gani creation, NPC-backed child, and
`playerlook` refresh. These are semantic translations supported by direct
Hex-Rays pseudocode and the surrounding target class order. The artifact
records changed sizes and block counts, and makes no byte identity claim.

The evidence is in
`artifacts/spectron_gani_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_runtime_anchors.py`. All four labels
were applied to a copy of v81 and reopened with zero failures in a serial IDA
check in `analysis/spectron_libqplay_translated_v82.i64`. The database SHA-256
is `2e57b6470fc9dd985cfa3f633ef63cbde493f60f13075da12a8ddfdd263d3fec`.

## Spectron Gani serialization and drawing anchors

The v83 pass mapped three methods in the Gani parameter and player draw path:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGaniParam_writeString_TString_const` | `0x161120` | `0x16462c` | numeric, image, and child-Gani decoding |
| `TGaniObject_reloadAnimation_void` | `0x1614bc` | `0x1649e0` | forced reload and child-script refresh |
| `TGaniObject_draw_TPlayer` | `0x162548` | `0x165aa0` | operation dispatch and player drawing |

The parameter writer retains numeric parsing, image detection, the `.gani`
child-animation path, owner-list insertion, and NPC-backed child creation.
The reload helper retains its forced start-animation call and child-script
refresh. The draw dispatcher preserves the animation, chat text, child sprite,
and text-token branches, along with world-position, matrix, bounds, color, and
style handling. These are semantic translations supported by direct Hex-Rays
pseudocode and class-local method order. The artifact records the changed
target sizes and block counts, with no byte identity claim.

The evidence is in
`artifacts/spectron_gani_render_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_render_anchors.py`. All three labels
were applied to a copy of v82 and reopened with zero failures in
`analysis/spectron_libqplay_translated_v83.i64`. The database SHA-256 is
`d9655d74b7e8e1c7cbcaed47d8840ee6274d61fb45fb2c2e75c8875a3b6d862c`.

## Spectron Gani frame and playback anchors

The v84 pass mapped the two large methods that complete the Gani frame and
playback path:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGaniObject_setFrame_int` | `0x163354` | `0x16690c` | actor properties, equipment, sprites, text, and style |
| `TGaniObject_playAnimation_void` | `0x164cf8` | `0x1684b0` | child updates, frame loop, sound lookup, and audio bridge |

The frame setter keeps the complete property vocabulary from 1.8. Both
versions apply `dx` and `dy` interpolation, layer and visibility, direction,
animation and chat state, body and equipment fields, `PARAM` and `ATTR` sprite
selectors, text and file values, colors, zoom, and the bold, italic, centered,
right-aligned, underline, strikeout, word-wrap, and shaded flags. All 28
property literals present in the 1.8 feature export are also present in the
Spectron target. The target grows to 7068 bytes, 1765 instructions, and 128
blocks from 6552 bytes, 1637 instructions, and 118 blocks.

The playback method keeps the child Gani, NPC-backed child, and object-list
updates, advances the frame counters, loops or reloads at the animation end,
checks active-player actions, and resolves `PARAM` or `ATTR` sound references.
It then loads the resource, calculates the playback position, and reaches the
audio bridge. The target is 1452 bytes, 363 instructions, and 62 blocks,
compared with 1396 bytes, 349 instructions, and 61 blocks in 1.8.

The target names are now recorded as `v18_TGaniObject_setFrame_int` and
`v18_TGaniObject_playAnimation_void` in the v84 disposable database. The
machine-readable evidence is in
`artifacts/spectron_gani_frame_playback_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_frame_playback_anchors.py`. Both
labels reopened with zero failures in
`analysis/spectron_libqplay_translated_v84.i64`. Its database SHA-256 is
`5ea5746f052d6940b6b7facae87de3875e381828847c57d9c03ac782d867984c`.

## Spectron Gani lifecycle anchors

The v85 pass filled in the remaining Gani object and TGraalAni lifecycle
surface with 50 high-confidence anchors. These were selected from direct
Hex-Rays comparisons, not from proximity alone. The target functions retain
the same class-local order, field offsets, virtual slots, destructor pairing,
or exact wrapper shape as the 1.8 functions.

The object and dispatch surface is:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGaniObject_clearChatWrapped_void` | `0x16526c` | `0x168a5c` | text-token child cleanup |
| GaniObject D1 destructor | `0x1652ac` | `0x168af8` | owner, child lists, strings, base teardown |
| GaniObject D0 destructor | `0x1654e0` | `0x168d48` | destructor and delete |
| `TLevelObject_getlocalx_void` | `0x1656c0` | `0x168ecc` | field offset 112 |
| `TLevelObject_getlocaly_void` | `0x1656c8` | `0x168ed4` | field offset 120 |
| `TLevelObject_setAttachedTo_TServerPlayer` | `0x1656d0` | `0x168edc` | field offset 144 |
| `TGaniObject_onNewAnimation_void` | `0x1656d8` | `0x168ee4` | no-op virtual hook |
| `TGaniObject_onGaniAttributeChanged_int` | `0x1656dc` | `0x168ee8` | no-op virtual hook |
| `TGaniObject_onGaniStepChanged_void` | `0x1656e0` | `0x168eec` | no-op virtual hook |
| `TGaniObject_getdir_void` and setter | `0x1656e4`, `0x1656ec` | `0x168ef0`, `0x168ef8` | direction field offset 260 |
| `TGaniObject_onUpdateColors_void` | `0x1656f4` | `0x168f00` | no-op virtual hook |
| Gani parameter property D1 pair | `0x1656f8`, `0x165714` | `0x168f04`, `0x168f20` | base destructor and thunk |
| Gani object property D1 pair | `0x16571c`, `0x165738` | `0x168f28`, `0x168f44` | base destructor and thunk |
| Gani parameter property D0 pair | `0x165740`, `0x165778` | `0x168f4c`, `0x168f84` | delete pair |
| Gani object property D0 pair | `0x165780`, `0x1657b8` | `0x168f8c`, `0x168fc4` | delete pair |
| `TGaniObject_receiveEvent_script_event` | `0x1657c0` | `0x168fcc` | virtual dispatch slot 128 |
| TColorVar D1 and D0 | `0x165824`, `0x165838` | `0x169030`, `0x169044` | Graal-variable base teardown |
| Gani event base thunk and wrapper | `0x165868`, `0x16586c` | `0x169074`, `0x169078` | temporary event and forwarding |

The source destructor display at `0x1652ac` looks like a constructor because
of the old IDA name, but its alternative name is `_ZN11TGaniObjectD1Ev` and
its pseudocode performs destruction. The target D2 body at `0x168af8` performs
the same visibility, owner, child-list, chat, string, lookup, and base cleanup.
It grows from 564 to 592 bytes, while the D0 wrapper remains an exact 32-byte
match. The property and TColorVar destructor pairs also preserve their source
metrics exactly.

The animation-state and resource surface is:

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| continuous getter and setter | `0x1658c4`, `0x1658cc` | `0x1690d0`, `0x1690d8` | byte offset 201 |
| loop getter and setter | `0x1658d4`, `0x1658dc` | `0x1690e0`, `0x1690e8` | byte offset 200 |
| movie getter and setter | `0x1658e4`, `0x1658ec` | `0x1690f0`, `0x1690f8` | byte offset 172 |
| singledirection getter | `0x1658f4` | `0x169100` | byte offset 202 |
| `setbackto` setter and getter | `0x165954`, `0x16595c` | `0x169160`, `0x169168` | string field offset 208 |
| `TGraalAni_clear_void` | `0x165a8c` | `0x1692bc` | sprite, step, owner, script reset |
| TGraalAni D0 destructor | `0x165db8` | `0x16956c` | destructor and delete |
| owner Add and Remove | `0x1660f4`, `0x1660fc` | `0x1698a8`, `0x1698b0` | owner-list operations |
| `TGraalAni_loadScriptEncrypted_void` | `0x1661b0` | `0x169964` | coded file, `gani::`, CRC, request |
| `TGraalAni_saveScriptEncrypted_TString_const` | `0x166360` | `0x169b6c` | coded stream and local save |
| `TGraalAni_calcGaniType_void` | `0x166444` | `0x169c6c` | `def`, `bomy_walk`, 31-name loop |
| `TGraalAni_TGraalAni_TString_const` | `0x16653c` | `0x169d84` | `sprites`, `steps`, list setup |
| `TGraalAni_removeGraalAnis_void` | `0x166860` | `0x16a114` | global cache clear |
| `TGraalAni_loadAni_TString_const_bool` | `0x1668a8` | `0x16a15c` | cache, `.gani`, reload, rectangle |
| `TGraalAni_initStaticVars_void` | `0x166cbc` | `0x16a5f0` | global hash-list setup |
| `TGraalAni_initStaticScriptVars_void` | `0x166cec` | `0x16a620` | property registration |
| TGraalAni property D1 pair | `0x166d30`, `0x166d4c` | `0x16a664`, `0x16a680` | base destructor and thunk |
| TGraalAni property D0 pair | `0x166d54`, `0x166d8c` | `0x16a688`, `0x16a6c0` | delete pair |

The seven short flag accessors were previously named only `sub_1690D0` through
`sub_169100` in the target. Their pseudocode reads or writes the same byte
offsets as 1.8, so the v85 database now gives them readable v18 labels. The
`setbackto` pair similarly retains the same string field and hidden return
object. `TGraalAni_clear` keeps all 25 source blocks even though target wrapper
calls reduce the body from 552 to 428 bytes.

The encrypted script loader preserves the local-file test, `gani::` class
construction, script-universe insertion, CRC path, and WantGaniScript request.
The saver keeps the four-block coded stream writer. The constructor creates the
same sprite and step arrays, while `loadAni` keeps the cache lookup, `.gani`
resource path, server request, reload, script load, and visible-rectangle
calculation.

The machine-readable record is
`artifacts/spectron_gani_lifecycle_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gani_lifecycle_anchors.py`. All 50 labels
reopened with zero failures in
`analysis/spectron_libqplay_translated_v85.i64`. The full translation check
also reopened all 3,641 high-confidence semantic labels with zero failures.
The v85 database has 11,679 functions and 1,688 default `sub_` names after
the nine short target accessors were labeled. Its SHA-256 is
`5ba0fe1662dc09dc2a0ed20cc917184ccbb971b6c1ee09be66459c8f8f9e3ef6`.

## Spectron TPlayer core anchors

The v86 pass reviewed two unmatched methods in the player class. The first
is the network-property serializer, which is a direct bridge between player
state and the wire format. The second is the integer constructor, which
establishes the player property storage, child variables, and defaults.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPlayer_getNetProperty_int` | `0x1712b8` | `0x1751b8` | property switch, packet encoding, field offsets, and literals |
| `TPlayer_TPlayer_int` | `0x1748f0` | `0x178a74` | constructor order, defaults, child variables, and literals |

The network-property source method maps to target
`_ZN10W6NzgawMJy10fAkcNaaWZ_Ei`. Its switch retains the same property IDs
and the same encoding strategy for strings, coordinates, filenames, colors,
actions, status, animation, level names, and fallback whitespace. The target
still contains the `head`, three-space, and four-space literals. Source
metrics are 3476 bytes, 867 instructions, and 187 blocks. Target metrics are
3668 bytes, 916 instructions, and 198 blocks. The target's larger body comes
from expanded string and wrapper code, not from a different property role.

The constructor maps to target `_ZN10W6NzgawMJyC2Ei`, with a C1 alternative
name. Both call the server-player base constructor, install the derived
vtable, initialize the repeated player state, publish the properties object,
create the `client` and `clientr` child variables, initialize account and
nickname data, and establish the platform, weapon, and animation defaults.
The target keeps the seven shared literals `android`, `client`, `clientr`,
`idle`, `letters.png`, `selectedlistplayers`, and `weapons`. Both bodies have
46 blocks. The source is 3920 bytes and 973 instructions. The target is 4208
bytes and 1044 instructions.

The target names are now recorded as
`v18_TPlayer_getNetProperty_int` and `v18_TPlayer_TPlayer_int` in the v86
disposable database. The machine-readable evidence is in
`artifacts/spectron_tplayer_core_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tplayer_core_anchors.py`. Both labels
reopened with zero failures in
`analysis/spectron_libqplay_translated_v86.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v86
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`92dbca0dbff23332208b4f7411576fbad2a46bed14c1e1d998c69618fc141e12`.

## Spectron resource and parser anchors

The v87 pass reviewed three unmatched routines on the resource and package
paths. The group covers the generated Gani lexer, cached-file path selection,
and update-package loading.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `lex_load_TGraalAni` | `0x192ec8` | `0x1979cc` | persistent lexer state and parser literals |
| `TCachedStream_getDownloadFilename_TString_const` | `0x1fa920` | `0x2000f8` | 53 shared path and extension literals |
| `TUpdatePackage_load_void` | `0x209fa4` | `0x210174` | package header, directives, and state reset |

The Gani lexer maps to `_Z10Qe7BkbfIGXP10Kc8uganwOu`. Both routines preserve
the persistent input and output buffers, buffer growth, cursor restoration,
and the generated parser state machine. The target keeps `ATTR`, `PARAM`,
and the parser alphabet string. Source metrics are 12748 bytes, 3184
instructions, and 651 blocks. Target metrics are 12768 bytes, 3188
instructions, and 651 blocks.

The cached-file method maps to
`_ZN10SDrvgadS3u10t0Nyga0GTxERK10C8THgaTQxF`. The target retains all 53
source literals for encrypted files, update packages, sounds, maps, Gani
files, fonts, paths, translations, GUI styles, music, videos, tiles, images,
emoticons, smilies, help files, hats, body, head, sword, and shield files.
The source is 3224 bytes, 803 instructions, and 89 blocks. The target is
3392 bytes, 845 instructions, and 95 blocks. The path categories and branch
order remain aligned.

The update-package loader maps to `_ZN10RH6ygazf9x4loadEv`. Both load from a
cached stream or package file, require `GRPKG001`, clear old package state,
and parse the same directive set. The target preserves all 19 source
directive literals, including `DESCRIPTIONEND`, `ISMAINEXECUTABLE`,
`PROTECTOVERWRITE`, `USECHECKSUM`, and `QPlay.box`. Both bodies have 63
blocks. The source is 2024 bytes and 505 instructions. The target is 2012
bytes and 501 instructions.

The target names are now recorded as `v18_lex_load_TGraalAni`,
`v18_TCachedStream_getDownloadFilename_TString_const`, and
`v18_TUpdatePackage_load_void` in the v87 disposable database. The
machine-readable evidence is in
`artifacts/spectron_resource_parser_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_resource_parser_anchors.py`. All three
labels reopened with zero failures in
`analysis/spectron_libqplay_translated_v87.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v87
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`fd1ec34b138c0cc18d21d32ba88e865725bde77e5acaa72fa10d80de575afa2d`.

## Spectron static utility anchors

The v88 pass reviewed five compact utility methods that remained unmatched.
They cover engine statistics, profiler output, GUI button styles, ZIP
resource scanning, and translation plural-rule handling.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TLogActions_getStats_TString_const_TStringList` | `0xf8890` | `0xfaee8` | report sections, filters, and counters |
| `TProfiler_dumpToList_TStringList` | `0xfa2e0` | `0xfc8d8` | profiler headings and timing format |
| `TGUIStyle_getButton_TString_const` | `0x1cdb8c` | `0x1d277c` | 16 style-property literals |
| `TFileNameScan_scanZipResource_TResourceObject` | `0xe8bac` | `0xe96d0` | `.uis` and `~!` markers |
| `TTranslationFile_addTranslation_TString_const_TString_const_TString_const` | `0xe3c30` | `0xe47f8` | plural-form header and rules |

The statistics method maps to `_ZN10SYX_HaZ3zD10EP5AFabwPBERK10C8THgaTQxFP10vuuHgangcF`.
Both build the system, graphics, memory, profiler, and script sections with
the same filters, time and client-version lines, counters, and profiler
handoff. The target adds a `GRAALRELOADED-version` line, which is recorded as
a target-specific version difference. Both bodies have 34 blocks. The source
is 1844 bytes and 461 instructions; the target is 1800 bytes and 450
instructions.

The profiler method maps to `_ZN10esKIvakHfi10_IfAFaEQ6AEP10vuuHgangcF`. It
preserves the ordered profiler tree, measured timing report, six source
headings, suffixes, and format strings. Both bodies have 61 blocks. The
source is 1488 bytes and 371 instructions. The target is 1368 bytes and 341
instructions.

The GUI style method maps to `_ZN10iHmzga6Hmy10T__fIaGC4QERK10C8THgaTQxF`. Both
extract the named button style, parse normal, pressed, disabled, and focus
images, and copy bitmap, frame, tile, border, and progress properties. The
target retains all 16 source style literals, including
`Normal,Pressed,Disabled,Focus`. Both have 23 blocks, with source metrics of
1428 bytes and 354 instructions and target metrics of 1460 bytes and 362
instructions.

The ZIP scanner maps to `_ZN10CDPvgaY2nv10c7PvgaJsovEP10bNZvga2Awv`. Both filter
archive entries, recognize `.uis`, and use the `~!` marker path when producing
the resource object. Both have 47 blocks. The source is 1388 bytes and 346
instructions; the target is 1436 bytes and 358 instructions.

The translation method maps to `_ZN10Ztjndb0_dS10Q96mdbXD3RERK10C8THgaTQxFS2_S2_`.
Both add a translation entry, recognize `Plural-Forms:`, `nplurals=2;`, and
`plural=n>1;`, and update the same translation structures. Both have 35
blocks. The source is 856 bytes and 214 instructions; the target is 888 bytes
and 222 instructions.

The target names are now recorded as
`v18_TLogActions_getStats_TString_const_TStringList`,
`v18_TProfiler_dumpToList_TStringList`, `v18_TGUIStyle_getButton_TString_const`,
`v18_TFileNameScan_scanZipResource_TResourceObject`, and
`v18_TTranslationFile_addTranslation_TString_const_TString_const_TString_const`
in the v88 disposable database. The machine-readable evidence is in
`artifacts/spectron_static_utility_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_static_utility_anchors.py`. All five
labels reopened with zero failures in
`analysis/spectron_libqplay_translated_v88.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v88
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`0b27f7a9e63f114eb4db2d59dd677c77002c03ab018c6dc75b53eb4d30f18249`.

## Spectron font and bitmap anchors

The v89 pass reviewed four unmatched methods in the font and bitmap path.
These assignments use direct pseudocode comparison, matching literals, and
class-local behavior. They are not based only on the address shift between
the two builds.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TFontCharInfo_setData_TFont_uchar_const_int_int_int_int_int_int` | `0x10d038` | `0x10f988` | glyph dimensions, bitmap rows, `Font `, and `#` texture key |
| `TFont_generateFontBitmap_void` | `0x10d4cc` | `0x10fe58` | atlas placement, texture naming, and graphics diagnostics |
| `TFontData_load_void` | `0x110ca0` | `0x113540` | resource stream, FreeType setup, cleanup, and load errors |
| `TBitmapLoader_load_TResourceObject` | `0x115464` | `0x117e4c` | bitmap load, type retry, failure report, and redownload |

The four target symbols are
`_ZN10DFeOfaFXSU10u6glKaa0vBEP10TZf6gaQ3S_PKhiiiiii`,
`_ZN10TZf6gaQ3S_10fl7q4asNqlEv`, `_ZN10fUWH_a_9zm4loadEv`, and
`_ZN10kM00HafgtE4loadEP10bNZvga2Awv`, respectively. The first method keeps
the font attachment, dimension clamps, old bitmap or texture cleanup, glyph
row copy, UTF-8 path, and texture-key construction. The second keeps atlas
placement and the ` in texture of `, `, size `, `Couldn't fit font `, and
`graphics` diagnostics. The third follows the system or resource font path,
stream creation, FreeType face setup, cleanup, and `Failed to load font `
reporting. The fourth preserves the profiler entry, stream validation, type
guess and retry, bitmap load, failure path, and cached-resource redownload.

The source and target metrics are 688/171/14 versus 716/178/14 for glyph
setup, 1016/252/26 versus 1052/261/26 for atlas generation, 1032/256/36
versus 840/208/34 for font loading, and 808/199/25 versus 932/229/25 for
bitmap loading. The font loader is two blocks shorter in Spectron because its
control flow merges source-side branches.

The target labels are recorded as
`v18_TFontCharInfo_setData_TFont_uchar_const_int_int_int_int_int_int`,
`v18_TFont_generateFontBitmap_void`, `v18_TFontData_load_void`, and
`v18_TBitmapLoader_load_TResourceObject` in the v89 disposable database. The
machine-readable evidence is in
`artifacts/spectron_font_bitmap_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_font_bitmap_anchors.py`. All four labels
reopened with zero failures in
`analysis/spectron_libqplay_translated_v89.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v89
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`733ada106f4a4cf74ca88ec309d4b0ae617d601767b197c1acbae4caf51ff1d0`.

## Spectron MNG animation decoder anchor

The v90 pass reviewed the large MNG animation-step decoder that remained
unmatched after the smaller image-animation helpers were translated. The
target is directly after the translated `TMNGAnimationStep` helpers and has
the same large pixel-pass structure.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TMNGAnimation_decode_TMNGAnimationStep` | `0x11b7a0` | `0x11e2d0` | pass geometry, channel branches, row copies, and pixel cleanup |

The target symbol is `_ZN10_5EhmbQbtm10yVYfmb2R2kEP10FZpembCtKj`. Both methods
accept the same animation-step object, call the corresponding pixel accessor,
calculate pass offsets and lengths, handle the same channel and color-mode
branches, copy rows into the output buffer, and clean up the temporary pixel
state. The source calls `memcpy`, `TMNGAnimationStep_getPixelBits_void`,
`png_getpasslength_int_int_int_int`, and `png_getpassoffset_int_int_int_int`.
The target calls `memcpy` plus the three corresponding obfuscated helpers.

Both feature records report 16,324 bytes and 4,081 instructions. The source
has 504 basic blocks and the target has 505. This one-block rebuild difference
does not change the direct correspondence. The target label is recorded as
`v18_TMNGAnimation_decode_TMNGAnimationStep` in the v90 disposable database.
The machine-readable evidence is in
`artifacts/spectron_mng_animation_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_mng_animation_anchor.py`. The label
reopened with zero failures in
`analysis/spectron_libqplay_translated_v90.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v90
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`ffd09f3d579539492b3ab27f199e3c2212a6a59062242085c5bf7ca4775335b8`.

## Spectron script-machine tail anchors

The v91 pass reviewed two adjacent script-machine methods outside the earlier
execution-machine anchors. They prepare script-function arguments and dispatch
native callbacks, and their exact method boundaries line up in both builds.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScriptMachine_prepareFunctionParameters_TString_const_int` | `0x21acac` | `0x222924` | format decoding, stack conversion, array creation, and string packing |
| `TScriptMachine_callCFunction_TGraalVar_TString_const_void_char_char_const_int` | `0x21b0dc` | `0x222dd4` | native callback argument conversion and multi-parameter dispatch |

The target symbols are
`_ZN10mTAogaaEip10F2qFPaZmt4ERK10C8THgaTQxFi` and
`_ZN10mTAogaaEip10icnYOaW7ouEP10G0gxgajWBwRK10CanTfaz6bZPvcPKci`. The first
method walks a format string, converts stack entries to float, string, object,
or array values, stores them in the machine list, and joins trailing string
parameters. The target adds an `e` format case and newer string wrappers. The
second method decodes the same format characters, fetches and converts values,
and calls the native function with up to twelve converted parameters. Its
target body includes a guarded string workspace and an `e` branch.

The source and target metrics are 1,072/267/50 versus 1,200/299/51 for
parameter preparation, and 2,496/618/100 versus 3,412/847/124 for callback
dispatch. In each group the values are bytes, instructions, and basic blocks.
The parameter method ends exactly at the callback method start in both builds.
The target callback method then ends immediately before the translated
suspend-after-call helper.

The target labels are recorded as
`v18_TScriptMachine_prepareFunctionParameters_TString_const_int` and
`v18_TScriptMachine_callCFunction_TGraalVar_TString_const_void_char_char_const_int`
in the v91 disposable database. The machine-readable evidence is in
`artifacts/spectron_script_machine_tail_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_machine_tail_anchors.py`. Both
labels reopened with zero failures in
`analysis/spectron_libqplay_translated_v91.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v91
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`1626932aed2ab1d56d21a788f71ed8587ec3d1041b473978a09ee1cb808f3aec`.

## Spectron script stream and profile anchors

The v92 pass reviewed two remaining `TScript` methods in the obfuscated
`zW2NgaU4IK` class. One parses the GS2 script stream and the other prints the
function and class profiler report.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TScript_setStream_TString_const` | `0x21624c` | `0x21cfb8` | script record parsing, `public.` handling, parameter decoding, and function registration |
| `TScript_printFunctionProfiles_TStringList_TString_const` | `0x217168` | `0x21e058` | timing, percentage formatting, sorting, and nested class profile output |

The target symbols are
`_ZN10zW2NgaU4IK10pKjZfaKdc3ERK10C8THgaTQxF` and
`_ZN10zW2NgaU4IK10JkKVfa5Ab0EP10vuuHgangcFRK10C8THgaTQxF`. The stream parser
keeps the same reset, bytecode walk, class and function record decoding,
`public.` marker, parameter parsing, function-registration, and update-hook
sequence. Its source and target metrics are 2,380/594/110 and 2,400/599/110,
respectively, in bytes, instructions, and blocks. Both make 67 calls.

The profile printer keeps the same profiling guard, elapsed-time calculation,
function and class iterations, percentage formatting, sorting, and `Class `
output. Its source and target metrics are 1,092/272/24 and 1,176/293/24,
respectively, with call counts of 59 and 65. The source exposes both ` %` and
`Class ` as string references. The target exposes `Class ` but not a separate
percent literal, and its decompilation uses long-double temporaries plus the
rebuilt string, list, hash, and iterator wrappers. Direct pseudocode comparison
supports the correspondence despite those target-version differences.

The labels are recorded as
`v18_TScript_setStream_TString_const` and
`v18_TScript_printFunctionProfiles_TStringList_TString_const` in the v92
disposable database. The machine-readable evidence is in
`artifacts/spectron_script_stream_profile_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_script_stream_profile_anchors.py`. Both
labels reopened with zero failures in
`analysis/spectron_libqplay_translated_v92.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v92
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`b6e314fe73ccbd43815c32fe690208460140593230aa99251fdb3b7f977641a1`.

## Spectron generated animation-lexer fatal callback

The v93 pass reviewed the compact fatal callback used by the generated Gani
lexer. The existing `lex_load_TGraalAni` correspondence already showed that
the target scanner calls the target helper, even though Spectron moved the
helper away from the scanner's address range.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `ani_lexer_fatalExit` | `0x1925e4` | `0x19af5c` | generated-lexer fatal exit path |

The target symbol is `_ZN10QYZugaRKGu10RzQ_IaWQttEv`. Both functions have 16
bytes, 4 instructions, 1 block, one direct exit call, and no string references.
The source calls `exit(2)` while the target calls `exit(0)`, which is recorded
as a behavior difference. The target helper is called from the target lexer at
`0x1979cc`, whose source and target metrics are 12,748/3,184/651 and
12,768/3,188/651 in bytes, instructions, and blocks. The scanner also keeps
the `ATTR`, `PARAM`, and generated alphabet strings.

The label is recorded as `v18_ani_lexer_fatalExit` in the v93 disposable
database. The machine-readable evidence is in
`artifacts/spectron_ani_lexer_fatal_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_ani_lexer_fatal_anchor.py`. The label
reopened with zero failures in
`analysis/spectron_libqplay_translated_v93.i64`. The full translation check
also passed with 3,641 high-confidence labels and zero failures. The v93
database has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`f48b51d672bd6d7cd57316f09312b9e90d22144ef61ddf473b6cabfb9d66722c`.

## Spectron numeric-array string anchors

The v94 pass reviewed eight double and short numeric-array methods that were
still unmatched after the broad map. The parallel template instantiations and
direct pseudocode make the assignments high confidence.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TNumberArrayVar_double_setArrayCellString_int_TString_const` | `0x18a318` | `0x18eb08` | parse numeric text, then call the indexed virtual setter |
| `TNumberArrayVar_double_getArrayCellString_int` | `0x18a440` | `0x18ebac` | indexed getter and string formatting |
| `TNumberArrayVar_double_readString_void` | `0x18a3bc` | `0x18ec04` | comma-separated array walk |
| `TNumberArrayVar_double_writeString_TString_const` | `0x18a474` | `0x18eca8` | split text and write each array element |
| `TNumberArrayVar_short_setArrayCellString_int_TString_const` | `0x1abb50` | `0x1afca0` | parse numeric text, then call the indexed virtual setter |
| `TNumberArrayVar_short_getArrayCellString_int` | `0x1abd28` | `0x1afe78` | indexed getter and string formatting |
| `TNumberArrayVar_short_readString_void` | `0x1abe00` | `0x1affa0` | comma-separated array walk |
| `TNumberArrayVar_short_writeString_TString_const` | `0x1abd5c` | `0x1afed0` | split text and write each array element |

The setter pairs are exact in size and shape at 64 bytes, 16 instructions,
and one block with two calls. The indexed-read pairs expand from 52/13/1 with
two calls to 88/22/1 with four calls. The array readers expand from 132/33/5
with two calls to 164/41/6 with four calls. The writers expand from 164/41/3
with six calls to 208/52/3 with ten calls. These are bytes, instructions,
basic blocks, and direct call counts. The changed target counts come from
explicit rebuilt string and list wrapper operations, not a changed array role.

The target class names retain `PfQXva4zXuIdE` for double and
`PfQXva4zXuIsE` for short. The target setter uses `nak8fakACb`, while the
source uses `strtofloat`. The read methods retain the element-specific double
or integer formatter, and the write methods retain the virtual setter and
temporary list walk. The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v94.i64`.

The evidence is in
`artifacts/spectron_number_array_string_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_number_array_string_anchors.py`. All
eight labels reopened with zero failures. The full translation check also
passed with 3,641 high-confidence labels and zero failures. The v94 database
has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`44e98e90efabe2ed93ea5b7c9b53797a12aa4c4147e34891f0403a0d5ec1daae`.

## Spectron client-environment clock anchors

The v95 pass reviewed the build-time and time-expiry helpers in the
obfuscated `a7qxJaHqKV` class.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TClientEnvironment_BuildTime_void` | `0x15d3a8` | `0x1603f4` | same time, localtime, and mktime sequence |
| `TClientEnvironment_TimeExpired_void` | `0x15d3ec` | `0x160458` | same expiry gates, BuildTime call, and difftime check |

The build-time helper is 68/17/1 with three calls in 1.8 and 100/25/1 with
three calls in Spectron. The source hardcodes 2019-02-13, while the target
loads year, month, and day globals. The expiry helper is 132/33/5 with three
calls in 1.8 and 164/41/5 with three calls in Spectron. The source uses a
fixed 15-day window, while the target multiplies a global day count by 24
hours. These are real target-version differences inside an otherwise matching
control-flow role.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v95.i64`. The evidence is in
`artifacts/spectron_client_environment_clock_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_environment_clock_anchors.py`.
Both labels reopened with zero failures. The full translation check also
passed with 3,641 high-confidence labels and zero failures. The v95 database
has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`79f62371f6ddbecdb94c923918126b1a9c109e18bcea0771163bb41c0bd8407f`.

## Spectron client-variable core anchors

The v96 pass reviewed the remaining send and string-update methods in the
obfuscated `znLtuaytEf` class.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TGraalClientVar_send_void` | `0x166ee8` | `0x16a81c` | dotted variable name, unset branch, and flag send |
| `TGraalClientVar_writeString_TString_const` | `0x1670c0` | `0x16aa24` | cached string equality and send on change |
| `TGraalClientVar_setArrayCellString_int_TString_const` | `0x1671b4` | `0x16ab54` | indexed equality and send on change |

The three target methods preserve the source control flow. The send method
expands from 400/100/12 with 18 calls to 448/112/12 with 22 calls. The string
writer changes from 100/25/5 with two calls to 96/24/5 with two calls. The
indexed writer changes from 120/30/3 with five calls to 152/38/3 with seven
calls. These are bytes, instructions, basic blocks, and direct call counts.
The target differences come from rebuilt string wrappers and do not alter the
change-suppression or outbound-send roles.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v96.i64`. The evidence is in
`artifacts/spectron_client_var_core_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_client_var_core_anchors.py`. All three
labels reopened with zero failures. The full translation check also passed
with 3,641 high-confidence labels and zero failures. The v96 database has
11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`343ea4a80616c6f53b1b7233ad339e44830cd084086bd4bd6204a18bdd5a1af3`.

## Spectron TDrawingPanel residual anchors

The v108 pass reviewed six remaining methods from the source `TDrawingPanel`
class. The target methods remain in the obfuscated `V8fxgahcBw` class, between
the translated panel initialization, primitive drawing, operation, and image
save methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TDrawingPanel_TDrawingPanel_TString_const` | `0x117bec` | `0x11a64c` | base construction and panel initialization |
| `TDrawingPanel_TDrawingPanel_TString_const_bool` | `0x117c28` | `0x11a6b4` | bool constructor overload |
| `TDrawingPanel_drawImage_Impl_int_int_TString_const` | `0x1191d4` | `0x11bc84` | tiles path, texture size, and image forwarding |
| `TDrawingPanel_drawImageRectangle_Impl_int_int_TString_const_int_int_int_int` | `0x1192f0` | `0x11bdd4` | rectangle forwarding and outside fill |
| `TDrawingPanel_filterRectangle_Impl_int_int_int_int_TString_const` | `0x11a48c` | `0x11cf8c` | six named image filters |
| `TDrawingPanel_setDrawPaletteNamed_TString_const_int` | `0x11a6a8` | `0x11d1ac` | palette parsing and indexed storage |

The two constructors are 60/15/2 and 68/17/2 in 1.8, with one direct base
constructor call each. Their target C2 and C1 counterparts are both 104/26/1
with four calls. The target keeps the `TGraalVar` base role, installs the
derived vtable, and calls the same panel initializer. The extra target calls
are explicit string conversion, profile construction, and panel-wrapper
operations.

The image wrapper changes from 184/46/4 with four calls to 236/59/4 with six
calls. The rectangle wrapper changes from 252/63/4 with five calls to
284/71/4 with seven calls. Both preserve the `tiles` special case, texture
size lookup, image rectangle forwarding, and temporary name cleanup. The
rectangle variant also keeps the outside-rectangle fill before forwarding to
the target six-argument image implementation.

The filter method changes only slightly from 536/133/19 with 17 calls to
540/134/19 with 17 calls. Both refresh the panel, lower-case the filter name,
and select the `gray`, `nightgoggle`, `negative`, `updown`, `blackwhite`, or
`lesscolors` filter before applying it to the requested rectangle. The target
uses the obfuscated `EYMwkbFObT` filter class and rebuilt `C8THgaTQxF` and
`vuuHgangcF` wrappers.

The named-palette method changes from 204/51/5 with eight calls to 208/52/5
with eight calls. Both parse the palette string, look up the named color,
select the requested palette slot, and clean up the temporary list. The
target's `Q9LCGaX7dt`, `vuuHgangcF`, and `V8fxgahcBw` wrappers preserve the
same behavior.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v108.i64`. The evidence is in
`artifacts/spectron_drawing_panel_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_drawing_panel_residual_anchors.py`. All
six labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v108 database has 1,684 remaining default `sub_` names. Its
SHA-256 is
`8350a43be6b31306954e34a17f77d742c8d1702015d671019d2bf2dd6c1bb1e1`.

## Spectron TString clear helper

The v175 pass resolves the core `TString_clear_void` method. Both builds use
the same reference-counted storage lifecycle, but the target also contains an
identical-shape `CanTfaz6bZ::clear` method. The class-qualified target name and
the surrounding `C8THgaTQxF` method cluster distinguish the TString row.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TString_clear_void` | `0xf0ef8` | `0xf23d0` | `_ZN10C8THgaTQxF5clearEv` | reference-counted storage clear |

The source and target functions are both 68/17/6/1 for size, instructions,
basic blocks, and calls. Every normalized feature field matches, including the
mnemonic, opcode, register, overall-shape, and string-reference hashes. The
local relocation is `+0x14d8`.

IDA pseudocode shows the same sequence in both builds. The method loads the
storage pointer, returns immediately for a null pointer, reads the reference
count, frees the storage when the count is at most one, decrements it otherwise,
and then clears the object pointer. The alternate target row at `0xf8c64` is
`CanTfaz6bZ::clear`, which has the same body but is a different class and is
not used for this alias.

The target already had an obfuscated C++ name, so this pass does not lower the
default `sub_` count. The alias reopened successfully in the v175 database.
The full semantic reopen check reports zero failures across 11,694 functions,
with 3,641 high-confidence labels and 1,250 default `sub_` names. The source
and target ARM64 library hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_tstring_clear_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tstring_clear_anchors.py`. The saved IDA
database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v175.i64`
with SHA-256
`b414cf0d0d025c85c0cb4ddab2ea9987ecfbd6484da7ca4846b0ed3588d35c49`.

## 2026-08-27: Spectron client and socket static cleanup callbacks

The v176 pass resolves two static cleanup callbacks that were still default
IDA names in the 2.2 database. These callbacks are not ordinary instance
methods. They clear global `TString` state during static teardown, so the
source callback table and the target callback table are important evidence.

| Source method or role | 1.8 address | Spectron address | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TClient_clearStaticStrings` | `0xe05ec` | `0xe0128` | `sub_E0128` | client static callback slot and `w6qzgacqqy` class state |
| `TSocket_clearStaticStrings` | `0xe0680` | `0xe0258` | `sub_E0258` | socket static callback slot and `XJLBgarMnA` class state |

The source callback pointers are stored at `0x35d2e8` and `0x35d2f0`. The
corresponding target callback slots are at `0x36ff18` and `0x36ff60`. The
target classes are not guessed from the cleanup bodies alone. The broader
translation already ties `w6qzgacqqy` to the client constructor, reset, and
connection methods, and ties `XJLBgarMnA` to the socket constructor, accept,
connect, and socket-state methods.

The client source body clears eleven global string fields, including login,
download, disconnect, ghost-message, and server-warp state. Its Spectron
counterpart preserves those cleanup calls and adds one `CanTfaz6bZ::clear`
call for a target-only field. The socket source clears its two allowed-port and
allowed-socket strings, while the target adds one corresponding target-only
cleanup. Both target bodies remain two-block routines, but grow from 148 to
160 bytes and from 40 to 52 bytes respectively. The instruction, branch, and
call counts grow in step with the extra cleanup. These are therefore
high-confidence layout-change anchors, not exact normalized-shape matches.

The target addresses do not share one useful global delta. The client row is
`-0x4c4` from the source address and the socket row is `-0x428`. This is
consistent with separate target callback-table and class placement, not with
a failed correspondence.

The target functions were default `sub_` names, so the aliases reduce the
remaining default count from 1,250 to 1,248. Both names reopened successfully
in the v176 disposable IDA copy. The full semantic reopen check still reports
zero failures across 11,694 functions, with 3,641 high-confidence labels. The
v176 database SHA-256 is
`0c5b0f55006fd4a22c6044a6addfcaa07346e1b1cec1f092676a06701ba12e7c`.

The machine-readable record is
`artifacts/spectron_static_clear_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_static_clear_anchors.py`.

The third source callback was intentionally left open in the v176 pass.
Follow-up data-reference work now resolves it separately in the v198 Android
state pass below. The v176 decision was still correct at the time: assigning
the callback to `TServerFlying` without isolating its target globals would
have been speculative.

## Static callback role correction

A direct data-reference review corrected the role of the third source callback.
The old review row proposed `TServerFlying_clearStaticStrings` for `0xe06a8`
because it cleared three `TString` objects near other server-object state. The
function actually clears these process-wide objects:

| Source global | Observed role evidence |
| --- | --- |
| `0x391210` | TapJoy secret or shared Android string cache, read by the TapJoy setup and connector paths |
| `0x391218` | TapJoy application-ID string cache, read by the application-ID setter and connector |
| `0x391238` | Video-player string or state cache, read by the video open and completion paths |

The companion reset at `0xe0ad0` clears the same three objects and also zeros
the four cached video rectangle integers at `0x391228` through `0x391234`.
`TServerFlying::animate` at `0x23eeb0` has zero data references to
`0x391210`, `0x391218`, and `0x391238`. Its known class property global is
`TServerFlying_properties` at `0x3911f8`, which is a separate object used by
the constructor and static script-variable initializer.

The corrected descriptive source role is
`Android_TapJoy_video_clearStaticStrings`. It is a behavior label, not a
recovered ELF symbol. At the time of this correction the target was left
unresolved. The later v198 pass resolves `sub_E0438` as the matching Android
and video cleanup callback and `sub_E1640` as its reset callback. The target
class `gId5RaV8_6`, with its constructor at `0x248dec`, properties constructor
at `0x248d50`, and animate method at `0x248e38`, remains unrelated. The
nearby target cleanup at `0xe0220` still clears request and `THTTPRequest`
state, so it is not part of the resolved pair.

The historical candidate and symbol overlay stay unchanged so the original
review remains reproducible. The correction and its feature hashes are in
`artifacts/spectron_static_callback_role_correction_20260827.json`, generated
by `tools/generate_spectron_static_callback_role_correction.py`. The later
target resolution is recorded in
`artifacts/spectron_android_tapjoy_video_state_manual_translation_anchors_20260827.json`.
The read-only IDA helper `tools/ida_dump_function_data_refs.py` records the
data-reference evidence used to separate these similar cleanup routines.

## Spectron residual TSocket client-list and property adapters

The v181 pass closes four residual methods in the obfuscated
`XJLBgarMnA` socket class. One method removes the socket from the owning
client's `clients` variable, one is the deleting destructor, and the last two
are the property adapters that forward socket error and IP queries to their
underlying methods.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TSocket_removeFromClientList_void` | `0x204c34` | `0x20ab0c` | `_ZN10XJLBgarMnA10nZIBgaeslAEv` | client-list cleanup, layout change |
| `TSocket_TSocket__2` | `0x204d74` | `0x20ac44` | `_ZN10XJLBgarMnAD0Ev` | deleting D0 destructor |
| `TSocket_getError` | `0x204e4c` | `0x20ad1c` | `sub_20AD1C` | error property adapter |
| `TSocket_getIP` | `0x204ea8` | `0x20ad78` | `sub_20AD78` | IP property adapter |

The source `removeFromClientList` method looks up the literal `clients` in
the socket's client hash table, removes the socket from the associated client
variable, invokes the variable cleanup callback when appropriate, and clears
the stored client pointer. The target `nZIBgaeslA` method preserves that
sequence through the target `KKhLga4xoI` and `G0gxgajWBw` families. Its body
is 152 bytes, 37 instructions, seven blocks, 11 branches, and six calls,
compared with 160 bytes, 40 instructions, eight blocks, 13 branches, and
seven calls in 1.8. Both retain the `clients` string reference.

The source and target deleting destructor rows are both 32 bytes, eight
instructions, two blocks, two branches, and one direct call. The target D0
body calls the complete `XJLBgarMnA` destructor and then `operator delete`,
matching the source `TSocket_TSocket__2` lifecycle role despite the
constructor-like source label.

The two property adapters are exact normalized matches. Each is 32 bytes,
eight instructions, one block, two branches, one return, and one direct call.
The target `sub_20AD1C` forwards to the already translated target error method
at `0x20acb4`, while `sub_20AD78` forwards to the target IP method at
`0x20ad3c`. This distinguishes these adapters from the larger underlying
socket methods.

All four aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v181.i64`.
The full semantic reopen check still reports zero failures across 11,694
functions, with 3,641 high-confidence labels and 1,238 default `sub_` names.
The v181 database SHA-256 is
`b8a14b0070e9dc9b23e9d7456088ef62f061247cfa3d8048f6c5e0e4b9e2857f`.
The machine-readable record is
`artifacts/spectron_tsocket_residual_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tsocket_residual_anchors.py`.

## Spectron TClientEnvironment restart-state cleanup

The v185 pass resolves the remaining named restart-state cleanup callback in
the obfuscated `a7qxJaHqKV` client-environment family.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TClientEnvironment_clearRestartState` | `0xe0814` | `0xdfdb4` | `sub_DFDB4` | high-confidence layout-change match |

The source callback at table slot `0x35d248` clears the application
path, saved server name, and saved server address fields
`0x38d4d8`, `0x38d4c0`, and `0x38d4b8`. The target
callback at slot `0x36fd90` clears
`a7qxJaHqKV::pZk1wamgKo`,
`a7qxJaHqKV::We1hLalFMo`, and
`a7qxJaHqKV::t7xiLaUjdp`. The target initializer
`sub_E0970` at `0xe0970` zeros the same three fields, and
the translated target restart method uses the saved name and address fields
when constructing the next restart destination.

The source callback is a 40-byte, ten-instruction, one-block cleanup with no
direct calls. The target grows to 68 bytes, 17 instructions, two blocks,
four branches, and three direct calls because it clears the three
`C8THgaTQxF` fields and then a target-only
`CanTfaz6bZ` object at `0x3a0d30`. This is recorded as a
layout change. The target class, cleanup-table slot, initializer, and
restart-path field uses make the correspondence high confidence despite the
different string implementation.

The alias reopened successfully in the v185 database. The machine record is
`artifacts/spectron_client_environment_restart_state_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_client_environment_restart_state_anchors.py`.
No APK or native code was modified.

## Spectron TClientEnvironment profiler cleanup callbacks

The v184 pass resolves two default-named callbacks in the obfuscated
`C8THgaTQxF` profiler-string cluster. Their registration sites inside the
already translated target `runTimers` and `drawGame` methods provide direct
caller context.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TClientEnvironment_clearStaticString38D428` | `0x15c620` | `0x15f678` | `sub_15F678` | exact atexit cleanup match |
| `TClientEnvironment_clearStaticString38D460` | `0x15c62c` | `0x15f684` | `sub_15F684` | exact atexit cleanup match |

The first source function clears the profiler string at `0x38d428` and is
passed to `atexit` by `runTimers` at `0x15d060`. The target
`runTimers` method passes `sub_15F678` at `0x1600b8`, and the target
callback clears `C8THgaTQxF` storage at `0x3a0ca8`. The second source
function clears `0x38d460` from `drawGame` at `0x15d304`; the target
method passes `sub_15F684` at `0x160350`, and the callback clears
`0x3a0ce0`.

The first source and target pair is 12 bytes, two instructions, two blocks,
and one branch. The second is 16 bytes, three instructions, two blocks, and
one branch. Both pairs have identical complete normalized feature records,
including mnemonic, opcode-shape, register-shape, normalized-shape, return,
and string-reference metrics. These are exact shape matches supported by
caller-local `atexit` order and the corresponding single-object clear
operation.

The aliases reopened successfully in the v184 database. The machine record is
`artifacts/spectron_client_environment_static_clear_manual_translation_anchors_20260827.json`,
generated by
`tools/generate_spectron_client_environment_static_clear_anchors.py`.
No APK or native code was modified.

## Spectron TClientEnvironment graphics initializer

The v183 pass resolves one short wrapper that remained unnamed in the
obfuscated `a7qxJaHqKV` client-environment class.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TClientEnvironment_initGraphics_void` | `0x15ce2c` | `0x15fe84` | `_ZN10a7qxJaHqKV10bA4tIa0sV1Ev` | exact normalized match |

The target method is between the translated target free-graphics method at
`0x15fe50` and the translated target window-size method at `0x15fe9c`.
That class-local order matches the source neighbors at `0x15cdf8` and
`0x15ce44`. Both wrappers test their graphics or adventure object, call its
initializer only when present, and return the object value otherwise.

All normalized metrics are identical: 24 bytes, six instructions, four basic
blocks, three branches, one return, and matching mnemonic, opcode-shape,
register-shape, normalized-shape, and string-reference hashes. The machine
record is
`artifacts/spectron_client_environment_graphics_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_client_environment_graphics_anchors.py`.
The alias reopened successfully in the v183 database. No APK or native code
was modified.

## Spectron TGameEnvironment startup and property helpers

The v182 pass resolves four small methods at the beginning of the obfuscated
`QYZugaRKGu` environment cluster. Their registration-table entries identify
the player-count, premium-version, demo-version, and `adventure_quit` roles.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `TGameEnvironment_getAllPlayersCount` | `0xe9cf8` | `0xea84c` | `sub_EA84C` | exact count getter |
| `TGameEnvironment_isPremiumVersion_void` | `0xe9d0c` | `0xea860` | `_ZN10QYZugaRKGu10JHX2IaxQ5vEv` | exact boolean getter |
| `TGameEnvironment_isDemoVersion_void` | `0xe9d14` | `0xea868` | `_ZN10QYZugaRKGu10AdR2Ia3n0vEv` | exact boolean getter |
| `TGameEnvironment_script_adventureQuit` | `0xe9d1c` | `0xea870` | `sub_EA870` | callback layout change |

The target property records at `0x389788`, `0x3897b8`, `0x3897e8`, and
`0x389818` decode to `allplayerscount`, `adventure_quit`,
`ispremiumversion`, and `isdemoversion`. The first record points its getter
to `0xea84c`; the other three point their callback slots to `0xea870`,
`0xea860`, and `0xea868`. This table evidence is stronger than address order
alone and also explains why the premium, demo, and quit methods occupy the
callback slot in this target build.

The count getter is an exact normalized match. Its target pseudocode returns
the count field from `QYZugaRKGu::MgGzgaMaDy`, corresponding to the source
`TGameEnvironment::allplayers` count. The premium and demo methods are also
exact 8-byte, 2-instruction constant-return matches. The target `adventure_quit`
callback remains one block with no direct calls, but grows from 20 to 36 bytes.
The source writes `closeapplication = 1`; the target writes
`TI0CgaxdrB = 1` and `rxN_IaKhrt = 1`, then returns the latter. That extra
flag is documented as a 2.2 state-layout difference.

All four aliases reopened successfully in the v182 IDA copy. The full
semantic reopen check still reports zero failures across 11,694 functions,
with 3,641 high-confidence labels and 1,236 default `sub_` names. The
machine-readable evidence is
`artifacts/spectron_game_environment_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_game_environment_anchors.py`. No APK or
native code was modified.

## Spectron HTTP request cleanup and properties ABI

The v180 pass closes the remaining request cleanup gap and the small
request-properties lifecycle family. The target already exposes obfuscated
C++ names for these methods, but the request object fields and destructor ABI
sequence make the correspondences straightforward to review.

| 1.8 role | Source | Spectron target | Target name before alias | Classification |
| --- | ---: | ---: | --- | --- |
| `THTTPRequest_clearRequest_void` | `0x1ff40c` | `0x204d5c` | `_ZN10ZAuvgaUl6u10zs2GHaFGPmEv` | request cleanup, layout change |
| `THTTPRequestProperties_THTTPRequestProperties` | `0x2029d0` | `0x208248` | `_ZN20ZAuvgaUl6uPropertiesD2Ev` | complete D2 destructor |
| `non_virtual_thunk_to_THTTPRequestProperties_THTTPRequestProperties` | `0x2029ec` | `0x208264` | `_ZThn16_N20ZAuvgaUl6uPropertiesD1Ev` | complete-destructor thunk |
| `THTTPRequestProperties_THTTPRequestProperties__2` | `0x2029f4` | `0x20826c` | `_ZN20ZAuvgaUl6uPropertiesD0Ev` | deleting D0 destructor |
| `non_virtual_thunk_to_THTTPRequestProperties_THTTPRequestProperties__2` | `0x202a2c` | `0x2082a4` | `_ZThn16_N20ZAuvgaUl6uPropertiesD0Ev` | deleting-destructor thunk |

The request cleanup comparison is semantic rather than exact shape. The
source body is 488 bytes, 122 instructions, 12 basic blocks, 36 branches,
and 29 direct calls. The target is 480 bytes, 120 instructions, 11 basic
blocks, 34 branches, and 28 direct calls. Both methods first run the
keep-alive check, release the request socket, find and remove the `data`
variable from the request hash table, clear the response stream, reset the
request flags and counters, and restore the request's temporary string
fields. The target uses `KKhLga4xoI`, `J7zOgaf09K`, `nenvgaH9_u`, and
`C8THgaTQxF` helpers, while preserving the source request-field offsets.

The four properties rows are exact normalized matches. The complete
destructor pair is 28 bytes, seven instructions, two blocks, one branch, and
zero direct calls in each build. The deleting destructor pair is 56 bytes,
14 instructions, two blocks, two branches, and one direct call. The two
adjusted-this thunks are each eight bytes, two instructions, two blocks, one
branch, and zero direct calls. Their normalized mnemonic, opcode, register, and
shape hashes match.

The source names for the properties rows are constructor-like because of the
old IDA naming convention. The source pseudocode identifies `0x2029d0` as
the complete D2 destructor and `0x2029f4` as the deleting D0 destructor. Both
thunks subtract 16 from the adjusted object pointer before forwarding to the
matching destructor. Spectron preserves this lifecycle arrangement with the
explicit `ZAuvgaUl6uProperties` D2, D0, D1 thunk, and D0 thunk names.

All five aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v180.i64`.
The full semantic reopen check still reports zero failures across 11,694
functions, with 3,641 high-confidence labels and 1,240 default `sub_` names.
The v180 database SHA-256 is
`a01af52c52de0c5d203d15ee0eb839b6a30ff13094a08474668c71773a0f17a2`.
The machine-readable record is
`artifacts/spectron_http_request_cleanup_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_http_request_cleanup_anchors.py`.

## Spectron server-list state accessors and setters

The v179 pass closes the small state-method gap immediately before the
server-list getter cluster. These methods are especially useful in the
stripped 2.2 build because every source and target function has the same
complete normalized feature record, and the target pseudocode exposes the
global that each method reads or writes.

| 1.8 role | Source | Spectron target | Target name before alias | Target global |
| --- | ---: | ---: | --- | --- |
| `TServerList_setRemoveVarsOnLogout` | `0x202a38` | `0x2082b0` | `sub_2082B0` | `xiYWfajld1::x7tqLaYXTv` |
| `TServerList_getAllowLoginReconnect` | `0x202a48` | `0x2082c0` | `sub_2082C0` | `xiYWfajld1::mLqqLax7Qv` |
| `TServerList_setServerStartParams` | `0x202a78` | `0x2082f0` | `sub_2082F0` | `xiYWfajld1::OcLpLarkhv` |
| `TServerList_setServerStartConnect` | `0x202a8c` | `0x208304` | `sub_208304` | `xiYWfajld1::Jq54MaebUU` |

All four source and target rows are exact normalized matches. The boolean
methods are each 16 bytes, four instructions, one basic block, one branch,
and one return. The two string setters are each 20 bytes, five instructions,
two basic blocks, one branch, and no direct call in the feature export because
the assignment is represented by a tail branch to the target string helper.
The complete mnemonic, opcode, register, and normalized shape hashes also
match.

The state roles are confirmed by target pseudocode and neighboring methods.
`0x2082b0` stores the remove-vars-on-logout value in
`xiYWfajld1::x7tqLaYXTv`. `0x2082c0` returns
`xiYWfajld1::mLqqLax7Qv`, the same global written by the already translated
`v18_TServerList_setAllowLoginReconnect` at `0x2082d0`. The setters at
`0x2082f0` and `0x208304` write the two globals read by the v178 getter aliases
at `0x208318` and `0x208350`. This creates a four-method setter/getter check
that does not depend on copying a source address delta into the target.

The target functions were default IDA names before this pass. All four aliases
reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v179.i64`.
The full semantic reopen check reports zero failures across 11,694 functions,
with 3,641 high-confidence labels and 1,240 default `sub_` names. The v179
database SHA-256 is
`c4f8361f9fa8d138358215b3d63ef4ada9755aa8cd0e60302d077002f400b37b`.
The machine-readable record is
`artifacts/spectron_server_list_state_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_server_list_state_anchors.py`.

## Spectron server-list getters and connection handoff

The v178 pass follows the server-list state that is consumed immediately
before connection setup. This small cluster is useful because the target
keeps both the getter shapes and the global setter or getter relationships,
while the larger handoff method exposes the meaning of the target server-name
global through its later window-identifier update.

| 1.8 role | Source | Spectron target | Target name before alias | Target state evidence |
| --- | ---: | ---: | --- | --- |
| `TServerList_getServerStartParams` | `0x202aa0` | `0x208318` | `sub_208318` | copies `xiYWfajld1::OcLpLarkhv`, written by `0x2082f0` |
| `TServerList_getServerStartConnect` | `0x202ad8` | `0x208350` | `sub_208350` | copies `xiYWfajld1::Jq54MaebUU`, written by `0x208304` |
| `TServerList_getServerName` | `0x202b10` | `0x208388` | `sub_208388` | copies `xiYWfajld1::VoXXfaKA21`, written by the handoff |
| `TServerList_getServerNameCopy` | `0x202b48` | `0x2083c0` | `sub_2083c0` | second copy of `xiYWfajld1::VoXXfaKA21` through the callback ABI |
| `TServerList_setConnectionAttributes_TString_const_TString_const_int` | `0x202f30` | `0x20a1f4` | `_ZN10xiYWfajld110iVlvLaT2ZzERK10C8THgaTQxFS2_i` | normalizes the name, stores address and port, restarts local players, and updates the window identifier |

The four getter pairs are exact across the normalized feature record. Each
source and target body is 56 bytes, 14 instructions, one basic block, two
branches, and one direct string-copy call. The target direct-call name is
obfuscated, but the register-shape hash and complete normalized shape are the
same. More importantly, the target getter globals are not inferred from
address arithmetic. The target setter at `0x2082f0` writes
`xiYWfajld1::OcLpLarkhv`, and the getter at `0x208318` reads it. The matching
setter and getter pair for `xiYWfajld1::Jq54MaebUU` is `0x208304` and
`0x208350`.

The two server-name getters both read `xiYWfajld1::VoXXfaKA21`. The larger
target method at `0x20a1f4` assigns that global from its normalized first
argument. Later, when a main window exists, it asks the target environment
whether an application identifier is available and otherwise copies the same
server-name global into the window update. That read-after-write relationship
resolves the target global as the source server name rather than another
server-list text field.

The handoff itself is a semantic layout match, not an exact shape match. The
source method is 564 bytes, 141 instructions, 17 basic blocks, 33 branches,
and 25 direct calls. The target method is 788 bytes, 196 instructions, 22
basic blocks, 48 branches, and 37 direct calls. Both bodies perform the same
state transition: trim the optional leading space from the server name, store
the server name and address, parse the port, preserve the restart values,
load tile definitions, initialize graphics for every local player, load each
player's start level, and notify the main window with an application
identifier or server name.

The target implements those responsibilities through the obfuscated
`xiYWfajld1`, `C8THgaTQxF`, `W6NzgawMJy`, and `QYZugaRKGu` families. It also
retains the `GPFDGfY4` string inside the handoff, where it participates in the
target's connection setup. The larger body and extra temporary objects are
consistent with the 2.2 object layout and helper vocabulary, so the artifact
records this row as a high-confidence layout-change anchor.

All five aliases reopened successfully in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v178.i64`.
The full semantic reopen check still reports zero failures across 11,694
functions, with 3,641 automatic high-confidence labels and 1,244 default
`sub_` names. The v178 database SHA-256 is
`4bc213e88a767e49efdef3c7d0ce160d946446846cfff53b6461bcc7654391c1`.
The machine-readable record is
`artifacts/spectron_server_list_connection_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_server_list_connection_anchors.py`.

## Spectron HTTP response read and parser anchors

The v177 pass closed two remaining response-side gaps in the target request
object. Both target functions belong to the obfuscated `ZAuvgaUl6u` class and
sit between the already translated download helpers and script execution.

| 1.8 role | Source | Spectron target | Target name before alias | Main evidence |
| --- | ---: | ---: | --- | --- |
| `THTTPRequest_read_void` | `0x200a70` | `0x206414` | `_ZN10ZAuvgaUl6u4readEv` | socket read, response stream, byte counters, and timestamp |
| `THTTPRequest_parseData_void` | `0x2023fc` | `0x207bec` | `_ZN10ZAuvgaUl6u10ZdIGHasPxmEv` | `data` lookup, response lines, array values, and callback loop |

The source read method is 676 bytes, 167 instructions, 17 basic blocks, and
28 direct calls. The target is 240 bytes, 60 instructions, 13 basic blocks,
and five direct calls. Despite the size change, the target still checks the
request socket for errors, calls the connection reader, appends or assigns the
result to the response stream, updates both byte counters, and records the
request and global web-download timestamps when new data arrives. The older
implementation also emitted a periodic `File download: (2)` log after a
threshold. The target does not retain that branch, which is an implementation
change worth preserving in future runtime comparisons.

The source parser is 420 bytes, 105 instructions, 13 basic blocks, and 17
direct calls. The target is 460 bytes, 115 instructions, 12 basic blocks, and
18 direct calls. Both clear the stream for a closed request, load non-binary
response data into a line list, look up the `data` variable, clear and retag
the existing value, allocate an array holder, and invoke the same virtual
callback slot once for each line. Spectron implements the same work with its
`vuuHgangcF`, `CanTfaz6bZ`, and `G0gxgajWBw` containers.

These are high-confidence semantic matches, not exact normalized-body matches.
The labels were applied to
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v177.i64`
and reopened with zero failures. The database SHA-256 is
`d4d343a931a408cf34d6e32ca11a335711df184d7124b7d4d23a831445aa3cc2`. The
machine-readable evidence is in
`artifacts/spectron_http_request_receive_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_http_request_receive_anchors.py`.

## Spectron TString helper family

The v174 pass resolves six short `TString` helpers that remained outside the
global semantic alias set. The target class is obfuscated as `C8THgaTQxF`, but
the integer insertion calls, prefix predicate, and libc comparison thunks are
clear in IDA pseudocode. The complete normalized ARM64 feature record matches
for every row.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TString_operator_lshift_int` | `0xf14c8` | `0xf29a0` | `_ZN10C8THgaTQxFlsEi` | signed integer insertion wrapper |
| `TString_operator_lshift_uint` | `0xf1614` | `0xf2aec` | `_ZN10C8THgaTQxFlsEj` | unsigned integer insertion wrapper |
| `TString_operator_lshift_ulong_long` | `0xf174c` | `0xf2c24` | `_ZN10C8THgaTQxFlsEy` | 64-bit integer insertion wrapper |
| `TString_starts_TString_const` | `0xf2fa0` | `0xf46c0` | `_ZNK10C8THgaTQxF10fEtHgarybFERKS_` | null, length, and `memcmp` prefix test |
| `TString_strcasecmp_char_const_char_const` | `0xf3538` | `0xf4c58` | `_ZN10C8THgaTQxF10strcasecmpEPKcS1_` | libc `strcasecmp` thunk |
| `TString_strncasecmp_char_const_char_const_int` | `0xf35e4` | `0xf4d04` | `_ZN10C8THgaTQxF11strncasecmpEPKcS1_i` | libc `strncasecmp` thunk |

The three insertion wrappers are each 48/12/1/1 for size, instructions,
basic blocks, and calls. The prefix predicate is 116/29/7/1. The
`strcasecmp` thunk is 4/1/2/0, and the bounded comparison thunk is 8/2/2/0.
Every pair matches all ten feature fields used by the exact-anchor
generators.

The relocation is split by local target placement. The three integer
overloads share `+0x14d8`, while the prefix and comparison helpers share
`+0x1720`. The integer methods call the corresponding internal signed,
unsigned, and unsigned-long-long formatting helpers with the same default
arguments as the source wrappers. The prefix method returns true for a null
or empty prefix, rejects a prefix longer than the input, and compares the
remaining bytes with `memcmp`. The final two methods are direct libc thunks.

All six target functions already had obfuscated C++ names, so this batch does
not lower the default `sub_` count. The six readable aliases reopened
successfully in the v174 database. The full semantic reopen check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,250
default `sub_` names. The source and target ARM64 library hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_tstring_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tstring_anchors.py`. The saved IDA
database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v174.i64`
with SHA-256
`782b29da324e6eac107788b32c1a03105adedd976d561f0802a10913692af4ed`.

## Spectron hash-container helper family

The v173 pass resolves five short methods across the remaining `THashList` and
`THashStrings` candidates. The target classes are obfuscated as
`KKhLga4xoI` and `yL3_IaDMFt`, but the destructor, iterator, count, and lookup
roles are clear in IDA pseudocode. The complete normalized ARM64 feature
record matches for every row.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `THashList_THashList__2` | `0xea5b4` | `0xeb1a0` | `_ZN10KKhLga4xoID0Ev` | destructor body followed by `operator delete` |
| `THashList_registerIterator_THashListIterator` | `0xea5d4` | `0xeb1c0` | `_ZN10KKhLga4xoI10AhL3TaqoMMEP10R_MvgaEQlv` | iterator-head insertion |
| `THashStrings_setMaxCount_int` | `0xeaddc` | `0xeba28` | `_ZN10yL3_IaDMFt10a5u9TaVLBREi` | max-count field store at `+16` |
| `THashStrings_THashStrings__2` | `0xeb1e8` | `0xebe5c` | `_ZN10yL3_IaDMFtD0Ev` | destructor body followed by `operator delete` |
| `THashStrings_contains_TString_const` | `0xeb338` | `0xebfac` | `_ZN10yL3_IaDMFt10r8HDgaOK0BERK10C8THgaTQxF` | lookup result converted to a boolean |

The two deleting destructors are each 32 bytes with eight instructions, two
basic blocks, and one call. Iterator registration is 20/5/3/0 for size,
instructions, basic blocks, and calls. The maximum-count setter is 8/2/1/0.
The membership wrapper is 32/8/1/1. Every pair matches all ten feature
fields used by the repository's exact-anchor generators.

The local relocations split into three groups. The two `THashList` rows use
`+0xbec`, the maximum-count setter uses `+0xc4c`, and the `THashStrings`
destructor and membership rows use `+0xc74`. These are class-local placement
checks, not one global address delta.

The source names ending in `__2` are kept with their original aliases in the
artifact, but their bodies clarify the lifecycle role. Each calls the class
destructor and then `operator delete`, and the target explicitly retains the
D0 deleting-destructor name. The iterator helper links a non-null iterator at
the head of the container. The maximum-count helper stores its integer at
object offset `+16`. The membership helper returns whether the underlying
string lookup returned an object.

All five target functions already had obfuscated C++ names, so this batch does
not lower the default `sub_` count. The five readable aliases reopened
successfully in the v173 database. The full semantic reopen check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,250
default `sub_` names. The source and target ARM64 library hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_hash_container_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_hash_container_anchors.py`. The saved
IDA database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v173.i64`
with SHA-256
`9640159d6f6080f9b0ec9c86c9fe244a68be1a43e768138f25e2b2ce49b958e5`.

## Spectron TSounds helper family

The v172 pass resolves eight short `TSounds` methods that remained outside
the global semantic alias set. The target implementation uses the obfuscated
class name `IUKzgam4Gy`, but its global state, script wrappers, cleanup paths,
and playback forwarding remain clear in IDA pseudocode. The complete
normalized ARM64 feature record matches for every row.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TSounds_getSoundOffscreenDistance` | `0xe0bf8` | `0xe17a8` | `sub_E17A8` | global offscreen-distance double getter |
| `TSounds_setSoundOffscreenDistance` | `0xe0c08` | `0xe17b8` | `sub_E17B8` | global offscreen-distance double setter |
| `TSounds_setDisabledSoundEffects` | `0xe0c70` | `0xe1820` | `sub_E1820` | disabled-effects comma-text setter |
| `TSounds_getDisabledSoundEffects` | `0xe0c84` | `0xe1834` | `sub_E1834` | disabled-effects comma-text getter |
| `TSounds_stopSounds` | `0xe0fa8` | `0xe1b7c` | `sub_E1B7C` | script stop-sounds forwarding wrapper |
| `TSounds_freeResources_void` | `0xe0ff8` | `0xe1bcc` | `_ZN10IUKzgam4Gy10wgSQgaCg5MEv` | sound-effects hash-list cleanup |
| `TSounds_stopMidi_void` | `0xe1060` | `0xe1c34` | `_ZN10IUKzgam4Gy10xcTMgag3JJEv` | conditional virtual MIDI-player shutdown |
| `TSounds_playabs_TString_const_bool_double_double` | `0xe2284` | `0xe2e6c` | `_ZN10IUKzgam4Gy10ISa_ZaGLVLERK10C8THgaTQxFbdd` | absolute-playback forwarding wrapper |

The offscreen-distance getter and setter are each 16 bytes with four
instructions and one basic block. The disabled-effects setter is 20/5/2/0,
while its getter is 44/11/1/1. The stop-sounds wrapper is 12/3/2/0. Resource
cleanup is 20/5/2/0, MIDI shutdown is 48/12/3/1, and the absolute-playback
wrapper is 12/3/2/0. These tuples list size, instructions, basic blocks, and
calls. Every pair matches all ten feature fields used by the repository's
exact-anchor generators.

The address deltas are local to the target layout: the first four rows use
`+0xbb0`, the stop, resource, and MIDI rows use `+0xbd4`, and the playback
wrapper uses `+0xbe8`. These groups reflect the target's method placement and
are not a global relocation rule.

The pseudocode confirms the roles. The distance accessors read and write one
global double. The disabled-effects pair calls the target string-list
comma-text setter and getter on the matching global list. The stop wrapper
forwards its two flags to the internal stop-SFX routine. Resource cleanup
clears the global sound-effects hash list with its cleanup flag, while MIDI
shutdown calls virtual slot `+72` only when the global sound player exists.
The absolute-playback wrapper forwards its string, flags, and two doubles to
the internal playback implementation.

Five target bodies had default `sub_` names before this pass. The other three
retained obfuscated C++ names. All eight readable aliases reopened
successfully in the v172 database. The full semantic reopen check reports
zero failures across 11,694 functions, with 3,641 high-confidence labels and
1,250 default `sub_` names. The source and target ARM64 library hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_sounds_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_sounds_anchors.py`. The saved IDA
database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v172.i64`
with SHA-256
`fb51afe8228075594ac0c80e0582ea2733cb38a73b8526542ebfcf1500dc23cd`.

## Spectron TList helper family

The v171 pass resolves six short `TList` methods that remained outside the
global semantic alias set. The target implementation uses the obfuscated
class name `vy1JgaKVkH`, but the list bounds, mutation loop, accessors, and
sorting thunk remain clear in IDA pseudocode. The complete normalized ARM64
feature record matches for every row.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TList_Replace_int_void` | `0xec9f8` | `0xed9c8` | `_ZN10vy1JgaKVkH7ReplaceEiPv` | indexed bounds check and pointer replacement |
| `TList_Remove_void` | `0xecbac` | `0xedb7c` | `_ZN10vy1JgaKVkH6RemoveEPv` | repeated search and delete loop |
| `TList_AddList_TList` | `0xecd78` | `0xedd48` | `_ZN10vy1JgaKVkH10TF9BgaVKIAEPS_` | full source-range append wrapper |
| `TList_getS32_int` | `0xecdb8` | `0xedd88` | `_ZNK10vy1JgaKVkH10iqwRgaITDNEi` | signed indexed accessor with bounds guard |
| `TList_getU32_int` | `0xecde4` | `0xeddb4` | `_ZNK10vy1JgaKVkH10sULREacVQZEi` | unsigned indexed accessor with bounds guard |
| `TList_qsort_void_ulong_ulong_int_void_const_void_const` | `0xece10` | `0xedde0` | `_ZN10vy1JgaKVkH5qsortEPvmmPFiPKvS2_E` | direct libc `qsort` thunk |

The replacement wrapper is 28 bytes with seven instructions, four basic
blocks, and no direct calls. The remove wrapper is 72 bytes with 18
instructions, four blocks, and two calls. The full-list append wrapper is 20
bytes with five instructions, four blocks, and no direct calls. Both signed
and unsigned accessors are 44 bytes with 11 instructions, five blocks, and no
direct calls. The qsort thunk is four bytes with one instruction, two blocks,
and no direct calls in the normalized feature export. Each pair matches all
ten feature fields used by the repository's exact-anchor generators. The
address delta is `+0xfd0` for all six rows.

The two accessors deserve explicit treatment. Their source and target bodies
are identical after normalization: negative or out-of-range indexes return
zero, while valid indexes load the pointer-sized list element. The adjacent
signed and unsigned overload order, together with the target C++ method names,
resolves which alias belongs to which body. The other rows have distinct
operations: replacement stores into one slot, remove searches and deletes
every occurrence, AddList forwards the source's full range, and qsort passes
all four arguments directly to the C library.

All six target functions already had obfuscated C++ names, so this batch does
not lower the default `sub_` count. The six readable aliases reopened
successfully in the v171 database. The full semantic reopen check reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,255
default `sub_` names. The source and target ARM64 library hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_tlist_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_tlist_anchors.py`. The saved IDA
database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v171.i64`
with SHA-256
`48c9462053b822cd6e511abfc317dd1fa8c5082c8152425d4130e710c4c97714`.

## Spectron TEncryption helper family

The v170 pass resolves nine short `TEncryption` methods that remained outside
the global semantic alias set. The rows cover DES, MD5, RSA signing, RC4, and
AES. The target uses the obfuscated class name `cHovga0n1u`, but the
algorithm-specific native calls and the surrounding helper order remain
visible in IDA pseudocode. The complete normalized ARM64 feature record
matches for every row.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TEncryption_des_encrypt_TString_const_TString_const` | `0xe5abc` | `0xe66a4` | `_ZN10cHovga0n1u10UHr4FaIVl0ERK10C8THgaTQxFS2_` | guarded unique-string DES encryption |
| `TEncryption_des_decrypt_TString_const_TString_const` | `0xe5c24` | `0xe680c` | `_ZN10cHovga0n1u10ga33Fadh1_ERK10C8THgaTQxFS2_` | guarded unique-string DES decryption |
| `TEncryption_script_md5` | `0xe5d6c` | `0xe6954` | `sub_E6954` | script wrapper for the MD5 digest helper |
| `TEncryption_rsa_sign_TString_const_TString_const` | `0xf7464` | `0xf96f8` | `_ZN10cHovga0n1u10GjD5FacHl1ERK10C8THgaTQxFS2_` | RSA private-key decode, sign, and cleanup |
| `TEncryption_rc4_deletekey_void` | `0xf77d4` | `0xf9a68` | `_ZN10cHovga0n1u10OQfeYa5WBhEPv` | conditional native state release |
| `TEncryption_rc4_process_void_uchar_uchar_int` | `0xf77e0` | `0xf9a74` | `_ZN10cHovga0n1u10r5NzYabLJzEPvPhS1_i` | guarded `Arc4Process` dispatch |
| `TEncryption_aes_deletekey_void` | `0xf79ec` | `0xf9c80` | `_ZN10cHovga0n1u10ZirdYaFAVgEPv` | conditional native state release |
| `TEncryption_aes_encrypt_void_uchar_uchar_int` | `0xf79f8` | `0xf9c8c` | `_ZN10cHovga0n1u10wdyzYa5owzEPvPhS1_i` | guarded `AesCbcEncrypt` dispatch |
| `TEncryption_aes_decrypt_void_uchar_uchar_int` | `0xf7a14` | `0xf9ca8` | `_ZN10cHovga0n1u10eDbEYaGoqDEPvPhS1_i` | guarded `AesCbcDecrypt` dispatch |

The DES string wrappers are each 236 bytes with 59 instructions, 12 basic
blocks, and five calls. The MD5 wrapper is 32 bytes with eight instructions,
one block, and one call. RSA signing is 296 bytes with 74 instructions, 12
blocks, and seven calls. The RC4 and AES lifecycle wrappers are 12 bytes with
three instructions and four blocks. Their process wrappers are 28 bytes with
seven instructions and seven blocks. Every pair matches all ten feature
fields used by the repository's exact-anchor generators.

The two address regions are useful context. The DES and MD5 rows share
`+0xbe8`, while RSA, RC4, and AES share `+0x2294`. This is a pair of stable
class-local relocations, not a claim that one global delta applies to the
whole library.

IDA pseudocode also records the safety checks that matter for later runtime
work. The DES wrappers require a nonempty input and a key longer than seven
bytes, make a unique temporary copy, call the corresponding DES memory
routine, copy the result, and clear the temporary. The RSA wrapper decodes a
private key, initializes an RNG, signs the input, appends a positive result,
and frees the key state. RC4 and AES process wrappers validate the state,
input, output, and positive length before calling `Arc4Process`,
`AesCbcEncrypt`, or `AesCbcDecrypt`. Invalid inputs return without dispatch.
The short MD5 row forwards the supplied string to the class digest helper.

One target row, the MD5 wrapper, had a default `sub_` name before this pass.
The other eight retained obfuscated C++ names. All nine readable aliases
reopened successfully in the v170 database. The full semantic reopen check
reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,255 default `sub_` names. The source and target ARM64 library
hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_encryption_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_encryption_anchors.py`. The saved IDA
database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v170.i64`
with SHA-256
`3464dc1d4195ae163bf8648b0de26d4e3d51c6722a27e4bd0600fd912d44d4e8`.

## Spectron TFiles helper family

The v169 pass resolves six short `TFiles` methods that remained outside the
global semantic alias set. The target implementation uses the obfuscated
class name `wiULgacZUI`, but its file metadata, separator, case, and URL-aware
path behavior remains clear in IDA pseudocode. The complete normalized ARM64
feature record matches for every row.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TFiles_fileSize_TString_const` | `0xe6c80` | `0xe7868` | `_ZN10wiULgacZUI10e4jIMaevUAERK10C8THgaTQxF` | `stat` regular-file guard and size return |
| `TFiles_getUTCFileModTime_TString_const` | `0xe7068` | `0xe7c50` | `_ZN10wiULgacZUI10rIU_fa5jx4ERK10C8THgaTQxF` | matching `stat` guard and timestamp return |
| `TFiles_extractFilename_TString_const` | `0xe7304` | `0xe7eec` | `_ZN10wiULgacZUI10_RVvga7htvERK10C8THgaTQxF` | last-separator extraction and trim |
| `TFiles_lowerCaseFilename_TString_const` | `0xe73b4` | `0xe7f9c` | `_ZN10wiULgacZUI10RUnvgavJ0uERK10C8THgaTQxF` | lower-case whole path or trailing component |
| `TFiles_stripFileName_TString_const` | `0xe7df0` | `0xe89d8` | `_ZN10wiULgacZUI10SoDvgaHLdvERK10C8THgaTQxF` | URL-aware filename preservation and cleanup |
| `TFiles_stripExtension_TString_const` | `0xe7ed8` | `0xe8ac0` | `_ZN10wiULgacZUI10VR1DEa2aiOERK10C8THgaTQxF` | URL-aware extension preservation and removal |

The two metadata helpers are each 96 bytes with 24 instructions, six basic
blocks, and one call. The extraction and lower-case helpers are each 176
bytes with 44 instructions, six blocks, and five calls. The two URL-aware
helpers are each 232 bytes with 58 instructions, six blocks, and ten calls.
Each source and target pair matches all ten feature fields used by the
repository's exact-anchor generators. The relocation is `+0xbe8` for all six
rows.

The decompiled behavior supplies the semantic distinction between the rows.
`fileSize` and `getUTCFileModTime` both require a valid regular file before
returning the requested `stat` field. `extractFilename` finds the last file
separator and trims the extracted suffix. `lowerCaseFilename` applies the
case conversion to the whole input or only that suffix, depending on whether
a separator was found. The two final helpers recognize both the regular and
encoded URL identifiers. They preserve URL inputs and otherwise route to the
lower-case or remove-extension helper, clearing their temporary identifier
strings on both paths.

All six target names were already obfuscated C++ names, so this batch does not
lower the default `sub_` count. The six readable aliases reopened
successfully in the v169 database. The full semantic reopen check remains at
zero failures across 11,694 functions, with 3,641 high-confidence labels and
1,256 default `sub_` names. The source and target ARM64 library hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_files_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_files_anchors.py`. The saved IDA
database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v169.i64`
with SHA-256
`0904e8d1b0f8f97a2536cd34a44f12974365f427f4c590c89e83efc1ca570d53`.

## Spectron compression helper family

The v168 pass resolves five short `TCompression` methods that remained
outside the global semantic alias set. The target cluster uses the obfuscated
class name `MHEiIauRiT`, but its wrapper behavior and ordered overload layout
remain recognizable. The source and target rows also match every normalized
ARM64 feature field, so this is a strong translation even though the target
does not retain the original class names.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TCompression_CompressBuf_TString_const_uchar_uint` | `0xe4f30` | `0xe5b18` | `_ZN10MHEiIauRiT10E8yGKaVaqTERK10C8THgaTQxFPhj` | TString extraction and raw `CompressBuf` dispatch |
| `TCompression_CompressBuf_void_const_int_uchar_uint` | `0xe4f68` | `0xe5b50` | `_ZN10MHEiIauRiT10E8yGKaVaqTEPKviPhj` | output reset, raw compression, and buffer append |
| `TCompression_DecompressBuf_TString_const_uchar_uint` | `0xe50d8` | `0xe5cc0` | `_ZN10MHEiIauRiT10FReiIaT6XSERK10C8THgaTQxFPhj` | embedded-string or dummy-string decompression input |
| `TCompression_CompressBuf2_TString_const_uchar_uint` | `0xe51d8` | `0xe5dc0` | `_ZN10MHEiIauRiT10H3FyYaR_MyERK10C8THgaTQxFPhj` | TString extraction and `CompressBuf2` dispatch |
| `TCompression_CompressBuf2_void_const_int_uchar_uint` | `0xe5210` | `0xe5df8` | `_ZN10MHEiIauRiT10H3FyYaR_MyEPKviPhj` | second-mode output reset and buffer append |

The first and fourth rows are 56-byte wrappers with 14 instructions and
four basic blocks. Their raw-buffer companions are 96 bytes with 24
instructions, five blocks, and three calls. The decompression wrapper is 108
bytes with 27 instructions, three blocks, and two calls. Every corresponding
pair has the same complete feature record, including all ten fields used by
the repository's exact-anchor generators. The address delta is `+0xbe8` for
all five rows.

IDA pseudocode gives the useful behavioral detail. The string overloads read
the embedded string pointer and length when the input is present, otherwise
select the shared dummy string storage. The raw compression wrappers clear
the output string, call the matching raw implementation, and append the
caller-provided buffer or the internal compression buffer when the caller
buffer is null. The decompression wrapper follows the same input fallback
before calling the raw decompressor. The two `CompressBuf2` rows are not
duplicates of the first pair because their wrappers call separate
implementation entries.

All five target names were already obfuscated C++ names, so this batch does
not lower the default `sub_` count. The five readable aliases reopened
successfully in the v168 database. The full semantic reopen check remains at
zero failures across 11,694 functions, with 3,641 high-confidence labels and
1,256 default `sub_` names. The source and target ARM64 library hashes are
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8` and
`f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.

The machine-readable record is
`artifacts/spectron_compression_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_compression_anchors.py`. The saved IDA
database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v168.i64`
with SHA-256
`f128cbd323aa0e5f1a021c447f404b0f9b3778d83ab1dfffc7095b004191b4fd`.

## Spectron server-object scalar helpers

The v167 pass resolves 12 short methods that the general semantic matcher
left unmatched because repeated getter and setter bodies collided under the
normalized feature keys. The rows are in four class-local clusters:
`TServerBomb`, `TServerChest`, `TServerFlying`, and `TExplosion`. Their
identity comes from the surrounding method order and the decompiled field or
constructor behavior, then the complete normalized feature record confirms
the exact body correspondence.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TServerBomb_getTime` | `0x23ce9c` | `0x246db4` | `sub_246DB4` | time field at `+244`, divided by 20.0 |
| `TServerBomb_getOrderPoint_void` | `0x23cf10` | `0x246e28` | `_ZN10irqhGaERgb10JhjWgazQFREv` | virtual x/y accessors and tile offsets |
| `TServerBomb_setImage` | `0x23cf98` | `0x246eb0` | `sub_246EB0` | string assignment to image field |
| `TServerChest_setOpen_bool` | `0x23e3e0` | `0x248368` | `_ZN10dJ10YaC3tX10tLt0YaEE0WEb` | boolean store at `+248` |
| `TServerFlying_getDx` | `0x23ec34` | `0x248bbc` | `sub_248BBC` | double getter at `+248` |
| `TServerFlying_setDx` | `0x23ec3c` | `0x248bc4` | `sub_248BC4` | double setter at `+248` |
| `TServerFlying_getDy` | `0x23ec44` | `0x248bcc` | `sub_248BCC` | double getter at `+256` |
| `TServerFlying_setDy` | `0x23ec4c` | `0x248bd4` | `sub_248BD4` | observed double store at `+248` |
| `TServerFlying_getType` | `0x23ec54` | `0x248bdc` | `sub_248BDC` | unsigned integer getter at `+272` |
| `TServerFlying_getFrom` | `0x23ec5c` | `0x248be4` | `sub_248BE4` | unsigned integer getter at `+264` |
| `TServerFlying_getOrderPoint_void` | `0x23ec64` | `0x248bec` | `_ZN10gId5RaV8_610JhjWgazQFREv` | virtual x/y accessors and tile offsets |
| `TExplosion_TExplosion_TServerLevel` | `0x23caa0` | `0x246950` | `_ZN10Dq2rua2EceC2EP10zF9VgaBKxR` | base construction, vtable, type byte, and property singleton |

All 12 pairs match size, instruction count, basic-block count, branches,
calls, mnemonic hash, opcode-shape hash, register-shape hash, overall-shape
hash, and string-reference digest. Eight target bodies were default `sub_`
names before the pass. The remaining four retained obfuscated C++ names, so
the aliases are an analysis overlay and not recovered 2.2 debug symbols.

The `TServerFlying` dy setter is worth recording precisely. Both analyzed
builds store its argument at `+248`, even though the neighboring dy getter
reads `+256`. The pass preserves the observed code and does not silently
repair it from an expected field layout. This is the kind of small detail
that can disappear if a translation is based only on guessed member names.

The address deltas are `+0x9eb0` for the explosion constructor, `+0x9f18`
for the three server-bomb rows, and `+0x9f88` for the eight chest and flying
rows. The target class names are `irqhGaERgb`, `dJ10YaC3tX`, `gId5RaV8_6`,
and `Dq2rua2Ece`, respectively. These stable local deltas and the adjacent
method order resolve the repeated eight-byte accessors that the global
semantic matcher correctly refused to choose automatically.

The machine-readable record is
`artifacts/spectron_server_object_scalar_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_server_object_scalar_anchors.py`. All
12 labels reopened successfully. The full semantic reopen check still
reports zero failures across 11,694 functions, with 3,641 high-confidence
labels and 1,256 default `sub_` names. The saved database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v167.i64`
with SHA-256
`99e9466a62544d22433484e73013683ff716f2308956066c83650abc6f449387`.

## Spectron TShowImg residual class methods

The v166 pass closes the remaining named `TShowImg` rows that were not
covered by the property callback table or the earlier visual-helper pass. It
uses the source and target class-local order as context, then checks the
normalized ARM64 function features and the decompiled behavior. The target
cluster runs from `0x23e124` through `0x242020` and retains the obfuscated
`eODlJaQ5OL` C++ symbols, so these aliases make the existing names readable
without treating a stripped binary as if it still had source symbols.

Twenty-two rows match the complete normalized feature set. The two
`TShowImgProperties` destructor rows have the same lifecycle role and common
metrics, but vtable literals differ between the builds. They are therefore
marked as layout-aware rather than exact-shape matches. The four code-delta
groups are `+0x9d58` for one row, `+0x9df0` for one, `+0x9e88` for seven, and
`+0x9ea0` for 15. This is another small example of why the translation pass
uses class and behavior evidence instead of one global address offset.

| 1.8 method or role | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TShowImg_getz_void` | `0x2343cc` | `0x23e124` | `_ZN10eODlJaQ5OL10gkQVgaDDgREv` | direct double read of the z-helper field |
| `TShowImg_TShowImg__2` | `0x23476c` | `0x23e55c` | `_ZN10eODlJaQ5OLD0Ev` | D0 deleting destructor, exact shape |
| `TShowImg_onResourceFileUpdated_TString_const` | `0x234dc4` | `0x23ec4c` | `_ZN10eODlJaQ5OL10py0qgaE4krERK10C8THgaTQxF` | two-argument resource-update thunk |
| `TShowImg_tilewidthplain_void` | `0x235554` | `0x23f3dc` | `_ZN10eODlJaQ5OL10NE5cXa4mDqEv` | zero-return plain tile-width helper |
| `TShowImg_tilesize_void` | `0x235854` | `0x23f6dc` | `_ZN10eODlJaQ5OL10pIS3IaYDSwEv` | pixelsize call and 1/16 conversion |
| `TShowImg_showText_TString_const` | `0x236a0c` | `0x240894` | `_ZN10eODlJaQ5OL10WoSUWaLnsaERK10C8THgaTQxF` | image type 2 and coded text |
| `TShowImg_showPoly_TString_const` | `0x236a9c` | `0x240924` | `_ZN10eODlJaQ5OL10__VUWaHpvaERK10C8THgaTQxF` | image type 3 and coded polygon |
| `TShowImg_showTexturedPoly_TString_const` | `0x236ad0` | `0x240958` | `_ZN10eODlJaQ5OL10nvvZWa56leERK10C8THgaTQxF` | image type 3 and textured coded polygon |
| `TShowImg_showAni_TString_const` | `0x236b58` | `0x2409e0` | `_ZN10eODlJaQ5OL10MtfZWaID8dERK10C8THgaTQxF` | image type 4 and coded animation |
| `TShowImg_getAni_void` | `0x237984` | `0x241824` | `_ZN10eODlJaQ5OL10jlavgawjQuEv` | particle animation getter |
| `TShowImg_setDir_int` | `0x237a58` | `0x2418f8` | `_ZN10eODlJaQ5OL10Bn9cHauvGYEi` | direction wrapper with image type 4 |
| `TShowImg_setFont_TString_const` | `0x237a90` | `0x241930` | `_ZN10eODlJaQ5OL10UgsKFaUoHJERK10C8THgaTQxF` | type 2 and font member assignment |
| `TShowImg_setImage_TString_const` | `0x237b34` | `0x2419d4` | `_ZN10eODlJaQ5OL10kcRIFa3mlIERK10C8THgaTQxF` | four-byte thunk to `showImage` |
| `TShowImg_getImageIndex_void` | `0x237b3c` | `0x2419dc` | `_ZN10eODlJaQ5OL10FSUSXaJsOZEv` | image-index field getter |
| `TShowImg_getLayer_void` | `0x237b48` | `0x2419e8` | `_ZN10eODlJaQ5OL10MJuWXagtP1Ev` | layer normalization for below and above |
| `TShowImg_setPolygon_TGraalVar` | `0x237c78` | `0x241b18` | `_ZN10eODlJaQ5OL10hoANFa0dkMEP10G0gxgajWBw` | type 3 and polygon variable wrapper |
| `TShowImg_setStyle_TString_const` | `0x237cb0` | `0x241b50` | `_ZN10eODlJaQ5OL10l7cPgaSEHLERK10C8THgaTQxF` | style member assignment |
| `TShowImg_setText_TString_const` | `0x237ce8` | `0x241b88` | `_ZN10eODlJaQ5OL10AceLgadzlIERK10C8THgaTQxF` | text member assignment |
| `TShowImg_getAttachToOwner_void` | `0x237d7c` | `0x241c1c` | `_ZN10eODlJaQ5OL10myF7XaBz3bEv` | attach-to-owner byte getter |
| `TShowImg_initStaticScriptVars_void` | `0x2380f4` | `0x241f94` | `_Z10soSA2abnDNv` | properties singleton initialization |
| `TShowImgProperties` complete destructor role | `0x238124` | `0x241fc4` | `_ZN20eODlJaQ5OLPropertiesD2Ev` | D1 source and D2 target lifecycle row, layout-aware |
| `TShowImgProperties` D0 deleting destructor role | `0x238148` | `0x241fe8` | `_ZN20eODlJaQ5OLPropertiesD0Ev` | deleting destructor lifecycle row, layout-aware |
| properties D1 non-virtual thunk | `0x238140` | `0x241fe0` | `_ZThn16_N20eODlJaQ5OLPropertiesD1Ev` | adjusted-this thunk, exact shape |
| properties D0 non-virtual thunk | `0x238180` | `0x242020` | `_ZThn16_N20eODlJaQ5OLPropertiesD0Ev` | adjusted-this thunk, exact shape |

Several of the wrapper matches are useful behavioral anchors, not just
short-function coincidences. `showText`, `showPoly`, `showTexturedPoly`, and
`showAni` set the same image type values as the source before forwarding the
coded string. `setDir` keeps the type 4 path, while `setFont`, `setStyle`, and
`setText` store into the corresponding members at the same object offsets.
`tilesize` still calls the pixel-size helper and scales both returned integer
components by `1/16`. The target `setImage` is the same kind of short thunk
as the source and forwards into the main image setter. The two properties
destructor rows are the only places where lifecycle evidence is deliberately
combined with common normalized metrics because vtable constants are a
layout-sensitive detail.

Before the pass, every target function in this table already had a meaningful
obfuscated C++ name. The aliases are therefore an analysis overlay and do not
change the target binary. The complete machine-readable evidence is in
`artifacts/spectron_showimg_residual_manual_translation_anchors_20260827.json`,
generated by `tools/generate_spectron_showimg_residual_anchors.py`. All 24
labels reopened successfully. The full semantic check still reports zero
failures across 11,694 functions, with 3,641 high-confidence labels and 1,264
default `sub_` names. The saved database is
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v166.i64`
with SHA-256
`31b96a52e45a605de9aa2c881ea9061c33afda1b2dfac5773c1a420ea7caec77`.

## Spectron TShowImg property callback table

The `TShowImgProperties` registry gives a direct translation anchor for the
show-image API. The source table is at `0x389fa0`; the obfuscated Spectron
table for `eODlJaQ5OL` is at `0x39d0f0`. Both tables use `0x30`-byte records.
The name pointer is at record offset `+0x0`, flags at `+0x8`, the getter at
`+0x10`, and the setter at `+0x18`. The common metadata pointer and trailing
fields are retained in the machine-readable record as well.

The decoded property names are identical and remain in the same 48-slot order:

```text
actor, ani, dir, playerlook, image, polygon, dimension, font,
shadowoffset, shadowcolor, style, text, textshadow, alpha, blue, code,
green, height, imageindex, layer, mode, parth, partw, partx, party,
position, red, rotation, rotationcenter, spin, stretchx, stretchy,
useowncenter, width, x, y, z, zoom, attachoffset, attachtoowner,
emitter, uniqueparticle, angle, lifetime, movementvector, speed, zangle,
sound
```

That gives 96 possible getter and setter slots. Ninety-three are non-null.
The three null setters are `actor`, `imageindex`, and `emitter`. The table
review produced 85 high-confidence source-to-target rows. Eight rows were
already represented by earlier semantic or manual aliases, while the other
rows received readable `v18_TShowImg_` labels in the v165 disposable IDA
copy.

| Property role | 1.8 callback | Source | Spectron target | Evidence |
| --- | --- | ---: | ---: | --- |
| actor getter | `TShowImg_get_actor` | `0x2340f8` | `0x23de98` | direct table pointer, exact 8-byte shape |
| alpha setter | `TShowImg_set_alpha` | `0x234108` | `0x23dea8` | direct pointer and clamped float store |
| dimension setter | `TShowImg_setDimension_int` | `0x237a54` | `0x2418f4` | direct pointer, exact shape |
| position getter | `TShowImg_get_position` | `0x237858` | `0x2416f8` | direct pointer, exact shape |
| stretchx setter | `TShowImg_set_stretchx` | `0x234e38` | `0x23ecc0` | table role resolves reordered body |
| attachoffset setter | `TShowImg_set_attachoffset` | `0x2380b8` | `0x241f58` | table role resolves reordered body |
| sound setter | `TShowImg_set_sound` | `0x234410` | `0x23e168` | direct pointer and member update |
| code getter | `TShowImg_get_code` | `0x234140` | `0x23e40c` | virtual slot preserved, wrapper grew |
| code setter | `TShowImg_set_code` | `0x234168` | `0x23e3c0` | shared target `v18_TGaniParam_writeFloat_double` |

Eighty-four rows have identical complete normalized fingerprints. The exact
fields include size, instruction count, basic-block count, branches, calls,
mnemonic hash, opcode shape, register shape, overall shape, and string
references. Their address deltas fall into six groups: `+0x9d58` for 53 rows,
`+0x9da0` for six, `+0x9df0` for two, `+0x9e88` for two, `+0x9ea0` for 21,
and `+0xa2cc` for the `code` getter. This spread is a useful warning against
copying symbols by source address plus one global constant.

The `code` getter is the one layout-aware row. The 1.8 callback is a 40-byte
wrapper around virtual slot `+184`. Spectron's 76-byte callback still uses
that slot, then converts the returned value and performs the target string
cleanup sequence. Its setter record points at the already translated
`v18_TGaniParam_writeFloat_double` implementation rather than at a unique
`TShowImg` body. Keeping that existing name preserves the shared target
context and avoids pretending that one native body implements only one
property role.

The full review is stored in
`artifacts/spectron_showimg_property_manual_translation_anchors_20260827.json`.
The table-driven generator is
`tools/generate_spectron_showimg_property_anchors.py`, and
`tools/ida_dump_property_table.py` provides the read-only IDA table dump used
to verify the decoded names and callback fields. The labels are persisted in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v165.i64`,
whose SHA-256 is
`284432daf4efd99359cd41c2dc436f554c65b43f4e1d579bab4b3030fb72c153`.
The 85-row manual reopen check and the full semantic reopen check both report
zero failures. This is an analysis overlay only. It does not modify the
Spectron APK or change runtime behavior.

## Spectron TServerPlayer lifecycle and property-runtime tail

The v164 pass closes the seven named `TServerPlayer` rows that were still
outside the larger registration-table batches. One row is tied directly to the
`attachedtoobject` property record. The remaining six are fixed by exact
normalized fingerprints together with their lifecycle, static-initializer, or
paired-coordinate sequence.

| 1.8 method | Source | Spectron target | Target name before alias | Evidence |
| --- | ---: | ---: | --- | --- |
| `TServerPlayer_setAttachedToObject` | `0x18ca40` | `0x1912f0` | `sub_1912F0` | `attachedtoobject` property index 3 setter |
| `TServerPlayer_clearNickWrapped_void` | `0x18dc58` | `0x192558` | `_ZN10MpGzgariDy10Zb7rwaMFgVEv` | draw-to-destructor lifecycle and exact shape |
| `TServerPlayer_TServerPlayer__2` | `0x18de80` | `0x192780` | `_ZN10MpGzgariDyD0Ev` | D0 deleting-destructor role and exact shape |
| `TServerPlayer_initStaticVars_void` | `0x1906e8` | `0x195118` | `_Z10HFtL2aJzyWv` | static-initializer pair before property accessors |
| `TServerPlayer_initStaticScriptVars_void` | `0x19072c` | `0x19515c` | `_Z10O36P2aSys_v` | static-script initializer pair before property accessors |
| `TServerPlayer_setlocalx_double_bool` | `0x1908b8` | `0x1952e8` | `_ZN10MpGzgariDy10yizVgakj2QEdb` | paired local-coordinate setter sequence |
| `TServerPlayer_setlocaly_double_bool` | `0x1909f0` | `0x195420` | `_ZN10MpGzgariDy10rysVgaGDXQEdb` | paired local-coordinate setter sequence |

The attachment mapping is independently visible in the source property table
at `0x37ce00` and the target table at `0x38fe60`. Record 3 is named
`attachedtoobject`, and its setter pointer is `0x18ca40` in 1.8 and
`0x1912f0` in Spectron. This resolves the short target body next to the large
`attachToNPC` implementation without using address proximity as the proof.

The cleanup and destructor rows preserve the class-local lifecycle. The
source cleanup method at `0x18dc58` is followed by the D1 destructor at
`0x18dc98` and the D0 destructor at `0x18de80`. Spectron keeps the same
relationship around `0x192558`, `0x192598`, and `0x192780`. The source alias
`TServerPlayer_TServerPlayer__2` is misleading when read as a C++ name, but
the source ELF symbol is `_ZN13TServerPlayerD0Ev`. It is therefore documented
and labeled as the D0 deleting destructor. The target `_ZN10MpGzgariDyD0Ev`
confirms that role.

The two static initializers form a 68-byte and 48-byte pair in both builds.
They sit after the large weapon-image method and immediately before the
property accessors. The local-coordinate setters are both 296 bytes with 74
instructions, 12 basic blocks, 11 branches, and five calls. Their target
addresses are source plus `0x4a30`, and the 0x10-byte gap after the first
setter is preserved.

All seven pairs match the complete normalized fingerprint, including control
flow, register shape, and string-reference fields. Only the attachment setter
had a default target name before the pass. The target aliases were applied in
the v164 packed IDA copy at
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v164.i64`.
The seven-row reopen check and the full semantic reopen check both reported
zero failures. The database contains 11,694 functions, 1,333 default `sub_`
names, and 3,641 high-confidence semantic labels. Its SHA-256 is
`321b0d07651f463e128399cc3e0e0f56669394cd6ba97ed1c13224b6a5462cc5`.
The complete record is
`artifacts/spectron_tserverplayer_tail_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tserverplayer_tail_anchors.py`.

## Spectron TServerPlayer registration-table residuals

The v163 pass resolves the next 25 `TServerPlayer` callbacks through the
registration data rather than through target address order. The source
`TServerPlayerProperties` table starts at `0x37ce00`; the Spectron table starts
at `0x38fe60`. Both contain 52 records of `0x30` bytes, and their decoded
property names are identical and in the same order. The getter pointer is at
record offset `+0x10` and the setter pointer is at `+0x18`. The companion
six-entry script-function tables are at `0x37d7c0` and `0x390820`, with the
callback pointer at `+0x18`.

This direct pointer evidence is important because the target reorders several
image and text methods. The table records still identify the target callback
even when the target body is far from the source-order neighbor.

| 1.8 callback | Source | Spectron target | Registration evidence | New alias |
| --- | ---: | ---: | --- | --- |
| `TServerPlayer_script_PMsWaiting` | `0x18aa68` | `0x18f2c8` | function `pmswaiting`, index 2 | `v18_TServerPlayer_script_PMsWaiting` |
| `TServerPlayer_script_openExternalHistory` | `0x18aa88` | `0x18f2e8` | function `openexternalhistory`, index 3 | `v18_TServerPlayer_script_openExternalHistory` |
| `TServerPlayer_script_openExternalPM` | `0x18aa90` | `0x18f2f0` | function `openexternalpm`, index 4 | `v18_TServerPlayer_script_openExternalPM` |
| `TServerPlayer_setSwordImg` | `0x18aac4` | `0x18f4b8` | property `swordimg`, index 48, setter | `v18_TServerPlayer_setSwordImg` |
| `TServerPlayer_setShieldImg` | `0x18aacc` | `0x18f4c0` | property `shieldimg`, index 46, setter | `v18_TServerPlayer_setShieldImg` |
| `TServerPlayer_setHorseImg` | `0x18aad4` | `0x18f324` | property `horseimg`, index 18, setter | `v18_TServerPlayer_setHorseImg` |
| `TServerPlayer_getSwordImg` | `0x18aadc` | `0x18f4c8` | property `swordimg`, index 48, getter | `v18_TServerPlayer_getSwordImg` |
| `TServerPlayer_getShieldImg` | `0x18ab0c` | `0x18f4f8` | property `shieldimg`, index 46, getter | `v18_TServerPlayer_getShieldImg` |
| `TServerPlayer_getPlatform` | `0x18ab3c` | `0x18f32c` | property `platform`, index 40, getter | `v18_TServerPlayer_getPlatform` |
| `TServerPlayer_getLevelName` | `0x18ab6c` | `0x18f528` | property `levelname`, index 34, getter | `v18_TServerPlayer_getLevelName` |
| `TServerPlayer_getLanguage` | `0x18ab9c` | `0x18f35c` | property `language`, index 32, getter | `v18_TServerPlayer_getLanguage` |
| `TServerPlayer_getHorseImg` | `0x18abcc` | `0x18f38c` | property `horseimg`, index 18, getter | `v18_TServerPlayer_getHorseImg` |
| `TServerPlayer_getHeadOrHeadImg` | `0x18abfc` | `0x18f558` | properties `head` and `headimg`, indices 14 and 15, shared getter | `v18_TServerPlayer_getHeadOrHeadImg` |
| `TServerPlayer_getGuild` | `0x18ac2c` | `0x18f3bc` | property `guild`, index 13, getter | `v18_TServerPlayer_getGuild` |
| `TServerPlayer_getCommunityName` | `0x18ac5c` | `0x18f3ec` | property `communityname`, index 7, getter | `v18_TServerPlayer_getCommunityName` |
| `TServerPlayer_getAccount` | `0x18ac8c` | `0x18f41c` | property `account`, index 0, getter | `v18_TServerPlayer_getAccount` |
| `TServerPlayer_getChat` | `0x18acbc` | `0x18f44c` | property `chat`, index 6, getter | `v18_TServerPlayer_getChat` |
| `TServerPlayer_getNick` | `0x18acec` | `0x18f47c` | property `nick`, index 38, getter | `v18_TServerPlayer_getNick` |
| `TServerPlayer_getLanguageDomain` | `0x18ae24` | `0x18f654` | property `languagedomain`, index 33, getter | `v18_TServerPlayer_getLanguageDomain` |
| `TServerPlayer_getHeadset` | `0x18ae48` | `0x18f678` | property `headset`, index 16, getter | `v18_TServerPlayer_getHeadset` |
| `TServerPlayer_setChatOffset` | `0x18ae9c` | `0x18f6e4` | property `chatoffset`, index 8, setter | `v18_TServerPlayer_setChatOffset` |
| `TServerPlayer_getChatOffset` | `0x18aec8` | `0x18f710` | property `chatoffset`, index 8, getter | `v18_TServerPlayer_getChatOffset` |
| `TServerPlayer_script_showProfile` | `0x18aeec` | `0x18f734` | function `showprofile`, index 5 | `v18_TServerPlayer_script_showProfile` |
| `TServerPlayer_setDarts` | `0x18b178` | `0x18fa44` | property `darts`, index 9, setter | `v18_TServerPlayer_setDarts` |
| `TServerPlayer_setBombs` | `0x18b1a0` | `0x18fa6c` | property `bombs`, index 4, setter | `v18_TServerPlayer_setBombs` |

The three script callbacks at `0x18f2c8..0x18f2f8` needed explicit target
function boundaries before they could be labeled. Their target bodies then
matched the 1.8 normalized fingerprints exactly. The other 20 exact-shape
rows also matched every recorded metric. The headset getter and show-profile
callback are high-confidence layout changes: their registration slots, string
or event roles, and surrounding class context match, but the target bodies
grow from 84 to 108 bytes and from 104 to 160 bytes respectively.

Two nearby methods were intentionally kept out of the new alias list because
their target bodies already have aliases from shared implementations:

| 1.8 context row | Source | Spectron target | Existing alias |
| --- | ---: | ---: | --- |
| `TServerPlayer_getPlayersIndex` | `0x18ad58` | `0x18f588` | `v18_TServerNPC_getNPCsIndex` |
| `TServerPlayer_getLogName_void` | `0x18af54` | `0x18f804` | `v18_TGraalAni_getLogName_void` |

The address relocation is therefore recorded per row. It is not safe to infer
one global offset for this class from the reordered methods. All 25 target
functions had default names before the pass. The target aliases were applied
in the v163 packed IDA copy at
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v163.i64`.
The new anchor check and the full semantic reopen check both reported zero
failures. The database contains 11,694 functions, 1,334 default `sub_` names,
and 3,641 high-confidence semantic labels. Its SHA-256 is
`a71091ea191f50791b1f5c74d11beb104b96fc828b80fee65ec4609ff9f2d6cb`.
The complete table inventory, layout-change notes, shared context, and input
hashes are in
`artifacts/spectron_tserverplayer_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tserverplayer_residual_anchors.py`.

## Spectron TServerPlayer property block

The v161 pass translates a large ordered property block from the readable 1.8
`TServerPlayer` class to the obfuscated `MpGzgariDy` implementation in
Spectron 2.2. The source range is `0x18a55c..0x18aa5c`, and the target range is
`0x18edbc..0x18f2bc`.

| Group | Source range | Spectron range | New rows |
| --- | --- | --- | ---: |
| scalar, flag, inventory, and combat properties | `0x18a55c..0x18a878` | `0x18edbc..0x18f0d8` | 35 |
| X and Y coordinate accessors and setters | `0x18a898..0x18a9b4` | `0x18f0f8..0x18f214` | 4 |

Four already translated rows are interleaved through the first group and act
as sequence checkpoints: `setAP`, `getAttached`, `setChat`, and `setMP`.
Their target starts are `0x18ede8`, `0x18ee3c`, `0x18ee8c`, and `0x18f024`.
The 39 new rows are all recorded in the machine-readable artifact, including
the target name that existed before the new alias was applied. The target
range contained 38 default `sub_` names and one surviving obfuscated C++ name.

Every new pair has the same complete normalized feature fingerprint. The
source and target bodies preserve the short scalar property wrappers, boolean
flag accessors, 52-byte coordinate getters, and 168-byte coordinate setters.
The target address is source plus `0x4860` for all 39 rows. The source and
target gaps around `setX` and `setY` also line up, which helps distinguish the
block from neighboring implementation code.

Hex-Rays provides the semantic confirmation. The paused setter writes the
same byte-valued state and calls the corresponding nick cleanup method. The
cleanup method removes the encoded text token, releases the object through a
virtual slot, and clears the member in both builds. The local X and Y setters
retain the direct-set path, animation-object update, tile alignment arithmetic,
and attached-object update loop. The target has different helper class names
and storage constants because its layout changed, but not a different role.

The target functions now have `v18_` aliases in
`analysis/spectron_libqplay_translated_v161.i64`. All 39 manual labels
reopened successfully. The full semantic map still reopens with 3,641
high-confidence labels and zero failures across 11,693 functions. The packed
database has 1,358 default `sub_` names and SHA-256
`000eb36e5ceb7dfc75c9b8565b92c16649cb0d835232972c4ccad81ebab044d0`.
The machine-readable record is
`artifacts/spectron_tserverplayer_property_block_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tserverplayer_property_block_anchors.py`.

## Spectron TPlayer flag-setter block

The v160 pass maps the remaining TPlayer flag setters from 1.8 to the
obfuscated `W6NzgawMJy` class in Spectron 2.2. Six boolean setters are
contiguous. The integer enabled-features setter follows the already translated
paused setter.

| 1.8 function | Source | Spectron target | Target symbol |
| --- | ---: | ---: | --- |
| `TPlayer_setWeaponsEnabled_bool` | `0x17b59c` | `0x17f940` | `_ZN10W6NzgawMJy10iUOZLa2qCZEb` |
| `TPlayer_setSwordHidden_bool` | `0x17b608` | `0x17f9ac` | `_ZN10W6NzgawMJy10rgGswaraKVEb` |
| `TPlayer_setDefaultMovement_bool` | `0x17b674` | `0x17fa18` | `_ZN10W6NzgawMJy10PeaZLa8d4YEb` |
| `TPlayer_setIsHurt_bool` | `0x17b6e0` | `0x17fa84` | `_ZN10W6NzgawMJy10iKOswaDiRVEb` |
| `TPlayer_setHidden_bool` | `0x17b74c` | `0x17faf0` | `_ZN10W6NzgawMJy10FZLZLawZzZEb` |
| `TPlayer_setDead_bool` | `0x17b7b8` | `0x17fb5c` | `_ZN10W6NzgawMJy10IOtYLapHuYEb` |
| `TPlayer_setEnabledFeatures_int` | `0x17b8a0` | `0x17fc44` | `_ZN10W6NzgawMJy10K2iswaYDqVEi` |

The existing `v18_TPlayer_setPaused_bool` row at source
`0x17b824..0x17b8a0` and target `0x17fbc8..0x17fc44` is an interstitial
boundary, not a duplicate anchor. Every new target is source plus `0x43a4`.
The six boolean pairs are 108 bytes with 26 instructions, while
`setEnabledFeatures` is 168 bytes with 41 instructions. All seven pairs have
identical complete normalized fingerprints. Hex-Rays shows the same lazy
allocation and encoded byte or integer write in both builds. The target storage
constants move with the changed class layout, so no global field-offset rule
is inferred from this region.

The next source method is `ObjectsYCompare_void_const_void_const` at
`0x17b948`. The next target method is its existing
`v18_ObjectsYCompare_void_const_void_const` alias at `0x17fcf0`. The target
functions now have `v18_` aliases in
`analysis/spectron_libqplay_translated_v160.i64`. All seven manual labels
reopened successfully. The full semantic map still reopens with 3,641
high-confidence labels and zero failures across 11,693 functions. The packed
database has 1,396 default `sub_` names and SHA-256
`bc4bfdf5b0b3f82dfc9e61802c6cafdaad535b8c876a77f1e6612def5d8fa9f8`.
The machine-readable record is
`artifacts/spectron_tplayer_flag_setter_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tplayer_flag_setter_anchors.py`.

## Spectron TPlayer scalar getter block

The v159 pass maps the contiguous 21-function getter block from the readable
1.8 `TPlayer` class to the obfuscated `W6NzgawMJy` class in Spectron 2.2.
It covers local coordinates, player statistics, inventory and combat values,
movement flags, and visibility state.

| 1.8 function | Source | Spectron target | Target symbol | Source storage | Target storage |
| --- | ---: | ---: | --- | ---: | ---: |
| `TPlayer_getlocalx_void` | `0x17afd8` | `0x17f37c` | `_ZNK10W6NzgawMJy10Qi2VgaCyrREv` | 1488 | 1512 |
| `TPlayer_getlocaly_void` | `0x17b020` | `0x17f3c4` | `_ZNK10W6NzgawMJy10qCgWga1ADREv` | 1504 | 1528 |
| `TPlayer_getHP_void` | `0x17b068` | `0x17f40c` | `_ZN10W6NzgawMJy10Lm1UgaOLAQEv` | 1120 | 1144 |
| `TPlayer_getMaxHP_void` | `0x17b0b0` | `0x17f454` | `_ZN10W6NzgawMJy10BwUDLa39aHEv` | 1136 | 1160 |
| `TPlayer_getGralats_void` | `0x17b100` | `0x17f4a4` | `_ZN10W6NzgawMJy10CPrDLa90NGEv` | 1152 | 1176 |
| `TPlayer_getBombsCount_void` | `0x17b150` | `0x17f4f4` | `_ZN10W6NzgawMJy10c8FDLaz3ZGEv` | 1168 | 1192 |
| `TPlayer_getArrows_void` | `0x17b1a0` | `0x17f544` | `_ZN10W6NzgawMJy10bzl1LagLK0Ev` | 1184 | 1208 |
| `TPlayer_getGlovePower_void` | `0x17b1f0` | `0x17f594` | `_ZN10W6NzgawMJy10m410Lagmu0Ev` | 1200 | 1224 |
| `TPlayer_getSwordPower_void` | `0x17b240` | `0x17f5e4` | `_ZN10W6NzgawMJy10BBd0Lag3N_Ev` | 1216 | 1240 |
| `TPlayer_getShieldPower_void` | `0x17b290` | `0x17f634` | `_ZN10W6NzgawMJy10mFbtwaoqaWEv` | 1232 | 1256 |
| `TPlayer_getAlignment_void` | `0x17b2e0` | `0x17f684` | `_ZN10W6NzgawMJy10DuT_Lapiw_Ev` | 1248 | 1272 |
| `TPlayer_getMagicPoints_void` | `0x17b330` | `0x17f6d4` | `_ZN10W6NzgawMJy10EYG_LaFLl_Ev` | 1264 | 1288 |
| `TPlayer_getCarrySprite_void` | `0x17b380` | `0x17f724` | `_ZN10W6NzgawMJy10Bp9swagx8VEv` | 1280 | 1304 |
| `TPlayer_getWeaponsEnabled_void` | `0x17b3d0` | `0x17f774` | `_ZN10W6NzgawMJy10sSM0LawJg0Ev` | 1296 | 1320 |
| `TPlayer_getDefaultMovement_void` | `0x17b3f8` | `0x17f79c` | `_ZN10W6NzgawMJy10_aK0La2se0Ev` | 1312 | 1336 |
| `TPlayer_getEnabledFeatures_void` | `0x17b420` | `0x17f7c4` | `_ZN10W6NzgawMJy10v3qmgaznunEv` | 1328 | 1352 |
| `TPlayer_getPaused_void` | `0x17b470` | `0x17f814` | `_ZN10W6NzgawMJy10YXBswaeyGVEv` | 1344 | 1368 |
| `TPlayer_getDead_void` | `0x17b498` | `0x17f83c` | `_ZN10W6NzgawMJy10pLeswaA1mVEv` | 1352 | 1376 |
| `TPlayer_getIsHurt_void` | `0x17b4c0` | `0x17f864` | `_ZN10W6NzgawMJy10d2dswarqmVEv` | 1360 | 1384 |
| `TPlayer_getHidden_void` | `0x17b4e8` | `0x17f88c` | `_ZN10W6NzgawMJy10GfKrwaWwXUEv` | 1376 | 1400 |
| `TPlayer_getSwordHidden_void` | `0x17b510` | `0x17f8b4` | `_ZN10W6NzgawMJy10ZORrwaAT2UEv` | 1408 | 1432 |

The address relocation is `+0x43a4` for every row. The first three getters
are 72 bytes with 18 instructions, the next ten four-byte getters are 80
bytes with 20 instructions, the two smaller movement getters are 40 bytes
with 10 instructions, and the final flag getters are also 40 bytes. All 21
pairs match the complete normalized feature set.

Hex-Rays shows the same guarded decode in both builds. The getter returns zero
when its encoded pointer is absent. Otherwise it XORs the stored value with a
per-object mask byte. The target storage pointer and mask offsets are source
plus 24 bytes for every row in this block. The next source function is the
`TPlayerProperties` constructor at `0x17b538`, while the next target function
is the `W6NzgawMJyProperties` destructor at `0x17f8dc`, providing an
independent class-boundary check.

The target functions now have `v18_` aliases in
`analysis/spectron_libqplay_translated_v159.i64`. All 21 manual labels
reopened successfully. The full semantic map still reopens with 3,641
high-confidence labels and zero failures across 11,693 functions. The packed
database has 1,396 default `sub_` names and SHA-256
`75cd77b15f4c27b4f73f7a39797f76459c42cb8d6abf3b75c3ba99fbddea914d`.
The machine-readable record is
`artifacts/spectron_tplayer_scalar_getter_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tplayer_scalar_getter_anchors.py`.

## Spectron TPlayer scalar setter block

The v158 pass maps a contiguous ten-function setter block from the readable
1.8 `TPlayer` class to the obfuscated `W6NzgawMJy` class in Spectron 2.2.
These are the scalar setters used for player inventory and combat state.

| 1.8 function | Source | Spectron target | Target symbol |
| --- | ---: | ---: | --- |
| `TPlayer_setGralats_int` | `0x16cec4` | `0x170ac4` | `_ZN10W6NzgawMJy10mLApwaxx8SEi` |
| `TPlayer_setAlignment_int` | `0x16cf6c` | `0x170b6c` | `_ZN10W6NzgawMJy10xjHpwa92dTEi` |
| `TPlayer_setSwordPower_int` | `0x16d038` | `0x170c38` | `_ZN10W6NzgawMJy10kCBtwaWfwWEi` |
| `TPlayer_setMagicPoints_int` | `0x16d104` | `0x170d04` | `_ZN10W6NzgawMJy10Bu_owanbESEi` |
| `TPlayer_setMaxHP_int` | `0x16d1d0` | `0x170dd0` | `_ZN10W6NzgawMJy10tA8owaoQLSEi` |
| `TPlayer_setShieldPower_int` | `0x16d29c` | `0x170e9c` | `_ZN10W6NzgawMJy10Cd4pwa59xTEi` |
| `TPlayer_setBombsCount_int` | `0x16d368` | `0x170f68` | `_ZN10W6NzgawMJy10CavpwaFQ3SEi` |
| `TPlayer_setArrows_int` | `0x16d434` | `0x171034` | `_ZN10W6NzgawMJy10KRDtwaS8xWEi` |
| `TPlayer_setGlovePower_int` | `0x16d500` | `0x171100` | `_ZN10W6NzgawMJy10uScpwasrPSEi` |
| `TPlayer_setCarrySprite_int` | `0x16d5cc` | `0x1711cc` | `_ZN10W6NzgawMJy10grzpwawq7SEi` |

The source and target blocks are aligned by class-local order and exact
normalized function shape. The target address is source plus `0x3c00` for all
ten rows. The first pair is 168 bytes and 41 instructions. The other nine
pairs are 204 bytes and 51 instructions. Every pair has the same basic-block,
branch, call, mnemonic, opcode, register, overall-shape, and string-reference
fingerprints in both builds.

The target is not a byte-for-byte copy of the source. Hex-Rays shows the same
encoded integer-buffer update and lazy allocation logic, while the target
uses relocated vtable positions and object-storage constants. Those constants
do not move by one uniform field delta across the ten setters, so the mapping
should be used as a block-level semantic translation rather than as a general
`TPlayer` layout formula. The following function is the already translated
`TPlayer_set_defaultwalkspeed` pair at `0x16d698` and `0x171298`, which gives a
second boundary check.

The target functions now have `v18_` aliases in
`analysis/spectron_libqplay_translated_v158.i64`. All ten manual labels
reopened successfully. The full semantic map still reopens with 3,641
high-confidence labels and zero failures. The packed database has 11,693
functions, 1,396 default `sub_` names, and SHA-256
`d779d88b82129c4502d0f6682449c519a698f7317b9e4b5be5af1de18d5a2444`.
The machine-readable record is
`artifacts/spectron_tplayer_scalar_setter_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tplayer_scalar_setter_anchors.py`.

## Spectron TServerPlayer scalar accessor block

The v157 pass translates the 37-function scalar accessor block at the front of
the server-player implementation. The source block runs from
`0x18a1a4..0x18a2c4`; the target block runs from `0x18e98c..0x18eaac` in the
obfuscated `MpGzgariDy` class.

| Area | Source fields | Spectron fields | Rows |
| --- | --- | --- | ---: |
| health and inventory | 680 through 700 | 704 through 724 | 10 |
| combat power and alignment | 704 through 716 | 728 through 740 | 8 |
| magic and carry state | 720 through 724 | 744 through 748 | 4 |
| movement and feature flags | 728 through 732 | 752 through 756 | 6 |
| paused, dead, hurt, hidden state | 736 through 740 | 760 through 764 | 9 |

The target address is source plus `0x47e8`, and every target field is source
plus 24. All 37 pairs match size, instruction count, basic blocks, branches,
calls, mnemonic shape, opcode shape, register shape, overall shape, and
string-reference hash. The alternating getter and setter order is preserved,
and the next function after each block is a different class boundary.

The source getters and setters are already readable, while Spectron retains
only obfuscated C++ method names such as `_ZN10MpGzgariDy10Lm1UgaOLAQEv`.
Their exact shape, class-local sequence, and field-offset relationship are
stronger evidence than the name text alone. This is a layout-aware mapping,
not a claim that the player object has an unchanged binary layout.

The labels are persisted in
`analysis/spectron_libqplay_translated_v157.i64`. All 37 names reopened with
zero failures. The v157 database has 11,693 functions and 1,396 default
`sub_` names. The machine-readable record is
`artifacts/spectron_tserverplayer_accessor_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tserverplayer_accessor_anchors.py`.

## Spectron CyaInt TLS residual anchors, batch two

The v156 pass finishes the remaining CyaInt rows with 53 additional exact
anchors. The full source-to-target address table is kept in the research notes
and machine-readable artifact. The groups are:

| Group | Source range | Spectron range | Rows |
| --- | --- | --- | ---: |
| runtime and RSA | `0x2b8bb0..0x2c0404` | `0x2c6140..0x2cd994` | 4 |
| TLS I/O and object state | `0x2c386c..0x2c3f3c` | `0x2d0dfc..0x2d14cc` | 21 |
| verification and DTLS | `0x2c5380..0x2c5588` | `0x2d2910..0x2d2b18` | 8 |
| timeout and compression | `0x2c5950..0x2c5e4c` | `0x2d2ee0..0x2d33dc` | 4 |
| X.509 and OCSP | `0x2c61d4..0x2c650c` | `0x2d3764..0x2d3a9c` | 9 |
| protocol methods and timer | `0x2c706c..0x2c906c` | `0x2d45fc..0x2d65fc` | 5 |
| mutex wrappers | `0x2ccbc4..0x2ccccc` | `0x2da154..0x2da25c` | 4 |

Every row uses source plus `0xd590` for the target address and matches size,
instruction count, basic blocks, branches, calls, mnemonic shape, opcode
shape, register shape, overall shape, and string-reference hash. The target
names are retained C++ manglings that still expose the CyaInt method names,
which makes this a useful class-local cross-check rather than an address-only
guess.

The second batch includes the most relevant decision points for the old
connection problem. `RsaSSL_Verify` preserves the source copy, inline verify,
output-size check, zeroing, and free sequence. `CyaSSL_SetIORecv` and
`CyaSSL_SetIOSend` store the same callback pointers. `CyaSSL_CTX_set_verify`
and `CyaSSL_set_verify` preserve the same verification flags and callback
fields. The TLS 1.2 client-method constructor still calls the matching
protocol selector and SSL-method initializer. The remaining rows cover the
supporting X.509, OCSP, timeout, and mutex surfaces.

Static correspondence does not mean that certificate verification is bypassed
or that a live service will accept the old client. The aliases give us stable
IDA names for the next controlled trust and handshake experiments, while
leaving the original behavior unchanged.

The labels are persisted in
`analysis/spectron_libqplay_translated_v156.i64`. All 53 names reopened with
zero failures. The v156 database has 11,693 functions and 1,396 default
`sub_` names. The machine-readable record is
`artifacts/spectron_cyaint_tls_residual_v2_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_cyaint_tls_residual_v2_anchors.py`.

## Spectron CyaInt TLS residual anchors

The v155 comparison pass translates 30 residual methods in the native CyaInt
TLS and cryptography block. This is one of the most useful remaining groups
for the connection investigation because it covers trust-path loading,
certificate buffers, session state, protocol selection, and the final
master-secret derivation. Every row has an exact match across the complete
normalized feature set used here. The target address is source plus `0xd590`
for every row.

| 1.8 method | Source | Spectron target | Role |
| --- | ---: | ---: | --- |
| `CyaInt_mp_dr_setup_CyaInt_mp_int_uint` | `0x2bb418` | `0x2c89a8` | Montgomery setup |
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
| `CyaInt_MakeTLSv1_void` | `0x2c703c` | `0x2d45cc` | TLS 1.0 |
| `CyaInt_MakeTLSv1_1_void` | `0x2c7054` | `0x2d45e4` | TLS 1.1 |
| `CyaInt_c32to24_uint_uchar` | `0x2c8c84` | `0x2d6214` | 24-bit encoding |
| `CyaInt_InitSSL_Method_CyaInt_CYASSL_METHOD_CyaInt_ProtocolVersion` | `0x2c8c9c` | `0x2d622c` | SSL method setup |
| `CyaInt_InitCiphers_CyaInt_CYASSL` | `0x2c8d14` | `0x2d62a4` | cipher reset |
| `CyaInt_MakeSSLv3_void` | `0x2c9064` | `0x2d65f4` | SSL 3.0 |
| `CyaInt_SetErrorString_int_char` | `0x2cbe18` | `0x2d93a8` | error text setter |
| `CyaInt_MakeMasterSecret_CyaInt_CYASSL` | `0x2cdad0` | `0x2db060` | master secret |

The target functions retain C++ mangled names whose text still exposes the
`CyaInt` class and method names. Direct pseudocode spot checks agree as well:
the nonblocking setter writes the same CyaSSL byte, the verification-path and
certificate-buffer wrappers call the same processing helpers, protocol
selectors return the same values, `InitCiphers` resets the same fields, and
`MakeMasterSecret` keeps the same hash, key-derivation, and cleanup sequence.
The target pseudocode omits the source PLT prefixes, which is a naming and
linkage difference rather than a behavioral change.

This pass identifies the trust and TLS code but does not claim a live
certificate result or disable pinning. It gives the IDA database a readable
`v18_` name for each method and provides exact addresses for any later
controlled comparison of trust-store setup, date validation, or handshake
failure handling.

The labels are persisted in
`analysis/spectron_libqplay_translated_v155.i64`. All 30 names reopened with
zero failures. The v155 database has 11,693 functions and 1,396 default
`sub_` names. The machine-readable record is
`artifacts/spectron_cyaint_tls_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_cyaint_tls_residual_anchors.py`.

## Spectron GSFunctionsClient exact residual anchors, batch four

The v154 pass closes the remaining `GSFunctionsClient` table rows that already
had separate target function records. The target fields below are the source
fields plus `0x13010`, and the table qwords contain the target addresses.

| 1.8 role | Source field | Spectron target | Target field | Match |
| --- | ---: | ---: | ---: | --- |
| `adventure_getwindowlist` | `0x378cd0` | `0x1592c8` | `0x38bce0` | exact shape |
| `adventure_reconnect` | `0x378eb0` | `0x1592d0` | `0x38bec0` | exact shape |
| `adventure_setgraalcontrolrecreate` | `0x378f40` | `0x1592e4` | `0x38bf50` | exact shape |
| `adventure_openexternalpm` | `0x378f70` | `0x1592f4` | `0x38bf80` | exact shape |
| `adventure_openexternaloptions` | `0x379000` | `0x1592fc` | `0x38c010` | exact shape |
| `script_isfullscreenmode` | `0x379030` | `0x159304` | `0x38c040` | exact shape |
| `adventure_setfullscreen` | `0x379060` | `0x159348` | `0x38c070` | exact shape |
| `script_isofflinemode` | `0x379210` | `0x15937c` | `0x38c220` | exact shape |
| `get_isapplicationactive` | `0x378488` | `0x159688` | `0x38b498` | exact shape |
| `script_openurl` | `0x379cc0` | `0x159adc` | `0x38ccd0` | exact shape |
| `script_openurl2` | `0x379cf0` | `0x159b18` | `0x38cd00` | exact shape |

These rows cover the final early client-table cluster: Adventure window and
mode helpers, fullscreen state, application activity, and URL dispatch. The
target functions retain their distinct boundaries and all eleven normalized
shape checks match. The target names were default `sub_` labels, so this batch
reduces the default-name count by 11.

The resulting `v18_` labels are persisted in
`analysis/spectron_libqplay_translated_v154.i64`. The copy has 11,693
functions, 1,396 default `sub_` functions, and SHA-256
`5464d8379812980ccd785837e6000adf82d9a965ccac563faed78ca43ac90c06`. The
machine-readable record is
`artifacts/spectron_gsfunctions_client_exact_residual_v4_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v4_anchors.py`.

## Spectron GSFunctionsClient boundary residual anchors

The v153 pass materializes 12 target callbacks that were present in the
relocated client table but missing as standalone IDA functions. The ranges are
based on a raw ARM64 control-flow walk. Every conditional path and explicit
return was checked, and the adjacent table record was retained as a separate
structural check.

| 1.8 role | Source field | Spectron target | Target range | Boundary evidence |
| --- | ---: | ---: | --- | --- |
| `get_focusy` | `0x378518` | `0x1598a0` | `0x1598a0..0x159904` | two cleanup returns |
| `get_isfocused` | `0x378548` | `0x159910` | `0x159910..0x15993c` | guarded and zero returns |
| `get_ghostsnear` | `0x378578` | `0x159948` | `0x159948..0x159968` | byte and zero returns |
| `get_iscarrying` | `0x378638` | `0x159a28` | `0x159a28..0x159a48` | byte and zero returns |
| `get_screenpixelscale` | `0x3789f8` | `0x159bd8` | `0x159bd8..0x159be0` | constant return |
| `get_mousey` | `0x378908` | `0x15a2a8` | `0x15a2a8..0x15a2c4` | tail call and zero return |
| `get_mousex` | `0x3788d8` | `0x15a428` | `0x15a428..0x15a444` | tail call and zero return |
| `script_worldy` | `0x37a4d0` | `0x15aa58` | `0x15aa58..0x15aae8` | coordinate conversion return |
| `script_worldx` | `0x37a4a0` | `0x15aaf0` | `0x15aaf0..0x15ab40` | coordinate conversion return |
| `adventure_uploadfile` | `0x37a470` | `0x15ab48` | `0x15ab48..0x15ab64` | guarded dispatch and return |
| `script_screenx` | `0x379ed0` | `0x15b8d0` | `0x15b8d0..0x15b950` | two conversion returns |
| `script_freezeplayer` | `0x379690` | `0x15d340` | `0x15d340..0x15d3f4` | clamp, update, and cleanup |

The table fields relocate by `+0x13010` and point to the target starts. The
raw ranges then account for the cases where IDA had no function record. The
world-coordinate and screen callbacks include tail branches into obfuscated
helpers, while the small state callbacks have ordinary local return blocks.
The 12 rows contain 17 explicit `RET` instructions. Their target names were
`loc_` labels rather than default `sub_` names, so the function count rises to
11,693 while the renamed database retains 1,407 default `sub_` functions.

The labels and reviewed ends are persisted in
`analysis/spectron_libqplay_translated_v153.i64`, SHA-256
`3c52ae8040e920dcf81c6a8ed5a5a9610d715bfbb56938bd2a40cb67ea8d35b9`. The
machine-readable record is
`artifacts/spectron_gsfunctions_client_boundary_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_boundary_residual_anchors.py`.
All 12 names and boundaries reopened successfully. This is static evidence
about the 2.2 callback layout, not runtime proof of server compatibility.

## Spectron GSFunctionsClient exact residual anchors, batch three

The v152 pass closes the nine remaining `GSFunctionsClient` rows whose target
code was already a separate IDA function. The other client residuals are
being kept in review-only form until their merged target ranges are split.

| 1.8 role | Source field | Spectron target | Target field | Match |
| --- | ---: | ---: | ---: | --- |
| `adventure_geteditnickname` | `0x378d00` | `0x15cb88` | `0x38bd10` | exact shape |
| `get_levelorgx` | `0x3786c8` | `0x15cd4c` | `0x38b6d8` | exact shape |
| `get_levelorgy` | `0x3786f8` | `0x15cdac` | `0x38b708` | exact shape |
| `get_screenheight` | `0x3789c8` | `0x15cee0` | `0x38b9d8` | exact shape |
| `get_screenwidth` | `0x378998` | `0x15cf14` | `0x38b9a8` | exact shape |
| `get_rightmousebutton` | `0x378878` | `0x15cf48` | `0x38b888` | exact shape |
| `get_leftmousebutton` | `0x3787b8` | `0x15cf90` | `0x38b7c8` | exact shape |
| `script_savelog` | `0x379e40` | `0x15cfd8` | `0x38ce50` | exact shape |
| `script_sendrpgmessage` | `0x379f60` | `0x15da2c` | `0x38cf70` | exact shape |

The table relocation and the exact normalized code shapes agree for all nine
rows. The target names were default `sub_` labels, and all nine target code
addresses already had independent function boundaries. The RPG message and
log rows both retain the small `echo` bridge, while the coordinate and mouse
rows preserve their original field-access logic.

The resulting `v18_` labels are persisted in
`analysis/spectron_libqplay_translated_v152.i64`. The copy has 11,681
functions, 1,407 default `sub_` functions, and SHA-256
`275a6c98896248bfd99b1cdae7e7344bee3ef67d468c75749ed13293ea9e102f`. The
machine-readable record is
`artifacts/spectron_gsfunctions_client_exact_residual_v3_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v3_anchors.py`.

## Spectron GSFunctionsClient exact residual anchors, batch two

The v151 pass adds a second group of 20 client callbacks. These rows continue
the same table-based translation rule used by v150. Each Spectron callback
pointer field is the 1.8 field plus `0x13010`, and each target field was read
back as the target code address.

| 1.8 role | Source field | Spectron target | Target field | Match |
| --- | ---: | ---: | ---: | --- |
| `script_setshootparams` | `0x37a200` | `0x159e58` | `0x38d210` | exact shape |
| `get_statusimage` | `0x378b18` | `0x159e94` | `0x38bb28` | exact shape |
| `get_spritesimage` | `0x378ae8` | `0x159ecc` | `0x38baf8` | exact shape |
| `adventure_getinstallationpath` | `0x378d60` | `0x159f04` | `0x38bd70` | exact shape |
| `set_selectedweapon` | `0x378ac0` | `0x159f38` | `0x38bad0` | exact shape |
| `set_selectedsword` | `0x378a90` | `0x159f9c` | `0x38baa0` | exact shape |
| `get_rightmousebuttonglobal` | `0x378848` | `0x15a478` | `0x38b858` | exact shape |
| `get_leftmousebuttonglobal` | `0x378788` | `0x15a498` | `0x38b798` | exact shape |
| `adventure_geteditaccountnames` | `0x378d30` | `0x15a570` | `0x38bd40` | exact shape |
| `script_setsword` | `0x37a290` | `0x15b208` | `0x38d2a0` | exact shape |
| `script_setshield` | `0x37a140` | `0x15b65c` | `0x38d150` | exact shape |
| `script_sendtorc` | `0x379f30` | `0x15b828` | `0x38cf40` | exact shape |
| `script_opengraalurl` | `0x379d20` | `0x15bb2c` | `0x38cd30` | exact shape |
| `script_keyname2` | `0x379a80` | `0x15be30` | `0x38ca90` | exact shape |
| `script_keyname` | `0x379a50` | `0x15be50` | `0x38ca60` | exact shape |
| `script_freefileresources` | `0x379660` | `0x15c4f8` | `0x38c670` | exact shape |
| `adventure_requestfilesmove` | `0x3791e0` | `0x15c830` | `0x38c1f0` | exact shape |
| `adventure_requestfilerename` | `0x3791b0` | `0x15c854` | `0x38c1c0` | exact shape |
| `adventure_requestfolderdeletion` | `0x379180` | `0x15c878` | `0x38c190` | exact shape |
| `adventure_requestfiledeletion` | `0x379150` | `0x15c894` | `0x38c160` | exact shape |

The rows cover three different kinds of client behavior. The first group
bridges script arguments into shooting, image, weapon, and mouse state. The
middle group handles URL and keyboard-name helpers. The final group handles
file-resource cleanup and Adventure file operations. The function sizes and
control flow remain exact across the builds even though the target names are
default `sub_` labels.

The resulting `v18_` labels are persisted in
`analysis/spectron_libqplay_translated_v151.i64`. The copy has 11,681
functions, 1,416 default `sub_` functions, and SHA-256
`853866783a4c652caf5dd594a47c70c398a9bbace25574eb95842bd108068229`. The
machine-readable record is
`artifacts/spectron_gsfunctions_client_exact_residual_v2_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_v2_anchors.py`.
The result is static cross-build evidence and does not change the separate
runtime conclusion about stale certificate material.

## Spectron GSFunctionsClient exact residual anchors

The v150 pass translated 20 residual client callbacks from the static
GSFunctionsClient tables. This is the first batch from the wider 72-row
client residual audit. The callback pointer fields provide a direct table
correspondence: every target field is exactly `0x13010` bytes after its source
field, and the target field contains the target code address.

| 1.8 role | Source field | Spectron target | Target field | Match |
| --- | ---: | ---: | ---: | --- |
| `get_allfeatures` | `0x3782a8` | `0x1593bc` | `0x38b2b8` | exact shape |
| `get_allrenderobjecttypes` | `0x3782d8` | `0x1593c4` | `0x38b2e8` | exact shape |
| `get_allstats` | `0x378308` | `0x1593cc` | `0x38b318` | exact shape |
| `get_carriesnpc` | `0x378368` | `0x15940c` | `0x38b378` | exact shape |
| `get_graalversion` | `0x3785a8` | `0x159968` | `0x38b5b8` | exact shape |
| `get_isopengl` | `0x3785d8` | `0x159978` | `0x38b5e8` | exact shape |
| `get_gravity` | `0x378608` | `0x159980` | `0x38b618` | exact shape |
| `set_gravity` | `0x378610` | `0x159990` | `0x38b620` | exact shape |
| `get_isonmap` | `0x378698` | `0x159a70` | `0x38b6a8` | exact shape |
| `get_middlemousebuttonglobal` | `0x3787e8` | `0x159a98` | `0x38b7f8` | exact shape |
| `get_mousewheeldelta` | `0x3788a8` | `0x159aa8` | `0x38b8b8` | exact shape |
| `get_scriptedcontrols` | `0x378a28` | `0x159be0` | `0x38ba38` | exact shape |
| `get_scriptedplayerlist` | `0x378a58` | `0x159bf0` | `0x38ba68` | exact shape |
| `get_selectedsword` | `0x378a88` | `0x159bf8` | `0x38ba98` | exact shape |
| `get_selectedweapon` | `0x378ab8` | `0x159c18` | `0x38bac8` | exact shape |
| `get_weapons` | `0x378bd8` | `0x159d68` | `0x38bbe8` | exact shape |
| `get_weaponsenabled` | `0x378c08` | `0x159d88` | `0x38bc18` | exact shape |
| `set_weaponsenabled` | `0x378c10` | `0x159dcc` | `0x38bc20` | exact shape |
| `set_statusimage` | `0x378b20` | `0x159e30` | `0x38bb30` | exact shape |
| `set_spritesimage` | `0x378af0` | `0x159e44` | `0x38bb00` | exact shape |

The source names identify the script-facing roles, while the target table
contents identify their moved implementations. The target names were all
default `sub_` labels before this batch. The exact normalized comparison also
matches size, instruction count, basic blocks, branches, calls, mnemonic
shape, opcode shape, register shape, and overall shape for every row. Because
all target entries were already separate IDA functions, no new boundaries had
to be guessed here.

The resulting `v18_` labels are persisted in
`analysis/spectron_libqplay_translated_v150.i64`. The copy has 11,681
functions, 1,436 default `sub_` functions, and SHA-256
`da6942a1bd21c3d56b602f33106803736391e6e6e4224de9108f96e674cb0cf6`. The
machine-readable record is
`artifacts/spectron_gsfunctions_client_exact_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gsfunctions_client_exact_residual_anchors.py`.
This batch is static evidence only. It does not imply that the 2.2 client can
authenticate to a current service or that any of these callbacks is involved
in the stale connector certificate path.

## Spectron GSFunctions randomstring residual anchor

The v149 pass translated the remaining `randomstring` callback using the
static script-table sequence. The target keeps the same slot after `strequals`
and retains the source list-selection behavior.

| 1.8 role | Source | Spectron target | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `randomstring` | `0x20cd34` | `sub_2130C4` | `0x2130c4` | trailing comma, list selection, and cleanup |

The source code pointer is referenced from `0x3872c0`; the corresponding
target table pointer is at `0x39a3e0`. Both routines remove an optional
trailing comma, construct a temporary string list, select an entry with
`rand` modulo the list count, append the result, and release the list. The
target grows from 260 to 264 bytes and from 65 to 66 instructions, while
keeping 9 basic blocks, 17 branches, 12 calls, and one return.

The label is recorded as `v18_` in
`analysis/spectron_libqplay_translated_v149.i64`. Evidence is stored in
`artifacts/spectron_gsfunctions_randomstring_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gsfunctions_randomstring_residual_anchors.py`.

## Spectron GSFunctions callback-table residual anchors

The v147 pass translated 13 remaining GSFunctions callbacks by combining the
source and target script-table order with function-shape comparison. The
target table retains the same sequence around already translated landmarks,
which makes the five larger matches high-confidence even though their helper
calls and layouts changed.

| 1.8 role | Source | Spectron target | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `getstringkeys` | `0x20afd8` | `sub_2111D8` | `0x2111d8` | table pointer and cleanup boundary |
| `callnpc` | `0x20b268` | `sub_211908` | `0x211908` | action-NPC and universe dispatch |
| `getmapx` | `0x20b404` | `sub_211580` | `0x211580` | level-position lookup |
| `getmapy` | `0x20b460` | `sub_2114B0` | `0x2114b0` | level-position lookup |
| `getimgwidth` | `0x20b4f8` | `sub_211610` | `0x211610` | exact normalized shape |
| `getimgheight` | `0x20b53c` | `sub_211654` | `0x211654` | exact normalized shape |
| `clearemptyglobalvars` | `0x20b7d8` | `sub_2118F0` | `0x2118f0` | exact normalized shape |
| `arcsin` | `0x20b7f0` | `sub_211AD4` | `0x211ad4` | exact normalized shape |
| `arccos` | `0x20b818` | `sub_211AFC` | `0x211afc` | exact normalized shape |
| `aindexof` | `0x20b840` | `sub_211B24` | `0x211b24` | exact normalized shape |
| `echo` | `0x20b858` | `sub_211B3C` | `0x211b3c` | exact normalized shape and `echo` literal |
| `trace` | `0x20bc48` | `sub_211F2C` | `0x211f2c` | exact normalized shape and `echo` literal |
| `findpathinarray` | `0x20bf6c` | `sub_21224C` | `0x21224c` | profiler path-array builder |

The target `getstringkeys` code pointer is stored at `0x39a290`. Its body
begins at `0x2111d8`, reaches its main `RET` at `0x2113ac`, and uses cleanup
branches through `0x211420`. The next script callback starts at `0x211424`,
so the target function range is `0x2111d8..0x211424`. This range was
materialized before the alias was applied.

Eight pairs have identical normalized size, instruction count, basic-block
count, branch count, call count, mnemonic hash, opcode shape, register shape,
and overall shape. The five layout-change rows are `getstringkeys`, `callnpc`,
`getmapx`, `getmapy`, and `findpathinarray`. The target `getstringkeys` body
grows from 516 to 588 bytes, `callnpc` from 412 to 460, `getmapx` from 92 to
144, `getmapy` from 140 to 196, and `findpathinarray` from 2,348 to 2,524.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v148.i64`. The machine-readable
evidence is in
`artifacts/spectron_gsfunctions_callback_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_gsfunctions_callback_residual_anchors.py`.

## Spectron GSFunctions math and string residual anchors

The v146 pass translated six callbacks from the GSFunctions script table.

| 1.8 role | Source | Spectron target | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| `degtorad` | `0x20abc8` | `sub_210DC8` | `0x210dc8` | pi divided by 180 |
| `radtodeg` | `0x20abf0` | `sub_210DF0` | `0x210df0` | 180 divided by pi |
| static string clearer | `0x20adbc` | `sub_210FBC` | `0x210fbc` | global `TString` cleanup |
| compare-ignore-case jump | `0x20adcc` | `j_._ZNK10C8THgaTQxF10nVCrgaSlRrERKS_` | `0x210fcc` | target comparison thunk |
| `uppercase` | `0x20add0` | `sub_210FD0` | `0x210fd0` | target `upper` method |
| `lowercase` | `0x20adf0` | `sub_210FF0` | `0x210ff0` | target `lower` method |

All six pairs have identical normalized metrics and hashes. The Spectron
script table points `radtodeg` to `0x210df0`, but IDA initially saw only a
code pointer there. The raw six-instruction body ends with `RET` at
`0x210e04`, so the pass materialized the explicit range through `0x210e08`
before applying the alias. Five default target names were replaced.

Evidence is stored in
`artifacts/spectron_gsfunctions_math_string_residual_manual_translation_anchors_20260826.json`.

## Spectron TUpdatePackageProperties residual anchors

The v145 pass translated the complete package-properties lifecycle family.

| 1.8 role | Source | Spectron target | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| uninstall jump thunk | `0x20aab8` | `j_._ZN10RH6ygazf9x10TrDxob8NUfEv` | `0x210cb4` | forwards to uninstall |
| complete destructor | `0x20aabc` | `_ZN20RH6ygazf9xPropertiesD2Ev` | `0x210cb8` | vtable and base cleanup |
| complete destructor thunk | `0x20aad8` | `_ZThn16_N20RH6ygazf9xPropertiesD1Ev` | `0x210cd4` | 16-byte adjustment |
| deleting destructor | `0x20aae0` | `_ZN20RH6ygazf9xPropertiesD0Ev` | `0x210cdc` | cleanup plus delete |
| deleting destructor thunk | `0x20ab18` | `_ZThn16_N20RH6ygazf9xPropertiesD0Ev` | `0x210d14` | 16-byte adjustment |

The source labels are constructor-like because IDA retained the class stem,
but the alternative D2 and D0 names and the vtable, base-cleanup, and delete
sequence establish the destructor roles. All five pairs have identical
normalized metrics and hashes. The target names were already non-default.

Evidence is stored in
`artifacts/spectron_update_package_properties_residual_manual_translation_anchors_20260826.json`.

## Spectron update-package event and lookup residual anchors

The v144 pass translated six remaining package-state helpers.

| 1.8 role | Source | Spectron target | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| failed-package event | `0x209260` | `_Z10PPxXSam4HQRK10C8THgaTQxF` | `0x20f3f8` | `.gupd` check and event |
| downloading-package lookup | `0x209310` | `_Z10e3y_Sao6eTRK10C8THgaTQxF` | `0x20f4e4` | nested package-file scan |
| privileged-package lookup | `0x209414` | `_Z10k1gxobOWBfRK10C8THgaTQxF` | `0x20f5e8` | nested package-file scan |
| no-force update wrapper | `0x20993c` | `sub_20FB10` | `0x20fb10` | constant false |
| force update wrapper | `0x209944` | `sub_20FB18` | `0x20fb18` | constant true |
| downloaded-package event | `0x20a798` | `_Z10by20SakLuURK10C8THgaTQxF` | `0x210958` | load, `.gupd` check, event |

The two containment lookups preserve lowercasing, list traversal, nested file
iteration, normalized comparison, and temporary-string cleanup. The force
wrappers preserve their boolean constants. The event wrappers grow in
Spectron because the target rebuilds temporary strings and event calls
through additional wrappers, but their `.gupd` and `onPackagesDownloaded`
behavior remains visible.

Four pairs have exact normalized shapes and two are documented layout-change
pairs. The force wrappers were the only default target entries, so this batch
removes two default `sub_` names. Evidence is stored in
`artifacts/spectron_update_package_wrapper_residual_manual_translation_anchors_20260826.json`.

## Spectron TUpdatePackage deleting-destructor residual anchor

The v143 pass closed the one remaining lifecycle row after the accessor
block. The source label looks constructor-like, but its body forwards to the
constructor entry and then deletes the object, making it a deleting
destructor.

| 1.8 role | Source | Spectron target | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| deleting destructor | `0x208eb4` | `_ZN10RH6ygazf9xD0Ev` | `0x20f04c` | cleanup plus `operator delete` |

The pair has identical normalized metrics and hashes: 32 bytes, 8
instructions, 2 basic blocks, 2 branches, and 1 call. The complete
constructor or destructor at `0x20ef60` was already translated, so this row
is recorded separately. The target name was already non-default, and the
label reopened successfully in the v143 copy.

Evidence is stored in
`artifacts/spectron_update_package_destructor_residual_manual_translation_anchors_20260826.json`.

## Spectron TClient and TUpdatePackage accessor residual anchors

The v142 pass translated the ordered accessor block from the client base
package through the update-package description field.

| 1.8 role | Source | Spectron target | Target | Evidence |
| --- | ---: | --- | ---: | --- |
| base-package pointer | `0x208a70` | `sub_20EC08` | `0x20ec08` | global pointer read |
| download-list count | `0x208a80` | `sub_20EC18` | `0x20ec18` | list count read |
| completion byte | `0x208a94` | `sub_20EC2C` | `0x20ec2c` | field +248 |
| downloaded bytes | `0x208a9c` | `sub_20EC34` | `0x20ec34` | field +228 |
| file-list count | `0x208aa4` | `sub_20EC3C` | `0x20ec3c` | nested count at +200 |
| dword field | `0x208ab0` | `sub_20EC48` | `0x20ec48` | field +236 |
| dword field | `0x208ab8` | `sub_20EC50` | `0x20ec50` | field +232 |
| byte field | `0x208ac0` | `sub_20EC58` | `0x20ec58` | field +249 |
| double field | `0x208ac8` | `sub_20EC60` | `0x20ec60` | field +216 |
| qword field | `0x208ad0` | `sub_20EC68` | `0x20ec68` | field +128 |
| protect-overwrite flag | `0x208ad8` | `sub_20EC70` | `0x20ec70` | `PROTECTOVERWRITE` |
| total bytes | `0x208ae0` | `sub_20EC78` | `0x20ec78` | field +224 |
| checksum flag | `0x208ae8` | `sub_20EC80` | `0x20ec80` | `USECHECKSUM` |
| version value | `0x208af0` | `sub_20EC88` | `0x20ec88` | `VERSION` |
| platform string | `0x208af8` | `sub_20EC90` | `0x20ec90` | `TString` copy |
| package name | `0x208b28` | `sub_20ECC0` | `0x20ecc0` | `TString` copy |
| package mode | `0x208b58` | `sub_20ECF0` | `0x20ecf0` | `TString` copy |
| auxiliary string | `0x208b88` | `sub_20ED20` | `0x20ed20` | field +240 |
| package filename | `0x208bb8` | `sub_20ED50` | `0x20ed50` | `TString` copy |
| description string | `0x208be8` | `sub_20ED80` | `0x20ed80` | `TString` copy |

All twenty pairs have identical normalized metrics and hashes. The target
functions were default `sub_` entries, so these aliases remove twenty
default names. The six string getters retain the same output initialization
and embedded-field assignment through `C8THgaTQxF::operator=`. The field
names that remain offset-based are intentionally conservative.

Evidence is stored in
`artifacts/spectron_update_package_accessor_residual_manual_translation_anchors_20260826.json`.

## Spectron client-thread residual anchors

The v141 pass translated seven client-thread helpers that were still unnamed
in the combined record.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| socket lock | `0x208344` | `_Z10E3UikbICwHv` | `0x20e4e0` | same pthread mutex |
| socket unlock | `0x208350` | `_Z10Tqmikbou3Gv` | `0x20e4ec` | same pthread mutex |
| incoming reader | `0x20835c` | `_Z10LK7hkb_7RGv` | `0x20e4f8` | lock, read, unlock |
| incoming queue clear | `0x208478` | `_Z10d5ahkbYW3Fv` | `0x20e614` | package cleanup loop |
| outgoing queue clear | `0x20858c` | `_Z10A0fhkbd57Fv` | `0x20e728` | package cleanup loop |
| thread disable guard | `0x2087a0` | `_Z10wlXykbJx0Uv` | `0x20e93c` | running flag and destroy |
| outgoing sender | `0x2088f8` | `_Z10aC0C_aG7qiv` | `0x20ea94` | lock, send, unlock |

All seven pairs have identical normalized metrics and hashes. The two queue
clear helpers preserve the package-pointer walk, embedded `TString` cleanup,
deallocation, list clear, and mutex release. The target class and list names
are obfuscated, but their call sequence is the same as the source. All target
names were already non-default, so this batch leaves the default `sub_` count
unchanged.

Evidence is stored in
`artifacts/spectron_client_thread_residual_manual_translation_anchors_20260826.json`.

## Spectron TPlayerList residual anchors

The v140 pass translated the last uncovered player-list support rows before
the client-socket helpers.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| staff-guild setter | `0x2081e4` | `_ZN10y3t2LaCUH110UpiB7az6Z_ERK10C8THgaTQxF` | `0x20e380` | comma-text list update |
| player-list initializer | `0x208310` | `_Z10LG6O2aDeCZv` | `0x20e4ac` | allocate, construct, publish |
| static-script initializer | `0x208340` | `_Z10ZdoB2ay_3Nv` | `0x20e4dc` | empty initializer |

The setter preserves the source staff-guild list role through the target
`vuuHgangcF` helper. The static initializer follows the same allocate,
construct, and global-publish sequence, but the target object is 0x20 bytes
instead of the source 0x18-byte `TStringList`, so it is classified as a layout
change. The empty static-script initializer has an exact normalized shape.
All three target names were already non-default. The labels reopened
successfully in the v140 copy, and the next target function at `0x20e4e0` is
kept as the client-socket lock boundary.

Evidence is stored in
`artifacts/spectron_player_list_residual_manual_translation_anchors_20260826.json`.

## Spectron URL-cache support residual anchors

The v139 pass translated the remaining URL-cache insertion, loading, and
cache-entry cleanup rows.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| URL cache insertion | `0x207d24` | `_ZN10uK2SHaPVVw10btKSHa7HFwERK10C8THgaTQxFS2_` | `0x20de90` | `.code` filter and save scheduling |
| URL cache initializer | `0x207ebc` | `_Z10IMaXHaJGoAv` | `0x20e054` | hash-list publication |
| URL cache load | `0x207eec` | `_ZN10uK2SHaPVVw4loadEv` | `0x20e084` | `URLCACHE.txt` parsing |
| cache-entry destructor | `0x20815c` | `_ZN10uK2SHaPVVw10S5XSHaIaRwD2Ev` | `0x20e2f8` | string and vtable cleanup |
| cache-entry deleting destructor | `0x20819c` | `_ZN10uK2SHaPVVw10S5XSHaIaRwD0Ev` | `0x20e338` | cleanup plus delete |

The initializer and both destructor pairs are exact normalized-shape matches.
`addURL` and `load` are modest wrapper-growth changes that preserve the
source cache behavior, including `.code` exclusion, hashed entry lookup,
`URLCACHE.txt`, and save scheduling. All five labels reopened successfully
in the v139 disposable copy. Evidence is stored in
`artifacts/spectron_url_cache_residual_manual_translation_anchors_20260826.json`.

## Spectron socket-cache support residual anchors

The v138 pass translated five support functions after `GetOwnIP`: static
initialization, allowed-host and port matching, and the two cached-host
destructors.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| socket static initializer | `0x207968` | `_Z10OYaS2aPQb1v` | `0x20dab4` | cached-host and global setup |
| script static initializer | `0x207998` | `_Z10TO_L1aAs_5v` | `0x20db00` | property registration |
| host and port predicate | `0x2079ac` | `_Z10mNHZ0adswrRK10C8THgaTQxFS1_i` | `0x20db14` | wildcard and range checks |
| cached-host destructor | `0x207c54` | `_ZN10reub2aL2gsD1Ev` | `0x20ddc0` | vtable and string cleanup |
| cached-host deleting destructor | `0x207c68` | `_ZN10reub2aL2gsD0Ev` | `0x20ddd4` | cleanup plus delete |

The target combines an additional global construction with the socket static
initializer. Its script initializer also uses a four-entry table where the
source uses two. `IsHostAndPortInList` keeps the source wildcard, host
pattern, single-port, and inclusive-range behavior. The two cached-host
destructors are exact normalized-shape matches.

All five labels reopened successfully in the v138 disposable copy, and the
full translation check still reports zero failures across 11,679 functions.
Evidence is stored in
`artifacts/spectron_socket_cache_residual_manual_translation_anchors_20260826.json`.

## Spectron TSocketProperties destructor residual anchors

The v137 pass translated the complete `TSocketProperties` destructor family.
The source constructor-like IDA labels are destructors in the underlying
symbols, with the complete and deleting pairs each followed by a 16-byte
non-virtual thunk.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| complete destructor | `0x205e94` | `_ZN20XJLBgarMnAPropertiesD1Ev` | `0x20bfa0` | vtable and base cleanup |
| complete destructor thunk | `0x205eb0` | `_ZThn16_N20XJLBgarMnAPropertiesD1Ev` | `0x20bfbc` | 16-byte this adjustment |
| deleting destructor | `0x205eb8` | `_ZN20XJLBgarMnAPropertiesD0Ev` | `0x20bfc4` | base cleanup and delete |
| deleting destructor thunk | `0x205ef0` | `_ZThn16_N20XJLBgarMnAPropertiesD0Ev` | `0x20bffc` | 16-byte this adjustment |

All four pairs are exact normalized-shape matches. The target names were
already non-default, and the labels reopened successfully in the v137 copy.
Evidence is stored in
`artifacts/spectron_tsocket_properties_residual_manual_translation_anchors_20260826.json`.

## Spectron TSocket host and logging residual anchors

The v136 pass translated three helpers in the host and logging region. The
plain send and receive functions immediately nearby were already represented
by canonical semantic-map labels.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_cacheHostAddress` | `0x205ef8` | `sub_20C020` | `0x20c020` | cached IPv4 object and timestamp |
| `TSocket_logSocketMessage` | `0x205fcc` | `sub_20C018` | `0x20c018` | CyaSSL logging callback |
| `resolveHost_TString_const` | `0x206108` | `_Z10dsmb2ajvasRK10C8THgaTQxF` | `0x20c20c` | cached lookup and gethostbyname |

The cache writer and resolver retain the same cached-host fields, address
validity flag, case-insensitive lookup, and timestamp handling. The source
and target bodies grow from 212 to 244 bytes for the cache writer and from
300 to 344 bytes for the resolver as target string and container wrappers are
made explicit.

The logging row is a deliberate callback-factoring match. The source method
formats a temporary string and calls `TLog_echo`. Spectron uses the small
target helper at `0x20c018` as the callback passed to
`CyaSSL_SetLoggingCb`, and that helper forwards the message into the target
logger. Its 8-byte thunk is therefore recorded as a layout-change anchor,
not rejected because its body is much smaller.

The target-only helper at `0x20c008` clears a separate global string object.
The already translated `v18_TSocket_sendPlain` at `0x20c114` and
`v18_TSocket_recvPlain` at `0x20c184` are explicit neighboring boundaries.
All three new labels reopened successfully in the v136 disposable copy, and
the full translation check still reports zero failures across 11,679
functions. Evidence is stored in
`artifacts/spectron_tsocket_host_residual_manual_translation_anchors_20260826.json`.

## Spectron TSocket lifecycle residual anchors

The v135 pass translated four remaining methods in the ordered `TSocket`
lifecycle block. `checkScriptActive` sits between `bind` and `runScript`, but
its exact match was already in the canonical semantic map and is documented
as an existing boundary rather than duplicated here.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_preDestroy_void` | `0x205780` | `_ZN10XJLBgarMnA10PWkBgafe1zEv` | `0x20b78c` | compact cleanup method |
| `TSocket_checkAllowBind_int` | `0x2057a0` | `_ZN10XJLBgarMnA10MXSAgaXQDzEi` | `0x20b7ac` | wildcard and port-range policy |
| `TSocket_bind_int_bool` | `0x205948` | `_ZN10XJLBgarMnA4bindEib` | `0x20b958` | connection and SSL setup |
| `TSocket_runScript_void` | `0x205bdc` | `_ZN10XJLBgarMnA10_xWAgaiSGzEv` | `0x20bc1c` | state machine and client events |

`preDestroy` is an exact normalized-shape match. The other three target
bodies are larger because Spectron makes encoded string and temporary wrapper
operations explicit. `checkAllowBind` still parses the allowed-port list and
supports wildcard and range checks. `bind` still rejects disallowed ports,
recreates the connection, applies SSL settings, and follows the bind success
or failure event path. `runScript` retains the connect, new-client, and close
state transitions, including insertion into `clients` and the base socket
script call.

The source-to-target deltas are `+0x600c` for `preDestroy` and
`checkAllowBind`, `+0x6010` for `bind`, and `+0x6040` for `runScript`. The
source bind jump at `0x205b94` and target jump at `0x20bbd4` remain separate
boundaries, as does the target `TSocketProperties` block after `0x20bfa0`.

All four labels reopened successfully in the v135 disposable copy. The full
translation check still reports zero failures across 11,679 functions and
1,497 default `sub_` names. Evidence is stored in
`artifacts/spectron_tsocket_lifecycle_residual_manual_translation_anchors_20260826.json`.

## Spectron TSocket receive residual anchors

The v134 pass translated the two larger receive-side `TSocket` methods. The
source `checkDataPackages` at `0x205328` maps to target `0x20b1f8`, and the
source `read` at `0x2054c4` maps to target `0x20b3f0`, both in class
`XJLBgarMnA`. The first target body grows by 92 bytes, so the second row is
aligned at `+0x5f2c` rather than the initial `+0x5ed0` offset.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_checkDataPackages_void` | `0x205328` | `_ZN10XJLBgarMnA10xS6AgaBoQzEv` | `0x20b1f8` | package split and event |
| `TSocket_read_void` | `0x2054c4` | `_ZN10XJLBgarMnA4readEv` | `0x20b3f0` | native read and data events |

`checkDataPackages` keeps the queued input fields at offsets 200 and 216,
delimiter search and line splitting, array construction, and
`onReceiveDataPackage` dispatch. Its source metrics are 376 bytes, 94
instructions, 14 blocks, 24 branches, and 15 calls. The target metrics are
468/117/14/30/21, reflecting explicit `C8THgaTQxF`, `CanTfaz6bZ`,
`D6TlgajP1m`, and `G0gxgajWBw` wrapper calls.

`read` retains the connection pointer at offset 176, error check, native read,
state transition from 4 to 5, UDP flag at connection offset 8344, and the
`onConnect`, `onReceiveUDPData`, and `onReceiveData` paths. The ordinary data
path still calls `checkDataPackages`. Its metrics change from 548/137/15/38/29
to 772/193/16/56/47 because the target makes encoded event strings and
temporary values explicit. The source exposes the four readable event
literals, while the target builds encoded values through `C8THgaTQxF` and
`KKhLga4xoI` and has no plain string references in the clean export.

Both target names were already non-default, so the v134 copy retains 1,497
default `sub_` functions. The full evidence record is
`artifacts/spectron_tsocket_receive_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tsocket_receive_residual_anchors.py`.
The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v134.i64`.
Both the manual anchor reopen check and the full translation check passed
with zero failures across 11,679 functions. The v134 database SHA-256 is
`0fa7676435cea1bdbdb334e9926d99dbb4437ccc4ff4c04d81c4531399b62971`.

## Spectron TSocket SSL residual anchors

The v133 pass translated four residual `TSocket` SSL and outgoing-buffer
methods. The source rows at `0x205120`, `0x20514c`, `0x2051a0`, and `0x205240`
map to the target rows at `0x20aff0`, `0x20b01c`, `0x20b070`, and `0x20b110`.
The block uses a fixed `+0x5ed0` delta in class `XJLBgarMnA`.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_setEnableSSL_bool` | `0x205120` | `_ZN10XJLBgarMnA10Sf9Aga1oSzEb` | `0x20aff0` | SSL state and connection update |
| `TSocket_setSSLCipherList_TString_const` | `0x20514c` | `_ZN10XJLBgarMnA10ze1AgaTELzERK10C8THgaTQxF` | `0x20b01c` | cipher propagation |
| `TSocket_setSSLProtocol_TString_const` | `0x2051a0` | `_ZN10XJLBgarMnA10S12AgafaNzERK10C8THgaTQxF` | `0x20b070` | protocol propagation |
| `TSocket_send_TString_const` | `0x205240` | `_ZN10XJLBgarMnA4sendERK10C8THgaTQxF` | `0x20b110` | outgoing append |

All four pairs are exact normalized-shape matches. The enable setter keeps
the byte-140 comparison and live connection at offset 176. Cipher and
protocol strings remain at socket offsets 144 and 152 and propagate to live
connection offsets 8248 and 8256. The send wrapper appends to the outgoing
buffer at offset 168. The target's `u3cBgayBVz` and `C8THgaTQxF` helper names
are wrapper changes only.

The already translated `setSSLVerifyCert`, `sendUDP`, and `close` rows at
target `0x20b0c4`, `0x20b11c`, and `0x20b1b8` confirm the surrounding order.
The v133 copy leaves 1,497 default `sub_` functions because all four target
entries already had obfuscated names. The full evidence record is
`artifacts/spectron_tsocket_ssl_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tsocket_ssl_residual_anchors.py`.
The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v133.i64`.
Both the manual anchor reopen check and the full translation check passed
with zero failures across 11,679 functions. The v133 database SHA-256 is
`d3d0be59f3cee7f3b10ab9f3da04910a4f6e4a7cdacdefa4996e4cb1a594afcd`.

## Spectron TSocket accessor and factory residual anchors

The v132 pass translated 19 residual `TSocket` methods. Seventeen field
accessors form the source block from `0x204630` through `0x2047e8` and the
target block from `0x20a508` through `0x20a6c0`. `sendOutgoing` and the socket
factory are included at `0x204894` and `0x204a70`. The complete block uses a
fixed `+0x5ed8` delta in target class `XJLBgarMnA`, with readable source names
retained as `v18_` labels.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `TSocket_getByte140` | `0x204630` | `sub_20A508` | `0x20a508` | byte accessor |
| `TSocket_getListCountField168` | `0x204638` | `sub_20A510` | `0x20a510` | list-count accessor |
| `TSocket_getField208` | `0x204650` | `sub_20A528` | `0x20a528` | field accessor |
| `TSocket_getDword192` | `0x204658` | `sub_20A530` | `0x20a530` | dword accessor |
| `TSocket_setStringField232` | `0x204660` | `sub_20A538` | `0x20a538` | string setter |
| `TSocket_setStringField224` | `0x204668` | `sub_20A540` | `0x20a540` | string setter |
| `TSocket_setStringField200` | `0x204670` | `sub_20A548` | `0x20a548` | string setter |
| `TSocket_setAllowedPortsBind` | `0x204678` | `sub_20A550` | `0x20a550` | allowed-port setter |
| `TSocket_setAllowedSocketsConnect` | `0x204688` | `sub_20A560` | `0x20a560` | allowed-socket setter |
| `TSocket_getStringField216` | `0x204698` | `sub_20A570` | `0x20a570` | string getter |
| `TSocket_getStringField232` | `0x2046c8` | `sub_20A5A0` | `0x20a5a0` | string getter |
| `TSocket_getStringField224` | `0x2046f8` | `sub_20A5D0` | `0x20a5d0` | string getter |
| `TSocket_getStringField200` | `0x204728` | `sub_20A600` | `0x20a600` | string getter |
| `TSocket_getStringField184` | `0x204758` | `sub_20A630` | `0x20a630` | string getter |
| `TSocket_getStringField144` | `0x204788` | `sub_20A660` | `0x20a660` | string getter |
| `TSocket_getStringField152` | `0x2047b8` | `sub_20A690` | `0x20a690` | string getter |
| `TSocket_getStringField160` | `0x2047e8` | `sub_20A6C0` | `0x20a6c0` | string getter |
| `TSocket_sendOutgoing_void` | `0x204894` | `_ZN10XJLBgarMnA10da7AgaaEQzEv` | `0x20a76c` | buffered send |
| `TSocket_create_TString_const` | `0x204a70` | `_Z20XJLBgarMnAE7Bm2aaHDBRK10C8THgaTQxF` | `0x20a948` | allocator and constructor |

Eighteen pairs have exact normalized metrics. The only layout-change row is
`setAllowedPortsBind`, where the target assigns through the obfuscated
`C8THgaTQxF` wrapper to the `XJLBgarMnA::gwjBgaP1_z` field. The remaining
accessors preserve their source field offsets and return or assign behavior.
None of these rows has string references.

`sendOutgoing` retains the connection-present and no-error guards, positive
buffer-length test, connection send, and removal of the accepted prefix. The
target's `u3cBgayBVz` and `C8THgaTQxF` names are wrapper changes only. The
factory has the same 48/12/1/3/2 normalized metrics, allocates `0xf0` bytes,
and calls the parameterized `XJLBgarMnA` constructor. Its source static-script
caller and translated target static-script caller provide an additional
cross-reference check.

The v132 copy reduced the default `sub_` count from 1,514 to 1,497. The full
evidence record is
`artifacts/spectron_tsocket_accessor_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tsocket_accessor_residual_anchors.py`.
The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v132.i64`.
Both the manual anchor reopen check and the full translation check passed
with zero failures across 11,679 functions. The v132 database SHA-256 is
`56d799699ce321c4e212fb2e9c9ca0e7d8fed8a349da89dc733972d8f4e8bef9`.

## Spectron GuiControl factory residual anchor

The v131 pass resolved the remaining `GuiControl_create_TString_const`
factory ambiguity. The source wrapper at `0x1b4974` allocates `0x1c8` bytes
and calls the parameterized constructor. The target wrapper at `0x1b9040` is
the class-specific Spectron factory
`_Z20w9XxgaJdbxE7Bm2aaHDBRK10C8THgaTQxF`.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `GuiControl_create_TString_const` | `0x1b4974` | `_Z20w9XxgaJdbxE7Bm2aaHDBRK10C8THgaTQxF` | `0x1b9040` | exact allocator wrapper and C2 call |

Both wrappers are 48 bytes, 12 instructions, one block, three branches, and
two calls. Their mnemonic, opcode-shape, register-shape, and overall-shape
hashes also match, and neither has string references. The target allocates
the same `0x1c8` object size and calls the target C2 constructor at
`0x1b8f68`.

The generic search had 26 candidates with this factory shape. The target
class name, exact normalized metrics, allocation size, and reference from
the already translated `v18_guiControl_initStaticScriptVars_void` caller
resolve the correct candidate. The target was already non-default and the
v131 copy retains 1,514 default `sub_` functions.

The full evidence record is
`artifacts/spectron_guicontrol_create_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_guicontrol_create_residual_anchors.py`.
The label is in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v131.i64`.
Both the manual anchor reopen check and the full translation check passed
with zero failures across 11,679 functions. The v131 database SHA-256 is
`0a9e38bcc80186b86ed83b5f6c92cad4101f8a2d7746e7379b2a192a02e8b603`.

## Spectron GuiControl initialization residual anchors

The v130 pass translated two residual `GuiControl` initialization methods.
The source `initObject` at `0x1b4680` and parameterized constructor at
`0x1b48c8` map to the ordered target entries at `0x1b8cfc` and `0x1b8f68` in
the obfuscated `w9XxgaJdbx` class.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `GuiControl_initObject_void` | `0x1b4680` | `_ZN10w9XxgaJdbx10j9gLgaw2nIEv` | `0x1b8cfc` | field and child-list initialization |
| `GuiControl_GuiControl_TString_const` | `0x1b48c8` | `_ZN10w9XxgaJdbxC2ERK10C8THgaTQxF` | `0x1b8f68` | parameterized C2 constructor |

The init method keeps the same object fields, static `controls` registry,
child-list allocation, vtable slot 72 lookup, and array-update operation. It
changes from 584 bytes, 145 instructions, 4 blocks, 12 branches, and 8 calls
to 620/154/4/14/10. The target's added work is the explicit
`CanTfaz6bZ` assignment and cleanup and the `G0gxgajWBw::tpNgMa2aKd` wrapper.
Both feature exports retain the `controls` string reference and the same
static initialization guard.

The parameterized constructor keeps the `TGraalVar` base, region setup at
offset 176, field clearing, and call into `initObject`. It changes from
172/43/2/3/2 to 216/54/1/6/5. The target C2 body uses an explicit temporary
`CanTfaz6bZ`, calls the obfuscated base constructor, clears that temporary,
and completes the same derived-object setup. The already translated source
default constructor at `0x1b49a4` and target C1 constructor at `0x1b9070`
have identical normalized metrics, confirming the C1 and C2 ordering.

`GuiControl_create_TString_const` at `0x1b4974` remains an explicit
ambiguity. Its current semantic search returns 26 target candidates, so no
name was assigned from adjacency alone. Both v130 target names were already
non-default obfuscated names, leaving 1,514 default `sub_` functions.

The full evidence record is
`artifacts/spectron_guicontrol_initialization_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_initialization_residual_anchors.py`.
The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v130.i64`.
Both the manual anchor reopen check and the full translation check passed
with zero failures across 11,679 functions. The v130 database SHA-256 is
`1113a2703e11e58c61ff69510de89d938801ca3c405ca03c7a0fab3faa5b574d`.

## Spectron GuiControl event-dispatch residual anchors

The v129 pass translated eight residual `GuiControl` event methods into the
ordered Spectron `w9XxgaJdbx` block. The source sequence is
`0x1b3984` through `0x1b3e40`, and the target sequence is `0x1b7eb8` through
`0x1b84bc`. Four rows already mapped inside the surrounding source sequence
remain alignment anchors: `setY`, `setX`, `onAcceleratorKeyEvent`, and
`getStyle` at `0x1b3bf0`, `0x1b3c34`, `0x1b3c78`, and `0x1b3d14`.

| 1.8 role | Source | Spectron symbol | Target | Main evidence |
| --- | ---: | --- | ---: | --- |
| `GuiControl_onBecomeFirstResponder_void` | `0x1b3984` | `_ZN10w9XxgaJdbx10xV7Kwa7ggaEv` | `0x1b7eb8` | first-responder event |
| `GuiControl_onDialogPush_void` | `0x1b39d0` | `_ZN10w9XxgaJdbx10fK5BgaArFAEv` | `0x1b7f3c` | dialog-push event |
| `GuiControl_onDialogPop_void` | `0x1b3a1c` | `_ZN10w9XxgaJdbx10qgnIBawbXkEv` | `0x1b7fc0` | dialog-pop event |
| `GuiControl_onAdd_void` | `0x1b3a68` | `_ZN10w9XxgaJdbx10VSoCgaTxVAEv` | `0x1b8044` | parent refresh after event |
| `GuiControl_notifyVisible_bool` | `0x1b3ad4` | `_ZN10w9XxgaJdbx10kpGWHa_hZzEb` | `0x1b80e8` | child visibility propagation |
| `GuiControl_onAction_void` | `0x1b3b9c` | `_ZN10w9XxgaJdbx10_pyQMazzPHEv` | `0x1b81e0` | action-state gate |
| `GuiControl_onMouseWheelUp_GuiEvent_const` | `0x1b3dd8` | `_ZN10w9XxgaJdbx10bvLrxaOzYKERK10cXoLgatBuI` | `0x1b8454` | exact mouse-wheel body |
| `GuiControl_onMouseWheelDown_GuiEvent_const` | `0x1b3e40` | `_ZN10w9XxgaJdbx10TwTrxark4KERK10cXoLgatBuI` | `0x1b84bc` | exact mouse-wheel body |

The first six target bodies are larger because Spectron makes its encoded
event strings and temporary wrappers visible in the native implementation.
The first responder, dialog, and action methods still build an event value,
call the `TGraalVar` event path, and clear their temporaries. The add method
keeps the parent refresh through virtual slot 480. Visibility notification
keeps the active-child loop and virtual slot 344. The action method retains
the source control-state check at byte offset 277.

The metric changes are consistent with wrapper growth. The first three rows
grow from 76 bytes, 18 instructions, one block, four branches, and three
calls to 132 bytes, 32 instructions, one block, eight branches, and seven
calls. `onAdd` changes from 108/26/3/6/4 to 164/40/3/10/8,
`notifyVisible` changes from 200/48/9/10/5 to 248/60/9/14/9, and `onAction`
changes from 84/21/3/5/3 to 140/34/3/9/7. The two mouse-wheel rows are exact
normalized-shape matches at 104/26/6/7/1. The wheel methods retain the byte
276 enabled check, byte 278 parent-window branch, and virtual slot 664.

The source literals are readable event names. Spectron's clean export instead
exposes the encoded strings `33cSO` for the add path and `22F>NF` for the
visibility path, with wrapper-only construction in the other event methods.
The string-reference difference is therefore recorded as target encoding
evidence. The target-only thunk at `0x1b7c6c` remains a separate boundary
before the already mapped `resizeChildren` method.

All eight target names were already non-default obfuscated names, so the
v129 copy leaves the default `sub_` count at 1,514. The full evidence record
is `artifacts/spectron_guicontrol_event_dispatch_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_guicontrol_event_dispatch_residual_anchors.py`.
The labels are in
`/home/v/Desktop/graal-decomp/analysis/spectron_libqplay_translated_v129.i64`.
Both the manual anchor reopen check and the full translation check passed
with zero failures across 11,679 functions. The v129 database SHA-256 is
`f2f0e0e125d868a43ed9aba2caf46025bd65df9254669fc6aa3caeef0771c0bf`.

## Spectron GuiControl style and bounds residual anchors

The v128 pass translated 12 residual `GuiControl` style, geometry, profile,
and color methods. The first three rows align at `+0x4500`. Spectron's
`getStyle` body grows by 0x34 bytes, shifting the remaining rows to a
piecewise `+0x4534` delta.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `GuiControl_setHint` | `0x1b30f8` | `0x1b75f8` | hint assignment |
| `GuiControl_getHint` | `0x1b3100` | `0x1b7600` | hint return |
| `GuiControl_getStyle` | `0x1b3130` | `0x1b7630` | style and level-resource fallback |
| `GuiControl_getMinExtent` | `0x1b33cc` | `0x1b7900` | point conversion |
| `GuiControl_getClientExtent` | `0x1b33f0` | `0x1b7924` | point conversion |
| `GuiControl_getPosition` | `0x1b3414` | `0x1b7948` | point conversion |
| `GuiControl_getExtent` | `0x1b3438` | `0x1b796c` | point conversion |
| `GuiControl_getRotationCenter` | `0x1b345c` | `0x1b7990` | rotation-center conversion |
| `GuiControl_setProfile` | `0x1b3494` | `0x1b79c8` | dynamic cast and vtable dispatch |
| `GuiControl_script_addControl` | `0x1b3518` | `0x1b7a4c` | script add-control wrapper |
| `GuiControl_getColor` | `0x1b3558` | `0x1b7a8c` | packed color reconstruction |
| `GuiControl_getBounds` | `0x1b3630` | `0x1b7b64` | rectangle conversion |

The Hint methods use the same object string at offset 424. `getStyle` keeps
the source decision tree: it reads the active profile through vtable slot
808, returns a nonempty style, otherwise derives the level-resource filename,
and finally returns the default style. Its target body grows from 256 to 308
bytes and from 8 to 12 calls because the target makes temporary resource and
string wrappers explicit. The target field and dispatch roles in the other
rows remain unchanged, including profile dispatch at slot 792 and color
conversion through the target string wrapper.

Eleven pairs have identical normalized metrics and one pair, `getStyle`, is
recorded as a layout-change anchor. All 12 target rows were generic `sub_`
functions and none has string references. The v128 copy verified every alias
after reopening, and the default `sub_` count fell from 1,526 to 1,514.

The target-only thunk at `0x1b7c6c` remains separate from this block and from
the next already mapped `resizeChildren` method. The full evidence record is
`artifacts/spectron_guicontrol_style_bounds_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_style_bounds_residual_anchors.py`. The
labels are in `analysis/spectron_libqplay_translated_v128.i64`. Both the
manual anchor reopen check and the full translation check passed with zero
failures across 11,679 functions. The v128 database has 1,514 remaining
default `sub_` functions. Its SHA-256 is
`d48e2c7f17fb26f72f4619589b6612cffdd862570476f3e3efa77b3b5c67d6b4`.

## Spectron GuiControl event and sizing residual anchors

The v127 pass translated eight named methods from the next `GuiControl`
event and sizing sequence. The source interval is `0x1b2b78` through
`0x1b306c`, and the target interval is `0x1b7078` through `0x1b74ec` at a
fixed `+0x4500` delta.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `GuiControl_onChildResized_GuiControl` | `0x1b2b78` | `0x1b7078` | empty child-resize hook |
| `GuiControl_onInputEvent_InputEvent_const` | `0x1b2e90` | `0x1b7390` | default input-event return |
| `GuiControl_onMouseMove_GuiEvent_const` | `0x1b2ec0` | `0x1b73c0` | empty mouse-move hook |
| `GuiControl_onKeyRepeat_GuiEvent_const` | `0x1b2ec4` | `0x1b73c4` | vtable forwarding at slot 760 |
| `GuiControl_getScrollLineSizes_uint_uint` | `0x1b2f48` | `0x1b7448` | paired scroll-line fields |
| `GuiControl_getVertSizing` | `0x1b2f5c` | `0x1b745c` | vertical sizing string lookup |
| `GuiControl_getHorizSizing` | `0x1b2f9c` | `0x1b749c` | horizontal sizing string lookup |
| `GuiControl_setVertSizing` | `0x1b2fec` | `0x1b74ec` | vertical sizing index setter |

Six rows inside the enclosing interval were already in the semantic map,
including `onParentResized`, `getNeededSpace`, `onChildMouseDown`, `onKeyUp`,
`showAlwaysTop`, and `setHorizSizing`. The source `sub_1B2FDC` row is not a
readable symbol and remains an explicit boundary, along with target
`sub_1B74DC`.

The event methods preserve their source behavior. The child-resized and
mouse-move hooks are empty, and the input-event default returns zero. Key
repeat forwards through the same vtable slot at byte offset 760. The
scroll-line helper writes the same two fields at offsets 324 and 328. The
vertical and horizontal sizing getters use the same static string tables,
and the vertical setter stores the selected table index at offset 404.

All eight pairs have identical normalized size, instruction, block, branch,
call, mnemonic, opcode-shape, register-shape, and overall-shape metrics. They
have no string references. Three target rows were generic `sub_` names. The
v127 copy verified all eight aliases after reopening, with seven new names
written because the scroll-line alias was already present in the v126
lineage. The default `sub_` count fell from 1,529 to 1,526.

The evidence is in
`artifacts/spectron_guicontrol_event_sizing_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_event_sizing_residual_anchors.py`. The
labels are in `analysis/spectron_libqplay_translated_v127.i64`. Both the
manual anchor reopen check and the full translation check passed with zero
failures across 11,679 functions. The v127 database has 1,526 remaining
default `sub_` functions. Its SHA-256 is
`a8b9293373fc4424b5a6de148a3822fd2819e21888703d1062aea3117bb1d1c5`.

## Spectron GuiControl virtual and base-hook residual anchors

The v126 pass translated 13 remaining `GuiControl` base and virtual-hook
methods. They form a short ordered source block and a matching Spectron block
inside the obfuscated `w9XxgaJdbx` class.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `GuiControl_requiredCacheSize_void` | `0x1ac750` | `0x1b0910` | cache-size output wrapper |
| `GuiControl_setMinExtent_TPoint_const` | `0x1ac76c` | `0x1b092c` | minimum extent setter |
| `GuiControl_getCursorType_GuiEvent_const` | `0x1ac778` | `0x1b0938` | cursor-type lookup |
| `GuiControl_getRoot_void` | `0x1ac780` | `0x1b0940` | parent root vtable dispatch |
| `GuiControl_getExternalWindow_void` | `0x1ac7b0` | `0x1b0970` | parent window vtable dispatch |
| `GuiControl_updateClientBounds_void` | `0x1ac7e0` | `0x1b09a0` | client-bound refresh |
| `GuiControl_onPreRender_void` | `0x1ac7fc` | `0x1b09bc` | empty virtual hook |
| `GuiControl_onRightMouseDown_GuiEvent_const` | `0x1ac800` | `0x1b09c0` | empty virtual hook |
| `GuiControl_onRightMouseUp_GuiEvent_const` | `0x1ac804` | `0x1b09c4` | empty virtual hook |
| `GuiControl_onRightMouseDragged_GuiEvent_const` | `0x1ac808` | `0x1b09c8` | empty virtual hook |
| `GuiControl_setScriptAccessRestricted_bool` | `0x1ac80c` | `0x1b09cc` | byte setter at offset 204 |
| `GuiControl_forceClipping_void` | `0x1ac814` | `0x1b09d4` | empty virtual hook |
| `GuiControl_showContextMenus_void` | `0x1ac81c` | `0x1b09dc` | empty virtual hook |

The target address is the source address plus `0x41c0` throughout the block.
The root and external-window methods preserve the parent pointer at object
slot 14 and the vtable slots at byte offsets 416 and 432. The cache-size
wrapper returns the same field through the output pointer, and the
script-access setter writes the same byte at offset 204. The empty hooks keep
their null-returning bodies. These bodies, together with the exact local
sequence, distinguish the matches from unrelated one-instruction functions.

All 13 pairs have identical normalized size, instruction, block, branch,
call, mnemonic, opcode-shape, register-shape, and overall-shape metrics. They
have no string references. The target already had obfuscated non-default
names, so the pass added readable `v18_` aliases without changing the default
`sub_` count. The next target class boundary is the destructor family at
`0x1b09e4`, which remains separate.

The evidence is in
`artifacts/spectron_guicontrol_virtual_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_virtual_residual_anchors.py`. The labels
are in `analysis/spectron_libqplay_translated_v126.i64`. Both the manual
anchor reopen check and the full translation check passed with zero failures
across 11,679 functions. The v126 database has 1,529 remaining default
`sub_` functions. Its SHA-256 is
`aed7e8fe3fd07cfe33c1ea0cc13df6742dec3e9a120e06873729203d9c4404a4`.

## Spectron GuiControl property residual anchors

The v125 pass translated 61 residual `GuiControl` property and script-wrapper
methods. They sit in one ordered source block and align with one ordered
Spectron block inside the obfuscated `w9XxgaJdbx` class.

| 1.8 range | Spectron range | Main evidence |
| --- | --- | --- |
| `0x1b2748` through `0x1b28e4` | `0x1b6c48` through `0x1b6de4` | byte, integer, color, clipping, focus, flicker, and height accessors |
| `0x1b2934` through `0x1b2a14` | `0x1b6e34` through `0x1b6f14` | hint, mouse-lock, mode, resize, rotation, and scroll-line accessors |
| `0x1b29fc` through `0x1b2ab4` | `0x1b6efc` through `0x1b6fb4` | topmost, visibility, profile ownership, position, and parent accessors |
| `0x1b2af4` through `0x1b2b14` | `0x1b6ff4` through `0x1b7014` | `showtop` and `showalwaysontop` script wrappers |

The target address is the source address plus `0x4500` throughout this
sequence. Seven rows inside the enclosing ranges were already in the
semantic map, so the artifact records the other 61 rows without duplicating
those existing labels. The omitted rows are `setClientHeight`,
`setClientWidth`, `setHeight`, `getIsInAnimation`, `setWidth`, `script_resize`,
and `compare_y`.

The short bodies make the mapping especially clear. `getAcceptDropFiles`
reads the same byte at offset 340. `setAreaClickPriority` clamps to 0 through
2 and stores offset 332. The larger height setter keeps the same fallback,
comparison, and virtual resize callback. The scroll-line setters preserve
their nonnegative clamp and field writes. `setUseOwnProfile` and the two
script wrappers dispatch through the same vtable slots as their 1.8 forms.

All 61 pairs have identical normalized size, instruction, block, branch,
call, mnemonic, opcode-shape, register-shape, and overall-shape metrics. They
have no string references. The clean target export showed all 61 as generic
`sub_` names. The v125 IDA copy verified all 61 names after reopening, with 60
new names written because one target name was already present in the v124
lineage.

The target-only helper at `0x1b7078` remains outside this interval and is not
given a source name. The full evidence record is
`artifacts/spectron_guicontrol_property_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_guicontrol_property_residual_anchors.py`. The labels
are in `analysis/spectron_libqplay_translated_v125.i64`. Both the manual
anchor reopen check and the full translation check passed with zero failures
across 11,679 functions. The v125 database has 1,529 remaining default
`sub_` functions. Its SHA-256 is
`0b55e73e765827d37e37e7403c2f0779229a178f3deb78314e86da17d770a75b`.

## Spectron GuiControlProfile destructor anchors

The v124 pass translated six destructor-family rows around the target
`XoqxgaMPJwProperties` and `XoqxgaMPJw` classes.

| 1.8 role | Source | Spectron target | Target class | Main evidence |
| --- | ---: | ---: | --- | --- |
| `GuiControlProfileProperties_GuiControlProfileProperties` | `0x112914` | `0x1151c8` | `XoqxgaMPJwProperties` | D1 or D2 complete destructor |
| `non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties` | `0x112930` | `0x1151e4` | `XoqxgaMPJwProperties` | 16-byte this adjustment |
| `GuiControlProfileProperties_GuiControlProfileProperties__2` | `0x112938` | `0x1151ec` | `XoqxgaMPJwProperties` | D0 deleting destructor |
| `non_virtual_thunk_to_GuiControlProfileProperties_GuiControlProfileProperties__2` | `0x112970` | `0x115224` | `XoqxgaMPJwProperties` | deleting this adjustment |
| `GuiControlProfile_GuiControlProfile` | `0x112978` | `0x11522c` | `XoqxgaMPJw` | profile complete destructor |
| `GuiControlProfile_GuiControlProfile__2` | `0x112a00` | `0x1152bc` | `XoqxgaMPJw` | profile deleting destructor |

The four properties rows have identical normalized metrics and shapes. The
target thunks subtract 16 from `this`, and the target D0 form adds
`operator delete` after the same base cleanup. The source constructor-style
names are historical IDA spellings for destructor entries, while the target
symbols make the D1 and D0 forms explicit.

The two main profile destructors are high-confidence lifecycle matches with
a target layout change. The target functions are eight bytes and two
instructions larger and make one additional cleanup call. Their pseudocode
still clears the same profile strings, destroys the two resource-file-user
subobjects, and calls the `TGraalVar` base destructor. The target wrappers are
obfuscated, but their order and class-local position remain clear.

All six labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v124.i64`. The evidence is in
`artifacts/spectron_gui_control_profile_destructor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gui_control_profile_destructor_anchors.py`. Both the
manual-anchor reopen check and the full translation check passed with zero
failures across 11,679 functions. The v124 database has 1,589 remaining
default `sub_` functions. Its SHA-256 is
`0db16cc6d06a77627a4b57048764aabb24f3a7b0c50cd9013b8b0a45c5bf0608`.

## Spectron GuiControlProfile accessor anchors

The v123 pass translated 89 residual `GuiControlProfile` accessors in the
obfuscated `XoqxgaMPJw` profile implementation. The block covers scalar
properties, alignment and point wrappers, font-style strings, color setters
and getters, background inset, resource-file notification, and the profile
font-color helper.

| Source range | Spectron range | Main evidence |
| --- | --- | --- |
| `0x111248` through `0x111370` | `0x113a28` through `0x113b50` | 38 ordered scalar accessors |
| `0x111378` | `0x113b58` | alignment getter |
| `0x1113b8` through `0x111484` | `0x113ba8` through `0x113c74` | point conversion wrappers |
| `0x1114a8` through `0x111658` | `0x113c98` through `0x113e48` | font-style fields and string returns |
| `0x111688` through `0x11189c` | `0x113e78` through `0x11408c` | color setters |
| `0x111974` | `0x114164` | font-color setter |
| `0x1119e0` through `0x111b48` | `0x1141f4` through `0x11435c` | eleven color getters |
| `0x111b90` | `0x114380` | shadow-color getter |
| `0x111c54` through `0x111c78` | `0x114444` through `0x114468` | background inset and alignment setter |
| `0x111cf8` through `0x111cfc` | `0x1144e8` through `0x1144ec` | notification and font-color helper |

The target preserves the source order and field roles. Scalar getters and
setters retain their two-instruction bodies with target-adjusted profile
offsets. Point and font-style methods keep the same string conversion and
temporary-result patterns. Color setters still parse packed color bytes,
scale them by 1/255, and store four floats. Color getters reverse that
conversion through the target `wC1CGa7Yrt` wrapper. The target parser for
setters is `Q9LCGaX7dt`.

Three coverage gaps remain explicit. The target-only 16-byte method at
`0x113b98` is not assigned a 1.8 name. The source gradient-color setter at
`0x111908` is followed by target data at `0x1140f4`, not a distinct target
function. The source border-color getter at `0x111b6c` has no distinct target
function before the target shadow-color getter at `0x114380`. This avoids
mislabeling a nearby method just because its shape is similar.

All 89 mapped pairs have matching normalized metrics and shape hashes. One
target helper already had an obfuscated class name, while 88 target rows were
generic `sub_` names. The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v123.i64`. The evidence is in
`artifacts/spectron_gui_control_profile_accessor_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_gui_control_profile_accessor_anchors.py`. Both the
manual-anchor reopen check and the full translation check passed with zero
failures across 11,679 functions. The v123 database has 1,589 remaining
default `sub_` functions. Its SHA-256 is
`50300d39030edb45142902407ff7651d7a436bb237fe54fe9d1aa59c8f3d7b8f`.

## Spectron font options, font data, window properties, and screen-panel lifecycle anchors

The v122 pass translated 16 short residual methods across four related
classes. These are all high-confidence context anchors. The target classes
are `SU3JfaCUmR`, `KcKRganuPN`, `fUWH_a_9zm`, and
`LJyzga9PwyProperties`.

| 1.8 role | Source | Spectron target | Target class | Main evidence |
| --- | ---: | ---: | --- | --- |
| `TScreenPanelOpenGL_isNative_void` | `0x10cbc4` | `0x10f514` | `SU3JfaCUmR` | returns one |
| `TScreenPanelOpenGL_TScreenPanelOpenGL` | `0x10cbcc` | `0x10f51c` | `SU3JfaCUmR` | D1 destructor |
| `TScreenPanelOpenGL_TScreenPanelOpenGL__2` | `0x10cbe0` | `0x10f530` | `SU3JfaCUmR` | D0 destructor |
| `TFontOptions_get_pref__graal__defaultfontsize` | `0x10f6d4` | `0x111f70` | `KcKRganuPN` | default-size getter |
| `TFontOptions_set_pref__graal__defaultfontsize` | `0x10f6e4` | `0x111f80` | `KcKRganuPN` | default-size setter |
| `TFontOptions_get_enableutf8` | `0x10f6f4` | `0x111f90` | `KcKRganuPN` | UTF-8 flag getter |
| `TFontOptions_set_pref__graal__defaultfontname` | `0x10f704` | `0x111fa0` | `KcKRganuPN` | default-name setter |
| `TFontOptions_get_pref__graal__utf8fontfile` | `0x10f718` | `0x111fb4` | `KcKRganuPN` | UTF-8 font-file getter |
| `TFontOptions_get_pref__graal__defaultfontname` | `0x10f750` | `0x111fec` | `KcKRganuPN` | default-name getter |
| `TFontData_TFontData__2` | `0x110ad8` | `0x113354` | `fUWH_a_9zm` | D0 destructor |
| `TFontData_findFontData_TString_const` | `0x110af8` | `0x113374` | `fUWH_a_9zm` | lower-case and hash lookup |
| `TFontData_initStaticVars_void` | `0x111218` | `0x1139f8` | `fUWH_a_9zm` | static hash-list setup |
| `TWindowProperties_TWindowProperties` | `0x108280` | `0x10abd4` | `LJyzga9PwyProperties` | D2 destructor |
| `non_virtual_thunk_to_TWindowProperties_TWindowProperties` | `0x10829c` | `0x10abf0` | `LJyzga9PwyProperties` | 16-byte adjusted-this thunk |
| `TWindowProperties_TWindowProperties__2` | `0x1082a4` | `0x10abf8` | `LJyzga9PwyProperties` | D0 destructor |
| `non_virtual_thunk_to_TWindowProperties_TWindowProperties__2` | `0x1082dc` | `0x10ac30` | `LJyzga9PwyProperties` | deleting adjusted-this thunk |

The screen-panel rows close the residual lifecycle gap around the already
translated renderer methods. The target native predicate returns one. Its
complete destructor installs the target vtable and calls the obfuscated
`oMhmIajzmW` base destructor. Its deleting destructor adds `operator delete`,
matching the source structure.

The six font-option target rows were still generic `sub_` names. Pseudocode
and local order identify them as the default font-size getter and setter, the
UTF-8 flag getter, the default font-name setter, and the UTF-8 font-file and
default font-name getters. The two string getters preserve the source
temporary-result and string-assignment pattern. They sit immediately before
the target methods already translated as `set_enableutf8`,
`script_clearutf8fontranges`, and `set_pref__graal__utf8fontfile`.

The font-data deleting destructor, filename lookup, and static initializer
also retain their source behavior. The lookup lowercases the filename,
computes a hash, queries the target hash list, and clears its temporary
string. The initializer allocates 0x28 bytes, constructs the hash list, and
publishes the registry pointer.

The window-properties rows are the D2 and D0 destructor forms plus their
non-virtual thunks. The source thunks adjust `this` by 16 bytes. Spectron
keeps that same adjustment and destructor ordering in its obfuscated
`LJyzga9PwyProperties` class.

All 16 pairs have matching normalized metrics and shape hashes. Six target
rows were default names, so the saved v122 database has 1,677 remaining
default `sub_` functions. The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v122.i64`. The evidence is in
`artifacts/spectron_font_options_font_data_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_font_options_font_data_residual_anchors.py`. Both
the manual-anchor reopen check and the full translation check passed with
zero failures across 11,679 functions. The v122 database SHA-256 is
`6163a6d7dcb2b510ec8664f72e40965ee31b56bc8d177a2c2ed1f969664a5c85`.

## Spectron font and font-manager residual anchors

The v121 pass translated nine remaining font methods across the target
`TZf6gaQ3S_`, `DFeOfaFXSU`, and `Kv6ugas5Mu` classes.

| 1.8 role | Source | Spectron target | Target class | Main evidence |
| --- | ---: | ---: | --- | --- |
| `TFont_TFont__2` | `0x10ce3c` | `0x10f780` | `TZf6gaQ3S_` | D0 destructor |
| `TFontCharInfo_TFontCharInfo__2` | `0x10d018` | `0x10f968` | `DFeOfaFXSU` | D0 destructor |
| `TFont_bindTexture_void` | `0x10d998` | `0x110364` | `TZf6gaQ3S_` | texture bind mode one |
| `TFont_getTextAscend_int` | `0x10da0c` | `0x1103d8` | `TZf6gaQ3S_` | scaled ascent |
| `TFont_getTextDescend_int` | `0x10da64` | `0x110430` | `TZf6gaQ3S_` | scaled descent |
| `TFontManager_freeResources_void` | `0x10e374` | `0x110d44` | `Kv6ugas5Mu` | font-cache clear |
| `TFontManager_getTextHeight...` | `0x10f438` | `0x111cfc` | `Kv6ugas5Mu` | lookup and height |
| `TFontManager_getTextAscent...` | `0x10f4a4` | `0x111d68` | `Kv6ugas5Mu` | lookup and ascent |
| `TFontManager_getTextDescent...` | `0x10f510` | `0x111dd4` | `Kv6ugas5Mu` | lookup and descent |

The target metric helpers keep the source timestamp update, zero-size
fallback, scaling formula, and ascent or descent field selection. The manager
wrappers still clamp the requested size, find a font, check `canRender`, and
dispatch the selected metric. The target class order and matching normalized
shapes confirm the correspondence. Both destructor wrappers call their
matching destructor and then `operator delete`.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v121.i64`. The evidence is in
`artifacts/spectron_font_manager_font_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_font_manager_font_residual_anchors.py`. All nine
labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v121 database has 1,683 remaining default `sub_` names. Its
SHA-256 is
`b331d230f59f5229f98c69747b501e7015a4a979fb50bf2e7d3f40ab48021fae`.

## Spectron screen-panel and GLES-window residual anchors

The v120 pass translated seven compact methods that remained outside the
semantic map: one screen-panel polygon-font stub and six `TWindowGLES`
methods.

| 1.8 role | Source | Spectron target | Target class | Main evidence |
| --- | ---: | ---: | --- | --- |
| `TScreenPanelOpenGL_drawPolygonFont...` | `0x10c5e4` | `0x10ef34` | `SU3JfaCUmR` | empty hook in font sequence |
| `TWindowGLES_flipOffscreen_void` | `0x10cc10` | `0x10f560` | `StGQIaOlWk` | empty hook |
| `TWindowGLES_setSizeImpl_bool` | `0x10cc14` | `0x10f564` | `StGQIaOlWk` | empty hook |
| `TWindowGLES_TWindowGLES` | `0x10cc18` | `0x10f568` | `StGQIaOlWk` | D1 destructor |
| `TWindowGLES_TWindowGLES__2` | `0x10cc2c` | `0x10f57c` | `StGQIaOlWk` | D0 destructor |
| `TWindowGLES_createPixelBuffer...` | `0x10cc4c` | `0x10f59c` | `StGQIaOlWk` | 0x78 or 0x80 allocation and constructor call |
| `TWindowGLES_isNative_void` | `0x10cd70` | `0x10f6c0` | `StGQIaOlWk` | true result |

The target preserves the source class-local order. The two rendering hooks
are empty, the destructor pair has the same complete and deleting structure,
the factory forwards the same arguments to the target pixel-buffer class, and
the native-mode predicate returns true. The target factory's 0x80 allocation
versus the source 0x78 allocation matches the target pixel-buffer layout
change already observed elsewhere.

Every reviewed pair has matching normalized function metrics and shape hashes.
The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v120.i64`. The evidence is in
`artifacts/spectron_screen_panel_window_gles_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_screen_panel_window_gles_residual_anchors.py`. All
seven labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v120 database has 1,683 remaining default `sub_` names. Its
SHA-256 is
`c110ed3f38aad8b12296aa81cc6d780c2911d608fba5b895e0eaee7a2f48d955`.

## Spectron screen-panel renderer residual anchors

The v119 pass translated ten residual methods in the concrete renderer
sequence. The source `TPixelBufferOpenGL` and `TScreenPanelOpenGL` methods
map to the target `uzN1fatj75` and `SU3JfaCUmR` classes.

| 1.8 role | Source | Spectron target | Target class | Main evidence |
| --- | ---: | ---: | --- | --- |
| `TPixelBufferOpenGL_hasTexture_void` | `0x109c34` | `0x10c584` | `uzN1fatj75` | texture-handle test |
| `TScreenPanelOpenGL_getProjMatrix_void` | `0x109c44` | `0x10c594` | `SU3JfaCUmR` | eight-word projection copy |
| `TScreenPanelOpenGL_getModelMatrix_void` | `0x109c70` | `0x10c5c0` | `SU3JfaCUmR` | eight-word model copy |
| `TScreenPanelOpenGL_setProjMatrix_MatrixF_const` | `0x109c9c` | `0x10c5ec` | `SU3JfaCUmR` | projection store and flag |
| `TScreenPanelOpenGL_setModelMatrix_MatrixF_const` | `0x109ccc` | `0x10c61c` | `SU3JfaCUmR` | model store and flag |
| `TScreenPanelOpenGL_drawTriangleStripPanel...` | `0x109d2c` | `0x10c67c` | `SU3JfaCUmR` | empty hook |
| `TScreenPanelOpenGL_canUseShader_void` | `0x109d40` | `0x10c690` | `SU3JfaCUmR` | false result |
| `TScreenPanelOpenGL_setShader...` | `0x109d48` | `0x10c698` | `SU3JfaCUmR` | empty hook |
| `TScreenPanelOpenGL_clearShader_void` | `0x109d4c` | `0x10c69c` | `SU3JfaCUmR` | empty hook |
| `TScreenPanelOpenGL_setAlphaReference_float` | `0x109d64` | `0x10c6b4` | `SU3JfaCUmR` | `glAlphaFunc(516, value)` |

The matrix methods preserve the same complete 4 by 4 copies. Spectron's
projection and model regions move from offsets 40 and 104 to 56 and 120, and
the two validity bytes move from 36 and 37 to 53 and 54. The texture-handle
predicate moves by the same four-byte layout increment. This is consistent
with the target class layout, not a different renderer role.

The triangle-strip method is empty in both builds. The shader capability
method returns false, the shader setter and clearer are empty, and the alpha
wrapper calls the same OpenGL function with the same constant. The adjacent
`clearStates` and `setBlendColor` rows already have earlier renderer labels,
so the gaps at their source addresses are intentional rather than missed
rows.

Every reviewed pair has matching normalized function metrics and shape hashes.
The target methods were already present as non-default mangled functions, and
none was in the semantic map. The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v119.i64`. The evidence is in
`artifacts/spectron_screen_panel_renderer_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_screen_panel_renderer_residual_anchors.py`. All ten
labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v119 database has 1,683 remaining default `sub_` names. Its
SHA-256 is
`d57ae1011d866d392898e057f6a1cc309955755a8c5175a5ca07c66644fdaa27`.

## Spectron dummy-panel residual anchors

The v118 pass completed 14 residual methods at the boundary between the
panel-interface base and the portable dummy-panel implementation.

| 1.8 role | Source | Spectron target | Target class |
| --- | ---: | ---: | --- |
| `addModificationClipped` | `0x103b40` | `0x1061a8` | `oMhmIajzmW` |
| `addModification` | `0x103b44` | `0x1061ac` | `oMhmIajzmW` |
| `drawArrays` | `0x103b48` | `0x1061b0` | `oMhmIajzmW` |
| `drawImage` | `0x103b4c` | `0x1061b4` | `HtZ2_aJk7E` |
| `drawLine` | `0x103b50` | `0x1061b8` | `HtZ2_aJk7E` |
| `fillRectangle` | `0x103b54` | `0x1061bc` | `HtZ2_aJk7E` |
| `drawDrawingPanel` | `0x103b58` | `0x1061c0` | `HtZ2_aJk7E` |
| `drawTriangleStripPanel` | `0x103b5c` | `0x1061c4` | `HtZ2_aJk7E` |
| `drawText` | `0x103b60` | `0x1061c8` | `HtZ2_aJk7E` |
| `createDrawingPanel` | `0x103b64` | `0x1061cc` | `HtZ2_aJk7E` |
| `setTransformedClippingRectangle` | `0x103b6c` | `0x1061d4` | `HtZ2_aJk7E` |
| `getTransformedClippingRectangle` | `0x103b70` | `0x1061d8` | `HtZ2_aJk7E` |
| `TDummyPanel` D1 | `0x103b8c` | `0x1061f4` | `HtZ2_aJk7E` |
| `TDummyPanel` D0 | `0x103ba0` | `0x106208` | `HtZ2_aJk7E` |

The first three methods are empty `TPanelInterface` hooks. The following
dummy-panel methods are also empty except for the zero-return factory and the
four-zero rectangle getter. Their target signatures and the unchanged local
order identify `HtZ2_aJk7E` as the corresponding portable dummy-panel class,
not the active OpenGL renderer.

The final two rows are the complete and deleting destructor forms. Both target
methods install the `HtZ2_aJk7E` vtable and call the `oMhmIajzmW` base
destructor. The deleting form then releases the object. All 14 pairs have
matching normalized function metrics and shape hashes.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v118.i64`. The evidence is in
`artifacts/spectron_dummy_panel_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_dummy_panel_residual_anchors.py`. All 14
labels reopened with zero failures. The full translation reopen check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v118 database has 1,683 remaining default `sub_` names. Its
SHA-256 is
`de9c45f75c839c7cbbe802544129f2021e29f1aec02f0543d374df89a777fbbf`.

## Spectron panel virtual and renderer residual anchors

The v117 pass translated 23 compact panel and renderer methods that were not
covered by the size-based semantic map. The source and target method blocks
are tied together by exact function metrics, class-local order, signatures,
and pseudocode behavior.

The 18 base `TPanelInterface` rows map as follows:

| 1.8 role | Source | Spectron target |
| --- | ---: | ---: |
| `isNative` | `0xfe308` | `0x100970` |
| `drawTextureStretched` | `0xfe310` | `0x100978` |
| `setArrays` | `0xfe314` | `0x10097c` |
| `drawElements` | `0xfe318` | `0x100984` |
| `requestState` | `0xfe31c` | `0x100988` |
| `clearStates` | `0xfe320` | `0x10098c` |
| `setBlendMode` | `0xfe324` | `0x100990` |
| `setBlendColor` | `0xfe328` | `0x100994` |
| `setAlphaReference` | `0xfe32c` | `0x100998` |
| `canUseShader` | `0xfe330` | `0x10099c` |
| `setShader` | `0xfe338` | `0x1009a4` |
| `clearShader` | `0xfe33c` | `0x1009a8` |
| `reloadDefaultShaders` | `0xfe340` | `0x1009ac` |
| `freeResources` | `0xfe344` | `0x1009b0` |
| `getProjMatrix` | `0xfe348` | `0x1009b4` |
| `getModelMatrix` | `0xfe398` | `0x100a04` |
| `setProjMatrix` | `0xfe3e8` | `0x100a54` |
| `setModelMatrix` | `0xfe3ec` | `0x100a58` |

The target adds a four-byte `oMhmIajzmW` method at `0x100980` after
`setArrays`. Its extra integer arguments distinguish it from every 1.8 row,
so it remains an explicit 2.2-only gap. The later rows resume at
`drawElements`, which is why the target address sequence is not a simple
constant offset.

The remaining five rows are the inherited flush hook, panel tail hooks, and
the renderer loop:

| 1.8 role | Source | Spectron target | Target class |
| --- | ---: | ---: | --- |
| `TDrawingPanelPort_flushTexture` | `0xfe3f0` | `0x100a5c` | `OYYKfaPU7R` |
| `TPanelInterface_captureScreen` | `0x102760` | `0x104dc8` | `oMhmIajzmW` |
| `TDrawingPanelPort_setPixels` | `0x102768` | `0x104dd0` | `OYYKfaPU7R` |
| `TDrawingPanelPort_getPixels` | `0x10276c` | `0x104dd4` | `OYYKfaPU7R` |
| `TGraphicOperation_flushTextures` | `0x1030a4` | `0x10570c` | `s40xgamwex` |

The first 22 rows are no-op hooks or identity and zero-return helpers. The
last row is a real renderer operation. It walks the drawing-panel list and
calls each panel's texture-flush virtual. The source uses a list helper and
vtable slot 320, while Spectron uses its renamed list helper and slot 328.
The body shape is still an exact 108/27/3 match, so the slot change is best
explained by the target class layout.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v117.i64`. The evidence is in
`artifacts/spectron_panel_virtual_renderer_residual_manual_translation_anchors_20260826.json`,
generated by
`tools/generate_spectron_panel_virtual_renderer_residual_anchors.py`. All 23
labels reopened with zero failures. The full translation reopen check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v117 database has 1,683 remaining default `sub_` names. Its
SHA-256 is
`82f78696b705112585e04e2b3c522b88bed026d9d281bc4fdc9a7fff085ad5c4`.

## Spectron animation and palette residual anchors

The v116 pass reviewed the two remaining base `TImageAnimation` hooks and the
deleting-destructor wrappers for the target MNG and palette classes.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TImageAnimation_makeNextBitmap_void` | `0x120610` | `0x123148` | zero-return base hook |
| `TImageAnimation_parsePicture_void` | `0x120618` | `0x123150` | zero-return base hook |
| `TMNGAnimation_TMNGAnimation__2` | `0x11f9b8` | `0x1224f0` | MNG deleting destructor |
| `TPalette_TPalette__2` | `0x12066c` | `0x1231a4` | palette deleting destructor |

The two base hooks have exact 8/2/1 bodies and return zero in both builds.
Their target methods are in the reviewed `n_rGfa49jO` image-animation class.
The derived `_5EhmbQbtm` class still contains the real MNG decoder and
animation-step construction.

The two deleting destructors have exact 32/8/2 shapes with one call. Each
target wrapper calls its matching class destructor and then `operator delete`.
The target names `_ZN10_5EhmbQbtmD0Ev` and `_ZN10NLT0HaSwmED0Ev` also provide a
direct class-local check against the previously translated D1 or D2 methods.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v116.i64`. The evidence is in
`artifacts/spectron_animation_palette_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_animation_palette_residual_anchors.py`.
All four labels reopened with zero failures, and the full translation check
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v116 database has 1,683 remaining default `sub_` names. Its
SHA-256 is
`e0befd5c98459fd191889bfe921fb9c2e1caa7d372a8e0feceed8ce2ffe69e77`.

## Spectron pixel-buffer and bitmap lifecycle correction

The v115 pass corrected one medium-confidence class collision from the
automatic semantic report and reviewed the two destructor pairs separately.
The original shape-only candidate had assigned the source pixel-buffer
destructor to the target bitmap destructor. That candidate was review-only and
was never applied to the translated IDA copy.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPixelBuffer_TPixelBuffer` | `0x104e5c` | `0x1074e4` | `uSjUgask_P` destructor and pixel cleanup |
| `TPixelBuffer_TPixelBuffer__2` | `0x104e8c` | `0x107514` | `uSjUgask_P` deleting destructor |
| `TBitmap_TBitmap` | `0x112e24` | `0x1156f4` | `Fcx_gaoydV` destructor and image cleanup |
| `TBitmap_TBitmap__2` | `0x112e54` | `0x115724` | `Fcx_gaoydV` deleting destructor |

The target has distinct destructor pairs for `uSjUgask_P` and `Fcx_gaoydV`.
The first pair calls the target pixel cleanup method and clears the target
string. The second pair calls the bitmap image cleanup method and clears its
own string. The deleting forms call their matching D1 or D2 form and then
`operator delete`. Both source and target pairs retain exact 48/12/2 and
32/8/2 shapes, while the cleanup callees establish the class identity.

The correction is kept separate from the original automatic map so the
shape-only result remains reproducible. The evidence file marks the old
medium-confidence collision as superseded and records the four corrected
class-local rows. It does not change the high-confidence map count.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v115.i64`. The evidence is in
`artifacts/spectron_pixelbuffer_bitmap_lifecycle_correction_anchors_20260826.json`,
generated by `tools/generate_spectron_pixelbuffer_bitmap_lifecycle_anchors.py`.
All four labels reopened with zero failures, and the full translation check
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v115 database has 1,683 remaining default `sub_` names. Its
SHA-256 is
`a0272f3a6d1a8acd0e700e6924b99a2faa93f87151f47581385cbe6bdadb932e`.

## Spectron TPixelBuffer residual anchors

The v114 pass reviewed ten small methods in the target `uSjUgask_P` pixel
buffer class. The surrounding constructor, pitch, destruction,
compatible-bitmap, kept-bitmap, and pixel-allocation methods were already
translated, which makes this a useful local class-order check.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPixelBuffer_setPixelsNoDestroy_uchar_int_int` | `0x104c90` | `0x107318` | pointer and dimension stores |
| `TPixelBuffer_setPalette_TPalette_const` | `0x104ca8` | `0x107330` | palette pointer store |
| `TPixelBuffer_unsetPixels_void` | `0x104eac` | `0x107534` | pointer clearing |
| `TPixelBuffer_setFormat_int` | `0x104eb8` | `0x107540` | format store |
| `TPixelBuffer_getPixels_void` | `0x105084` | `0x10770c` | allocation helper and pointer return |
| `TPixelBuffer_hasTexture_void` | `0x1050a4` | `0x10772c` | zero-valued base predicate |
| `TPixelBuffer_createTexture_void` | `0x1050ac` | `0x107734` | empty base hook |
| `TPixelBuffer_updateTexture_void` | `0x1050b0` | `0x107738` | empty base hook |
| `TPixelBuffer_updateTexture_int_int_int_int` | `0x1050b4` | `0x10773c` | indirect rectangle update |
| `TPixelBuffer_bindTexture_int` | `0x1050d4` | `0x10775c` | empty base hook |

The first four pairs have exact size, instruction, and block counts. Their
target field offsets differ because the `uSjUgask_P` layout is not identical,
but the pseudocode preserves the pointer, dimension, palette, and format
roles. The target `getPixels` calls `gnoUnb962I` before returning its pixel
pointer, matching the source call to `createPixels`. Both `hasTexture` methods
return zero. Both versions leave the base create, no-argument update, and
bind hooks empty. The four-argument update overload has the same 32/8/1 shape
and one indirect vtable call in both versions.

The three empty hooks are supported by their position between the exact
`getPixels` and already translated derived texture methods, as well as by the
paired overloaded update names in the target. They are not being presented as
OpenGL implementations. The actual OpenGL work remains in the derived
`TPixelBufferOpenGL` class.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v114.i64`. The evidence is in
`artifacts/spectron_pixelbuffer_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_pixelbuffer_residual_anchors.py`. All
ten labels reopened with zero failures, and the full translation check passed
with 3,641 high-confidence labels and zero failures across 11,679 functions.
The v114 database has 1,683 remaining default `sub_` names. Its SHA-256 is
`62362bfe045dfa107edc90dc3ca501baec50eaf6477b949f9e74be888c6fd725`.

## Spectron sound-runtime anchors

The v113 pass reviewed three residual audio methods. The target sound manager
is `IUKzgam4Gy`; the Java effect implementation is `QPh5pbnC3y`.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TSounds_play_impl_TString_const_bool_bool_double_double` | `0xe135c` | `0xe1f34` | extension, volume, cache, and playback flow |
| `TSounds_script_setSoundPitchByNote` | `0xe2858` | `0xe3440` | twelve-note table and `powf` pitch ratio |
| `TSoundEffectJava_play_void` | `0xe31d0` | `0xe3dc0` | Java method lookup and sound playback |

The dispatcher changes from 1,312/328/72 with 42 calls to 1,328/332/72 with
44 calls. Its source and target pseudocode follow the same sound path:
lower-case and classify the extension, select the music, radio, or effect
volume, initialize sounds, test player capability, download missing files,
look up or create cached effects, stop or restart music, and update the
effect's playback state. The target's obfuscated string and file wrappers are
different, but the sequence and the `.mid`, `.wav`, and compressed-audio
checks remain visible.

The note helper changes from 548/135/21 with 26 calls to 556/137/21 with 26
calls. It retains the same note list, two-character split, octave conversion,
semitone calculation, and `powf(2, delta / 12)` call. The target was a
default `sub_E3440` name before this anchor was applied.

The Java method changes from 720/178/20 with 12 calls to 676/168/19 with 9
calls. Both resolve `startSound([BII)V`, strip the base data folder from the
resource name when applicable, obtain and release a Java byte array, calculate
the sound channels, enforce the short playback interval, and store the
playing flag and timestamp. The source `steps` exception is not present in
the target body, so it remains a noted target-version difference.

The source `TSoundEffect` constructor at `0xe0dc0` was reviewed but not
renamed. The target effect class is visible from the dispatcher return type,
but its stripped constructor was not uniquely isolated. The evidence file
therefore contains only the three high-confidence rows above.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v113.i64`. The evidence is in
`artifacts/spectron_sound_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_sound_runtime_anchors.py`. All three
labels reopened with zero failures, and the full translation check passed
with 3,641 high-confidence labels and zero failures across 11,679 functions.
The v113 database has 1,683 remaining default `sub_` names. Its SHA-256 is
`b8d25d41ea73f217003a7e39799ce9f124f2452c12f4df694b22c3caf4c70b37`.

## Spectron TWindow residual anchors

The v112 pass reviewed two small methods in the target `LJyzga9Pwy` window
class, beside the previously translated input and window lifecycle helpers.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TWindow_onCloseQuery_void` | `0x1066e8` | `0x1090b4` | main-window guard and shutdown state |
| `TWindow_createPixelBuffer_TString_const_int_int_int` | `0x1068a0` | `0x109048` | 0x78-byte allocation and constructor call |

The close-query body changes from 72/18/3 with one call to 88/22/3 with one
call. Both compare against the main-window global, prepare the client
environment for shutdown, and set the application-close state. Spectron also
writes a second shutdown-state value of `2`, which is recorded as a
target-version difference.

The pixel-buffer factory is an exact 100/25/1 and two-call shape in both
versions. Both allocate 0x78 bytes and pass the window, name, dimensions, and
format or flags to the window-backed pixel-buffer constructor. The target
uses the `uSjUgask_P` class wrapper.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v112.i64`. The evidence is in
`artifacts/spectron_window_residual_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_window_residual_anchors.py`. Both labels
reopened with zero failures, and the full translation check still passed with
3,641 high-confidence labels and zero failures across 11,679 functions. The
v112 database has 1,684 remaining default `sub_` names. Its SHA-256 is
`d8c782e2040a57c3bae8e406c90e0d94d7bc32fef82b203a33621fcd0a6c9209`.

## Spectron GIF decoder anchor

The v111 pass reviewed the changed `TBitmap` GIF decoder in the target's
`Fcx_gaoydV` class. It is called by the v110 bitmap extension dispatcher.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TBitmap_readGIF_TStream` | `0x150a38` | `0x153578` | GIF records, palettes, and animation steps |

The decoder changes from 1,096/274/50 with 27 calls to 1,840/457/66 with 67
calls. Both open the stream, process image and extension records, decode
transparency and frame delay, convert the palette to RGBA, allocate and fill
animation steps, insert them into the bitmap list, close the file, and build
the first bitmap from the first frame.

Spectron adds the retry or diagnostic flag, `GifErrorString` messages for
numbered failure points, and a success log containing the animation-step
count. These additions account for the larger body while the decoder's
allocation cleanup, row-order state machine, palette byte order, and final
bitmap setup remain aligned with 1.8.

The label is recorded as a `v18_` name in
`analysis/spectron_libqplay_translated_v111.i64`. The evidence is in
`artifacts/spectron_gif_decoder_manual_translation_anchor_20260826.json`,
generated by `tools/generate_spectron_gif_decoder_anchor.py`. It reopened with
zero failures, and the full translation check still passed with 3,641
high-confidence labels and zero failures across 11,679 functions. The v111
database has 1,684 remaining default `sub_` names. Its SHA-256 is
`aa225a0d07cbd7f7ab3e015762c3d9ab14e4c6c46b6154b0bf11ef6852d3d64c`.

## Spectron panel and bitmap-loader anchors

The v110 pass reviewed four methods spanning panel construction and bitmap
resource loading. The target panel implementation is in `oMhmIajzmW`, the
bitmap implementation is in `Fcx_gaoydV`, and the resource loader is in
`kM00HafgtE`.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TPanelInterface_TPanelInterface_TWindow_TString_const` | `0x103fcc` | `0x106634` | window pointer and vtable setup |
| `TBitmap_loadBitmap_TStream_TString_const` | `0x114be8` | `0x1174b8` | extension and decoder selection |
| `TBitmapLoader_forceRedownload_TResourceObject` | `0x114f80` | `0x1178e8` | download reset and restart |
| `TBitmapLoader_findImageFile_TString_const` | `0x114fbc` | `0x117988` | resource lookup and extension fallback |

The panel constructor changes from 64/16/1 with one direct call to 96/24/1
with three calls. Both construct the named panel object, retain the owning
window pointer, and install the vtable. The target exposes a temporary
`C8THgaTQxF` to `CanTfaz6bZ` conversion before constructing `J7zOgaf09K`.

The bitmap dispatcher changes from 352/88/19 with eight calls to 504/125/15
with 20 calls. Both route `.png` and `.mng`, `.bmp` and `.dib`, `.gif`, `.jpg`
and `.jpeg`, and `.tga` to the same decoder families. Spectron adds the
`PROBLEM reading gif=` diagnostic and retries a failed GIF read in a second
mode. The retry is recorded as a target-version difference, not treated as a
new source role.

The force-redownload helper changes from 60/15/4 with two calls to 160/40/4
with nine calls. Both remove the requested file from the client, ignore the
existing download, and start the replacement download. The target's extra
calls are temporary string operations and rebuilt `w6qzgacqqy` and
`uq9xgaUxlx` wrappers.

The image lookup helper changes from 364/90/19 with 15 calls to 392/97/19
with 17 calls. Both reject an empty or zero name, try the level resource,
probe configured image extensions, request a download on failure, check the
resource load state, and refresh stale resource data. The target keeps this
order through `f6WHgaQkAF`, `wiULgacZUI`, `bNZvga2Awv`, and `uq9xgaUxlx`.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v110.i64`. The evidence is in
`artifacts/spectron_panel_bitmap_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_panel_bitmap_anchors.py`. All four
labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v110 database has 1,684 remaining default `sub_` names. Its
SHA-256 is
`1a10cd6b7c5a586ecdd8c6f475c753dbbdc9ac5d21b74e3590758212fe8a2129`.

## Spectron HTML color and image-animation anchors

The v109 pass reviewed four compact methods connecting the renderer's HTML
color registry and image-animation lifecycle. The target functions are in
the obfuscated `nDIHgaJ9nF` and `n_rGfa49jO` classes.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THTMLColors_initHTMLColorList_void` | `0x11b1f0` | `0x11dcf8` | color table iteration and dual-list insertion |
| `TImageAnimation_TImageAnimation_void` | `0x11b508` | `0x11e030` | two palettes, frame list, and default fields |
| `TImageAnimation_TImageAnimation` | `0x11f898` | `0x1223c8` | buffer release and palette cleanup |
| `TImageAnimation_TImageAnimation__2` | `0x11f8dc` | `0x122414` | deleting-destructor call chain |

The HTML color initializer changes from 272/67/3 with nine direct calls to
304/76/3 with 11 calls. Both publish a one-time flag, allocate the hash and
string lists, walk the embedded color table, create each color object, and
insert it into both lists. The target makes its `C8THgaTQxF` to `CanTfaz6bZ`
conversion explicit before constructing `J7zOgaf09K` and adding it through
`KKhLga4xoI` and `vy1JgaKVkH`.

The image-animation constructor changes from 140/35/1 with three calls to
148/37/1 with three calls. Both install the vtable, construct two palettes,
initialize dimensions and flags, create the small frame list, and clear the
optional state. The target's `NLT0HaSwmE` palette and rebuilt string wrappers
shift field offsets, but the initialization order remains recognizable.

The complete destructor changes from 68/17/4 with two calls to 76/19/4 with
three calls. Both free the optional bitmap buffer, restore the vtable, destroy
both palettes, and clear the backing string. The deleting destructor remains
an exact 32/8/2 one-call wrapper around the complete destructor and object
free.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v109.i64`. The evidence is in
`artifacts/spectron_image_html_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_image_html_anchors.py`. All four labels
reopened with zero failures, and the full translation check still passed with
3,641 high-confidence labels and zero failures across 11,679 functions. The
v109 database has 1,684 remaining default `sub_` names. Its SHA-256 is
`50b930130628290213ede4905c578676ca3996280c40ac8d9bb8527e44d5695d`.

## Spectron TWindow input anchors

The v107 pass reviewed two remaining methods from the source `TWindow` input
path. The target methods remain in the obfuscated `LJyzga9Pwy` class beside
the translated focus, pointer, wheel, and window-state helpers.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TWindow_invokeMouseEvent_int_int_int_int_double_double_int` | `0x107334` | `0x109bac` | canvas dispatch, cursor adjustment, and input fallback |
| `TWindow_onKeyEvent_int_int_TString_const_int_bool_bool` | `0x107728` | `0x109f64` | special-key mapping, bindings, and control events |

The mouse dispatcher changes from 548/137/24 with nine direct calls to
488/122/23 with eight calls, measured as bytes, instructions, and basic
blocks. Both obtain the canvas, translate the window event type into the same
mouse codes, map button values, adjust coordinates when the cursor is locked,
and send the event through the canvas before falling back to the input object.
The target uses `LJyzga9Pwy::ggIZgagRwU`, `SsrLga3IwI::i2GxgaCPXw`, and the
target canvas or input dispatch wrappers.

The key dispatcher changes from 516/129/22 with nine calls to 792/195/23 with
30 calls. Both normalize the special key values 16, 17, and 18, choose the
modifier and press-state codes, dispatch to the canvas, check main-window
control bindings, and invoke `onControlKeyDown` or `onControlKeyUp` when the
scan code is 4. Spectron adds a diagnostic `onKeyEvent` log and makes the
temporary event-name string construction explicit. The extra target calls do
not change the key state or control-event branches.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v107.i64`. The evidence is in
`artifacts/spectron_window_input_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_window_input_anchors.py`. Both labels
reopened with zero failures, and the full translation check still passed with
3,641 high-confidence labels and zero failures across 11,679 functions. The
v107 database has 1,684 remaining default `sub_` names. Its SHA-256 is
`53c6c656d4f44bf6b74977e9a6441658bf0bd502f1013d387b078098caac3dee`.

## Spectron font and resource anchors

The v106 pass reviewed six remaining methods from the source font and
resource classes. The target methods stay in the obfuscated `TZf6gaQ3S_`
font, `Kv6ugas5Mu` font-manager, `KcKRganuPN` font-options, and
`fUWH_a_9zm` font-data clusters.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TFont_TFont_TString_const` | `0x10d348` | `0x10fcb4` | glyph-cache construction and field defaults |
| `TFont_makeFontTexture_void` | `0x10d8c4` | `0x110274` | bitmap generation, texture creation, and upload |
| `TFontManager_findFontFile_TString_const_TString_const` | `0x10e998` | `0x111368` | `.ttf`, `it.ttf`, system, and resource fallback |
| `TFontManager_initStaticVars_void` | `0x10f660` | `0x111f24` | font and missing-font registry publication |
| `TFontOptions_script_addutf8fontrange` | `0x10f81c` | `0x1120b8` | range validation and list insertion |
| `TFontData_TFontData_TString_const` | `0x110c00` | `0x11347c` | normalized name and glyph-data list setup |

The TFont constructor changes from 156/39/3 with two direct calls to
188/47/3 with four calls, measured as bytes, instructions, and basic blocks.
Both call the hash-list base, initialize 256 glyph records, install the
derived vtable, and reset the same cache and texture fields. Spectron makes
the temporary `C8THgaTQxF` to `CanTfaz6bZ` conversion explicit.

The texture builder changes from 212/52/3 with eight calls to 240/59/3 with
ten calls. Both call the font bitmap generator, stop when it returns no
bitmap, create a texture named with the `Font ` prefix, set the same texture
flags, upload the generated bitmap, and record the current high-precision
time. The target calls the previously translated `TZf6gaQ3S_` bitmap helper
and `_WevgakbUu` texture helper.

The font-file resolver changes from 828/207/15 with 52 calls to 560/140/10
with 34 calls. Despite the smaller target body, the pseudocode preserves the
same search order: derive the base and style suffix, try the `.ttf` name,
try the `it.ttf` fallback when appropriate, check the system-font directory,
and fall back to the resource lookup. Both return an empty string when no
candidate exists. The target's `C8THgaTQxF` and `f6WHgaQkAF` wrappers account
for the changed call inventory.

The font-manager static initializer is a version-specific case. The source
is 116/29/1 with six calls and initializes the `/system/fonts/` string, the
font hash list, and the missing-font list. The target is 76/19/1 with four
calls and publishes the corresponding hash list and string list, but does not
seed that path literal in this function. The path is therefore not claimed to
have the same initialization location in Spectron.

The UTF-8 range helper changes from 232/58/6 with nine calls to 200/50/4
with eight calls. Both reject invalid ranges, normalize or reduce the font
path, allocate a four-field range record, and append it to the global range
list. The target retains the same `KcKRganuPN` state and uses the obfuscated
list and filename helpers. The font-data constructor changes from 160/40/1
with five calls to 196/49/1 with seven calls. Both normalize the list key,
construct the hash-list base, store the requested name, clear resource fields,
and allocate the 0x18-byte glyph-data list.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v106.i64`. The evidence is in
`artifacts/spectron_font_runtime_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_font_runtime_anchors.py`. All six
labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v106 database has 1,684 remaining default `sub_` names. Its
SHA-256 is
`f4089384f3663f387e9838fa1b4f6ad4932b003b163940ddd1a78e0047729c52`.

## Spectron TColorManager anchors

The v105 pass reviewed five remaining methods from the source
`TColorManager` class. The target methods are in the obfuscated
`X7ZxganTcx` class, around the already translated color lookup and push
helpers. Their shared global matrix list is named `UuAMgaMjuJ` in the target
decompiler.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TColorManager_isActivated_void` | `0xfdacc` | `0x100134` | global list guard and non-empty test |
| `TColorManager_getTop_void` | `0xfdaf4` | `0x10015c` | final list entry lookup |
| `TColorManager_clear_void` | `0xfdb40` | `0x1001a8` | delete every transform and clear |
| `TColorManager_pop_void` | `0xfdf2c` | `0x100594` | remove and delete the final transform |
| `TColorManager_initStaticVars_void` | `0xfdf94` | `0xffafc` | matrix-list allocation and publication |

The activation test is an exact 40/10/3 body, measured as bytes, instructions,
and basic blocks, with no direct calls in either build. Both return true only
when the target global matrix list exists and has a positive count. The top
accessor is also an exact 76/19/4 body with one direct list-index call. It
keeps the same null and count guards and returns the last entry through the
target `vy1JgaKVkH` indexed-list wrapper.

The cleanup method is an exact 116/29/7 body with two direct calls. It walks
the list, deletes every stored transform, and clears the list. The target
spells those operations through its indexed-list wrapper and `operator delete`.
The pop method is an exact 104/26/5 body with two direct calls. It keeps the
same empty-list guard, removes the final entry, and deletes that transform.
The target uses its `Delete` and indexed-access wrappers for this operation.

The static initializer is an exact 68/17/1 body with one direct allocation
call. Both builds allocate an 0x18-byte list, clear its fields, install the
list vtable, and publish it through the class global. The target initializer is
`_Z10HnexgaAIzwv`, and the target class and global names are recorded as
obfuscated implementation context rather than presented as restored source
symbols.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v105.i64`. The evidence is in
`artifacts/spectron_color_manager_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_color_manager_anchors.py`. All five
labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures across 11,679
functions. The v105 database has 1,685 remaining default `sub_` names. Its
SHA-256 is
`705878c4d7ceaf711e1a93e80bc6bed3449d0af9d28ac3c38c7f5f4ca69dc36c`.

## Spectron TBitmapArrayHolder anchors

The v104 pass reviewed five remaining methods from the source
`TBitmapArrayHolder` class. The target methods are in the obfuscated
`r1dvgaPpTu` class and sit beside the already translated rectangle and file
update helpers.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TBitmapArrayHolder_TBitmapArrayHolder_TString_const` | `0xfd524` | `0xffb40` | base construction and null rectangle list |
| `TBitmapArrayHolder_TBitmapArrayHolder__2` | `0xfd600` | `0xffc44` | deleting destructor |
| `TBitmapArrayHolder_calcRects_void` | `0xfd620` | `0xffc64` | color-run rectangle discovery |
| `TBitmapArrayHolder_getBitmapArrayRects_TString_const` | `0xfd9d4` | `0x100034` | normalized lookup and lazy creation |
| `TBitmapArrayHolder_initStaticVars_void` | `0xfda9c` | `0x100104` | registry initialization |

The string constructor changes from 48/12/1 with one call to 88/22/1 with
three calls. Both construct the hash-list-object base, set the rectangle list
to null, and install the derived vtable. The target adds explicit
`CanTfaz6bZ` conversion and cleanup. The deleting destructor remains exact at
32/8/2 with one call and maps to the target D0 ABI wrapper.

The rectangle calculator changes from 804/201/38 with 11 calls to 832/208/38
with 13 calls. Both load the Graal bitmap, test its first pixel, clear prior
rectangles, scan horizontal and vertical color runs, and append discovered
rectangles. The target's extra calls come from typed string and list wrappers.
The rectangle lookup changes from 200/50/7 with nine calls to 208/52/7 with
eight calls, while preserving normalized filename lookup, hash lookup, lazy
holder creation, registry insertion, list return, and temporary cleanup.
The static initializer is exact at 48/12/1 with two calls and publishes the
same global hash-list registry.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v104.i64`. The evidence is in
`artifacts/spectron_bitmap_array_holder_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_bitmap_array_holder_anchors.py`. All
five labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures. The v104 database
has 11,679 functions and 1,685 remaining default `sub_` names. Its SHA-256 is
`a2f163408c9fb6e29863efd888d98597ae87cdb514335fdc27647e4b9f5f0fe1`.

## Spectron TDrawTexture anchors

The v103 pass reviewed four remaining methods from the source `TDrawTexture`
class. The target methods are in the obfuscated `NVxhJah9mI` class and remain
in the local sequence around its translated load, constructor, destructor,
repeat, and draw methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TDrawTexture_initializeTexturesList` | `0xe0770` | `0xe0754` | texture-list allocation and global publish |
| `TDrawTexture_freeResources_void` | `0x108d1c` | `0x10b66c` | indexed cleanup and delete |
| `TDrawTexture_reloadTextures_void` | `0x108d7c` | `0x10b6cc` | indexed reload and load |
| `TDrawTexture_bindTexture_void` | `0x108e60` | `0x10b7b0` | OpenGL bind wrapper |

The static initializer is exact at 68/17/1 with one direct allocation call.
It creates the same 0x18-byte list, clears its fields, installs the list
vtable, and publishes the global. The target was still named `sub_E0754` and
is now labeled with the readable v18 role. Its obfuscated global is
`NVxhJah9mI::w_AhJajKpI`.

The cleanup and reload methods are each exact at 96/24/3 with two direct
calls. Both iterate the same global list and use the indexed list accessor.
Cleanup calls the target deleting texture method, while reload calls the
target load method. The bind helper is exact at 12/3/2 with no direct calls in
the feature export. It calls `glBindTexture` with target 3553 and the same
texture ID field.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v103.i64`. The evidence is in
`artifacts/spectron_draw_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_draw_texture_anchors.py`. All four labels
reopened with zero failures, and the full translation check still passed with
3,641 high-confidence labels and zero failures. The v103 database has 11,679
functions and 1,685 remaining default `sub_` names. Its SHA-256 is
`bb0cb110ad0926c183bccc00d71d084ba5f5220945f56d70950d0f7bb300808e`.

## Spectron TDrawingPanelTexture anchors

The v102 pass reviewed five remaining methods from the source
`TDrawingPanelTexture` class. The target methods are in the obfuscated
`BP3Kfa2PcS` class and preserve the local method order around the panel-port
and OpenGL texture helpers.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TDrawingPanelTexture_TDrawingPanelTexture` | `0x1082e8` | `0x10ac38` | complete destructor and base cleanup |
| `TDrawingPanelTexture_TDrawingPanelTexture__2` | `0x10832c` | `0x10ac7c` | deleting destructor |
| `TDrawingPanelTexture_TDrawingPanelTexture_TWindow_int_int_int_int` | `0x1084d0` | `0x10ae20` | window-backed construction |
| `TDrawingPanelTexture_getTextureWidth_void` | `0x108500` | `0x10ae50` | virtual update and width read |
| `TDrawingPanelTexture_getTextureHeight_void` | `0x108540` | `0x10ae90` | virtual update and height read |

The complete destructor is an exact 68/17/4 body with one direct call in each
build. Both release the panel texture when present, clear the stored handle,
and invoke the panel-port base destructor. The target spells the same ABI role
as D1, with D2 as its alternative name. The deleting destructor is exact at
32/8/2 with one call and maps to the target D0 variant, which calls D1 and
`operator delete`.

The window constructor is exact at 48/12/1 with one call. It forwards the
window and four dimensions to the panel-port base, clears the texture handle,
and installs the derived vtable. The target uses C1 spelling and the
obfuscated base class `OYYKfaPU7R`.

The width and height methods are exact at 64/16/3 with one call each. Both
invoke the virtual texture update method, return the corresponding field from
the stored texture object, and return zero when the object is absent. The
target vtable slot and method names differ, but the branch structure and field
offsets are unchanged.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v102.i64`. The evidence is in
`artifacts/spectron_drawing_panel_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_drawing_panel_texture_anchors.py`. All
five labels reopened with zero failures, and the full translation check still
passed with 3,641 high-confidence labels and zero failures. The v102 database
has 11,679 functions and 1,686 remaining default `sub_` names. Its SHA-256 is
`387015ee8aa3b32836bec8914d471f111ea310780a9da2dd2d5349fcde98f650`.

## Spectron TTexture anchors

The v101 pass reviewed ten remaining methods from the source `TTexture` class.
The target methods are in the obfuscated `_WevgakbUu` class and occupy the
corresponding local method sequence between its bitmap helpers and the
following `TDrawTexture` class.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TTexture_getWidth_void` | `0x10540c` | `0x107a94` | lazy bitmap width and fallback |
| `TTexture_getHeight_void` | `0x105474` | `0x107afc` | lazy bitmap height and fallback |
| `TTexture_createTexture_void` | `0x10566c` | `0x107cf4` | GPU allocation and update choice |
| `TTexture_getTextureWidth_void` | `0x105794` | `0x107e34` | lazy GPU width read |
| `TTexture_getTextureHeight_void` | `0x1057cc` | `0x107e6c` | lazy GPU height read |
| `TTexture_TTexture__2` | `0x1058e0` | `0x107f80` | deleting destructor |
| `TTexture_TTexture_TWindow_TString_const` | `0x105ad0` | `0x108170` | constructor initialization order |
| `TTexture_getGraalBitmap_TString_const_bool_bool` | `0x105d5c` | `0x1084cc` | lookup, reload flags, and virtual load |
| `TTexture_freeResources_void` | `0x105e54` | `0x108644` | image registry clear |
| `TTexture_initStaticVars_void` | `0x1065e4` | `0x108dd4` | image and animation registry setup |

The width and height methods have the same 104/26/8 shape and one direct call
in each build. Both check the loaded bitmap dimensions, return one for a zero
dimension, use stored fallback dimensions for an already loaded object, and
invoke the virtual loader before returning zero when no bitmap is available.
The GPU width and height accessors also retain their exact 56/14/3 shape and
lazy-load the texture before reading its dimension fields.

The allocator changes from 152/38/10 with one recorded call to 176/44/10 with
four calls. Both allocate the GPU texture only when the window, bitmap, and
texture slot are valid, then select the update mode from the bitmap animation
state and reload flag. The target's extra calls are explicit temporary string
conversion and cleanup operations.

The deleting destructor remains an exact 32/8/2 wrapper. The target spelling
`_ZN10_WevgakbUuD0Ev` is the deleting ABI variant that calls the target D1
destructor and `operator delete`. The window constructor changes from
252/63/1 with five calls to 280/70/1 with seven calls, while preserving name
derivation, base construction, window and name storage, bitmap and GPU reset,
lazy-load flags, and timing initialization. The target exposes a C1 spelling
and uses explicit `C8THgaTQxF` and `CanTfaz6bZ` wrappers.

The Graal bitmap accessor has an exact 128/32/9 shape with three calls in each
build. Both preserve lookup, missing or guarded-resource rejection, optional
reload flag updates, virtual loading, and the returned texture pointer. The
target body at `0x1084cc` delegates lookup to a typed helper at `0x108418` and
has an additional overload at `0x10854c` that has no one-to-one 1.8 source
counterpart. The anchor records the target body whose three-argument behavior
matches the source.

The cleanup helper is an exact 20/5/2 body and clears the global image registry.
The static initializer is an exact 76/19/1 body with four calls and creates
the target image hash list and allowed-animation string list. These target
class names are `KKhLga4xoI` and `vuuHgangcF`.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v101.i64`. The evidence is in
`artifacts/spectron_texture_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_texture_anchors.py`. All ten labels
reopened with zero failures, and the full translation check still passed with
3,641 high-confidence labels and zero failures. The v101 database has 11,679
functions and 1,686 remaining default `sub_` names. Its SHA-256 is
`8944246d7b9b491cecbeec2298383defe1d624a6643d654fdc28894885c15913`.

## Spectron TOptions anchors

The v100 pass reviewed seven remaining methods from the source `TOptions`
class. The target methods are in the obfuscated `K7FLgag3II` class and remain
in the expected local order around the options load, save, and credential
methods.

| 1.8 role | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TOptions_set_pref__video__externalguistyle` | `0x16a4f0` | `0x16df48` | change guard and external-style event |
| `TOptions_set_pref__video__defaultguistyle` | `0x16a5a8` | `0x16e03c` | change guard and default-style event |
| `TOptions_getGraalNickName_void` | `0x16b8ec` | `0x16f3bc` | decoded credential slot 0 |
| `TOptions_getGraalAccountName_void` | `0x16bc24` | `0x16f720` | decoded credential slot 1 |
| `TOptions_setGraalAccountName_TString_const` | `0x16bcd8` | `0x16f800` | account persistence and recent list |
| `TOptions_getGraalPassWord_void` | `0x16be70` | `0x16f9e0` | decoded credential slot 2 |
| `TOptions_runOptionsTimer_void` | `0x16bf24` | `0x16fac0` | stored-value refresh timer |

The two style setters preserve the source compare, conditional assignment,
universe guard, event dispatch, and temporary cleanup. The target grows from
184/46/7 with five direct calls to 244/60/7 with nine calls. The extra work is
the rebuilt target string wrapper and obfuscated event helper. The target
functions were default `sub_` names before the pass, and their event-name
literals were recovered from the pseudocode and context even though they were
not exported as standalone target feature string references.

The three getters preserve the same null-global handling and decode slots 0,
1, and 2 from the options hash-list state. The nickname getter changes from
64/16/3 with one call to 108/27/3 with three calls. The account and password
getters change from 68/17/3 with one call to 112/28/3 with three calls. The
target makes temporary `C8THgaTQxF` and `CanTfaz6bZ` operations explicit.

The account setter preserves simple setter dispatch, active-player state,
lowercasing, early filtering for guest, `guest_`, and cookie names, recent
account removal and insertion, five-entry trimming, comma serialization, and
registry persistence. It changes from 408/101/10 with 20 calls to 480/119/10
with 24 calls. The target uses explicit string wrappers and the literal
`accountname_new` where the source uses `accountname`. This is recorded as a
target-version difference.

The timer preserves the three stored-value refreshes and uniqueness calls. It
changes from 132/33/3 with seven calls to 156/39/3 with nine calls. These
measurements are bytes, instructions, basic blocks, and direct calls.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v100.i64`. The evidence is in
`artifacts/spectron_options_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_options_anchors.py`. All seven labels
reopened with zero failures, and the full translation check still passed with
3,641 high-confidence labels and zero failures. The v100 database has 11,679
functions and 1,686 remaining default `sub_` names. Its SHA-256 is
`3b438b39ec6f02fe7a8059c1abe8172338b0d1cee936522ce9e23611f4f94b5d`.

## Spectron hash-list and hash-string anchors

The v99 pass reviewed nine `THashList` and `THashStrings` methods that
remained unmatched after the broad semantic map. The target classes are the
obfuscated `KKhLga4xoI` and `yL3_IaDMFt`, with translated iterator and mutation
neighbors providing local ordering evidence.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `THashList_getObject_uint_TString_const` | `0xea674` | `0xeb260` | bucket chain and string equality |
| `THashList_getObjectIgnoreCase_uint_TString_const` | `0xea700` | `0xeb3a0` | ASCII-folded bucket comparison |
| `THashList_getObjectEncoded_uint_TString_const` | `0xea7fc` | `0xeb50c` | encoded character comparison |
| `THashStrings_getObject_TString_const` | `0xeade4` | `0xeba30` | hash lookup and key equality |
| `THashStrings_setValue_TString_const_TString_const` | `0xeb358` | `0xebfcc` | add, replace, or remove value |
| `THashList_Assign_THashList_bool_bool` | `0xebaa4` | `0xec840` | clear, iterate, and copy |
| `THashList_getListSorted_void` | `0xebba8` | `0xec90c` | ordered insertion |
| `THashStrings_listStrings_void` | `0xebea0` | `0xecc58` | name/value list construction |
| `THashStrings_GetCommaText2_void` | `0xebff0` | `0xecde8` | comma joining and quote escaping |

The three lookup targets stay in `KKhLga4xoI`. The case-sensitive method
changes from 140/35/9 with one call to 180/45/9 with three calls. The
case-insensitive method changes from 252/63/24 with no direct calls to
364/91/31 with three calls. The encoded method changes from 284/71/24 with no
direct calls to 320/80/25 with two calls. In each case the target preserves
bucket selection, chain traversal, hash matching, and the corresponding exact,
ASCII-folded, or encoded character comparison. The extra target calls are
temporary `C8THgaTQxF` operations or the target string indexed accessor.

The `THashStrings` lookup target
`_ZN10yL3_IaDMFt10TBCvgay5cvERK10C8THgaTQxF` changes from 136/34/7 with two
calls to 176/44/7 with four calls. The value update target
`_ZN10yL3_IaDMFt10juVsfa5YWCERK10C8THgaTQxFS2_` changes from 280/70/11 with
seven calls to 308/77/11 with nine calls. Both preserve hash lookup, new-key
insertion, unchanged-write suppression, replacement, and empty-value removal.

The hash-list assignment target `_ZN10KKhLga4xoI6AssignEPS_b` is smaller than
the source, at 104/26/4 with six calls versus 160/40/6 with nine calls. Both
clear the destination and copy objects through an iterator. The source has a
second boolean that selects an encoded-add branch, while the target exposes
one boolean and only the normal add path. This is recorded as a target
behavior and signature difference. The sorted-list target
`_ZN10KKhLga4xoI10AotaUajlqSEv` changes from 260/65/9 with ten calls to
324/81/9 with fourteen calls, preserving ordered comparison and append or
indexed insertion.

The hash-string list target `_ZN10yL3_IaDMFt10SpbdUardIUEv` changes from
272/68/7 with 14 calls to 336/84/7 with 18 calls. The comma serializer target
`_ZN10yL3_IaDMFt10glvHgatZcFEv` changes from 360/90/9 with 17 calls to
440/110/9 with 23 calls. Both preserve iterator traversal, name/value
assembly, bare-name handling, commas, and double-quote escaping. Spectron's
`Z1ceJasAzF` helper fills the source `escaped34_TString_const` role. The
target feature export omits the standalone equals literal even though the
pseudocode still constructs `name=value` strings.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v99.i64`. The evidence is in
`artifacts/spectron_hash_family_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_hash_family_anchors.py`. All nine labels
reopened with zero failures. The full translation check also passed with
3,641 high-confidence labels and zero failures. The v99 database has 11,679
functions and 1,688 default `sub_` names. Its SHA-256 is
`0760c6fb90cd51a7f575eb46bedcb07f8d72eb6885055b48f2305aedd7ef276b`.

## Spectron extended TStringList anchors

The v98 pass reviewed seven more `TStringList` methods that remained unmatched
after the broad semantic map. The target class remains `vuuHgangcF`, and the
methods follow the v97 comma-text group in the same local method sequence.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TStringList_Assign_TStringList` | `0xf5e50` | `0xf76c8` | list copy and indexed value allocation |
| `TStringList_AddList_TStringList_int_int` | `0xf5ef8` | `0xf7790` | bounded range append |
| `TStringList_getValue_TString_const` | `0xf5ff8` | `0xf7904` | equals-key lookup and substring return |
| `TStringList_setValue_TString_const_TString_const` | `0xf60dc` | `0xf79f0` | add, replace, or delete empty value |
| `TStringList_toString_void` | `0xf6408` | `0xf7d40` | newline-separated serialization |
| `TStringList_SaveToFile_TString_const_uint` | `0xf6580` | `0xf7ef4` | file mode, fwrite loop, and error log |
| `TStringList_Tokenize_TString_const_TString_const` | `0xf6950` | `0xf82f8` | delimiter-aware quoted tokenizer |

The assignment target is `_ZN10vuuHgangcF6AssignEPS_`. It changes from
168/42/8 with four calls to 200/50/9 with six calls, measured as bytes,
instructions, blocks, and direct calls. Both clear the destination, reserve
space, allocate one value per source entry, copy through the indexed accessor,
and set the destination count. The range append target is
`_ZN10vuuHgangcF10TF9BgaVKIAEPS_ii`; it changes from 216/54/8 with three calls
to 244/61/8 with five calls while retaining start and end clamping, capacity
calculation, and tail placement.

The key/value targets are
`_ZNK10vuuHgangcF10iVjofaNm4yERK10C8THgaTQxF` and
`_ZN10vuuHgangcF10juVsfa5YWCERK10C8THgaTQxFS2_`. Lookup changes from
228/57/9 with six calls to 236/59/10 with eight calls. The setter changes from
372/93/12 with 15 calls to 408/102/12 with 17 calls. Both builds retain the
equals-key scan and substring result. The setter also retains append for a
missing nonempty key, replacement for an existing key, and deletion when the
new value is empty. Spectron's feature export does not list the standalone
equals literal, although the pseudocode still constructs the same key.

The newline serializer target is `_ZNK10vuuHgangcF10bwoY2aKeq6Ev`. It changes
from 376/94/17 with three calls to 436/109/19 with six calls. The file-output
target is `_ZNK10vuuHgangcF10IA7WHax_lAERK10C8THgaTQxFj`, changing from
472/116/16 with 16 calls to 524/129/18 with 18 calls. Both preserve the
newline loop, empty-value handling, file mode selection, fwrite, fclose,
extension filtering, and error-log behavior. The target's
`wiULgacZUI::Rr3vga6vAv` and `qjQMgaXCHJ::cWQMgaD8HJ` methods occupy the
source file-extension and logging roles.

The tokenizer target is
`_ZN10vuuHgangcF10q316gaulx0ERK10C8THgaTQxFS2_`. It changes from 1020/253/49
with 37 calls to 972/241/49 with 33 calls. Both initialize delimiter tables,
scan quoted and unquoted fields, handle backslash escapes, trim tokens, and
preserve trailing empty fields. The target makes the C8THgaTQxF temporary and
trim operations explicit. It exposes the newline/comma delimiter table but
not a separate quote-table string reference, matching the target's byte-data
representation.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v98.i64`. The evidence is in
`artifacts/spectron_tstringlist_extended_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tstringlist_extended_anchors.py`. All
seven labels reopened with zero failures. The full translation check also
passed with 3,641 high-confidence labels and zero failures. The v98 database
has 11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`1819af30ea8729c14088b398f0994c6b35af92054b433a13c14a238ad5b4b76c`.

## Spectron TStringList comma-text anchors

The v97 pass reviewed four `TStringList` methods that remained unmatched after
the broad semantic map. The target class is `vuuHgangcF`, and its local method
ordering agrees with the source list implementation.

| 1.8 function | Source | Spectron target | Main evidence |
| --- | ---: | ---: | --- |
| `TStringList_SetCommaText2_TString_const` | `0xf5938` | `0xf71a8` | quoted comma parser and length limits |
| `TStringList_TStringList_TString_const` | `0xf5c18` | `0xf744c` | list initialization and parser call |
| `TStringList_GetCommaText_void` | `0xf5c4c` | `0xf7484` | single-quote escaping and overflow fallback |
| `TStringList_GetCommaText2_void` | `0xf5d4c` | `0xf75a8` | double-quote escaping and comma joining |

The parser target is
`_ZN10vuuHgangcF10gzgLgalynIERK10C8THgaTQxF`. It preserves the source clear,
unquoted split, quoted-field scan, backslash handling, trailing empty-field
case, and 60000 and 65000 guards. The source is 736/182/35 with 23 calls,
while the target is 676/168/35 with 19 calls. The source has a quote-table
string reference, while the target represents the same table as byte data.

The constructor target is
`_ZN10vuuHgangcFC2ERK10C8THgaTQxFb`. It is 56/14/2 versus 52/13/2 in the
source and accepts an additional byte flag. The parser and storage
initialization roles remain the same. The serializer targets are
`_ZNK10vuuHgangcF10LzrhKaQOhyEv` and
`_ZNK10vuuHgangcF10glvHgatZcFEv`. The first grows from 256/64/12 with seven
calls to 292/73/12 with nine calls. The second grows from 172/43/6 with four
calls to 200/50/6 with six calls. Spectron's explicit C8THgaTQxF copies and
assignments account for those extra operations. `R3jeJaVuFF` and `Z1ceJasAzF`
are the target escaping helpers for the source single-quote and double-quote
serializers.

The labels are recorded as `v18_` names in
`analysis/spectron_libqplay_translated_v97.i64`. The evidence is in
`artifacts/spectron_tstringlist_comma_manual_translation_anchors_20260826.json`,
generated by `tools/generate_spectron_tstringlist_comma_anchors.py`. All four
labels reopened with zero failures. The full translation check also passed
with 3,641 high-confidence labels and zero failures. The v97 database has
11,679 functions and 1,688 default `sub_` names. Its SHA-256 is
`e7287802d3f8f7d967fd12259a45ff3c5635d78005648c0d86d698917c767c0a`.

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

## v349 TSounds and Java-audio comparison

The v349 comparison resolves ten rows that the semantic matcher had left
ambiguous. The target library is still the exact Spectron ARM64 build with
SHA-256 `f57f7da48bcddf3738f15502328b36032313ad760eea04c5cc19ef82b4232219`.
The source rows come from the original 1.8 ARM64 feature export. The target
names already had `v18_` aliases in IDA, so this is a semantic reconciliation
pass rather than a first-time target rename.

| Source role | Source EA | Spectron EA | Target alias | Target raw cluster | Evidence |
| --- | ---: | ---: | --- | --- | --- |
| `TSounds_isMusicPlaying` | `0xe0af8` | `0xe16a8` | `v18_TSounds_isMusicPlaying` | `IUKzgam4Gy` | vtable `+56` |
| `TSounds_getMusicPos_void` | `0xe0b3c` | `0xe16ec` | `v18_TSounds_getMusicPos_void` | `IUKzgam4Gy` | vtable `+80` |
| `TSounds_getMusicLen_void` | `0xe0b7c` | `0xe172c` | `v18_TSounds_getMusicLen_void` | `IUKzgam4Gy` | vtable `+88` |
| `TSounds_getDisabledSoundEffects` | `0xe0c84` | `0xe1834` | `v18_TSounds_getDisabledSoundEffects` | `vuuHgangcF` | comma-text list getter |
| `TSounds_getSoundEffect_TString_const` | `0xe0e48` | `0xe1a1c` | `v18_TSounds_getSoundEffect_TString_const` | `IUKzgam4Gy` | lowercase, hash, ignore-case lookup |
| `TSounds_stopMidi_void` | `0xe1060` | `0xe1c34` | `v18_TSounds_stopMidi_void` | `IUKzgam4Gy` | vtable `+72` |
| `TSounds_updateMusic_void` | `0xe1888` | `0xe2470` | `v18_TSounds_updateMusic_void` | `IUKzgam4Gy` | vtable `+48` |
| `TSoundPlayerJava_stopMidi_void` | `0xe2b58` | `0xe3748` | `v18_TSoundPlayerJava_stopMidi_void` | Java player cluster | adjacent helper order |
| `TSoundPlayerJava_setMusicVolumeAndPan_int_int` | `0xe2b78` | `0xe3768` | `v18_TSoundPlayerJava_setMusicVolumeAndPan_int_int` | Java player cluster | adjacent helper order |
| `TSoundEffectJava_TSoundEffectJava__2` | `0xe2c14` | `0xe3804` | `v18_TSoundEffectJava_TSoundEffectJava__2` | `QPh5pbnC3y` | two-block constructor wrapper |

### Exact feature comparison

All ten rows match every field in the normalized feature schema. The main
shape groups are:

| Source to target | Size | Instructions | Blocks | Branches | Calls | Address delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| music state and disabled-effects getter | 68, 64, 64, 44 | 17, 16, 16, 11 | 3, 3, 3, 1 | 4, 4, 4, 2 | 1, 1, 1, 1 | `+0xbb0` |
| sound lookup and stop MIDI | 92, 48 | 23, 12 | 1, 3 | 5, 3 | 4, 1 | `+0xbd4` |
| music update | 48 | 12 | 3 | 3 | 1 | `+0xbe8` |
| Java-player and Java-effect wrappers | 32, 32, 32 | 8, 8, 8 | 1, 1, 2 | 2, 2, 2 | 1, 1, 1 | `+0xbf0` |

The normalized record includes size, instruction count, basic blocks, branch
count, call count, mnemonic hash, opcode-shape hash, register-shape hash,
coarse shape hash, and string-reference hash. The target's direct-call names
change where the later build replaces `TString`, `THashList`, and
`TStringList` with `C8THgaTQxF`, `KKhLga4xoI`, and `vuuHgangcF`. Those changes
do not affect the exact normalized shape result.

### Layout-change candidates kept separate

The following pairs are behaviorally convincing but are not part of the exact
v349 anchor artifact:

| Source | Target | Structural difference |
| --- | --- | --- |
| `TSounds_initStaticVars_void` `0xe2a88` | `0xe3678` | target list wrapper layouts differ |
| `TSoundEffect_TSoundEffect_TString_const` `0xe0dc0` | `0xe1970` | target adds the encoded-string bridge |
| `TSounds_play_impl_TString_const_bool_bool_double_double` `0xe135c` | `0xe1f34` | target adds wrapper calls and four instructions |
| `TSounds_script_setSoundPitchByNote` `0xe2858` | `0xe3440` | target adds two wrapper instructions |
| `TSoundEffectJava_play_void` `0xe31d0` | `0xe3dc0` | target removes the `steps` branch and is shorter |

The target playback implementation keeps the source's 72-block selection,
download, cache, and play flow. The target note parser keeps the twelve-note
literal and `powf` ratio calculation. The Java play method keeps byte-array
creation, static method invocation, local-reference release, loaded-state
assignment, and timestamp assignment. These are strong layout-aware findings,
but mixing them with the exact rows would overstate the evidence.

### v349 records

The ten anchors were applied to a fresh v348-derived IDA copy. Reopening it
verified all ten names and boundaries. Since the names already existed, the
application report shows zero new renames, nine new comments, and zero
failures. The new semantic map contains 3,732 mapped pairs, 3,672 of them
high confidence, with 1,004 ambiguities and 608 unmatched source functions.

The saved database is
`analysis/spectron_libqplay_translated_v349_sounds_exact.i64` with SHA-256
`ede4f9187e01c4a415181f423dd9c7b8467deb38595d399dcb19341fd9203faf`.
The records are
`artifacts/spectron_sounds_exact_manual_translation_anchors_20260829.json`,
`artifacts/spectron_sounds_exact_manual_translation_application_20260829.json`,
`artifacts/spectron_sounds_exact_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v349_sounds_exact.json`,
`artifacts/spectron_name_coverage_audit_v349.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v349.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v349.json`,
`artifacts/spectron_semantic_translation_v349.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v349.json`.

This comparison was offline. It did not patch the APK, contact the game
server, or change the connector or loading-state experiments.

## v351 hash-family residual comparison

The v351 pass resolves eight rows that automatic normalized matching left
unresolved. The evidence combines direct source and target pseudocode with
overload signatures and class-local order.

| Source role | Source EA | Spectron EA | Target alias | Source shape | Target shape |
| --- | ---: | ---: | --- | --- | --- |
| string-key add wrapper | `0xeac64` | `0xeb904` | `v18_THashList_addObject_THashListObject_TString_const` | 48 / 12 / 2 / 2 / 1 | 48 / 12 / 2 / 2 / 1 |
| encoded-key add wrapper | `0xeacd4` | `0xeb934` | `v18_THashList_addObjectEncoded_THashListObject` | 132 / 33 / 9 / 5 / 0 | 48 / 12 / 2 / 2 / 1 |
| string-key remove wrapper | `0xeb844` | `0xec570` | `v18_THashList_removeObject_THashListObject_TString_const` | 48 / 12 / 2 / 2 / 1 | 48 / 12 / 2 / 2 / 1 |
| encoded-key remove wrapper | `0xeb8c0` | `0xec5a0` | `v18_THashList_removeObjectEncoded_THashListObject` | 144 / 36 / 10 / 5 / 0 | 48 / 12 / 2 / 2 / 1 |
| hash-string key lookup | `0xeade4` | `0xeba30` | `v18_THashStrings_getObject_TString_const` | 136 / 34 / 7 / 8 / 2 | 176 / 44 / 7 / 10 / 4 |
| hash-string value update | `0xeb358` | `0xebfcc` | `v18_THashStrings_setValue_TString_const_TString_const` | 280 / 70 / 11 / 15 / 7 | 308 / 77 / 11 / 17 / 9 |
| name/value list serialization | `0xebea0` | `0xecc58` | `v18_THashStrings_listStrings_void` | 272 / 68 / 7 / 19 / 14 | 336 / 84 / 7 / 23 / 18 |
| comma-text serialization | `0xebff0` | `0xecde8` | `v18_THashStrings_GetCommaText2_void` | 360 / 90 / 9 / 23 / 17 | 440 / 110 / 9 / 29 / 23 |

The five shape values in each row are size, instruction count, basic-block
count, branch count, and call count. The normal add and remove wrappers are
exact across the complete normalized feature record, so the target alias is
strongly grounded even though its mangled method name differs. The encoded
wrappers are shorter because target `g4ouMaaIbp` centralizes the encoded hash
calculation.

The four THashStrings rows keep the source behavior in direct pseudocode.
Target `0xeba30` still performs bucket selection, collision-chain traversal,
key comparison, and object return. Target `0xebfcc` keeps missing-value
insertion, changed-value replacement, and empty-value removal. Targets
`0xecc58` and `0xecde8` preserve name=value assembly, empty-value handling,
comma joining, and escaping. The changed metrics come from explicit C8TH and
iterator temporaries, not from a different role.

The v351 artifact contains two exact-shape rows and six layout-aware rows. It
promotes two parent ambiguities and six unmatched source functions. The
semantic map now has 3,745 mapped pairs, 3,685 high-confidence pairs, 1,001
remaining ambiguities, and 598 unmatched source functions. The v351 database
has 11,707 functions, zero audited default names, and 5,782 exact dynamic
function starts.

The v351 database is
`analysis/spectron_libqplay_translated_v351_hash_residual.i64` with SHA-256
`0fb0662dffea1f1f6223e0e52745a19505687a79cf47f207280ce098f61b87f0`.
The records are
`artifacts/spectron_hash_residual_manual_translation_anchors_20260829.json`,
`artifacts/spectron_hash_residual_manual_translation_application_20260829.json`,
`artifacts/spectron_hash_residual_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v351_hash_residual.json`,
`artifacts/spectron_name_coverage_audit_v351.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v351.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v351.json`,
`artifacts/spectron_semantic_translation_v351.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v351.json`.

This comparison was offline. It did not patch the APK, contact the game
server, or change the connector or loading-state experiments.

## v350 layout-aware sound comparison

The v350 pass records the five larger audio counterparts that cannot be
validated as exact normalized-shape matches. The semantic evidence comes from
direct source and target pseudocode, preserved literals, matching callers or
class-local order, and explicit structural deltas.

| Source role | Source EA | Spectron EA | Target alias | Source shape | Target shape |
| --- | ---: | ---: | --- | --- | --- |
| `TSounds_initStaticVars_void` | `0xe2a88` | `0xe3678` | `v18_TSounds_initStaticVars_void` | 76 / 19 / 1 / 5 / 4 | 76 / 19 / 1 / 5 / 4 |
| `TSoundEffect_TSoundEffect_TString_const` | `0xe0dc0` | `0xe1970` | `v18_TSoundEffect_TSoundEffect_TString_const` | 136 / 34 / 1 / 5 / 4 | 172 / 43 / 1 / 7 / 6 |
| `TSounds_play_impl_TString_const_bool_bool_double_double` | `0xe135c` | `0xe1f34` | `v18_TSounds_play_impl_TString_const_bool_bool_double_double` | 1312 / 328 / 72 / 96 / 42 | 1328 / 332 / 72 / 98 / 44 |
| `TSounds_script_setSoundPitchByNote` | `0xe2858` | `0xe3440` | `v18_TSounds_script_setSoundPitchByNote` | 548 / 135 / 21 / 41 / 26 | 556 / 137 / 21 / 41 / 26 |
| `TSoundEffectJava_play_void` | `0xe31d0` | `0xe3dc0` | `v18_TSoundEffectJava_play_void` | 720 / 178 / 20 / 26 / 12 | 676 / 168 / 19 / 22 / 9 |

The five shape columns use size, instruction count, basic-block count, branch
count, and call count in that order. The static initializer is the special
case where those coarse counts are unchanged but the wrapper-specific hashes
differ. It constructs `THashList` and `TStringList` in source, while target
constructs `KKhLga4xoI` and `vuuHgangcF` and stores them in the target sound
manager fields.

The constructor row is identified by the same lowercasing, base construction,
name copy, and field initialization. Target `0xe1970` adds the
`CanTfaz6bZ` to `J7zOgaf09K` bridge. The playback row retains the source
72-block flow and the `.mid` and `.mp2 .mp3 .ogg .wma .asf` literals while
target wrappers account for the four-instruction and two-call increase. The
note parser retains its twelve-note literal and `powf` calculation. The Java
play row retains `startSound`, byte-array creation, static invocation, local
reference release, loaded state, and timestamp state, but no longer checks the
source `steps` prefix.

The v350 artifact reports five high-confidence layout-change rows, zero exact
shape rows, and zero target-default rows. One source was an ambiguity in the
v349 map, while four were unmatched because their changed wrappers produced no
useful automatic candidate. All five target aliases and comments were already
present in the v349 IDA copy. The application report shows five resolved
starts, zero new renames, zero new comments, and zero failures. Reopening the
copy verified all five names and boundaries.

The semantic map now has 3,737 mapped pairs, 3,677 high-confidence pairs,
1,003 remaining ambiguities, and 604 unmatched source functions. The v350
database is
`analysis/spectron_libqplay_translated_v350_sounds_layout.i64` with SHA-256
`056db23f2015b33134e1fc2bcb99deb5821b96c9590646eb6100c0f7d3462870`.
The records are
`artifacts/spectron_sounds_layout_manual_translation_anchors_20260829.json`,
`artifacts/spectron_sounds_layout_manual_translation_application_20260829.json`,
`artifacts/spectron_sounds_layout_manual_translation_verification_20260829.json`,
`artifacts/spectron_features_v350_sounds_layout.json`,
`artifacts/spectron_name_coverage_audit_v350.json`,
`artifacts/spectron_dynamic_symbol_boundaries_v350.json`,
`artifacts/spectron_dynamic_symbol_coverage_audit_v350.json`,
`artifacts/spectron_semantic_translation_v350.json`, and
`artifacts/spectron_translation_checkpoint_20260829_v350.json`.

This comparison was offline. It did not patch the APK, contact the game
server, or change the TLS or loading-state experiments.

## v352 existing alias reconciliation

The v352 comparison is about provenance rather than new target code. The
target feature export already showed 509 functions named exactly
`v18_<source name>` for source rows still listed as unmatched in v351. Each
pair was accepted only after locating one earlier reviewed anchor artifact
with the same source and target addresses. This recovered 509 semantic rows,
with 508 inherited high-confidence classifications and one inherited
medium-confidence classification.

No new target aliases were created. The map-only application report records
509 resolved rows, zero renames, zero comments, zero failures, and no database
write. The verification report checks all 509 target names against the current
11,707-function feature export. The target database hash remains
`0fb0662dffea1f1f6223e0e52745a19505687a79cf47f207280ce098f61b87f0`.

| Semantic quantity | v351 | v352 |
| --- | ---: | ---: |
| mapped pairs | 3,745 | 4,254 |
| high-confidence pairs | 3,685 | 4,193 |
| medium-confidence pairs | 60 | 61 |
| ambiguous rows | 1,001 | 1,001 |
| unmatched rows | 598 | 89 |

The 89 remaining unmatched rows have no unique existing `v18_` target alias.
They are still open for direct source and target analysis. The complete
reconciliation rows and the 336-file provenance manifest are in
`artifacts/spectron_existing_v18_alias_reconciliation_20260829.json`. The
semantic map and strict checkpoint are
`artifacts/spectron_semantic_translation_v352.json` and
`artifacts/spectron_translation_checkpoint_20260829_v352.json`.
