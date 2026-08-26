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
6,773 and 6,770. Only 1,036 names are exact matches, mostly shared third-party
code. A simple application-name heuristic finds 1,035 readable names in the
original but only 28 in Spectron, where the C++ names have been obfuscated.
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
embedding a newer certificate. Any working behavior in that package must come
from its separate routing, hook, package, or service logic.

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
A playable world was not verified for the modded package.

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
