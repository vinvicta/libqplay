# Helper toolchain verification

Two public helper repositories were supplied for this investigation. They
were cloned with Git and tested locally at fixed commits. Their source is not
vendored into this repository, and no private key files from either checkout
were copied into the research archive.

## HexaParser

Repository: `MorenoLand/GScript.Go-HexaParser`

Verified commit:

```text
ad9bd3657feece825b5f5a888f5db34ffe37afb9
Rename parser module to HexaParser
```

The checkout targets Go 1.22. The available local toolchain was Go 1.22.2.
The normal commands are:

```bash
git clone https://github.com/MorenoLand/GScript.Go-HexaParser.git /tmp/GScript.Go-HexaParser
git -C /tmp/GScript.Go-HexaParser checkout ad9bd3657feece825b5f5a888f5db34ffe37afb9
cd /tmp/GScript.Go-HexaParser
go test ./...
```

The complete test run passed. The `gsbyte` package completed in about 7.5
seconds, and the other packages reported no test files. The test run needed a
writable Go build cache and the declared ANTLR and `x/exp` modules. It did not
need any changes to the repository.

The tool can decompile the archived connector script produced by the local
connector parser:

```bash
go run . decompile \
  -o /tmp/StartScript_Connector.hexaparser.gs2 \
  /path/to/graal-decomp/analysis/StartScript_Connector.dec.bin
```

The output is 552 lines and 25,677 bytes. Its SHA-256 in this run was:

```text
cf60e41536ddebed89ca1c3b3342476763b3d28c1cc9fff29e211931a080afa5
```

The generated source made the connector logic easier to review. It exposes
the `getPremiumOption()` switch, the Classic endpoint list, the NewGraal login
setup, the packet handler arrays, and the reconnect and resource callbacks in
ordinary GS2 syntax. This is a useful second view of the bytecode beside the
existing instruction-level summary in `analysis/`.

The compiler path was also checked against the repository's Issue 37 fixture:

```bash
go run . compile \
  -grammar gs2 \
  -type weapon \
  -name issue37 \
  -o /tmp/issue37.gs2bc \
  tests/scripts/issue37/07_addcontrol_in_new.gs2
go run . decompile \
  -o /tmp/issue37.roundtrip.gs2 \
  /tmp/issue37.gs2bc
```

That compile succeeded and the bytecode SHA-256 was
`9fb11056e6ce0cd8fc8caf497c25a5ba8b55e0c9c9667376d27eaee2da07b29f`. The
round-trip source retained the nested `LoginBackground.addcontrol(this)` call.

A direct compile of the complete generated connector source currently stops
with a parser error at line 469, beginning at
`function onAppleMessageBoxButton(title, buttonindex)`. The decompiler output
is therefore verified as a readable GS2 view, while full source-to-bytecode
round-tripping of this particular script remains an open toolchain issue. The
failure does not invalidate the successful bytecode decompilation or the
compiler fixture test.

## Moreno.kahn

Repository: `MorenoLand/Moreno.kahn`

Verified commit:

```text
5e3a05fc8fbcf3c3f72b3c263238b2ed275fc66d
Add custom archive signing support
```

The Linux connector utility was built from `contool.c`:

```bash
gcc -O2 -Wall -Wextra \
  -o /tmp/contool \
  /tmp/Moreno.kahn/contool.c \
  -ldl
```

Its `conn-extract` command was run against the saved local connector response:

```bash
/tmp/contool conn-extract \
  /path/to/graal-decomp/analysis/live_connector_response_local.bin \
  /tmp/contool-local.zip
```

The helper produced the exact same archive as the repository's Python parser:

```text
fc937afa039dff52ff4ae7f2e3ad809d75c19f5698875d862e5646644446b2b5
```

The archive contains three entries with a combined uncompressed size of
15,857 bytes:

```text
.rk                              256 bytes
.t                                 20 bytes
NPCS/StartScript_Connector     15,581 bytes
```

This independently confirms the outer response layout and RC4 stream key
used by the local parser. `conn-extract` is an archive extraction check, not a
signature-verification check. The existing parser still reports that the
archived response's RSA signature does not match the public key embedded in
the APK. That stale-package result remains a compatibility diagnostic, not a
production trust decision.

The optional `conpack_wsl.c` creator was inspected but not built in this
environment because the checkout does not include the required wolfSSL
headers and sources. A direct Linux compile stops at
`wolfssl/wolfcrypt/rsa.h`; the README's wolfSSL include and source paths are
needed for a complete build. The supplied `outer-private.rsa.der` also
derives to public-key SHA-256
`07714f7eac2ff6e3236f2887ebab9c367714120c834acff3f745e674ccd46d1a`, while
the APK's embedded public DER is
`35e7245d68e6ab6c84bd55061704fe2d3d16800cbe0a671aceae6c85e1301b82`.
Archives created with that helper key are therefore useful for testing a
custom packer, but they are not automatically signed for this APK.

The same utility has commands for the DES/Base64 connector query, resource
DES, RC4, and the game's zlib wrapper. The query command is useful for format
experiments, but it is not a byte-for-byte client query generator by itself.
The native client reverses the bit order in each DES key byte, while the
helper's standalone DES implementation uses its own standard byte handling.
The exact captured plaintext list is
`g=classic,p=android,v=6.15401,"b=Jul  4 2019 09:35:48"`. The quotes cover the
whole `b=` item because it contains spaces. Use
`tools/encode_connector_query.py` for an exact offline reproduction. No live
fetch or live connector request was made while testing this repository.

## Why these checks matter

The two helpers cover different layers. HexaParser validates the recovered
GS2 bytecode and provides a readable source-level cross-check. Moreno.kahn
validates the binary connector envelope before the native client consumes the
script. Together they reduce the chance that a native finding is based on a
bad archive extraction or a misleading bytecode listing.

The reproducible artifacts used for these checks remain local: the APK, the
connector response, the decoded script, and the generated GS2 text are not
committed here. The public repository records the pinned commits, commands,
hashes, and limitations instead.
