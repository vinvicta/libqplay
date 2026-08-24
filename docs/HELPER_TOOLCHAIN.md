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

The complete generated connector source first stopped with a parser error at
line 469, beginning at `function onAppleMessageBoxButton(title, buttonindex)`.
Inspection showed that the generated text was missing one closing brace after
`printDisconnectError`. Adding that brace produced a 552-line, 25,683-byte
source file with SHA-256
`a30f9eca136e3b8ff827bfb1bfe13fb442bd2e882963bf9863cd8de5f2669e68`. The
repaired source compiled successfully to a 16,141-byte bytecode file with
SHA-256
`67b70c449f87d6e3b71ef0fe92ba73fff9fe5fe7a1ad63aedb34e9daf4a7b752`.

That compile result is a useful milestone, but it was not initially a runtime
replacement for the archived script. The original ARM64 client accepted the
original bytecode after it was repacked with the compatible ZIP headers below,
then connected to the local game responder. The same client requested the
connector package but did not reach the expected game-server flow when given
the raw recompiled bytecode. The first single-port run looked like it had not
opened a game socket. A later two-port negative control showed the more precise
behavior: the raw output opened three connections to the alternate `14896`
listener, but opened none to the expected `14900` listener and never completed
the normal resource replay.

## HexaParser literal-order adapter

The next comparison found the bytecode-parity issue. The native-order
reconstruction and the repaired HexaParser source contain the same handler
data, but the decompiler prints each same-line brace literal backwards. The
most useful examples are:

```text
native-order setInDataHandlers: {178, 0, 9, 1, ..., 94}
HexaParser output:             {94, 108, ..., 9, 0, 178}

native-order setOutDataHandlers: {158, 161, 157, ..., 163}
HexaParser output:               {163, 44, 162, ..., 158}

native-order onData pair: {42, 18}
HexaParser output:        {18, 42}
```

The Classic login-server lists are reversed in the same way. IDA's trace of
`TScript_setStream_TString_const` shows that this code is loaded as a script
function table, string table, and opcode stream. The observed ordering is
consistent with the old VM constructing a literal on a stack while HexaParser
prints values in the order it encounters them. This is a decompiler and
compiler-boundary issue, not evidence that the original native handler table
needs an operand swap. The earlier swap experiment remains a false lead.

`tools/reverse_hexaparser_literals.py` is a deliberately narrow adapter. It
reverses comma-separated brace literals that begin and end on one source line,
while skipping bodies that look like statement blocks or function calls. The
missing closing brace described above must still be repaired before applying
the adapter. A complete local round trip was:

```bash
python3 tools/reverse_hexaparser_literals.py \
  /tmp/StartScript_Connector.repaired.gs2 \
  /tmp/StartScript_Connector.native-order.gs2

cd /tmp/GScript.Go-HexaParser
go run . compile \
  -grammar gs2 \
  -type weapon \
  -name StartScript_Connector \
  -o /tmp/StartScript_Connector.native-order.gs2bc \
  /tmp/StartScript_Connector.native-order.gs2
```

For the checked fixture, the repaired input source has SHA-256
`a30f9eca136e3b8ff827bfb1bfe13fb442bd2e882963bf9863cd8de5f2669e68`, the
adapted source has SHA-256
`e3a825b81bde930b8b26625ee7f14d3035d7b0dafb1015ee5d8df23591059572`, and the
compiled 16,141-byte script has SHA-256
`ab5b500216b560603ba433618c85a3d8e38ac06ad12c42a978f923930c79742a`. The
compiled file ends in `0x0a`. That trailer was accepted by the native loader in
the successful replay, so removing it is not required for this fixture.

Packing that script with the legacy ZIP patch, the archived `.rk` and `.t`
metadata, and the local diagnostic signature path produced a 16,446-byte
package with SHA-256
`d4dc4fc9969daeed648a671b92934606d6b54f0f86620c7ec82fa0d1676ca297`. With
the raw output, the same package path produced the wrong-endpoint result
described above. With the literal-order adapter, the loopback replay produced
two `14900` game connections, the expected map, three level files,
`pics1.png`, and continuing heartbeat packets. Its screenshot SHA-256 was
`fa83f17b4fe8d4ab880512f970879d09a49648714cde85add86d51280af1333e`, exactly
matching the earlier original-bytecode compatibility replay.

This proves runtime parity for the recovered connector fixture after the
targeted literal-order repair. It does not prove that every script emitted by
HexaParser needs, or will safely tolerate, the same transformation. The
adapter should therefore be applied only after comparing its output with the
native-order reconstruction and checking the resulting bytecode locally.

## Source-level game-server TLS replacement

The script certificate is a separate concern from the handler-table ordering.
`tools/encode_game_server_tls_certificate.py` edits the disassembler's JSON
string table, which is useful when working directly with bytecode records.
For the supplied HexaParser source, `tools/replace_game_server_tls_source.py`
performs the same native transform at the source level.

By default the source helper requires both recovered `setSSLParameters` calls.
It verifies that every existing literal decrypts to a stable X.509 DER
certificate, accepts exactly one certificate-only PEM replacement, and refuses
to overwrite the input source. It does not bypass peer or hostname
verification and opens no socket.

The source-level command is:

```bash
python3 tools/replace_game_server_tls_source.py \
  /tmp/StartScript_Connector.repaired.gs2 \
  /path/to/current-authorized-server.cert.pem \
  --output /tmp/StartScript_Connector.server-cert.gs2 \
  --report /tmp/StartScript_Connector.server-cert.json
```

The default output allows a longer Base64 value because a normal recompilation
can allocate a new string-table entry. Use
`--max-base64-characters 960` only when an in-place capacity limit is part of
the chosen bytecode workflow. Use `--expected-occurrences 1` for a source
that intentionally contains only one SSL call.

The source helper was tested in three ways. Replacing the recovered
certificate with itself found two occurrences and produced the exact repaired
source hash `a30f9eca136e3b8ff827bfb1bfe13fb442bd2e882963bf9863cd8de5f2669e68`.
HexaParser then produced the known 16,141-byte bytecode hash
`67b70c449f87d6e3b71ef0fe92ba73fff9fe5fe7a1ad63aedb34e9daf4a7b752`. A
self-signed offline test certificate produced a 1,072-character replacement
and compiled to 16,253 bytes with SHA-256
`119653464dc0692cc2fc478d7edc6ea1080096559fbac7b9e24a993a2862235d`.
Applying the existing literal-order adapter to that source also compiled to
16,253 bytes. These checks validate source compilation and the native transform
only. They do not establish a current server chain or authorize a release
package.

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
signature-verification check. The parser also reproduces the native wolfSSL
signature format now. It hashes the encrypted payload with SHA-256, recovers
the raw message from the RSA type-1 block, and compares the two byte strings.
The standard ASN.1 `DigestInfo` form is reported separately because the old
client does not use it. The saved archived response passes the native check
against the public key embedded in the APK. The earlier stale-package result
was caused by the wrong high-level verifier, not by this fixture's signing
key.

The optional `conpack_wsl.c` creator initially stopped at the missing
`wolfssl/wolfcrypt/rsa.h` header. Cloning the wolfSSL source at commit
`cb138b22a2e9111e5ac9fb9e13a690762c86b884` supplied the required headers and
sources. The resulting Linux build used:

```bash
cp /tmp/Moreno.kahn/conpack_wsl.c /tmp/conpack_wsl.c
patch -p0 /tmp/conpack_wsl.c < tools/conpack_legacy_zip_compat.patch
gcc -O2 -I/tmp/wolfssl \
  /tmp/conpack_wsl.c \
  /tmp/wolfssl/wolfcrypt/src/*.c \
  -lz -lm -o /tmp/conpack_wsl
```

The supplied `outer-private.rsa.der` derives to public-key SHA-256
`07714f7eac2ff6e3236f2887ebab9c367714120c834acff3f745e674ccd46d1a`, while
the APK's embedded public DER is
`35e7245d68e6ab6c84bd55061704fe2d3d16800cbe0a671aceae6c85e1301b82`.
The helper key is therefore useful for testing a custom packer, but it is not
automatically trusted by the original APK. The local ARM64 candidate used a
diagnostic package-signature bypass before the native verifier correction. The
saved fixture can now be replayed with that RSA bypass omitted.

The native-key substitution helper provides a stronger, still private test.
`tools/patch_connector_test_public_key.py` replaces the encrypted connector
key text at ARM64 `0x2e1798` or x86_64 `0x3003d8` with a locally generated
public key. It checks the original 360-character text before writing and does
not carry the matching private key. A `con.png` generated with that private
key passed the native raw-digest verifier. This preserves the RSA branch and
isolates the earlier package-key mismatch from the separate certificate and
loading-state experiments. It is a test harness, not a production key update.

The first packages produced by the unmodified helper were valid ZIP files,
but the old client rejected them before the script ran. Comparing the
decrypted archive with the saved connector archive isolated four legacy ZIP
header requirements:

* local and central entries use general-purpose flag `0x0002`;
* local and central entries use DOS time and date `0xffff`;
* central-directory version-made-by is `0` rather than `20`;
* the remaining compression method, sizes, CRCs, and entry names are ordinary
  deflate metadata.

The minimal source patch is recorded in
`tools/conpack_legacy_zip_compat.patch`. It must be applied before the helper
signs the outer payload. A package made with that patch and the original
15,581-byte connector bytecode had SHA-256
`c242e73cf1abf7a4bd80fa1c5e2e17a1f569960937a83f52cfda1c422307392a`. Running
`conn-extract` on it produced an archive with the same SHA-256 as the saved
local archive, `fc937afa039dff52ff4ae7f2e3ad809d75c19f5698875d862e5646644446b2b5`.
The APK then completed the two-connection loopback login, map and level-file
sequence, and continued sending heartbeat packets. The render candidate
displayed the tiled world and HUD. This is a local diagnostic result, not a
live-service login.

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
bad archive extraction or a misleading bytecode listing. The experiments also
show why both layers need separate acceptance tests: an archive can be
structurally correct while its ZIP dialect is too new for this client, and a
source compiler can emit a parseable bytecode file whose literal order is
wrong for the old runtime. The targeted adapter fixes the checked connector
fixture, but it is not a general compiler validation.

The reproducible artifacts used for these checks remain local: the APK, the
connector response, the decoded script, and the generated GS2 text are not
committed here. The public repository records the pinned commits, commands,
hashes, and limitations instead.

## Loopback proof versus live verification

The successful local replay is a bounded native integration proof. A
loopback connector and game responder completed the connector parse, the
encrypted game handshake, server warp, map and resource requests, and
translated ARM64 rendering. The responder also observed continuing heartbeat
packets. Both the archived script and the adapted HexaParser output reached
that replay; the raw HexaParser output did not. The archive packer and the
literal-order adapter were checked separately before the integrated run, so
the result is tied to recorded hashes rather than an unexamined generated
package.

No live game-server login, current connector response, account authentication,
production certificate chain, production package signature, or physical
ARM64 renderer run has been verified. The repository should describe the
current result as a controlled loopback render proof and keep live login and
real-device validation as open milestones.
