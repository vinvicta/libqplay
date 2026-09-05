# Helper toolchain verification

Two public helper repositories were supplied for this investigation. They
were cloned with Git and tested locally at fixed commits. Their source is not
vendored into this repository, and no private key files from either checkout
were copied into the research archive.

## Current checkout

On 2026-08-28, the pinned commits were also cloned with Git into
`<workspace>/vendor/GScript.Go-HexaParser` and
`<workspace>/vendor/Moreno.kahn`. These are working
checkouts for this investigation and are still separate from the public
archive. The current shell does not have a `go` executable, so this pass does
not claim a new Go test run. The historical test results below remain tied to
the earlier environment where Go 1.22.2 was available.

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

The pinned checkouts have been restored in `/tmp` for this continuation. A
fresh run on 2026-08-26 used the local Go 1.22.2 toolchain with temporary
module and build caches. The declared ANTLR and `x/exp` modules were fetched
into those temporary caches; the run did not contact a game or connector
service.

The complete test run passed. The `gsbyte` package completed in about 7.1
seconds, and the other packages reported no test files. No source changes
were made to the helper checkout.

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

The same command was rerun during the 2026-08-26 check and produced the same
hash. This makes the decompiler output deterministic for the archived
connector stream.

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
`printDisconnectError`. The public helper
`tools/repair_hexaparser_source.py` now checks for that exact malformed block
and inserts only the missing brace. It produced a 552-line, 25,683-byte
source file with SHA-256
`a30f9eca136e3b8ff827bfb1bfe13fb442bd2e882963bf9863cd8de5f2669e68`. The
repaired source compiled successfully to a 16,141-byte bytecode file with
SHA-256
`67b70c449f87d6e3b71ef0fe92ba73fff9fe5fe7a1ad63aedb34e9daf4a7b752`.

The repair command is:

```bash
python3 tools/repair_hexaparser_source.py \
  /tmp/StartScript_Connector.hexaparser.gs2 \
  /tmp/StartScript_Connector.repaired.gs2 \
  --report /tmp/StartScript_Connector.repair.json
```

The helper refuses an already repaired source and refuses to overwrite its
input, which keeps a future decompiler comparison honest.

That compile result is a useful source and parser milestone, but it is not a
runtime replacement for the archived script. The original ARM64 client
accepted the original bytecode after it was repacked with the compatible ZIP
headers below, then connected to the local game responder. The same client
requested the connector package but did not reach the expected game-server
flow when given the raw recompiled bytecode. A later two-port negative control
showed the more precise behavior: the raw output opened three connections to
the alternate `14896` listener, but opened none to the expected `14900`
listener and never completed the normal resource replay.

The fresh compiler check also decoded the rebuilt stream for a structural
comparison. After ignoring the compiler's trailing `0x0a`, the original
stream has record lengths `4/553/8293/6699`, while the rebuilt stream has
`4/553/8271/7280`. The original instruction count is 3,143 and the rebuilt
count is 3,582. The function names remain recognizable, but the rebuilt
instruction layout is not a bytecode-preserving round trip. The raw output's
`14896` connections are consistent with the recovered Classic server-list
literal, while the larger record and instruction differences are the reason
the rebuilt stream remains a source experiment rather than a runtime
replacement.

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
source should first be passed through
`tools/repair_hexaparser_source.py`. A complete local round trip was:

```bash
python3 tools/repair_hexaparser_source.py \
  /tmp/StartScript_Connector.hexaparser.gs2 \
  /tmp/StartScript_Connector.repaired.gs2

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
compiled file ends in `0x0a`. The clean control tested both the compiler output
and a version with that trailer removed; neither reached the expected game
listener. The trailer is therefore not the explanation for the compiler/runtime
mismatch.

Packing that script with the legacy ZIP patch, the archived `.rk` and `.t`
metadata, and the local diagnostic signature path still produces a structurally
valid test package. A clean replay under the same native library, Kahn test
signer, local TLS responder, and game responder did not reproduce the earlier
adapted-runtime claim, however. The adapted output requested the connector but
opened no connection to the expected `14900` listener. Removing the compiler's
trailing `0x0a` did not change that result.

The clean comparison also shows that this is more than a literal-order issue.
The original stream has record lengths `4/553/8293/6699`, 3,143 instructions,
and 302 strings. The adapted stream, after removing its trailing byte, has
record lengths `4/553/8271/7280`, 3,582 instructions, and 299 strings. The
function names remain recognizable, but the function boundaries and opcode
stream are substantially different. The adapter is still useful as a readable
source experiment, but its output is not currently proven compatible with
this old VM. The earlier adapted screenshot claim is retained only as a
historical note and is not used as current evidence.

## Original-bytecode loading-state patch

The proven original stream contains the exact three-instruction assignment
`loadingscreenenabled = false` in `printDisconnectError`. The new
`tools/patch_connector_bytecode_loading_clear.py` copies those six serialized
bytes into `onServerLogin`, immediately before the existing
`this.reconnections = 0` sequence. It then adjusts function entry offsets and
branch targets that move after the insertion. It does not change the string
table, the handler arrays, the RSA branch, or the native library.

The offline command is:

```bash
python3 tools/patch_connector_bytecode_loading_clear.py \
  /path/to/graal-decomp/analysis/StartScript_Connector.dec.bin \
  /tmp/StartScript_Connector.loading-clear.dec.bin \
  --report /tmp/StartScript_Connector.loading-clear.json
```

For the checked fixture, the output grows from 15,581 to 15,587 bytes and
from 3,143 to 3,146 instructions. Its SHA-256 is
`3c8286ece57d96ecf088f6ba01b6a6094f6d317dda451369392bfa731aa0fb2f`. The
Kahn-signed outer package is 16,452 bytes, with an encrypted payload of
16,188 bytes, and has SHA-256
`7473bac833911005821d210874be2e53df6eeed0d1ae8831dfa0fdf713f27e9e`. The
package passes the native raw RSA check with the matching private test key.

The ARM64-only package using that script and the same local native library
made one connector TLS request, opened two `14900` game connections, completed
the encrypted login exchange, received `classiciphone.gmap`, three level
files, and continuing heartbeat traffic. The native log reached
`Serverwarp...` without a crash. The title/loading artwork remained visible
in the captured frame because this synthetic responder stops at a bounded
post-login resource boundary. This is strong evidence that the original VM
stream and the script-level insertion are accepted, but it is not yet proof
that this insertion alone produces a visible world on a physical ARM64 device
or against a live service. The full hash record is in
`artifacts/bytecode_loading_clear_replay.json`.

Adding the already validated one-instruction native startup candidate to that
same private library produced the next bounded render check. The combined
native library SHA-256 is
`8f7b343d81a1cd8eef390d0a494912f86ab03f7a22f4fe4a2f2bb170409d6722`, and the
debug APK SHA-256 is
`57e6987a920b261c9a6b9abeb909cd4156c4995bb4dd6930422b87a27adc3dde`. With
the direct script package still installed, the emulator observed the same two
game connections, map and level requests, image traffic, and heartbeats. The
translated ARM64 renderer left the title/loading artwork and displayed the
green world field with the HUD. This is a combined diagnostic result, so it
does not prove that the script assignment itself clears the native byte; the
native branch edit remains the variable associated with the visual change.

For source review, `tools/patch_gs2_success_loading_clear.py` inserts the same
assignment into the recovered `onServerLogin` function before compilation. On
the checked source its output SHA-256 is
`c1728c540c89ec5d7b69ad642c9dbaa7d6517e8369cfeb705baa14a9ddd722d6`. That
source-level candidate is useful for documenting the intended change, but its
HexaParser output belongs to the compiler stream that failed the clean runtime
control above. The direct decoded-bytecode patch remains the compatibility
candidate for this VM.

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

This is the revision used for the archive-signing and extraction cross-check.
The later mode-3 semantic-role control used Moreno.kahn commit
`e1f49b5ce6fa46b41354d9a81f75994f91d3ff16`, which defines the separate
`StartScript_Fail` and `StartScript_Connector` output slots. The two commits
support different parts of the investigation.

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

## Linux utility recheck

On 2026-09-04, the same pinned `contool.c` source was rebuilt in the current
Linux environment. The source SHA-256 was
`88deda939a9c8c9837b6fda42ed4a2dbdacb57c9e5fb28eca44e2fc2652ed474`, and the
temporary executable SHA-256 was
`3d70b8f597383bc39a9b89baceff4d7ac5f3187421f2e3b448d6e952f4249875`.

The recheck used only local files. `conn-extract` reproduced the archived
15,857-byte connector ZIP with SHA-256
`fc937afa039dff52ff4ae7f2e3ad809d75c19f5698875d862e5646644446b2b5`.
The `z-compress` and `z-decompress` pair, the DES encrypt/decrypt pair, and
the resource-name encrypt/decrypt pair each returned the original input byte
for byte. The `connector` command also produced a deterministic escaped
query for a synthetic local parameter string. The utility's optional `fetch`
command was not invoked, so this recheck contacted no network service.

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
GS2 source as a readable source-level cross-check. Moreno.kahn validates the
binary connector envelope before the native client consumes the script.
Together they reduce the chance that a native finding is based on a bad
archive extraction or a misleading bytecode listing. The experiments also
show why both layers need separate acceptance tests: an archive can be
structurally correct while its ZIP dialect is too new for this client, and a
source compiler can emit a parseable bytecode file whose instruction layout is
not compatible with the old runtime. The literal adapter fixes the observed
same-line list ordering for static comparison, but it is not currently a
runtime repair. The original-stream bytecode insertion is the tested script
compatibility path.

The reproducible artifacts used for these checks remain local: the APK, the
connector response, the decoded script, and the generated GS2 text are not
committed here. The public repository records the pinned commits, commands,
hashes, and limitations instead.

## Loopback proof versus live verification

The successful local replay is a bounded native integration proof. A
loopback connector and game responder completed the connector parse, the
encrypted game handshake, server warp, map and resource requests, and
continuing heartbeat packets with the original bytecode and with the direct
loading-state bytecode insertion. The clean HexaParser control did not reach
the expected game port under those same conditions. The archive packer and
the bytecode patcher were checked separately before the integrated run, so
the result is tied to recorded hashes rather than an unexamined generated
package. Earlier notes described an adapted HexaParser screenshot; that
result was not reproducible in the clean control and is no longer treated as
verified.

No live game-server login, current connector response, account authentication,
production certificate chain, production package signature, or physical
ARM64 renderer run has been verified. The repository should describe the
current result as a controlled loopback render proof and keep live login and
real-device validation as open milestones.
