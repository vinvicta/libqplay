# libqplay research archive

This repository records a careful reverse-engineering pass over the ARM64
`libqplay.so` shipped with Graal Online Classic 1.8, together with a small
set of local-only protocol tools. The goal is to make the work reproducible
for people who have a lawful copy of the client and are trying to understand
why an old installation no longer starts.

The notes are written as a lab record. They separate facts observed in the
binary, facts reproduced in an emulator, and hypotheses that still need a
server-side test. That distinction matters here because a successful TCP
handshake is not the same thing as a successful game login.

## Current status

The symbol pass is complete. The ARM64 IDA database contains 8,601 translated
and applied names with zero rename failures:

| Kind | Count |
| --- | ---: |
| Functions | 4,714 |
| PLT thunks | 3,183 |
| Jump thunks | 199 |
| Data symbols | 505 |
| Total translated symbols | 8,601 |

The old connector has a concrete compatibility problem. Its embedded
GraalWeb certificate expired on 2023-07-29, so the original HTTPS path cannot
be trusted by a current clock. There is also a separate script-to-native
handler-table ordering bug in this build. A diagnostic x86_64 build with the
two compatibility repairs can connect to a loopback responder, complete the
NewGraal key exchange, receive a server-warp, request the map, and request
encrypted level files.

The corrected two-connection replay now renders the level tile field and game
HUD. The blue connecting control remains visible because packet 182 is present
in the encrypted capture but does not reach the native handler that static
analysis associates with hiding that control. This is the active runtime
blocker, not a claim that the live service is working.

The game has not yet been verified against a live game server. The local test
client renders a synthetic world but still displays its connecting control.
That is an active investigation item, not a claimed success.

## Repository layout

* `docs/RESEARCH_NOTES.md` is the chronological investigation record.
* `docs/PROTOCOL.md` describes the connector and NewGraal wire formats.
* `docs/LEVEL_CONTAINER.md` describes the encrypted `.code` level container.
* `docs/SYMBOLS.md` explains the symbol export and naming policy.
* `docs/RUNTIME_STATUS.md` lists verified milestones and open blockers.
* `docs/TESTING.md` describes local-only reproduction without contacting a
  live game service.
* `symbols/libqplay.symbols.csv` is the searchable symbol table.
* `symbols/libqplay.symbols.json` is the machine-readable equivalent.
* `symbols/libqplay.symbols.summary.json` records the translation counts.
* `tools/` contains IDAPython, parsing, replay, and diagnostic patch helpers.
* `artifacts/` contains small metadata exports. APKs, certificates, private
  keys, captured credentials, and game assets are intentionally not included.

## Inputs used for the analysis

The primary input was the ARM64 library from the original Graal Online
Classic 1.8 APK. The x86_64 library from the same package was used only for
repeatable emulator experiments because the available Android emulator is
x86_64. A separate `spectron_client_1.0.2.apk` was compared as a reference,
not treated as proof that its routing or signing behavior belongs to the
original client.

Two helper repositories were also checked out locally during the work:

* `MorenoLand/GScript.Go-HexaParser`, used as a reference for GS2 bytecode
  tooling.
* `MorenoLand/Moreno.kahn`, used to validate the archived connector package
  and its `con.png` container.

Their source is not vendored here. The exact commits and the comparison
results are recorded in the research notes.

## Safety and scope

The tools are intended for an owned or otherwise authorized copy of the
client, and the runtime tests are designed to stay on loopback. The patch
helpers are diagnostic artifacts. They bypass stale package verification or
redirect a test endpoint, so they should not be installed as a general client
repair without first replacing the endpoint and trust material with values
that are independently verified.

Do not put account passwords, private keys, live server responses, or copied
game assets into commits. Hashes and structural metadata are enough to make
the analysis auditable without publishing secrets or a full game data set.

## Next investigation step

The next useful experiment is to inspect the live `indatahandlers[182]` value
on the second connection and repeat the sequence on ARM64. Static analysis
maps packet 182 to handler index 14, but the x86_64 dispatch probe does not
reach that handler even though the packet is present on the wire. The renderer
already runs, so adding more guessed level packets is less useful than
resolving this table mismatch.
