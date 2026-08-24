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
be trusted by a current clock. The archived connector package also fails the
RSA check against this APK's embedded public key. Both findings are separate
from the game-server protocol and are handled only by private diagnostic
patches in the local test build.

The symbolized handler-table investigation also produced an important
correction. The original `setInDataHandlers` instructions are correct for this
client revision. The earlier x86_64 `xchg` patch and the matching ARM64
operand swap were a false lead caused by reading the intermediate bytecode
array in the wrong order. The decoded runtime pairs are packet type first,
handler index second, and the unmodified table accepts the normal local
sequence.

The corrected two-connection replay renders the level tile field, player HUD,
and status icons with the x86_64 diagnostic build. The client accepts a
server-warp, a player-properties packet, the connecting-window completion
packet, the map transition, three encrypted level containers, and `pics1.png`.
The file response is packet 102, not packet 59. A direct packet-59 parser jump
was retained only as a negative control because it breaks the normal request
sequence.

The same replay was run with an ARM64-only diagnostic APK. The available
Android emulator is x86_64, so Android loaded the ARM64 library through its
native translation layer. The ordinary ARM64 build completed the connector
request, server warp, encrypted login exchange, map request, three level-file
requests, `pics1.png` request, and continuing heartbeats, but stayed on the
title or loading image. A second diagnostic build cleared the loading byte
only after timer and packet processing, at the JNI render boundary. That build
displayed the tiled world, player HUD, and status icons. A stronger
one-instruction candidate instead forces the existing non-premium
initialization path at `0x15ca7c`; with the corrected map fixture, it displays
the same world through the normal render branch. The candidate still needs
real ARM64-device and authorized live-service validation.

The game has not yet been verified against a live game server. The local test
proves that the x86_64 native client and the patched ARM64 library can reach a
rendered world through a bounded loopback responder. Live endpoint
availability, current package signing, account authentication, and physical
ARM64-device behavior remain open.

## Repository layout

* `docs/RESEARCH_NOTES.md` is the chronological investigation record.
* `docs/PROTOCOL.md` describes the connector and NewGraal wire formats.
* `docs/LEVEL_CONTAINER.md` describes the encrypted `.code` level container.
* `docs/SYMBOLS.md` explains the symbol export and naming policy.
* `docs/RUNTIME_STATUS.md` lists verified milestones and open blockers.
* `docs/ARM64_RENDER_REPAIR.md` records the ARM64 loading-state experiments
  and the successful render-boundary diagnostic.
* `docs/HELPER_TOOLCHAIN.md` records the pinned GS2 and connector-helper
  checks, including their reproducible hashes and current limitations.
* `docs/SPECTRON_COMPARISON.md` records the supplied modded APK comparison.
* `docs/TESTING.md` describes local-only reproduction without contacting a
  live game service.
* `symbols/libqplay.symbols.csv` is the searchable symbol table.
* `symbols/libqplay.symbols.json` is the machine-readable equivalent.
* `symbols/libqplay.symbols.summary.json` records the translation counts.
* `artifacts/premium_option.json` records the complete marker bytes and the
  native decoded value.
* `tools/` contains IDAPython, parsing, replay, and diagnostic patch helpers.
  `tools/encode_connector_query.py` reproduces the captured connector query
  without opening a socket.
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

The highest-value remaining work is live-service and ARM64 validation. The
next checks are to trace the native state transition that should clear the
loading byte, verify the current connector trust and package-signing chain,
repeat the same packet sequence on a real ARM64 device, and compare the live
server's resource and login responses with the captured local trace. Those
tests should only use an endpoint and account that the operator is authorized
to test.
