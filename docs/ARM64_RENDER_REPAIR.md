# ARM64 render repair notes

This note records what is known about the ARM64 loading screen and render
boundary. It describes diagnostic patches and their evidence. It does not
claim that the ARM64 library has a finished production repair.

## The loading flag

The ARM64 library has a native `TClientEnvironment` loading-screen flag. The
getter is `TClientEnvironment::getLoadingScreenEnabled` at `0x15d35c`. Its
value is read by the connecting-window code, the GUI canvas pre-render path,
and the JNI render loop.

The initial setup also matters. In
`TClientEnvironment::sigcheck(TString const&, bool)`, the premium-option
check branches at `0x15ca7c`. When the option is not enabled, the code clears
the loading flag at `0x15cac8`. When the option is enabled, that clear is
skipped. This means the byte is part of startup state, not merely a final
overlay switch.

The option is not read as a numeric entitlement in this routine. IDA shows the
printable prefix `a9a` at `0x2ce1d0`, but the native `strlen` call sees the full
seven bytes `61 39 61 15 11 35 49` before the NUL terminator. The two simple
string codecs transform that seven-byte marker into `classic`. `sigcheck`
then tests the resulting string length at `0x15ca70`, so the original path
treats the option as enabled and skips the flag clear. The same evidence is
recorded in `artifacts/premium_option.json`.

## Native ownership audit

A second pass over the ARM64 IDA database traced the flag itself rather than
only the screen that it controls. The byte at `0x37a549` starts at `1`, and its
GOT slot is `0x375e30`.

The address-level reader and writer table is preserved in
`artifacts/loading_state_ownership.json`. The IDA database also carries
comments at the key call sites so the same conclusion is visible while
navigating the ARM64 file.

The native access pattern is narrow:

* `TClientEnvironment::getLoadingScreenEnabled` at `0x15d35c` reads the byte
  and returns it.
* `TClientEnvironment::setLoadingScreenEnabled` at `0x15d370` writes the byte.
  When it writes false and `loadingstate` is at most `2`, it also changes
  `loadingstate` to `3`.
* `TClientEnvironment::sigcheck` at `0x15ca08` reaches the existing clear at
  `0x15cac8` only when the decoded premium-option string is empty.

The data xrefs in the ARM64 database show the flag being accessed by those
three routines, with no later native store in the successful connector and
resource path. The only call xrefs to the setter's PLT entry are the message
box path at `0x16882c` and the connect-failure path at `0x2037c0`. Those are
error paths. The packet-190 wrapper at `0x1eb4c0` hides the connecting window
and invokes the server-list callback, but it does not clear this flag.

The JNI loop makes the consequence explicit. After `runTimers`,
`QPlayLoop` reads the getter at `0x244228` and branches at `0x244230` to the
loading-screen draw path when the value is nonzero. This explains how the
unmodified ARM64 replay can complete both game connections, download the map
and other resources, and still draw the loading image. The local evidence is
therefore a native startup-state gate, not a general connector or resource
failure.

This is an audit of native writers. It does not rule out a write from a GS2
script or another VM path. The recovered connector source does not clear the
flag after a successful login; its visible assignment is in the disconnect
error handler. No successful-login native clear was found in this ARM64
revision.

## Script-level loading clear candidate

The recovered bytecode does contain a loading-state assignment, but it is in
`printDisconnectError`, not in `onServerLogin`. The compiler output from
HexaParser is readable and structurally parseable, yet the clean runtime
control did not reach the expected game port after the literal-order adapter.
Its stream expands from 3,143 to 3,582 instructions, so recompiling the source
is not currently a safe way to preserve this old VM's behavior.

`tools/patch_connector_bytecode_loading_clear.py` takes the smaller path. It
copies the original six serialized bytes for
`loadingscreenenabled = false` into `onServerLogin`, immediately before the
existing `this.reconnections = 0` assignment. It updates only shifted function
entry offsets and branch targets. The direct candidate retains the original
handler tables, string table, opcodes, native RSA branch, and native TLS code.

In a clean loopback replay, the direct candidate made the connector TLS
request, completed two encrypted game connections, received the GMAP and
three level files, and continued heartbeat traffic. The title/loading artwork
remained visible in the captured frame, so this is not yet a render-success
claim. It does establish that a script-level insertion in the original VM
stream can be loaded and can coexist with the full protocol/resource path.
The exact hashes and test scope are in
`artifacts/bytecode_loading_clear_replay.json`.

When the direct script patch was combined with the one-instruction native
startup clear at `0x15ca7c`, the same translated ARM64 fixture displayed the
green world field, HUD, and status icons. The script package, TLS path, RSA
branch, and game responder were otherwise unchanged. Since the combined run
contains two edits, it confirms that the direct script patch is compatible
with the rendering candidate but does not replace the native ownership
finding. The native branch remains the variable tied to the visible
title-to-world transition in this test.

## x86 diagnostic scope

The x86_64 comparison needs a separate qualification. Its original library
also starts with the loading byte set and contains the same premium-option
branch. Several historical x86 diagnostic APKs in the local test set,
including the no-swap and current-normal variants, override the loading getter
at `0x16ee80` to return false. Their rendered screenshots prove that the
protocol, resource, and downstream renderer paths can work, but they do not
prove how an unmodified x86 build resolves its loading state. The ARM64 native
ownership result above is the architecture-specific finding being carried
forward.

The JNI render loop checks the flag at `0x244228`, immediately before choosing
between the loading-screen path and the normal game drawing path. The useful
diagnostic boundary is therefore the render-loop check, while the getter and
the earlier setup code are involved in more than drawing.

## Negative controls

### Getter-only patch

`tools/patch_loading_screen_getter_test.py` replaces the ARM64 getter at
`0x15d35c` with a return of false. This patch was intentionally used as a
negative control.

It did not produce a rendered world. More importantly, it suppressed the
normal connector startup log and generated no request at the local connector
port, even though the process and its OpenGL context stayed alive. That result
shows that callers use the getter during startup and UI sequencing. Returning
false globally is not a safe loading-screen repair.

### Packet-190 flag experiments

Packet 190 is correctly mapped to handler index 14 and the native
`sub_1EB4C0` wrapper. That wrapper hides the connecting window and invokes the
server-list connection callback. It is not the right place to force the ARM64
render flag.

Two bounded experiments tried to clear the flag around this handler. One
changed additional loading state and stalled before the map request. A
narrower trampoline called the original hide routine and cleared only the
loading byte. Its first version crashed because of an unsafe translated
link-register return. A branch-back version avoided the crash, but still
stalled before the map request and left the screen black. The evidence says
that changing the flag at packet 190 is too early, or otherwise interferes
with the normal transition. Packet 190 remains part of the working protocol
sequence and is not a repair point.

## Non-premium initialization candidate

The most promising repair is the one-instruction test
`tools/patch_force_no_premium_loading_test.py`. It changes the conditional
branch at `0x15ca7c` from `B.LE 0x15cac0` to an unconditional branch to the
existing flag-clear path. The rest of `sigcheck`, environment initialization,
and the normal JNI render-loop branch are unchanged.

The first run of this candidate appeared to stall, but that run used a map
body without the required `.gmap` suffix. Repeating it with
`classiciphone.gmap` produced the map request, all three level requests,
`pics1.png`, continuing heartbeats, and a rendered world with the ordinary
render loop. The resulting ARM64 library SHA-256 was
`89a7cf3a10d9da9fb00f50e6917ce10402c1147bcf5738a176c26b32868ba858`.

This is currently the leading local compatibility candidate because it
corrects initialization state instead of forcing a draw every frame. It still
needs validation on the intended ARM64 device and against an authorized live
service. The decoded value is statically confirmed as `classic`; the
production meaning of the entitlement branch still deserves a final check
before calling this a production repair.

## Successful render-boundary diagnostic

The stronger diagnostic hooks the getter call at `0x244228`, after the loop
has already run timers and processed packets. A trampoline at the zero-filled
code cave `0x1f9508` clears the one-byte flag through its GOT slot at
`0x375e30`, sets the return value to zero, and branches back to `0x24422c`.
The original `UXTB` and conditional branch at `0x244230` remain in place.
The patch is available as
`tools/patch_render_loop_clear_loading_flag_test.py`.

This timing is important. It leaves connector startup, packet dispatch, and
the map transition untouched, then changes only the render decision for that
frame. With this ARM64 build, the emulator displayed a green tiled world, the
player HUD, and the status icons. The same build completed the connector
exchange, server warp, encrypted game login, map request, level-file requests,
and image request before the screenshot was taken.

An earlier branch-only diagnostic replaced the conditional branch at
`0x244230` with a NOP and produced the same kind of rendered-world evidence.
That test remains useful as a comparison, but the new trampoline better
isolates the state boundary because the normal branch and its surrounding code
still execute.

This is still a diagnostic patch, not a recommended final patch. It clears the
flag on every render iteration. A proper repair should explain and correct
the state transition, then preserve the normal conditional behavior.

## Exact local replay fixture

The second game connection must receive the corrected comma-separated warp
body, not the earlier colon-separated form:

```text
,classic,127.0.0.1,14900
```

After the login and completion sequence, the map transition uses packet 49
with the map name `classiciphone.gmap`. The local responder must provide a
fixture under that exact name, and it must send packet 49 again after the map
response so the pending transition is completed. The verified fixture used
by the replay has this SHA-256:

```text
classiciphone.gmap  bc061465a7705bad074e7ae872bd9d0da14ce3d420f395fc4084760c48b682a8
```

The associated replay also served the verified level and image fixtures:

```text
overworld_west_ocean_02.nw-14900.code  9003d2474c556fb69b04a6f019523dd738b1bad6701099a08274fe5be2b30779
pics1.png                              fe2dff5c4af86179d0cf83306a40c7e7b92d728a99f1f73a5ec2cf9c897764eb
```

The exact file name is important. A different map name or the earlier warp
body can exercise a different client path and produce a misleading failure.

## What the local evidence proves

On the available Android 36 x86_64 emulator, Android loaded the ARM64
library through its native translation layer. The ARM64 diagnostic replay
made both game connections, completed the `fd` and `fc` exchange, accepted the
encrypted login result, received packets 9, 190, and 49, requested the GMAP,
requested three encrypted level containers, requested `pics1.png`, and kept
sending packet 24 heartbeats. The verified files appeared in the external
Android cache.

The ordinary ARM64-only replay stayed on the title or loading image despite
those completed requests. The render-boundary diagnostic then showed the
green world and HUD. Together, these observations narrow the failure to the
loading-versus-game draw decision under translation. They do not show a
missing map, a failed game socket, or a general ARM64 resource-loader failure.

## Limitations and next validation

This work uses a local synthetic connector and game responder. It does not
verify account authentication, current server availability, live certificate
behavior, package signatures, or compatibility with a live game server.

The ARM64 result was observed through an x86_64 emulator translation layer,
not on a physical ARM64 device. The forced-draw screenshot proves that the
translated process can execute the relevant draw path, but it does not prove
that the same behavior is correct on real ARM64 hardware.

The next safe step is to test the initialization candidate and the render
boundary control on an authorized physical ARM64 device, then compare them
with a live service only when that service and account are authorized for the
test. The native ownership audit makes a later resource-completion trace a
lower-priority follow-up. The render-boundary bypass should remain available
as a diagnostic comparison, but should not be treated as the final
compatibility fix.
