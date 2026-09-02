# Update packages and file-transfer completion

This page documents the update-package path in the original Graal Online
Classic 1.8 ARM64 library. It covers two related layers:

* the line-oriented `GRPKG001` manifest parser; and
* the NewGraal packet state machine that downloads ordinary and large files.

The static addresses refer to the original ARM64 `libqplay.so`, SHA-256
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8`. Runtime
observations came from a private x86_64 diagnostic build and loopback-only
responders. They are useful controls, not live-server results. The compact
machine-readable record is
`artifacts/update_package_transfer_review_20260902.json`.

## What the client calls a package

An update package is a text manifest whose first line must be `GRPKG001`.
The parser is `TUpdatePackage_load_void` at ARM64 `0x209fa4`. It loads either
a cached stream or a local package file into a line list, clears the previous
package state, and then examines recognized directives.

| Directive | Observed behavior |
| --- | --- |
| `NAME` | Sets the package display or lookup name. |
| `FLAG` | Stores a named `TGraalVar` subvariable. |
| `VERSION` | Parses the package version as a floating-point value. |
| `PLATFORM` | Stores the platform selector used by file records. |
| `ACCOUNTS` | Splits a comma-separated account list. |
| `MODE` | Stores the package mode string. |
| `SUBPACKAGE` | Reduces the value to a basename, requires `.gupd`, and loads or starts the nested package. |
| `FILE` | Parses a directory and final filename, checks platform and filename policy, and adds an accepted file entry. |
| `DESCRIPTION` | Starts a multiline description. |
| `DESCRIPTIONEND` | Ends the multiline description. |
| `ISMAINEXECUTABLE` | Sets the main-executable marker and its associated state. |
| `USECHECKSUM` | Enables the package checksum flag. |
| `PROTECTOVERWRITE` | Sets the protected-overwrite flag. |

The private local cache contained a 152-byte `basepackage.gupd` with the
following high-level shape: a package name, version, `PLATFORM any`, several
subpackage entries, and protection/checksum flags. Its body is intentionally
not copied into this repository. The public record contains its hash and size
only.

### Nested packages

`SUBPACKAGE` is more active than a display-only relationship. The parser
lowercases the value, keeps the portion after the last slash or backslash,
checks for a `.gupd` extension, and looks up the resulting package. A nested
package can be added to the download set while the parent manifest is still
being loaded. This is why a minimal manifest with no `SUBPACKAGE` line does
not reproduce the normal startup graph.

The basename step prevents a literal value such as `../../other.gupd` from
reaching the package filename builder as a traversal path. That is useful
normalization, but it is not a complete filesystem guarantee. The later cache
path still needs canonical containment and symlink-safe file creation.

### File records and path policy

`FILE` records retain a directory and a final filename. The parser checks the
platform, calls `TFileScripting_AllowedFoldername` with the package policy,
rejects disallowed characters and ordinary parent-directory spellings, and
blocks selected executable extensions. The protected extension checks include
`.exe`, `.lexe`, `.bat`, and `.com` unless the package is privileged. A file
matching the configured base executable is also treated specially.

The reviewed path does not show a general `realpath` check or a no-follow open.
The resource and cache helpers use string prefixes, `stat`, and ordinary file
opens. An accepted path is therefore not automatically a proof of escape from
the application data directory, but symlink behavior remains a relevant test
target in a disposable directory.

The parser also has no single visible budget for total records, description
bytes, nested package expansion, or aggregate file size. Those are resource
exhaustion concerns if an untrusted package can reach this path. The package
signature boundary is separate from this manifest parser. The reviewed
parser does not itself authenticate the response bytes.

## Wire-level transfer state

The inbound table maps the large-file sequence as follows:

| Wire type | Internal handler index | ARM64 handler | State change |
| ---: | ---: | --- | --- |
| 68 | 21 | `TClient_beginBigFileDownload` at `0x1eb12c` | Selects the large-file filename and starts transfer state. |
| 84 | 22 | `TClient_setBigFileSize` at `0x1ef48c` | Decodes five characters into a 32-bit declared-size field. |
| 102 | 24 | `TClient_parseEncodedFileChunk` at `0x1f0de4` | Parses a chunk and forwards it to `TClient_processFileChunk` at `0x1ec764`. |
| 69 | 23 | `TClient_finishFileDownload` at `0x1eb294` | Tests the completion filename, then looks up a cached stream and can finalize it. |

The internal handler index is not the wire packet number. The full table and
the packet-to-index mapping are in `artifacts/inbound_handler_table.json`.
Packets are drained by `TClient_processIncomingPackages_void` at `0x1e7d68`
and dispatched by `TClient_processIncomingPackage_int_TString_const` at
`0x1e7c90`.

The packet-102 parser requires a body longer than six bytes. Its first five
encoded characters form the protocol's file field, the next field supplies a
filename length, and the filename and data follow. The decompiler identifies
the first field as an offset or size value in this protocol family. The
reviewed chunk path appends data to the active dynamic stream; it does not show
a strict seek-to-offset operation or a comparison of accumulated bytes with
the type-84 declaration before saving.

### Declared-size decoding

`TClient_setBigFileSize` at `0x1ef48c` checks that its input exists and has
length greater than four. It then reads five bytes and combines them with
32-bit ARM arithmetic:

```text
(b1 << 28) + ((b2 - 0x20) << 21) + ((b3 - 0x20) << 14)
            + ((b4 - 0x20) << 7) + (b5 - 0x20)
```

There is no visible character-range, signedness, upper-bound, or overflow
check before the result is stored in `bigfilesize`. The reviewed code passes
the field into progress and `onFileChunkReceived` values. This is a clear
input-validation gap, but this pass did not establish that the field directly
controls an allocation or causes memory corruption.

The state machine is easiest to read as two paths:

```text
ordinary response:
  packet 102
    -> parse filename and data
    -> processFileChunk
    -> onFileChunkReceived
    -> onFileDownloaded
    -> save cache and update resource

large-file response:
  packet 68 -> select big filename
  packet 84 -> store declared size
  packet 102 -> append data and emit onFileChunkReceived
  packet 69 -> match filename
             -> clear big-file state
             -> onFileDownloaded
             -> save cache and update resource
```

For a `.gupd` filename, either completion path can call
`updatePackageDownloaded_TString_const` at `0x20a798`. That function reloads
the package state and eventually emits package-completion script events. The
client completion handler at `0x1ec044` updates the local package version,
emits `onUpdatePackageDownloaded` and `onPackagesDownloadComplete`, and can
enter the executable-replacement path when the package is marked for it.

## The completion-path observation

The first synthetic test returned a 49-byte metadata-only `basepackage.gupd`
with no file or nested-package entries. In the x86_64 diagnostic replay, the
client accepted the transfer sequence and then faulted at a null address:

```text
SIGSEGV, fault address 0x0, thread GLThread
TScriptSpace::receiveEvent + 38
TScriptSpace::invokeCreatedEvent
TScriptSpace::TScriptSpace
TGraalVar::createScriptSpace
TGraalVar::receiveEvent
TClient::processIncomingPackages
```

The ARM64 constructor at `0x229cf8` invokes the `created` event through
`TScriptSpace_invokeCreatedEvent_void` at `0x229c74`. The first instructions
of `TScriptSpace_receiveEvent` at `0x229898` dereference the owner
`TGraalVar`, load its vtable, and call the virtual slot at offset `0x98` before
the ordinary event queue work. The local x86_64 instruction offset was
`0x242246`, with the instruction pointer reported as zero. That is consistent
with a null or invalid owner callback, although it does not by itself prove
which object field was wrong in the diagnostic build.

The filename check in `TClient_finishFileDownload` is also less restrictive
than its name suggests. The handler tests whether the supplied filename equals
the active `bigfilename` and clears that global on equality. The equal and
unequal branches then converge on `TCachedStream_getCachedFile` with the
supplied name. If a cached stream is found, the handler can emit
`onFileDownloaded`, save it, and take the `.gupd` callback path. No early
reject for a mismatch is visible in the ARM64 decompilation. This is a
state-confusion lead that needs an isolated filename-mismatch replay; it is
not evidence that an arbitrary filesystem path is accepted.

The important follow-up was to vary only the transfer state:

| Control | Result | What it tells us |
| --- | --- | --- |
| Valid local 152-byte package, packets 68, 84, 102, omit 69 | Process stayed alive and requested the package again. | Packet-102 data alone did not reproduce the crash. |
| Same package, packet 69 delayed by two seconds | Same `TScriptSpace` crash. | The completion transition or its immediate callback is the leading local trigger. |
| Same large-file sequence with `probe.bin` instead of a `.gupd` name | Same `TScriptSpace` crash. | The local failure does not require package-specific metadata completion. |
| Same package in one ordinary packet 102 | Process stayed alive during the bounded replay. | Ordinary completion and large-file completion have different state. |
| Metadata-only package, packets 68, 84, 102, 69 | Same crash family. | Missing startup records may expose the unguarded script setup path, but are not required by the filename control. |

The delayed-finish capture is identified by hashes in
`artifacts/update_package_transfer_review_20260902.json`. No packet body,
credential, APK, or native library is stored in the public repository.

## Security interpretation

This is an availability lead, not a confirmed remote exploit. The local
evidence supports three narrow statements:

1. The original ARM64 code has a distinct completion callback for large-file
   transfers.
2. The x86_64 diagnostic build reaches script-space construction after the
   large-file completion transition and faults on a null indirect call.
3. The same local trace appears with a non-package filename, so the result is
   not explained solely by parsing the `GRPKG001` records.

The evidence does not show that the stock ARM64 build, a production server, or
an unmodified APK accepts an attacker-chosen sequence. It also does not show
code execution. The diagnostic build may differ in object initialization,
architecture-specific layout, cached state, or script contents. ARM64 runtime
confirmation and a debugger-backed comparison with a stock x86_64 build are
still required before assigning a production severity.

Other update-path concerns remain independent of this crash:

* received data is appended before a visible declared-size, offset-order, or
  response-signature check;
* the packet-84 declared-size decoder has no visible range or overflow check;
* packet-69 does not visibly reject a completion filename mismatch before
  cached-file lookup;
* manifest and nested-package expansion lack a single visible aggregate
  budget;
* cache writes are non-atomic and the reviewed `fwrite` result is not checked;
* executable replacement is a separate high-impact capability and must not be
  enabled without authenticated package provenance.

## Repair targets

A compatible repair should make the state machine explicit and defensive:

* Reject packet 69 when no matching large-file transfer is active, and reject
  a completion filename that does not match the selected transfer.
* Track received bytes and offsets, enforce the declared size with overflow-safe
  arithmetic, and cap each file plus the aggregate download set.
* Bound manifest records, description bytes, nested package count, and total
  expansion before scheduling additional work.
* Authenticate the package and each executable-bearing update before activation.
* Save to a temporary file, check every write, fsync as appropriate, and rename
  atomically only after validation.
* Resolve the final path below an application-owned canonical root and use
  no-follow semantics for each component where the platform permits it.
* Have script-space construction return a controlled error when the owner or
  its callback is absent instead of making an unchecked virtual call.

These repairs should be tested with loopback fixtures first. The goal is to
restore the old client without turning a compatibility workaround into a new
trust bypass.
