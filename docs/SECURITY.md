# Security and trust-boundary review

This page records the security review of the original Graal Online Classic 1.8
APK and its ARM64 `libqplay.so`. It is intentionally conservative. A string,
an imported function, or an update capability is evidence of an attack surface;
it is not by itself proof that a remote attacker can reach or exploit it.

The review was performed against the following private inputs:

* APK SHA-256: `6d6c0428fe890d0f18fb1ce572798d7a8a95853b10078f693026164d6a5f56d7`.
* ARM64 `libqplay.so` SHA-256: `9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ae9982eb00e5b9c8`.
* Package: `com.quattroplay.GraalClassic`.
* Version: code `6158`, name `1.8`.

The machine-readable evidence is in
`artifacts/original_apk_security_audit_20260830.json` and
`artifacts/original_security_callsite_review_20260830.json`. The first report
is produced by `tools/audit_original_apk.py`. The second is exported directly
from the original ARM64 IDA database by
`tools/ida_export_original_security_callsite_review.py`.

## Executive assessment

The most likely reason this old client no longer starts is compatibility, not a
newly introduced exploit. The native connector embeds a historical trust bundle
whose first recorded certificate expired on 2023-07-29. The connector also has
legacy HTTP parsing and a native CyaSSL path that is independent of Android's
Java trust store. A current service chain cannot be assumed to work with the
old embedded material.

There are also several meaningful security boundaries:

1. The APK has network permission and four native ABI variants. The native
   library opens sockets directly and contains its own TLS implementation.
2. The main activity accepts `graalclassic://` and
   `graalclassicplus://`. The manifest does not write an explicit
   `android:exported` value, but its intent filters make the activity effectively
   exported under the old Android component rules. Other applications can
   therefore request that activity.
3. The Java DEX contains a WebView path with JavaScript enabled and a native
   JavaScript bridge. The audit establishes the capability and its input
   boundary. It does not establish that an attacker-controlled page can reach
   every bridge method.
4. Update code can remove package files and can start a replacement executable.
   The generic deletion helper calls `unlink`, while the reviewed script and
   update callers provide the path policy around it. The executable handoff is
   a high-impact capability, but this pass did not prove an attacker-controlled
   update package or executable path.
5. Device-identification code reads the `eth0` hardware address, hashes it for
   a network identifier, and exposes other system-ID modes including Android ID.
   This is a privacy concern and an account-correlation surface, not evidence of
   code execution.

The native libraries do have useful baseline mitigations. All four packaged
libraries report a non-executable `GNU_STACK`, GNU RELRO, and `BIND_NOW` in the
ELF metadata. Those properties do not compensate for unsafe input, stale trust
material, or an overly broad update path.

## Evidence boundaries

The findings use these terms:

* **Confirmed static** means the item was read from the APK, ELF metadata, DEX
  string table, or decompiled ARM64 code.
* **Local runtime** means a behavior was reproduced with an emulator and a
  loopback responder. The runtime work in this repository reached a rendered
  world using diagnostic-only builds and did not contact a live game service.
* **Unproven reachability** means the code or capability exists, but the review
  has not shown that an untrusted page, URI, package, or server response can
  supply its input.
* **Live** would mean a current production service accepted the client. No live
  result is claimed here.

The report does not install the APK, send an intent to another application,
inject DEX, fuzz the native parser, contact a production endpoint, or attempt
to bypass a signature on a live service.

## Android package surface

The binary manifest reports:

| Property | Value | Security meaning |
| --- | --- | --- |
| Package | `com.quattroplay.GraalClassic` | Identifies the old application namespace |
| Version | `6158`, `1.8` | The reviewed release |
| Minimum SDK | 9 | The package predates modern platform defaults |
| Target SDK | 26 | Old component and cleartext defaults matter on newer Android versions |
| Network permission | `android.permission.INTERNET` | Native connector and game sockets can reach remote hosts |
| Storage permission | `WRITE_EXTERNAL_STORAGE`, capped at SDK 18 | Legacy external-cache behavior |
| Custom schemes | `graalclassic://`, `graalclassicplus://` | URI input reaches the launcher activity |

The main activity has launcher and browsable intent filters but no explicit
`android:exported` attribute. The audit records both the raw attribute and an
`exported_effective` value inferred from the presence of intent filters. This is
important when reading the manifest with modern tooling, which may present the
omitted field differently from an old Android runtime.

The package does not declare `android:usesCleartextTraffic=true` in the binary
manifest. Its absence is not the same as a modern explicit false. Since the
target SDK is 26, platform behavior and the individual networking stack still
need to be checked before treating the package as cleartext-safe. The native
connector is separately reviewed as a CyaSSL client, so a manifest conclusion
alone cannot explain its network behavior.

## WebView and Java bridge

The DEX string inventory finds `WebView`, `setJavaScriptEnabled`,
`addJavascriptInterface`, `JavascriptInterface`, `getSharedPreferences`, and
`android_id`. This is enough to identify a native WebView bridge boundary in
the Java layer. It is not enough to say that a remote attacker owns the bridge.

The risks to resolve in a follow-up review are straightforward:

* What exact URL or local content is loaded into the WebView?
* Is navigation restricted to an allowlist, or can arbitrary redirects reach the
  page with the bridge attached?
* Which bridge methods are annotated and what data do they return or write?
* Can message data be inserted into JavaScript without quoting or escaping?
* Can a URI or native server message trigger the WebView path before the user
  has authenticated?

The safe maintenance direction is to remove the bridge from untrusted pages,
use an explicit URL allowlist, validate every message as structured data, and
avoid enabling JavaScript where it is not required. Those changes are for a
new authorized build. They are not assumptions about the behavior of the
original package.

## Native connector and TLS

The original ARM64 library imports socket, resolver, send, receive, and file
operations directly. It contains a bundled CyaSSL implementation and a fixed
trust buffer. The native path is visible in the translated symbols:

* `TSocketConnection_connectSocket` at `0x206bd8` creates the TCP connection
  and resolves the host.
* `TSocketConnection_enableSSLOnSocket` at `0x206450` selects a CyaSSL client
  method, loads the configured verify buffer, enables peer verification when a
  buffer is present, checks the configured hostname, sets nonblocking mode, and
  calls `CyaSSL_connect`.
* `TSocketConnection_read` at `0x2074d4` reads through CyaSSL when a TLS object
  exists and closes the socket on terminal read errors.

The embedded trust text is 12,820 bytes and has SHA-256
`c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0`. The
certificate-date parser calls the current UTC clock. The earliest connector
certificate recovered from the bundle expired on 2023-07-29. This is a strong
compatibility explanation for a current-clock device, but it is not a reason
to disable verification globally.

The binary also contains identifiers for TLS 1.1, TLS 1.2, RC4, and NULL
cipher suites. Those names show that the bundled implementation knows about
legacy options. They do not prove that a weak suite was selected or
negotiated. The local loopback tests kept peer and hostname checks in the
native path; the private diagnostic changes were used only to separate stale
trust and parser problems from the rest of the game protocol.

The APK contains `res/raw/fabzat_com.crt`, whose subject is
`admin.fabzat.com` and whose recorded validity ended in 2014. Its presence is
legacy material, not proof that the startup connector consumes it. It should
not be treated as a current trust anchor.

## Update and file operations

### Executable replacement

`TClient_handleUpdatePackageDownloaded` at `0x1ec044` calls the package lookup,
marks the package as downloaded, updates its local version, invokes the
`onUpdatePackageDownloaded` and `onPackagesDownloadComplete` script events, and
then checks the replacement flag. If all package downloads are complete and
the flag is set, it calls `TSetup_startExeReplacer_TString_const`.

The reviewed replacement function at `0x196fe0` does the following:

1. Copies the configured full executable path.
2. Calls `chmod(path, 0775)`.
3. Prepares shutdown and forks.
4. In the child, calls `execvp(path, argv)` with the path as `argv[0]` and no
   additional arguments.
5. In the parent, sets the close-application flag.

The reviewed function does not itself verify a package signature. That does not
prove that earlier update code fails to verify one. It means the signature and
path provenance must be traced through the package parser and download
completion code before enabling an update repair. A safe current implementation
should verify an authorized package signature, constrain the executable path to
the application-owned directory, avoid making it group or world executable,
and use an atomic replacement strategy.

### File deletion

`TFiles_deleteFile_TString_const` at `0xe6dfc` is a thin wrapper around
`unlink`. It does not perform a policy check itself. The caller determines
whether the path is safe.

The reviewed package uninstall function at `0x20a9cc` skips packages named
`optional`, iterates the package file list, lowercases each name, resolves it
through `TResourceFunctions_getGameFile`, and then calls the generic deletion
helper. It saves the local package version after the loop. This is a capability
to remove cached game files, not proof of arbitrary file deletion.

The script-facing path is more constrained. `TFileScripting_initStaticVars` at
`0xfd054` initializes blocked extensions including `.exe`, `.dll`, `.so`,
`.sh`, `.bat`, `.cmd`, `.msi`, `.scr`, and `.sys`. It also initializes allowed
filename characters and approved directory prefixes such as `levels/`,
`translations/`, `offline/`, `tileobjects/`, `updatepackages/`, `profiles/`,
and `maps/`. `TFileScripting_AllowedFoldername` checks folder characters and
approved segments. `TFileScripting_script_deleteFile` resolves the script
access path, checks that it exists, calls the deletion helper, and updates the
resource object.

These checks reduce the script API's reach, but they are not a substitute for a
complete path-traversal review. The next native pass should test separator,
percent-escape, symlink, case-folding, and archive-entry behavior entirely on
loopback and inside a disposable application directory.

## Device identifiers and stored state

The identification path is more privacy-sensitive than it first appears.

* `TIdentification_getMacAddressBuffer_void` asks the kernel for `eth0` using
  `SIOCGIFHWADDR`.
* `TIdentification_retrieveMACAddress_bool` stores the six-byte result in the
  native identification state.
* `TIdentification_getNetworkID_void` computes an MD5 digest over the stored
  MAC address when retrieval succeeds.
* `TIdentification_getSystemID_int` selects among a fixed `dc:id2` value,
  hard-disk ID, network ID, OS ID, and Android ID.
* `TIdentification_getCookieFilename_void` chooses
  `basedatafolder/cache/creationtime.dat` when present, otherwise
  `basedatafolder/files/creationtime.dat`.
* `TIdentification_getCookie_void` loads that file into a native string.

The MD5 output appears to be used as a stable identifier rather than as a
password hash. Hashing does not make a hardware identifier anonymous when the
input space is small or the same construction is reused across services. A
modern replacement should use a documented, resettable, per-installation
identifier and disclose its purpose.

## ELF hardening inventory

The APK packages `libqplay.so` for ARM64, ARM, x86, and x86_64. The offline
audit extracted each library into a temporary directory and ran `readelf` only
on those temporary copies. All four report:

* non-executable `GNU_STACK` program headers;
* a GNU RELRO segment; and
* `BIND_NOW` dynamic-linker metadata.

The ARM64 library has 6,674 dynamic symbol-table entries and retains the
exported names used by the IDA translation pass. Its interesting imports include
`chmod`, `connect`, `execvp`, `fork`, `gethostbyname`, `ioctl`, `open`,
`recv`, `recvfrom`, `send`, `sendto`, `socket`, and `unlink`. Imports are
capabilities. The call-site review is what establishes the specific behavior
described above.

## Priorities for a safe repair

The practical order is:

1. Keep the original APK and library hashes recorded. Use a disposable private
   diagnostic build for every patch.
2. Replace the stale connector trust material only with a certificate chain
   obtained from an endpoint and service owner that the operator is authorized
   to test. Keep peer and hostname verification enabled.
3. Reproduce the connector response with exact legacy headers and body framing
   on loopback before attributing a failure to TLS. The old parser is strict
   about some lowercase header spellings.
4. Trace package signature verification from package input to
   `TClient_handleUpdatePackageDownloaded` before testing executable replacement.
5. Exercise deep links, WebView messages, script paths, archive names, and
   update entries only against loopback and disposable directories.
6. Do not publish private keys, account credentials, production server
   responses, or full game assets. Hashes and structural metadata are enough
   for an auditable report.

## Reproduction

From the repository root, with the original APK at its default private path:

```text
python3 tools/audit_original_apk.py
```

The command writes the compact report to
`artifacts/original_apk_security_audit_20260830.json`. It makes no network
connection and does not install the package. The IDA call-site exporter is run
inside the open original ARM64 IDA database and writes the second report after
the `IDA_SECURITY_REVIEW_OUT` environment variable is set. Both reports carry
the input hash so a later result can be compared without publishing the input.
