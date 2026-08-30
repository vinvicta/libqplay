# Spectron APK security review

This is a focused security and attack-surface review of the supplied
`spectron_client_1.0.2.apk`. The package is a modified Graal client, not a
trusted upstream release. The review is useful for deciding what must be
contained while reverse engineering it, and for separating compatibility code
from modding code.

The report is based on local static analysis of the APK, the ARM64 native
libraries, the DEX bytecode, the binary Android manifest, and earlier IDA
review of the native WebTop hooks. It did not open the recovered WebTop URL,
contact a production server, send a malicious deep link, inject DEX, or try to
turn a candidate sink into an exploit.

The compact machine-readable record is
[`artifacts/spectron_apk_security_audit_20260830.json`](../artifacts/spectron_apk_security_audit_20260830.json).
The scan can be repeated with
[`tools/audit_spectron_apk.py`](../tools/audit_spectron_apk.py). It reads only
the APK and writes the requested report. Large generated exports remain in the
ignored local archive according to [`ARTIFACT_POLICY.md`](ARTIFACT_POLICY.md).

## Evidence labels

The word "confirmed" below means that the capability or artifact was found in
the package. It does not necessarily mean that the capability is reachable from
an untrusted network response.

| Label | Meaning |
| --- | --- |
| Confirmed | Directly visible in the manifest, DEX, ELF, or an embedded certificate. |
| Confirmed capability | The code path is present, but the attacker-controlled input path still needs a separate reachability test. |
| Candidate | A potentially dangerous API or dataflow was found, but the reviewed path does not yet prove unsafe input. |
| Local runtime | Reproduced against a loopback responder or emulator under controlled conditions. |
| Live unverified | Not tested. No production endpoint was contacted for this review. |

This distinction is important for old game clients. A native socket import, a
TLS cipher string, or a JavaScript bridge is an attack surface. None of those
facts alone proves a remotely exploitable vulnerability.

## Package profile

The supplied APK has SHA-256
`5b10289ad2b67fba77f5f4159d51cdbeaf4ca2710fb1459da69c8d4b1af5149c` and
contains:

| Property | Observed value |
| --- | --- |
| Package | `com.quattroplay.GraalClassiC` |
| Version | `2.2`, version code `6612` |
| Compile SDK | `33` |
| Target SDK | `33` |
| Minimum SDK | `19` |
| ZIP entries | `7,546` |
| Uncompressed package size | `75,535,273` bytes |
| DEX files | `classes.dex`, `classes2.dex` |
| Native libraries | ARM64 and 32-bit ARM copies of `libqplay.so` and `libxposed.so` |
| Application class | `androidx.multidex.MultiDexApplication` |
| Cleartext policy | `android:usesCleartextTraffic="true"` |

The APK has the usual large `assets/offline/` game-content tree. The archive
does not contain duplicate ZIP names, encrypted entries, or traversal-style
entry names according to the compact scan. Those checks are useful hygiene
signals, not a complete parser-hardening review of every consumer.

The declared permissions include `INTERNET`, `ACCESS_NETWORK_STATE`,
`WAKE_LOCK`, `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE`,
`POST_NOTIFICATIONS`, the Google billing and license permissions, and the
package-scoped Firebase, advertising ID, and install-referrer permissions.
`WRITE_EXTERNAL_STORAGE` is present only with `maxSdkVersion=18`.

## Findings at a glance

| ID | Severity | Status | Finding |
| --- | --- | --- | --- |
| APK-001 | Medium | Confirmed | Framework cleartext traffic is allowed. |
| APK-002 | Medium | Confirmed capability | An exported activity accepts custom Graal schemes and forwards the URI to native deep-link handling. |
| APK-003 | High-interest | Confirmed capability | WebTop enables JavaScript and exposes device, preference, and native-message methods. |
| APK-004 | High-interest | Confirmed capability | WebTop can write DEX bytes, create a `DexClassLoader`, and invoke reflected methods. |
| APK-005 | Medium | Confirmed legacy material | An expired SHA-1 Fabzat certificate is embedded in the APK. |
| APK-006 | Medium | Confirmed legacy vocabulary | Native qplay contains TLS 1.1, RC4, and NULL-cipher identifiers. Active selection is not proven by strings alone. |
| APK-007 | Critical stability and integrity risk in the supplied mod | Confirmed | `libxposed.so` installs hooks and contains destructive WebTop command paths. |
| APK-008 | Informational | Confirmed positive | Native libraries have non-executable GNU_STACK segments, GNU_RELRO, and BIND_NOW metadata. |
| APK-009 | Medium | Confirmed embedded bundle | Spectron carries the historical native connector trust text used by the old client family. |

The high-interest items are not labeled as remotely exploitable because the
reachability question depends on the native WebTop URL, page content, and hook
dispatch. That page was recovered statically but not opened.

## APK-001: cleartext traffic policy

The application manifest explicitly sets
`android:usesCleartextTraffic="true"`, and no separate
`android:networkSecurityConfig` attribute was observed. This permits Android
framework networking components to make HTTP connections that a stricter
application policy would reject.

This does not prove that login uses HTTP. The old game connector makes its own
socket and TLS decisions inside native qplay. The local compatibility replay
kept certificate and hostname checks enabled and used a loopback TLS fixture.
The finding is still important because the Java WebTop, billing, update, and
modding layers may use different networking stacks.

Recommended repair:

1. Set the cleartext policy to false.
2. Add a narrow network security configuration if an explicitly local or
   legacy exception is unavoidable.
3. Audit each Java, WebView, and native endpoint separately instead of treating
   the manifest setting as proof of transport security.

## APK-002: exported custom-scheme entry point

`com.quattroplay.GraalClassic.QPlayActivity` is explicitly exported without a
component permission. It has a launcher filter and a browsable VIEW filter for
`graalclassic://` and `graalclassicplus://`.

The observed Java flow is:

```text
external Intent URI
        -> QPlayActivity.onCreate
        -> OnIntent(action, data.toString())
        -> UI or GL-thread runnable
        -> Natives.onInvokeEvent("OnDeepLink", data)
```

The Java helper also maps several Graal-related URL schemes to package or
component intents. The native event consumer was not treated as trusted merely
because the Java activity was launched by the system. A second application can
request the custom scheme, so the native event must validate the action, scheme,
host, path, and every parameter before it changes account, world, file, or
update state.

Recommended repair:

* Require a signature-level permission if the link is intended only for a
  companion application.
* Otherwise accept only an explicit scheme and host allowlist, reject embedded
  credentials and unexpected ports, and treat all query and fragment values as
  untrusted.
* Add a test that launches the activity with malformed, oversized, nested, and
  cross-package URIs and verifies that no native state changes.

## APK-003: WebTop JavaScript bridge

The `com.WebTop` class is a public `WebView` subclass. Its constructor enables
JavaScript, installs a `WebChromeClient` and `WebViewClient`, loads the URL
returned by native `getMainUrl()`, and exposes itself to the page as the
JavaScript object `native`.

The following methods carry `@JavascriptInterface` in `classes2.dex`:

| Bridge method | Observed behavior |
| --- | --- |
| `getAndroidId()` | Returns `Settings.Secure.android_id`. |
| `getSZ()` | Returns the current APK source file length, or `-1` on error. |
| `loadData(key)` | Reads a value from the app's `database` shared preferences. |
| `saveData(key, value)` | Writes a value to the same persistent preferences. |
| `message(id, data)` | Posts a message to the UI handler, which calls Java dispatch and native `onmsg`. |

There is also a particularly important native-to-page path. `messageGui(id,
data)` constructs JavaScript with the shape
`window.onMessageGui('<id>','<data>')` by concatenating the arguments without
escaping. If an attacker can control either value and can cause that callback
to run, a quote or script delimiter can change the generated JavaScript. The
static review proves the sink, not the attacker-controlled source.

The recovered native URL is
`https://spectronnative-page.onrender.com?device=NOID`. It belongs to the
supplied Spectron modding layer, not to the old 1.8 connector. It was not
opened. This leaves two separate questions for later work:

1. Is the page origin fixed and authenticated in every build?
2. Can any server response, local HTML, or native packet reach the bridge with
   attacker-controlled values?

Recommended repair:

* Do not expose a bridge to remote or mixed-trust pages.
* Use a local asset origin or a tightly scoped WebView origin allowlist.
* Remove `getAndroidId` and persistent preference access from page JavaScript
  unless each use is necessary.
* Encode JavaScript arguments with a real serializer, or pass structured data
  through a safe channel instead of string concatenation.
* Disable JavaScript and bridge exposure on error, redirect, unknown scheme, or
  certificate failure.

## APK-004: dynamic DEX loading and reflection

`WebTop.onMessage` recognizes `load_dex` and `java_reflection`. The `load_dex`
format contains an identifier, class name, and DEX content. `com.iDex` converts
the content to bytes, writes
`webview_injected_<id>.dex` under the app files directory, creates an optimized
directory, constructs a `DexClassLoader`, and stores it in a static map.

The `java_reflection` path retrieves a loader by identifier, loads a class,
looks up a method taking `Context`, constructs an object when needed, and
invokes the method. The DEX magic check is a format check, not an authenticity
check. No signature, hash allowlist, or origin binding was observed in the
reviewed path.

This may be intentional mod support. It is nevertheless a code-loading
boundary with the app's permissions and data. If an untrusted page or native
message source can supply the command, the page effectively gains a route to
new in-process code.

Recommended repair:

* Remove the feature from a production package, or compile it out of release
  builds.
* If mod support is required, accept only signed bundles with an allowlisted
  signer and a user-visible opt-in.
* Bind the bundle to a local file or authenticated channel, enforce size and
  class-name limits, and delete temporary files when the loader is removed.
* Keep the loader in a separate, least-privileged process when the platform
  design permits it.

## APK-005: embedded Fabzat certificate

`res/raw/fabzat_com.crt` is a PEM certificate whose subject contains
`admin.fabzat.com`. The certificate is valid from 2013-08-22 through
2014-08-23, uses a SHA-1 signature, and has SHA-256 fingerprint
`7ef70360e4c1228706d96ecf0d5b8e6b391b15c36151e0a5c976a37637d8cdfa`.

The private key is not present in the APK. The file may be an old integration
asset rather than a current trust anchor. Its presence becomes a real
availability or trust problem only if current code loads it for pinning or
validation. The scanner therefore records it as confirmed legacy material with
active use unproven.

## APK-006 and APK-009: native TLS and trust material

The ARM64 qplay library is a native CyaSSL build. Its string table contains
`TLSv1.1`, `TLSv1.2`, `SSL_RSA_WITH_RC4_128_SHA`,
`SSL_RSA_WITH_RC4_128_MD5`, `TLS_RSA_WITH_NULL_SHA`, and
`TLS_RSA_WITH_NULL_SHA256`. It also contains PEM markers and raw socket
imports. These are confirmed implementation and configuration vocabulary, not
proof of a weak negotiated session.

The same qplay build contains a 12,820-byte trust text at file offset
`0x2ea9e0` with SHA-256
`c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0`.
Cross-build comparison shows that this is the historical six-certificate
bundle also present in the original ARM64 library. The decoded bundle contains
expired historical material, with the earliest recorded leaf ending in 2023.
The full decode is documented in
[`graalweb_trust_bundle.json`](../artifacts/graalweb_trust_bundle.json), and
the connector behavior is explained in
[`CONNECTOR_TLS.md`](CONNECTOR_TLS.md).

The old Classic path has a separate control in which `usessl` is false for the
main game-server connector. Other paths, update flows, and future builds can
make different choices. The safe local replay did not bypass peer or hostname
verification. Therefore the correct conclusion is that the APK carries stale
TLS and trust options that need cleanup, not that a live connection was
silently downgraded.

Recommended repair:

* Remove RC4, NULL suites, TLS 1.1, and other legacy options from release
  builds.
* Replace the fixed historical trust bundle with a current, auditable chain or
  the platform trust store.
* Keep hostname and peer verification enabled and test renewal before a
  certificate expires.
* Treat the native connector separately from Java `NetworkSecurityConfig`.

## APK-007: Spectron hook and command layer

The supplied package includes `libxposed.so` in both ABIs. The ARM64 library
imports `dlopen`, `dlsym`, `mprotect`, and `syscall`, and contains `A64_HOOK`,
`dl_iterate_phdr`, and inline-hook strings. Earlier IDA review mapped a worker
that waits for `libqplay.so`, resolves native exports, and installs hooks,
including an anti-Frida target.

The native WebTop dispatcher has six reviewed command names:

```text
crash      deliberate null store
freeze     infinite loop
abort      process abort
load_menu  forwards a menu payload
setscript  forwards a script payload
gs2call    forwards a GS2 payload
```

The first three were reproduced as intentional destructive branches when the
supplied package was launched. A private safe control skipped only those
branches and then reached the local game entry. That runtime result is recorded
in [`RUNTIME_STATUS.md`](RUNTIME_STATUS.md) and
[`SPECTRON_COMPARISON.md`](SPECTRON_COMPARISON.md).

This is a confirmed stability and integrity risk in the supplied modded APK.
It is not evidence that the original 1.8 client contains the same hook layer.
For analysis, keep the modded package isolated, do not give the WebTop layer
production credentials, and use a private signed copy for any runtime control.

## Native attack surface and mitigations

The ARM64 qplay import table includes raw socket calls such as `socket`,
`connect`, `bind`, `listen`, `accept`, `send`, `sendto`, `recv`, and `recvfrom`.
It also includes filesystem and process primitives such as `open`, `fopen`,
`chmod`, `unlink`, `fork`, and `execvp`, plus `dlopen` and `dlsym`. These
imports identify code worth reviewing at call sites. They are not individual
vulnerabilities.

All four packaged native libraries report `RW` GNU_STACK, so no executable
stack was requested. They also report GNU_RELRO and BIND_NOW metadata. These
are useful hardening signals, but the package should not be described as fully
hardened because the scan does not establish full RELRO, control-flow
integrity, allocator hardening, or safe input handling.

## What remains unproven

The following questions are intentionally open rather than filled with
assumptions:

* Whether the recovered WebTop page is still reachable, what it serves, and
  whether it is the source of any command data.
* Whether a production server can send input that reaches `messageGui`,
  `load_dex`, or `java_reflection`.
* Which native TLS suite is selected on each connector path in each build.
* Whether the Fabzat certificate is referenced by live Java or native code.
* Whether the exported deep-link event can change account, file, or update
  state after native validation.
* Whether the old package's v2 signing block uses the same certificate as the
  legacy v1 `META-INF/CERT.RSA` entry. The archive contains a v2 signing block
  and v1 signature files; the compact audit reports both without publishing a
  signing key.

No claim in this document should be read as authorization to contact a third-
party service. Any future dynamic test should use a private emulator, a
loopback responder, synthetic credentials, and a recorded allowlist of ports.

## Reproduction

From the repository root:

```bash
python3 tools/audit_spectron_apk.py \
  /home/v/Desktop/graal-decomp/spectron_client_1.0.2.apk \
  --output artifacts/spectron_apk_security_audit_20260830.json
python3 tools/validate_research_archive.py
```

The first command extracts no persistent files. It parses the manifest and DEX
strings, runs local `readelf` on temporary native copies, parses the embedded
Fabzat certificate when the `cryptography` module is available, and inspects
the APK signing block. It never installs, launches, resolves, or connects.

For the broader connector and runtime evidence, use
[`CONNECTOR_TLS.md`](CONNECTOR_TLS.md),
[`TESTING.md`](TESTING.md), and
[`SPECTRON_COMPARISON.md`](SPECTRON_COMPARISON.md). The source and target IDA
translation work remains separate from this security inventory so that a
convenient symbol name is never mistaken for proof of safe behavior.
