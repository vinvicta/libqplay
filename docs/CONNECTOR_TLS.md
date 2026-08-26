# Connector TLS path

This page brings together the static and local runtime evidence for the old
connector. It is intentionally specific about what was proven and what still
needs a current service-side test.

## What the client does

`THTTPRequest_sendRequest` at `0x1ffde8` builds the connector request. It uses
the native `TSocketConnection` class, not Android's Java trust store. When
certificate verification is enabled, `TSocketConnection_setVerifyGraalWebCert`
at `0x20ab20` decrypts the embedded trust buffer and passes it to CyaSSL.
`TSocketConnection_enableSSLOnSocket` at `0x206450` loads that buffer with
`CyaSSL_CTX_load_verify_buffer`, enables peer verification, checks the
configured hostname, and starts a nonblocking CyaSSL handshake.

The extracted trust buffer is stale. Its first certificate expired on
2023-07-29, and other historical chain entries are also past their validity
dates. Replacing the buffer with an authorized current certificate chain is
the production-compatible repair direction. The certificate-skip branch is
useful only as a private diagnostic control.

## Date checks recovered in CyaSSL

Clean IDA decompilation of the bundled certificate parser found the date logic
inside `CyaInt_DecodeToKey` at `0x2b56cc`. It calls
`CyaInt_ValidateDate` at `0x2b53b8` for both X.509 validity fields. The helper
accepts ASN.1 `UTCTime` tag 23 and `GeneralizedTime` tag 24, obtains the
current UTC time with `time(nullptr)` and `gmtime()`, and compares the parsed
certificate time to that clock.

The first field is `notBefore` and is checked in mode zero. Mode zero accepts a
time at or before the current clock. The second field is `notAfter` and is
checked in mode one. Mode one accepts a time at or after the current clock.
When the parser's strict flag is active, the disassembly retains separate
negative results: `-140` for a `notBefore` failure and `-151` for a
`notAfter` failure. These values are parser results that later TLS code may
wrap or translate.

The call chain is:

```text
CyaSSL_connect
  -> ProcessReply
     -> certificate record type 11
        -> certificate-chain helper at 0x2ca940
           -> ParseCertRelative
              -> DecodeToKey
                 -> ValidateDate
```

The trust-buffer loader also reaches `ParseCertRelative` through
`CyaSSL_CertManagerVerifyBuffer` at `0x2c4d34`. The complete function map and
the decompilation-derived date mapping are in
`artifacts/connector_tls_parser_analysis_20260826.json`.

## Local validity control

The paired control used identical ARM64 native code, hostname routing, port,
loading-state setup, responder key, and one-certificate trust-bundle shape.
Only the certificate dates changed. The valid certificate covered
2025-01-01 through 2035-01-01. The expired certificate ended on 2021-01-01.

The valid package completed TLS and sent one `GET /con.png` request. The
expired package reached the local TCP listener but sent no HTTP request. The
responder recorded a TLS EOF during the expired handshake. This aligns with
the static date checks and places the failure before connector HTTP in this
translated ARM64 environment.

The full hashes and raw observations are in
`artifacts/connector_tls_expiry_control_20260826.json`. The test packages,
private keys, and emulator logs remain outside the repository.

## Repair boundary

The old embedded chain should not be replaced with a guessed certificate. A
valid repair needs an authorized current chain for the endpoint that the
client actually contacts, plus a test on a controlled device or responder.
The local test only proves that this native path can load a matching chain and
that the historical date logic rejects an expired certificate before HTTP.
