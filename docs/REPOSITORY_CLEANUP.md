# Repository cleanup

This repository is the public research record. APKs, native libraries, IDA
databases, emulator captures, private keys, and temporary packages stay
outside it. The checked-in artifacts contain hashes, bounded metadata, and
small protocol observations rather than raw application payloads.

## Current tree

The cleanup audit on 2026-09-02 found 243 tracked files and about 18.1 MiB in
the current checkout. There are 99 JSON records containing 432,124 lines. No
APK, ELF library, IDA database, signing key, or packet capture is tracked. The
source tree contains no retired comparison-package filename or reference.

The ignore policy now covers the common IDA database sidecars as well as APK,
ELF, signing, capture, and temporary files. JSON is intentionally not ignored:
small, reviewed metadata records are part of the reproducible research log.
Large raw dumps should be summarized before they are added.

## History status

The current tree is clean, but the pre-cleanup Git history still contains
obsolete comparison commits and unreachable objects. Removing those objects
from public `main` requires rebuilding the branch and force-pushing it. That
operation is intentionally separate from ordinary research commits because it
changes commit IDs for every downstream clone.

A local history preview was built without changing the public branch. The
preview retained the useful research commits, removed the obsolete comparison
content from reachable history and messages, passed a full object check, and
reduced the history to 82 commits. It remains a staging result until the
repository owner explicitly authorizes replacing public `main`.

## Review rules

Before each push:

1. Run `git diff --check`.
2. Validate new JSON with `python3 -m json.tool`.
3. Search documentation and artifacts for private paths, keys, raw packages,
   and retired comparison names.
4. Check that binaries and IDA sidecars are ignored and untracked.
5. Push a focused commit with the `vinvicta` author identity.

The research record should prefer one compact artifact per question, with a
generator when a result depends on parsing or measurement. Raw input files
remain local and are identified by SHA-256 in the public record.
