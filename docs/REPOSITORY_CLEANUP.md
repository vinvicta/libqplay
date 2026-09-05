# Repository cleanup

This repository is the public research record. APKs, native libraries, IDA
databases, emulator captures, private keys, and temporary packages stay
outside it. The checked-in artifacts contain hashes, bounded metadata, and
small protocol observations rather than raw application payloads.

## Current tree

The cleanup audit refreshed on 2026-09-04 found 259 tracked files and about
20.4 MiB in the current checkout. There are 105 JSON records containing
469,936 lines. The current tree also includes compact CSV indexes for the
translated 1.8 symbols, the retained 2.2 dynamic symbols, and the exact-byte
cross-version candidates. No APK, ELF library, IDA database, signing key, or
packet capture is tracked. The
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

A refreshed local history preview was built from the current `main` without
changing the public branch. Commit `f204393` is the first clean tree in the
existing line of development. The preview made that tree the new root and
retained its 95 descendants, for 96 research commits in total. Reachable tree,
commit-message, and path scans found no retired comparison-package material.
The preview also removed its remote-tracking refs before packing, so the old
history was not retained by an in-preview branch or tag. It remains a staging
result until the repository owner explicitly authorizes replacing public
`main`, because that replacement changes commit IDs for every later commit.

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
