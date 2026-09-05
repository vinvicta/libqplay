# Repository cleanup

This repository is the public research record. APKs, native libraries, IDA
databases, emulator captures, private keys, and temporary packages stay
outside it. The checked-in artifacts contain hashes, bounded metadata, and
small protocol observations rather than raw application payloads.

## Current tree

The cleanup audit refreshed on 2026-09-04 found 237 tracked files and about
17.8 MiB in the current checkout. There are 97 JSON records containing
422,251 lines. The current tree contains compact indexes for the translated
1.8 symbols and bounded protocol observations. No APK, ELF library, IDA
database, signing key, or packet capture is tracked. Package-specific
comparison reports and their generators have been removed from the source
tree.

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

A local history preview was built from `main` at `8a9e645` without changing
the public branch. Commit `f204393` is the first clean tree in the existing
line of development. That preview made the tree a new root and retained its
95 descendants, for 96 research commits in total. Reachable tree,
commit-message, and path scans found no retired comparison-package material.
The preview predates the latest cleanup commits and must be rebuilt from the
current `main` before any history replacement.
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
