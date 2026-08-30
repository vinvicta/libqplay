# Research artifact policy

This project contains two kinds of output. The first kind is the evidence a
reader needs to review a conclusion: a small anchor record, a checkpoint,
symbol inventory, protocol capture summary, security finding, or a short
reproduction script. These files belong in Git.

The second kind is a machine-generated snapshot of an entire IDA database or
an entire function population. It is useful while doing the analysis, but it
repeats almost the same data at every checkpoint. It makes cloning and review
slow, and it hides the interesting changes inside millions of unchanged JSON
lines. These files stay on the analysis workstation under
`research-data/generated/` and are ignored by Git.

## What stays public

The public tree keeps:

- prose findings and review notes under `docs/`;
- source and target symbol inventories that are the stable starting point for
  the work;
- compact manual-translation anchors, application reports, and reopen checks;
- translation checkpoints and runtime or protocol summaries;
- scripts that regenerate IDA exports or summarize local exports;
- security reports with evidence, confidence, and reproduction boundaries.

The public tree does not contain APKs, native libraries, IDA databases, packet
captures, private keys, or local emulator state. The existing ignore rules
cover those inputs. The new `research-data/` rule also covers large derived
feature exports and repeated per-checkpoint audits.

## What was moved locally

The cleanup moved the repeated full-population exports, rather than deleting
them. This includes Spectron feature inventories, name-coverage audits,
dynamic-symbol audits, boundary tables, and carried-forward semantic maps.
Their original paths, local archive paths, byte counts, line counts, and
SHA-256 values are recorded in
`artifacts/research_archive_manifest.json`.

The local archive is deliberately outside the tracked tree's working set for
Git purposes, but it remains available for follow-up analysis. If a historical
tool needs one of these files, use the `archive_path` in the manifest. Do not
copy the whole archive back into `artifacts/` before committing.

## Regeneration and verification

The translation generators under `tools/` write their full exports beside the
compact evidence. When a full export is needed, keep it in the local archive
and refresh the manifest with:

```text
python3 tools/build_research_archive_manifest.py
```

The command reads files in streaming chunks, so it does not need to parse the
large JSON documents. A changed export produces a changed hash and is easy to
spot in the manifest review.

Before adding a new JSON artifact, ask whether it records a new fact or merely
repeats a complete previous snapshot. Prefer a compact summary with the input
hash, generator name, selected rows, counts, and uncertainty notes. Keep the
large source export local unless a reviewer specifically needs it.

## Git history note

This cleanup removes large files from the current branch and stops future
commits from reintroducing them. Earlier published commits still contain the
old blobs because rewriting a public branch would invalidate existing clones.
A complete history rewrite is a separate, destructive maintenance operation
and should only happen after explicit approval.
