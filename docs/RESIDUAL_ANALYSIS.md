# Residual function analysis

The ELF symbol pass translated every name retained in the original ARM64
library. The reviewed callback and role passes then added names only when the
address, callers, and body supported the role. The current IDA inventory has
124 address-only `sub_` functions. They are mostly compiler-generated cleanup
and registration paths, not an unexamined application boundary.

The current address list is in
`artifacts/ida_final_residual_audit_20260902.json`. The report was generated
from the 11,296-row inventory for the original library hash
`9348dd87a571050e05a9c9b76d71d37aa697de1836be5b86ea9982eb00e5b9c8`.

## How the count changed

The pre-persistence profile contained 488 unresolved default entries. The
current residual profile accounts for every change:

```text
488 old unresolved entries
- 28 application and engine role aliases
- 41 CyaSSL and bundled-library aliases
-145 reclassified entries: 141 FreeType, three GPC, and one named thunk
-149 exact source matches that intersected the old residual profile
-  1 false function boundary removed from literal data
=124 current residual entries
```

The source-match total is 155, not 149. It consists of 153 IJG libjpeg 6b
matches, one zlib 1.2.5 match, and one giflib role match. Six IJG callbacks
are genuine source-backed no-op functions that were already outside the old
`sub_` residual profile, so they do not affect the arithmetic above.

## Source-backed corrections

The old address bucket around the image libraries was useful for finding code,
but it was not a source identity. The follow-up pass separated the families.

The three marker-reader functions are now named as follows:

| Address | Current IDA name | Source role | Evidence |
| --- | --- | --- | --- |
| `0xe0454` | `libjpeg_jdmarker_examine_app14` | IJG `examine_app14` | Parses the Adobe APP14 signature, version, flags, and transform, then records the marker state |
| `0x28d2ec` | `libjpeg_jdmarker_skip_variable` | IJG `skip_variable` | Reads a two-byte marker length and skips the variable payload |
| `0x28db3c` | `libjpeg_jdmarker_next_marker` | IJG `next_marker` | Scans the input for the next JPEG marker introducer |

The complete 153-entry report is
`artifacts/ida_libjpeg_source_matches_20260902.json`. It is based on the
official IJG 6b source archive, released 27-Mar-1998, whose local archive
SHA-256 is
`75c3ec241e9996504fe02a9ed4d12f16b74ade713972f3db9e65ce95cd27e35d`.

The residual at `0x28a2f4` is zlib's `inflate_fast`, not a JPEG helper. Its
loop decodes literal, length, and distance Huffman codes and contains zlib's
invalid literal/length, invalid distance, and too-far-back diagnostics. It is
recorded as `zlib_inflate_fast` in
`artifacts/ida_zlib_source_matches_20260902.json`.

The residual at `0x2acb20` is a static GIF decoder helper. The preserved
`DGifGetLine` at `0x2ae28c` and `DGifGetPixel` at `0x2ae350` both reference it.
The body maintains the GIF prefix, suffix, and pixel stack arrays, handles
clear and EOF codes, grows the variable-width code size, follows dictionary
links, and emits a line of decoded pixels. It is named
`giflib_DGifDecompressLine` and documented in
`artifacts/ida_giflib_source_matches_20260902.json`. The exact giflib release
is intentionally left open because the available evidence establishes the
role, not a unique release number.

The focused security comparison is in
`artifacts/gif_decoder_security_review_20260902.json`. The LZW helper visibly
rejects an overfull pixel stack, stops growing the dictionary at the 12-bit
boundary, checks dictionary indices before the dependent loads, and limits
prefix-chain walks. Those checks are evidence against a direct copy of the
unchecked `CrntCode` and `RunningCode - 2` patterns described by
[CVE-2018-11489](https://nvd.nist.gov/vuln/detail/CVE-2018-11489) and
[CVE-2018-11490](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11490),
but they do not identify the exact giflib release or replace malformed-input
testing.

The high-level `DGifSlurp` body at `0x2ae6ec` remains a separate hardening
concern. It multiplies image width and height in 32-bit registers before
calling `reallocarray`, and it multiplies width by a row index again when
forming decoded-frame offsets. There is no application pixel or cumulative
decoded-byte budget in this path. This is recorded as `GIF-003`, an
availability and memory-pressure risk, not as a demonstrated memory
corruption. The zero-height divide-by-zero described by
[CVE-2019-15133](https://nvd.nist.gov/vuln/detail/CVE-2019-15133) was not
assigned to this APK because the current `DGifSlurp` body does not show that
direct divider state and the embedded giflib release is unknown.

The same high-level loop retains every nonempty extension block. Its calls at
`0x2ae77c`, `0x2ae7a0`, and `0x2ae914` feed `GifAddExtensionBlock`, whose
`reallocarray(count + 1, 24)` and payload allocation occur at `0x2af03c` and
`0x2af074`. Individual sub-blocks are at most 255 bytes, but there is no
aggregate extension count or byte budget. This is recorded as `GIF-004`, a
static availability and memory-pressure concern rather than a demonstrated
overwrite.

`DGifGetImageDesc` also grows the `SavedImages` array for every image record.
The `reallocarray(existing, ImageCount + 1, 56)` call is at `0x2ada90`, the
count increment is at `0x2adafc`, and `DGifSlurp` keeps walking records from
`0x2ae72c` until a trailer. No application frame-count limit was visible.
This is recorded as `GIF-005`, a frame-metadata and cumulative-resource
availability concern rather than a demonstrated overwrite.

The direct bitmap wrapper has a separate arithmetic risk. At `0x150b88` and
`0x150b90`, `TBitmap_readGIF_TStream` uses a 32-bit height-times-width value
for the temporary source allocation and `DGifGetLine` length. At `0x150c9c`,
`0x150ca0`, `0x150cb0`, and `0x150cb8`, it derives the destination allocation
from a 32-bit width-times-height-times-8 calculation. The row copy at
`0x150d40` through `0x150d50` still writes one row per decoded source row.
The dimensions `16385` by `32768` make the source and copy length
`536903680` bytes while the wrapped destination size is `32768` bytes. This
is recorded as `GIF-006`, a conditional static heap-overflow candidate that
still needs a bounded malformed-GIF harness and allocator validation.

One apparent function at `0x2ac400` was not code. The preserved ELF symbol
`jpeg_fdct_float` ends at `0x2ac3fc`, and the preserved
`jpeg_fdct_ifast` function begins at `0x2ac440`. The bytes from `0x2ac3fc`
through `0x2ac43f` are alignment and floating-point constants referenced by
the DCT code. IDA had incorrectly created a 64-byte `sub_2AC400` over that
literal pool. The current database removes that false boundary and describes
the range as data.

## Remaining categories

The 124 real residual functions are accounted for by the persisted profile:

| Category | Count | What the name means |
| --- | ---: | --- |
| `tstring_static_cleanup_wrapper` | 97 | Fixed global `TString` cleanup thunks |
| `init_or_fini_array_entry` | 19 | Entries reached through ELF initialization or finalization arrays |
| `tstringlist_static_cleanup_wrapper` | 5 | Fixed global `TStringList` cleanup thunks |
| `tgraalvar_static_cleanup_wrapper` | 2 | Fixed global `TGraalVar` cleanup thunks |
| `plt0_resolver` | 1 | The AArch64 resolver slot at `0xd2170` |

These labels describe behavior and ownership. They do not claim that an
original source symbol survived. The machine-readable classification is in
`artifacts/ida_residual_profile.json`, and the compact inventory is in
`artifacts/ida_final_residual_audit_20260902.json`.

## Reviewed high-reference routines

The older semantic review remains useful as a historical snapshot of the
pre-source-match queue. Its two selected FreeType diagnostic helpers are now
source-labeled, so it should not be read as a list of current unnamed
functions. The historical record is
`artifacts/original_residual_semantic_review_20260830.json`.

| Address | Size | References | Current name | Observed role |
| --- | ---: | ---: | --- | --- |
| `0x256060` | 880 | 12 | `tt_name_entry_ascii_from_utf16` | Printable byte-string sanitizer |
| `0x2563d0` | 524 | 16 | `tt_name_entry_ascii_from_other` | Printable 16-bit string sanitizer |

The exact FreeType artifact covers the SFNT face and table loaders, smooth
rasterization, the TrueType interpreter and glyph loader, and the Latin,
Latin2, CJK, and dummy autofit classes. The source body, address, size, xrefs,
and line anchor are kept in
`artifacts/ida_freetype_source_matches_20260901.json`.

## Security boundary

This page is not a vulnerability claim by itself. A static GIF LZW helper or
an old JPEG implementation becomes a security boundary only when attacker-
controlled bytes can reach the image reader. The separate image, archive,
font, protocol, and network reviews document those gates and the missing
resource budgets. No malformed-image fuzzing or live service test was part of
this residual pass.
