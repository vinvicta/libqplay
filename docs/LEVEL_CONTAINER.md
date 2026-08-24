# Encrypted `.code` level container

The native level loader is `TServerLevel_LoadEncrypted_void` at ARM64
`0x1aa198`. It derives a file path from the server identity, reads a coded
container, checks its checksum, and then parses the `GWEBL001` stream.

## Cache path

The runtime uses the Android external app-data cache for downloaded assets in
the emulator:

```text
/storage/emulated/0/Android/data/com.quattroplay.GraalClassiC/files/
```

The relevant encrypted path is:

```text
weblevels/<serveripstr>/<level-name>-<server-port>.code
```

The native filename helper is `TServerLevel_getEncryptedFilename` at ARM64
`0x1a1b00`. The suffix is the server port, not the server signature.

For the loopback test:

```text
server host     = 127.0.0.1
server port     = 14900
serveripstr     = md5("127.0.0.1" + "14900")
                = 5034ec765552177b890e732a02e3b699
```

The Android downloader may first save a generic packet-102 response under a
level-image cache path. The server-level loader later looks for the
`weblevels/<serveripstr>/...-14900.code` path. This distinction explains why
placing a file in the generic image directory did not make the loader see it.

## Outer coded file

`TEncryption_saveCodedFile` at ARM64 `0xe6100` writes the following layout:

```text
little-endian u32: original plaintext length + 8
DES ciphertext:    plaintext padded with 0x0a to a multiple of 8
8-byte checksum:   column sums over the padded plaintext
```

The reader rounds the meaningful length up to consume complete DES blocks,
but copies only the original meaningful length into the returned stream. The
checksum covers the padded bytes.

The DES key stream is not one fixed key. The seed starts at `78121784` and is
multiplied by every UTF-8 byte of the level filename modulo 2^32. Each block
then consumes eight values from the native PRNG:

```text
state = (134775813 * state + 1) & 0xffffffff
value = state & 0xff
```

Each eight-byte PRNG key is bit-reversed byte by byte before it is used for
DES ECB. The helper `tools/make_level_code.py` implements this exact rule and
checks its own output by decrypting it again.

## `GWEBL001` plaintext

The decrypted stream begins with:

```text
GWEBL001
```

The fields observed in the loader are:

1. one encoded length byte followed by `serveripstr`;
2. two encoded signature bytes;
3. five encoded modification-time bytes;
4. one encoded length byte followed by the level filename;
5. eight-byte version, normally `GR-V1.03`, `GR-V1.04`, or `GR-V1.05`.

For a version 1.05 container, the remaining stream includes layer count and
board data followed by links, baddies, NPCs, chests, and signs. Version 1.03
is accepted by this loader and was useful as a small known-good source
container.

The signature is decoded as:

```text
((byte0 - 32) << 7) + (byte1 - 32)
```

The loader accepts an exact server signature. It also accepts payload
signature 1 when the server signature is 73. The local test used signature 73
in both the synthetic login response and the rewritten level header.

The server identity must match the client's `serveripstr`. A mismatch is
rejected before the board is parsed. This is why changing only the filename
without re-encrypting and rewriting the identity produces a plausible-looking
file that still fails.

## Re-keying the known-good source

The local test began with a valid cached `black.nw-14896.code` container. The
helper preserves its decoded board and entity stream, then rewrites the
identity fields and re-encrypts under each new level filename. It produced
316-byte containers for:

```text
overworld_west_ocean_02.nw-14900.code
overworld_west_ocean_09.nw-14900.code
overworld_west_ocean_10.nw-14900.code
```

Those files decrypt and pass the checksum in the local helper. They are test
fixtures, not claimed to be faithful copies of the live overworld levels.
