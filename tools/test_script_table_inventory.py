"""Small regression tests for the static script-name decoder."""

from generate_script_table_inventory import decode_script_name


def encode_table_name(name):
    length = len(name)
    encoded = []
    for index, character in enumerate(name):
        value = (
            0xFF
            - (
                (length + 10)
                + 4 * (ord(character) + index)
                + (((ord(character) + index) >> 6) & 3)
            )
        ) & 0xFF
        if value == 0:
            # This is the C-string sentinel repaired by codesimplefix0.
            value = (-11 - length - (4 * index)) & 0xFF
        encoded.append(value)
    return bytes(encoded)


def check(name):
    raw = encode_table_name(name)
    binary = bytearray(0x200)
    binary[0x100 : 0x100 + len(raw)] = raw
    decoded, raw_hex, exact = decode_script_name(bytes(binary), 0x100)
    assert decoded == name, (name, decoded)
    assert raw_hex == raw.hex(), (name, raw_hex, raw.hex())
    assert exact, name


def main():
    for name in (
        "communityname",
        "getmusicfilename",
        "disabledsoundeffects",
        "showhint",
        "$pref::graal::defaultfontsize",
    ):
        check(name)
    print("script table decoder tests: ok")


if __name__ == "__main__":
    main()
