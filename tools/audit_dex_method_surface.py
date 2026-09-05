#!/usr/bin/env python3
"""Build a bounded, offline method-level surface map for the original APK.

The older APK audit intentionally stopped at DEX string tables.  This pass
parses the compact DEX indexes and class-data/code items so sensitive method
references can be tied to their Java callers.  It does not install, execute,
or contact the APK, and it does not copy method bodies into the report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APK = ROOT.parent / "GraalOnline+Classic_1.8_APKPure.apk"
DEFAULT_OUTPUT = ROOT / "artifacts" / "original_dex_method_surface_review_20260904.json"


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def uleb(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 35:
            break
    raise ValueError("malformed DEX ULEB128")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def descriptor_name(descriptor: str) -> str:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor


class Dex:
    def __init__(self, data: bytes):
        if len(data) < 0x70 or not data.startswith(b"dex\n"):
            raise ValueError("not a DEX file")
        self.data = data
        self.magic = data[:8].decode("ascii", errors="replace")
        self.string_ids_size = u32(data, 0x38)
        self.string_ids_off = u32(data, 0x3C)
        self.type_ids_size = u32(data, 0x40)
        self.type_ids_off = u32(data, 0x44)
        self.proto_ids_size = u32(data, 0x48)
        self.proto_ids_off = u32(data, 0x4C)
        self.field_ids_size = u32(data, 0x50)
        self.field_ids_off = u32(data, 0x54)
        self.method_ids_size = u32(data, 0x58)
        self.method_ids_off = u32(data, 0x5C)
        self.class_defs_size = u32(data, 0x60)
        self.class_defs_off = u32(data, 0x64)
        self.strings = self._strings()
        self.types = [self.strings[u32(data, self.type_ids_off + i * 4)] for i in range(self.type_ids_size)]
        self.protos = [self._proto(i) for i in range(self.proto_ids_size)]
        self.methods = [self._method_ref(i) for i in range(self.method_ids_size)]
        self.classes, self.defined_methods = self._classes_and_methods()

    def _strings(self) -> list[str]:
        result = []
        for i in range(self.string_ids_size):
            offset = u32(self.data, self.string_ids_off + i * 4)
            _length, offset = uleb(self.data, offset)
            end = self.data.find(b"\0", offset)
            if end < 0:
                raise ValueError("unterminated DEX string")
            result.append(self.data[offset:end].decode("utf-8", errors="replace"))
        return result

    def _type(self, index: int) -> str:
        return self.types[index] if index < len(self.types) else "<bad-type-%d>" % index

    def _proto(self, index: int) -> dict:
        offset = self.proto_ids_off + index * 12
        shorty_idx, return_type_idx, parameters_off = struct.unpack_from("<III", self.data, offset)
        parameters = []
        if parameters_off:
            count = u32(self.data, parameters_off)
            parameters = [self._type(u16(self.data, parameters_off + 4 + i * 2)) for i in range(count)]
        return {
            "shorty": self.strings[shorty_idx],
            "return_type": self._type(return_type_idx),
            "parameters": parameters,
        }

    def _method_ref(self, index: int) -> dict:
        offset = self.method_ids_off + index * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, offset)
        proto = self.protos[proto_idx]
        descriptor = "(" + "".join(proto["parameters"]) + ")" + proto["return_type"]
        class_descriptor = self._type(class_idx)
        return {
            "class_descriptor": class_descriptor,
            "class": descriptor_name(class_descriptor),
            "name": self.strings[name_idx],
            "descriptor": descriptor,
        }

    def _class_data(self, offset: int) -> list[dict]:
        static_count, offset = uleb(self.data, offset)
        instance_count, offset = uleb(self.data, offset)
        direct_count, offset = uleb(self.data, offset)
        virtual_count, offset = uleb(self.data, offset)
        for _ in range(static_count + instance_count):
            _field_diff, offset = uleb(self.data, offset)
            _access_flags, offset = uleb(self.data, offset)
        methods = []
        for kind, count in (("direct", direct_count), ("virtual", virtual_count)):
            method_idx = 0
            for _ in range(count):
                diff, offset = uleb(self.data, offset)
                access_flags, offset = uleb(self.data, offset)
                code_off, offset = uleb(self.data, offset)
                method_idx += diff
                if method_idx >= len(self.methods):
                    raise ValueError("class-data method index is out of range")
                methods.append(
                    {
                        "method_idx": method_idx,
                        "access_flags": access_flags,
                        "code_off": code_off,
                        "kind": kind,
                    }
                )
        return methods

    def _classes_and_methods(self) -> tuple[list[dict], list[dict]]:
        classes = []
        definitions = []
        for i in range(self.class_defs_size):
            offset = self.class_defs_off + i * 32
            class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off = struct.unpack_from(
                "<IIIIIIII", self.data, offset
            )
            del interfaces_off, annotations_off, static_values_off
            class_descriptor = self._type(class_idx)
            class_record = {
                "class": descriptor_name(class_descriptor),
                "descriptor": class_descriptor,
                "access_flags": access_flags,
                "superclass": descriptor_name(self._type(superclass_idx)) if superclass_idx != 0xFFFFFFFF else None,
                "source_file": self.strings[source_file_idx] if source_file_idx != 0xFFFFFFFF else None,
            }
            methods = self._class_data(class_data_off) if class_data_off else []
            for method in methods:
                ref = self.methods[method["method_idx"]]
                definitions.append(
                    {
                        "class": class_record["class"],
                        "class_descriptor": class_descriptor,
                        "name": ref["name"],
                        "descriptor": ref["descriptor"],
                        "access_flags": method["access_flags"],
                        "code_off": method["code_off"],
                        "kind": method["kind"],
                    }
                )
            class_record["method_count"] = len(methods)
            class_record["native_method_count"] = sum(1 for method in methods if method["access_flags"] & 0x100)
            classes.append(class_record)
        return classes, definitions

    def method_label(self, method_idx: int) -> str:
        if method_idx >= len(self.methods):
            return "<bad-method-%d>" % method_idx
        ref = self.methods[method_idx]
        return "%s->%s%s" % (ref["class"], ref["name"], ref["descriptor"])

    def code_units(self, code_off: int) -> list[int]:
        if not code_off:
            return []
        if code_off + 16 > len(self.data):
            raise ValueError("code item is outside DEX")
        insns_size = u32(self.data, code_off + 12)
        start = code_off + 16
        end = start + insns_size * 2
        if end > len(self.data):
            raise ValueError("code item instructions are outside DEX")
        return [u16(self.data, start + i * 2) for i in range(insns_size)]

    def calls(self, code_off: int) -> list[int]:
        """Return method indexes from invoke instructions in one code item.

        The decoder follows DEX instruction widths and skips packed, sparse,
        and fill-array payloads. Unknown opcodes advance one code unit as a
        bounded fallback.
        """
        units = self.code_units(code_off)
        calls = []
        i = 0
        while i < len(units):
            op = units[i] & 0xFF
            if op in range(0x6E, 0x73) and i + 1 < len(units):
                calls.append(units[i + 1])
                i += 3
                continue
            if op in range(0x74, 0x79) and i + 1 < len(units):
                calls.append(units[i + 1])
                i += 3
                continue
            if op in (0xFA, 0xFB) and i + 2 < len(units):
                calls.append(units[i + 1])
                i += 4
                continue
            if op in (0xFC, 0xFD) and i + 1 < len(units):
                calls.append(units[i + 1])
                i += 3
                continue
            width = opcode_width(units, i)
            i += width if width > 0 else 1
        return [index for index in calls if index < len(self.methods)]


def opcode_width(units: list[int], index: int) -> int:
    """Return the width of one DEX instruction in 16-bit code units."""
    first = units[index]
    op = first & 0xFF
    if op == 0x00:
        payload = first >> 8
        if payload == 0x01 and index + 1 < len(units):
            return 4 + units[index + 1] * 2
        if payload == 0x02 and index + 1 < len(units):
            return 2 + units[index + 1] * 4
        if payload == 0x03 and index + 3 < len(units):
            element_width = units[index + 1]
            element_count = units[index + 2] | (units[index + 3] << 16)
            return 4 + (element_width * element_count + 1) // 2
        return 1
    if op in {
        0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C,
        0x1F, 0x20, 0x22, 0x23, 0x29, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x52, 0x53, 0x54, 0x55,
        0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
        0x6A, 0x6B, 0x6C, 0x6D, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
        0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xFE, 0xFF,
    }:
        return 2
    if op in {0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x26, 0x2A, 0x2B, 0x2C}:
        return 3
    if op == 0x18:
        return 5
    if op in {0x24, 0x25, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xFC, 0xFD}:
        return 3
    if op in {0xFA, 0xFB}:
        return 4
    if 0x2D <= op <= 0x31 or 0x90 <= op <= 0xAF:
        return 2
    if 0x44 <= op <= 0x6D:
        return 2
    if 0xD0 <= op <= 0xE2:
        return 2
    return 1


SENSITIVE_RULES = (
    ("webview", "android.webkit.WebSettings", {"setJavaScriptEnabled"}),
    ("webview", "android.webkit.WebView", {"addJavascriptInterface", "evaluateJavascript", "loadUrl", "loadData", "loadDataWithBaseURL"}),
    ("webview_ssl", "android.webkit.WebViewClient", {"onReceivedSslError"}),
    ("dynamic_code_loading", "dalvik.system.DexClassLoader", {"<init>"}),
    ("reflection", "java.lang.Class", {"forName", "getDeclaredMethod", "getMethod", "getDeclaredField", "getField"}),
    ("reflection", "java.lang.reflect.Method", {"invoke"}),
    ("process_execution", "java.lang.Runtime", {"exec"}),
    ("process_execution", "java.lang.ProcessBuilder", {"<init>", "start"}),
    ("native_loading", "java.lang.System", {"load", "loadLibrary"}),
    ("preferences", "android.content.Context", {"getSharedPreferences"}),
    ("device_identifier", "android.provider.Settings$Secure", {"getString"}),
    ("intent_boundary", "android.content.Intent", {"getData", "getDataString", "getStringExtra", "getExtras", "getScheme", "getHost", "getQuery"}),
    ("activity_launch", "android.content.Context", {"startActivity", "startActivityForResult"}),
    ("network", "java.net.URL", {"<init>", "openConnection"}),
    ("network", "java.net.URLConnection", {"connect", "getInputStream", "getOutputStream"}),
)


def sensitive_family(ref: dict) -> str | None:
    for family, cls, names in SENSITIVE_RULES:
        if ref["class"] == cls and ref["name"] in names:
            return family
    return None


def caller_label(method: dict) -> str:
    return "%s->%s%s" % (method["class"], method["name"], method["descriptor"])


def owner_group(class_name: str) -> str:
    if class_name.startswith("com.quattroplay.GraalClassic"):
        return "application"
    if class_name.startswith("android.support."):
        return "android_support"
    if class_name.startswith("com.facebook"):
        return "facebook_sdk"
    if class_name.startswith("bolts."):
        return "bolts"
    if class_name.startswith("org.onepf."):
        return "billing_sdk"
    return "other_bundled_or_platform"


def analyze(apk: Path) -> dict:
    apk_data = apk.read_bytes()
    with zipfile.ZipFile(apk) as archive:
        dex_data = archive.read("classes.dex")
    dex = Dex(dex_data)
    class_prefixes = Counter()
    for item in dex.classes:
        package = item["class"].rsplit(".", 1)[0] if "." in item["class"] else item["class"]
        class_prefixes[package] += 1

    native_methods = [
        {
            "method": caller_label(method),
            "access_flags": "0x%x" % method["access_flags"],
        }
        for method in dex.defined_methods
        if method["access_flags"] & 0x100
    ]
    native_method_keys = {
        (method["class"], method["name"], method["descriptor"])
        for method in dex.defined_methods
        if method["access_flags"] & 0x100
    }
    call_sites = []
    native_call_sites = []
    family_callers = defaultdict(set)
    family_targets = defaultdict(set)
    family_groups = defaultdict(Counter)
    code_method_count = 0
    code_errors = []
    for method in dex.defined_methods:
        if not method["code_off"]:
            continue
        code_method_count += 1
        try:
            method_indices = dex.calls(method["code_off"])
        except ValueError as exc:
            if len(code_errors) < 10:
                code_errors.append({"method": caller_label(method), "error": str(exc)})
            continue
        for method_idx in method_indices:
            ref = dex.methods[method_idx]
            caller = caller_label(method)
            target = dex.method_label(method_idx)
            if (ref["class"], ref["name"], ref["descriptor"]) in native_method_keys:
                native_call_sites.append({
                    "caller": caller,
                    "caller_group": owner_group(method["class"]),
                    "target": target,
                })
            family = sensitive_family(ref)
            if family is None:
                continue
            family_callers[family].add(caller)
            family_targets[family].add(target)
            family_groups[family][owner_group(method["class"])] += 1
            call_sites.append({"family": family, "caller": caller, "target": target})

    family_records = {}
    for family in sorted(set(family_callers) | set(family_targets)):
        family_records[family] = {
            "call_site_count": sum(1 for site in call_sites if site["family"] == family),
            "caller_count": len(family_callers[family]),
            "target_count": len(family_targets[family]),
            "caller_groups": dict(sorted(family_groups[family].items())),
            "callers": sorted(family_callers[family])[:80],
            "targets": sorted(family_targets[family])[:80],
        }
    native_targets = {item["target"] for item in native_call_sites}
    native_method_labels = {caller_label(method) for method in dex.defined_methods if method["access_flags"] & 0x100}

    return {
        "schema": "libqplay.original-dex-method-surface-review.v1",
        "analysis_date": "2026-09-04",
        "analysis_scope": "offline DEX index, class-data, and code-item method-reference inventory for the original APK",
        "input": {
            "name": apk.name,
            "path": "private local APK, not committed",
            "size": len(apk_data),
            "sha256": sha256(apk_data),
        },
        "dex": {
            "name": "classes.dex",
            "magic": dex.magic,
            "size": len(dex_data),
            "sha256": sha256(dex_data),
            "string_count": dex.string_ids_size,
            "type_count": dex.type_ids_size,
            "proto_count": dex.proto_ids_size,
            "field_count": dex.field_ids_size,
            "method_reference_count": dex.method_ids_size,
            "class_count": dex.class_defs_size,
            "defined_method_count": len(dex.defined_methods),
            "methods_with_code": code_method_count,
            "native_method_count": len(native_methods),
            "native_methods_with_direct_calls": len(native_targets),
            "native_methods_without_direct_calls": len(native_method_labels - native_targets),
            "code_parse_error_count": len(code_errors),
            "top_class_prefixes": [
                {"prefix": prefix, "class_count": count}
                for prefix, count in class_prefixes.most_common(20)
            ],
        },
        "native_methods": native_methods[:200],
        "native_call_sites": sorted(native_call_sites, key=lambda item: (item["caller"], item["target"])),
        "native_methods_without_direct_calls": sorted(native_method_labels - native_targets),
        "sensitive_call_sites": sorted(call_sites, key=lambda item: (item["family"], item["caller"], item["target"])),
        "sensitive_families": family_records,
        "code_parse_errors": code_errors,
        "network_contacted": False,
        "execution_performed": False,
        "notes": [
            "A call site means the decoded DEX method body contains an invoke instruction targeting the listed method reference. It does not prove runtime reachability.",
            "The report records API names and bounded callers only. It does not include method bodies, APK payloads, credentials, or live responses.",
            "The native methods identify Java-to-native boundaries that should be paired with the translated ARM64 symbol inventory.",
        ],
        "tool": "tools/audit_dex_method_surface.py",
        "tool_version": 1,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, default=DEFAULT_APK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = analyze(args.apk)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "class_count": report["dex"]["class_count"],
        "defined_method_count": report["dex"]["defined_method_count"],
        "native_method_count": report["dex"]["native_method_count"],
        "sensitive_call_site_count": len(report["sensitive_call_sites"]),
        "native_call_site_count": len(report["native_call_sites"]),
        "sensitive_families": sorted(report["sensitive_families"]),
        "code_parse_error_count": report["dex"]["code_parse_error_count"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
