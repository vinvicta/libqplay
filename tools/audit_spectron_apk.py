#!/usr/bin/env python3
"""Build a compact, offline security inventory for the supplied Spectron APK.

The scanner intentionally uses only local ZIP, binary-XML, DEX, ELF, and
certificate data. It does not install the package, start an emulator, resolve a
hostname, or open a socket. The output is a small evidence index rather than a
replacement for source review or a penetration test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APK = ROOT.parent / "spectron_client_1.0.2.apk"
DEFAULT_OUTPUT = ROOT / "artifacts" / "spectron_apk_security_audit_20260830.json"
ANDROID_URI = "http://schemas.android.com/apk/res/android"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def decode_length8(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset], offset + 1
    return first, offset


def decode_length16(data: bytes, offset: int) -> tuple[int, int]:
    first = read_u16(data, offset)
    offset += 2
    if first & 0x8000:
        return ((first & 0x7FFF) << 16) | read_u16(data, offset), offset + 2
    return first, offset


def parse_string_pool(data: bytes, offset: int) -> tuple[list[str], int]:
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    if chunk_type != 0x0001 or header_size < 28:
        raise ValueError("Android string pool is missing or malformed")
    string_count, style_count, flags, strings_start, _styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )
    offsets_start = offset + header_size
    strings_base = offset + strings_start
    utf8 = bool(flags & 0x100)
    strings: list[str] = []
    for index in range(string_count):
        relative = read_u32(data, offsets_start + index * 4)
        position = strings_base + relative
        if utf8:
            _utf16_length, position = decode_length8(data, position)
            byte_length, position = decode_length8(data, position)
            raw = data[position : position + byte_length]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            utf16_length, position = decode_length16(data, position)
            raw = data[position : position + utf16_length * 2]
            strings.append(raw.decode("utf-16le", errors="replace"))
    return strings, offset + chunk_size


def typed_value(data_type: int, data_value: int, strings: list[str]):
    if data_type == 0x00:
        return None
    if data_type == 0x01:
        return f"@0x{data_value:08x}"
    if data_type == 0x02:
        return f"?0x{data_value:08x}"
    if data_type == 0x03:
        return strings[data_value] if data_value < len(strings) else f"<string:{data_value}>"
    if data_type == 0x04:
        return struct.unpack("<f", struct.pack("<I", data_value))[0]
    if data_type == 0x10:
        return data_value if data_value < 0x80000000 else data_value - 0x100000000
    if data_type == 0x11:
        return f"0x{data_value:08x}"
    if data_type == 0x12:
        return bool(data_value)
    return {"type": f"0x{data_type:02x}", "data": data_value}


def attr_value(attrs: dict[str, object], local_name: str, default=None):
    return attrs.get("android:" + local_name, attrs.get(local_name, default))


def parse_binary_manifest(data: bytes) -> dict:
    if len(data) < 8 or read_u16(data, 0) != 0x0003:
        raise ValueError("input is not an Android binary XML document")
    document_header_size = read_u16(data, 2)
    document_size = read_u32(data, 4)
    document_end = min(len(data), document_size)

    strings: list[str] = []
    namespace_prefixes: dict[int, str] = {}
    nodes: list[dict] = []
    stack: list[int] = []
    offset = document_header_size

    while offset + 8 <= document_end:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_size < 8 or offset + chunk_size > document_end:
            raise ValueError(f"invalid XML chunk at 0x{offset:x}")

        if chunk_type == 0x0001:
            strings, _ = parse_string_pool(data, offset)
        elif chunk_type == 0x0100:
            prefix_id, uri_id = struct.unpack_from("<II", data, offset + 16)
            if uri_id < len(strings):
                namespace_prefixes[uri_id] = strings[prefix_id] if prefix_id < len(strings) else ""
        elif chunk_type == 0x0102:
            extension = offset + 16
            namespace_id, name_id = struct.unpack_from("<II", data, extension)
            attribute_start, attribute_size, attribute_count = struct.unpack_from(
                "<HHH", data, extension + 8
            )
            name = strings[name_id] if name_id < len(strings) else f"<name:{name_id}>"
            attrs: dict[str, object] = {}
            raw_attrs: list[dict] = []
            attrs_offset = extension + attribute_start
            for index in range(attribute_count):
                current = attrs_offset + index * attribute_size
                attr_namespace, attr_name, raw_value = struct.unpack_from("<III", data, current)
                value_size, _res0, value_type, value_data = struct.unpack_from(
                    "<HBBI", data, current + 12
                )
                local = strings[attr_name] if attr_name < len(strings) else f"<attr:{attr_name}>"
                prefix = namespace_prefixes.get(attr_namespace, "")
                key = f"{prefix}:{local}" if prefix else local
                value = typed_value(value_type, value_data, strings)
                attrs[key] = value
                raw_attrs.append(
                    {
                        "name": key,
                        "value": value,
                        "raw_value": (
                            strings[raw_value] if raw_value < len(strings) else None
                        ),
                        "type": f"0x{value_type:02x}",
                        "data": value_data,
                        "size": value_size,
                    }
                )
            parent = nodes[stack[-1]]["name"] if stack else None
            node = {
                "name": name,
                "parent": parent,
                "parent_index": stack[-1] if stack else None,
                "attrs": attrs,
                "raw_attrs": raw_attrs,
            }
            nodes.append(node)
            stack.append(len(nodes) - 1)
        elif chunk_type == 0x0103:
            if stack:
                stack.pop()

        offset += chunk_size

    manifest_node = next((node for node in nodes if node["name"] == "manifest"), None)
    if manifest_node is None:
        raise ValueError("Android manifest element was not found")

    application_index = next(
        (
            index
            for index, node in enumerate(nodes)
            if node["name"] == "application" and node["parent"] == "manifest"
        ),
        None,
    )
    application = nodes[application_index] if application_index is not None else None

    permissions = []
    for node in nodes:
        if node["name"] in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
            permissions.append(
                {
                    "name": attr_value(node["attrs"], "name"),
                    "max_sdk_version": attr_value(node["attrs"], "maxSdkVersion"),
                    "node": node["name"],
                }
            )

    sdk_node = next((node for node in nodes if node["name"] == "uses-sdk"), None)
    sdk = {}
    if sdk_node:
        for key in ("minSdkVersion", "targetSdkVersion", "maxSdkVersion"):
            value = attr_value(sdk_node["attrs"], key)
            if value is not None:
                sdk[key] = value

    component_names = {"activity", "activity-alias", "service", "receiver", "provider"}
    components = []
    for index, node in enumerate(nodes):
        if node["name"] not in component_names or node["parent_index"] != application_index:
            continue
        filters = []
        for filter_index, filter_node in enumerate(nodes):
            if filter_node["name"] != "intent-filter" or filter_node["parent_index"] != index:
                continue
            actions = []
            categories = []
            data = []
            for child in nodes:
                if child["parent_index"] != filter_index:
                    continue
                if child["name"] == "action":
                    actions.append(attr_value(child["attrs"], "name"))
                elif child["name"] == "category":
                    categories.append(attr_value(child["attrs"], "name"))
                elif child["name"] == "data":
                    data.append(
                        {
                            key: value
                            for key, value in child["attrs"].items()
                            if key.startswith("android:")
                        }
                    )
            filters.append({"actions": actions, "categories": categories, "data": data})
        attrs = node["attrs"]
        components.append(
            {
                "type": node["name"],
                "name": attr_value(attrs, "name"),
                "exported": attr_value(attrs, "exported"),
                "permission": attr_value(attrs, "permission"),
                "authorities": attr_value(attrs, "authorities"),
                "direct_boot_aware": attr_value(attrs, "directBootAware"),
                "intent_filters": filters,
            }
        )

    return {
        "package": attr_value(manifest_node["attrs"], "package"),
        "version_code": attr_value(manifest_node["attrs"], "versionCode"),
        "version_name": attr_value(manifest_node["attrs"], "versionName"),
        "compile_sdk_version": attr_value(manifest_node["attrs"], "compileSdkVersion"),
        "platform_build_version_name": attr_value(
            manifest_node["attrs"], "platformBuildVersionName"
        ),
        "permissions": permissions,
        "sdk": sdk,
        "application": {
            "name": attr_value(application["attrs"], "name") if application else None,
            "label": attr_value(application["attrs"], "label") if application else None,
            "uses_cleartext_traffic": (
                attr_value(application["attrs"], "usesCleartextTraffic") if application else None
            ),
            "network_security_config": (
                attr_value(application["attrs"], "networkSecurityConfig") if application else None
            ),
            "debuggable": attr_value(application["attrs"], "debuggable") if application else None,
            "allow_backup": attr_value(application["attrs"], "allowBackup") if application else None,
            "data_extraction_rules": (
                attr_value(application["attrs"], "dataExtractionRules") if application else None
            ),
        },
        "components": components,
    }


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
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
    raise ValueError("malformed DEX ULEB128 value")


def dex_strings(data: bytes) -> tuple[str, list[str]]:
    if len(data) < 0x70 or not data.startswith(b"dex\n"):
        raise ValueError("not a DEX file")
    magic = data[:8].decode("ascii", errors="replace")
    string_count = read_u32(data, 0x38)
    string_ids_offset = read_u32(data, 0x3C)
    strings = []
    for index in range(string_count):
        item_offset = string_ids_offset + index * 4
        string_offset = read_u32(data, item_offset)
        _utf16_length, position = read_uleb128(data, string_offset)
        end = data.find(b"\x00", position)
        if end < 0:
            raise ValueError("unterminated DEX string")
        strings.append(data[position:end].decode("utf-8", errors="replace"))
    return magic, strings


DEX_INDICATORS = {
    "webview_class": "WebView",
    "webview_javascript_enabled": "setJavaScriptEnabled",
    "webview_javascript_bridge": "addJavascriptInterface",
    "webview_script_evaluation": "evaluateJavascript",
    "javascript_interface_annotation": "JavascriptInterface",
    "dynamic_dex_loader": "DexClassLoader",
    "dynamic_dex_command": "load_dex",
    "reflection_command": "java_reflection",
    "device_identifier": "android_id",
    "persistent_preferences": "getSharedPreferences",
    "webtop_class": "WebTop",
    "webtop_message_gui": "messageGui",
    "deep_link_classic": "graalclassic://",
    "deep_link_classic_plus": "graalclassicplus://",
    "xposed_marker": "xposed",
}


def summarize_dex(name: str, data: bytes) -> dict:
    magic, strings = dex_strings(data)
    indicators = {}
    for key, needle in DEX_INDICATORS.items():
        matches = [value for value in strings if needle in value]
        if matches:
            indicators[key] = {
                "needle": needle,
                "count": len(matches),
                "examples": sorted(set(matches))[:8],
            }
    return {
        "name": name,
        "size": len(data),
        "sha256": sha256_bytes(data),
        "magic": magic,
        "string_count": len(strings),
        "indicators": indicators,
    }


def run_tool(command: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


def parse_readelf(path: Path) -> dict:
    header = run_tool(["readelf", "-h", str(path)])
    dynamic = run_tool(["readelf", "-W", "-d", str(path)])
    program = run_tool(["readelf", "-W", "-l", str(path)])
    symbols = run_tool(["readelf", "-W", "-Ws", str(path)])

    needed = re.findall(r"Shared library: \[([^\]]+)\]", dynamic)
    soname_match = re.search(r"Library soname: \[([^\]]+)\]", dynamic)
    entry_match = re.search(r"Entry point address:\s+0x([0-9a-fA-F]+)", header)
    class_match = re.search(r"Class:\s+(\S+)", header)
    machine_match = re.search(r"Machine:\s+(.+)", header)
    symbol_count_match = re.search(r"Symbol table '.dynsym' contains (\d+) entries", symbols)

    imports = []
    defined_functions = 0
    named_dynamic_symbols = 0
    for line in symbols.splitlines():
        if not re.match(r"^\s*\d+:\s", line):
            continue
        fields = line.split()
        if len(fields) < 8:
            continue
        symbol_type = fields[3]
        section = fields[6]
        symbol_name = " ".join(fields[7:])
        if symbol_name:
            named_dynamic_symbols += 1
        if section == "UND" and symbol_name:
            imports.append(symbol_name.split("@", 1)[0])
        elif section != "UND" and symbol_type == "FUNC":
            defined_functions += 1

    stack_flags = None
    for line in program.splitlines():
        fields = line.split()
        if "GNU_STACK" in fields:
            index = fields.index("GNU_STACK")
            if len(fields) > index + 6:
                stack_flags = fields[index + 6]
            break
    import_set = set(imports)
    interesting_imports = sorted(
        name
        for name in import_set
        if name
        in {
            "abort",
            "accept",
            "bind",
            "chmod",
            "connect",
            "dlopen",
            "dlsym",
            "execvp",
            "fopen",
            "fork",
            "gethostbyname",
            "listen",
            "mprotect",
            "open",
            "read",
            "recv",
            "recvfrom",
            "send",
            "sendto",
            "socket",
            "syscall",
            "unlink",
            "write",
        }
    )
    return {
        "class": class_match.group(1) if class_match else None,
        "machine": machine_match.group(1).strip() if machine_match else None,
        "entry_point": f"0x{entry_match.group(1)}" if entry_match else None,
        "needed": needed,
        "soname": soname_match.group(1) if soname_match else None,
        "dynamic_symbol_count": int(symbol_count_match.group(1)) if symbol_count_match else None,
        "named_dynamic_symbol_count": named_dynamic_symbols,
        "defined_function_count": defined_functions,
        "imports": interesting_imports,
        "has_gnu_relro": "GNU_RELRO" in program,
        "gnu_stack_flags": stack_flags,
        "executable_stack": bool(stack_flags and "E" in stack_flags),
        "bind_now": "(BIND_NOW)" in dynamic or "Flags: NOW" in dynamic,
    }


NATIVE_INDICATORS = {
    "legacy_tls_versions": [b"TLSv1.1", b"TLSv1.2"],
    "legacy_or_weak_cipher_names": [
        b"SSL_RSA_WITH_RC4_128_SHA",
        b"SSL_RSA_WITH_RC4_128_MD5",
        b"TLS_RSA_WITH_NULL_SHA",
        b"TLS_RSA_WITH_NULL_SHA256",
    ],
    "pem_key_markers": [b"-----BEGIN CERTIFICATE-----", b"-----BEGIN RSA PRIVATE KEY-----"],
    "hook_runtime_markers": [b"A64_HOOK", b"inline hook", b"dl_iterate_phdr"],
    "webtop_commands": [b"crash", b"freeze", b"abort", b"load_menu", b"setscript", b"gs2call"],
    "jni_bridge_exports": [b"Java_com_WebTop_getMainUrl", b"Java_com_WebTop_onmsg", b"Java_com_WebTop_onCreated"],
}


def native_string_indicators(data: bytes) -> dict:
    result = {}
    for group, needles in NATIVE_INDICATORS.items():
        hits = {}
        for needle in needles:
            count = data.count(needle)
            if count:
                hits[needle.decode("ascii", errors="replace")] = count
        if hits:
            result[group] = hits
    trust_marker = b"6erxf21jcqpGrZR4"
    trust_start = data.find(trust_marker)
    if trust_start >= 0:
        trust_end = data.find(b"\x00", trust_start)
        if trust_end < 0:
            trust_end = len(data)
        trust_text = data[trust_start:trust_end]
        result["embedded_trust_text"] = {
            "file_offset": trust_start,
            "bytes": len(trust_text),
            "sha256": sha256_bytes(trust_text),
        }
    return result


def apk_signing_block(data: bytes, central_directory_offset: int) -> dict:
    magic = b"APK Sig Block 42"
    if central_directory_offset < 24:
        return {"present": False, "ids": []}
    footer_magic = data[central_directory_offset - 16 : central_directory_offset]
    if footer_magic != magic:
        return {"present": False, "ids": []}
    block_size = struct.unpack_from("<Q", data, central_directory_offset - 24)[0]
    block_start = central_directory_offset - block_size - 8
    if block_start < 0 or block_start + 8 > len(data):
        return {"present": False, "ids": [], "malformed": True}
    ids = []
    position = block_start + 8
    end = central_directory_offset - 24
    while position + 8 <= end:
        length = struct.unpack_from("<Q", data, position)[0]
        position += 8
        if length < 4 or position + length > end:
            return {"present": True, "ids": ids, "malformed": True}
        identifier = struct.unpack_from("<I", data, position)[0]
        ids.append(f"0x{identifier:08x}")
        position += length
    return {"present": True, "ids": ids, "malformed": position != end}


def certificate_record(name: str, data: bytes, pem: bool) -> dict | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return None
    try:
        certificate = (
            x509.load_pem_x509_certificate(data)
            if pem
            else x509.load_der_x509_certificate(data)
        )
    except ValueError:
        return None

    def field_values(subject) -> list[dict]:
        return [
            {
                "oid": attribute.oid.dotted_string,
                "name": attribute.oid._name or attribute.oid.dotted_string,
                "value": attribute.value,
            }
            for attribute in subject
        ]

    not_before = getattr(certificate, "not_valid_before_utc", certificate.not_valid_before)
    not_after = getattr(certificate, "not_valid_after_utc", certificate.not_valid_after)
    public_key = certificate.public_key()
    key_info = {"type": type(public_key).__name__}
    if hasattr(public_key, "public_numbers"):
        numbers = public_key.public_numbers()
        key_info["size"] = public_key.key_size
        if hasattr(numbers, "e"):
            key_info["exponent"] = numbers.e
    return {
        "name": name,
        "encoding": "PEM" if pem else "DER",
        "subject": field_values(certificate.subject),
        "issuer": field_values(certificate.issuer),
        "serial_number": f"0x{certificate.serial_number:x}",
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "signature_hash": certificate.signature_hash_algorithm.name,
        "public_key": key_info,
        "sha256_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
    }


def extract_v1_certificate(data: bytes, name: str) -> dict | None:
    with tempfile.TemporaryDirectory(prefix="spectron-cert-") as directory:
        source = Path(directory) / "signature.bin"
        pem_path = Path(directory) / "certificate.pem"
        source.write_bytes(data)
        try:
            result = subprocess.run(
                [
                    "openssl",
                    "pkcs7",
                    "-inform",
                    "DER",
                    "-in",
                    str(source),
                    "-print_certs",
                    "-out",
                    str(pem_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0 or not pem_path.is_file():
            return None
        pem = pem_path.read_bytes()
        record = certificate_record(name, pem, pem=True)
        if record is not None:
            record["container"] = "PKCS#7 SignedData"
        return record


def zip_summary(apk_data: bytes, archive: zipfile.ZipFile) -> dict:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    duplicate_names = sorted(name for name, count in Counter(names).items() if count > 1)
    path_anomalies = sorted(
        name
        for name in names
        if name.startswith("/") or any(part == ".." for part in Path(name).parts)
    )
    encrypted = sorted(info.filename for info in infos if info.flag_bits & 0x1)
    files = [info for info in infos if not info.is_dir()]
    top_entries = [
        {"name": info.filename, "bytes": info.file_size, "compressed_bytes": info.compress_size}
        for info in sorted(files, key=lambda item: (-item.file_size, item.filename))[:20]
    ]
    asset_files = [info for info in files if info.filename.startswith("assets/")]
    return {
        "archive_bytes": len(apk_data),
        "entry_count": len(infos),
        "file_count": len(files),
        "uncompressed_bytes": sum(info.file_size for info in files),
        "duplicate_entry_names": duplicate_names,
        "path_anomalies": path_anomalies,
        "encrypted_entries": encrypted,
        "top_entries_by_uncompressed_size": top_entries,
        "asset_file_count": len(asset_files),
        "asset_uncompressed_bytes": sum(info.file_size for info in asset_files),
        "apk_signing_block": apk_signing_block(apk_data, archive.start_dir),
    }


def selected_components(manifest: dict) -> dict:
    exported = [
        component
        for component in manifest["components"]
        if component.get("exported") is True
    ]
    deep_link = [
        component
        for component in exported
        if any(
            data.get("android:scheme", data.get("scheme"))
            in {"graalclassic", "graalclassicplus"}
            for intent_filter in component["intent_filters"]
            for data in intent_filter["data"]
        )
    ]
    return {
        "exported_explicit_true": exported,
        "exported_deep_link_components": deep_link,
    }


def build_findings(manifest: dict, dex_reports: list[dict], native_reports: list[dict], certs: dict) -> list[dict]:
    findings = []
    application = manifest["application"]
    indicators = {key for report in dex_reports for key in report["indicators"]}
    libxposed = next((report for report in native_reports if report["name"].endswith("libxposed.so")), None)
    libqplay = next((report for report in native_reports if report["name"].endswith("libqplay.so")), None)

    if application.get("uses_cleartext_traffic") is True:
        findings.append(
            {
                "id": "APK-001",
                "severity": "medium",
                "confidence": "confirmed",
                "title": "Application permits cleartext traffic",
                "evidence": ["AndroidManifest.xml application android:usesCleartextTraffic=true"],
                "impact": "HTTP connections made by Android framework components are not rejected by the manifest policy.",
                "limit": "This does not prove that a particular login or update request uses HTTP. The native connector has its own TLS implementation.",
            }
        )

    deep_link_components = selected_components(manifest)["exported_deep_link_components"]
    if deep_link_components:
        findings.append(
            {
                "id": "APK-002",
                "severity": "medium",
                "confidence": "confirmed capability, exploitability untested",
                "title": "Exported custom-scheme activity reaches native deep-link handling",
                "evidence": [
                    "QPlayActivity is explicitly exported and accepts graalclassic:// and graalclassicplus://.",
                    "OnCreate passes the Intent action and URI string to OnIntent, which posts OnDeepLink to Natives.onInvokeEvent.",
                ],
                "impact": "Any installed application can request the exported scheme. The native event handler must treat action, URI, and extras as untrusted input.",
                "limit": "No malicious caller or server payload was used in this audit.",
            }
        )

    if {"webview_class", "webview_javascript_enabled", "webview_javascript_bridge"} <= indicators:
        findings.append(
            {
                "id": "APK-003",
                "severity": "high-interest",
                "confidence": "confirmed capability, reachability depends on page source",
                "title": "WebTop enables JavaScript and exposes a native JavaScript bridge",
                "evidence": [
                    "classes2.dex contains WebTop, setJavaScriptEnabled, and addJavascriptInterface.",
                    "The bridge exposes getAndroidId, getSZ, loadData, message, and saveData.",
                    "messageGui builds a quoted JavaScript call by concatenating id and data without escaping.",
                ],
                "impact": "A page that can reach the bridge can read device and persistent state, write preferences, and send messages into native dispatch. Unescaped messageGui data is a JavaScript injection sink if attacker-controlled data reaches it.",
                "limit": "The recovered WebTop URL was not opened, and this report does not claim that a remote page can reach every bridge method in a production run.",
            }
        )

    if {"dynamic_dex_loader", "dynamic_dex_command", "reflection_command"} <= indicators:
        findings.append(
            {
                "id": "APK-004",
                "severity": "high-interest",
                "confidence": "confirmed capability, reachability depends on command source",
                "title": "WebTop can write DEX bytes and load classes reflectively",
                "evidence": [
                    "WebTop recognizes load_dex and java_reflection commands.",
                    "iDex writes webview_injected_<id>.dex under the app files directory, creates a DexClassLoader, and invokes a reflected Context method.",
                ],
                "impact": "If an untrusted page or message source can supply these commands, it creates an in-process code-loading boundary with access to the app's permissions and data.",
                "limit": "The audit did not inject DEX, invoke reflection, or contact the recovered WebTop URL.",
            }
        )

    fabzat = certs.get("fabzat")
    if fabzat:
        findings.append(
            {
                "id": "APK-005",
                "severity": "medium",
                "confidence": "confirmed embedded legacy material, active trust use unproven",
                "title": "APK embeds an expired SHA-1 Fabzat certificate",
                "evidence": [
                    "res/raw/fabzat_com.crt is a PEM certificate for admin.fabzat.com.",
                    f"Validity ends at {fabzat['not_after']} and the signature hash is {fabzat['signature_hash']}.",
                ],
                "impact": "Any code that treats this file as a trust anchor or pins it cannot validate a current service certificate after expiry.",
                "limit": "The file's presence does not prove that current startup or login consumes it.",
            }
        )

    if libqplay and libqplay["native_strings"].get("legacy_or_weak_cipher_names"):
        findings.append(
            {
                "id": "APK-006",
                "severity": "medium",
                "confidence": "confirmed legacy vocabulary, active suite selection unproven",
                "title": "Native qplay contains legacy TLS and weak cipher identifiers",
                "evidence": [
                    "ARM64 libqplay.so contains TLSv1.1, TLSv1.2, RC4, and NULL cipher suite names.",
                    "The library uses a bundled CyaSSL implementation rather than Android's Java trust stack.",
                ],
                "impact": "Legacy protocol support expands downgrade and configuration risk if those suites are enabled by the connector path.",
                "limit": "String presence alone does not show that a weak suite was negotiated. Existing loopback evidence preserved peer and hostname verification.",
            }
        )

    trust_text = libqplay["native_strings"].get("embedded_trust_text") if libqplay else None
    if trust_text and trust_text.get("sha256") == "c87ea7bc32005cca699fb724ab455926fd852a1bd40ce0985aadf31a994878a0":
        findings.append(
            {
                "id": "APK-009",
                "severity": "medium",
                "confidence": "confirmed embedded bundle, active validation path separately reviewed",
                "title": "Spectron carries the historical native connector trust bundle",
                "evidence": [
                    "The ARM64 qplay library contains the 12,820-byte trust text also found in the 1.8 library.",
                    "The repository's CyaSSL review decodes six historical certificate blocks; the earliest recorded leaf expired in 2023.",
                ],
                "impact": "A connector path that still validates against this fixed bundle can fail against a renewed service chain or require an unsafe verification bypass.",
                "limit": "This audit did not contact a live service and does not claim that every Spectron connection enables this trust path.",
            }
        )

    if libxposed and libxposed["native_strings"].get("webtop_commands"):
        findings.append(
            {
                "id": "APK-007",
                "severity": "critical stability and integrity risk in the supplied mod",
                "confidence": "confirmed by static review",
                "title": "Bundled libxposed installs hooks and contains destructive WebTop commands",
                "evidence": [
                    "libxposed.so imports dlopen, dlsym, and mprotect and contains A64_HOOK and inline-hook strings.",
                    "IDA review mapped crash, freeze, and abort branches in Java_com_WebTop_onmsg; load_menu, setscript, and gs2call forward modding payloads.",
                ],
                "impact": "The mod layer can alter qplay behavior and deliberately terminate or hang the process. It is a separate trust boundary from the old connector.",
                "limit": "This finding describes the supplied modded APK and is not attributed to the original 1.8 package.",
            }
        )

    if native_reports and all(not report["elf"]["executable_stack"] for report in native_reports):
        findings.append(
            {
                "id": "APK-008",
                "severity": "informational",
                "confidence": "confirmed",
                "title": "Native libraries have non-executable GNU_STACK segments",
                "evidence": [
                    "readelf reports RW GNU_STACK for the packaged native libraries.",
                    "The qplay and xposed libraries also contain GNU_RELRO and BIND_NOW metadata.",
                ],
                "impact": "These are useful exploit mitigations, although they do not compensate for unsafe input or code-loading paths.",
                "limit": "The report does not claim full RELRO or complete runtime hardening.",
            }
        )
    return findings


def audit(apk_path: Path) -> dict:
    apk_data = apk_path.read_bytes()
    with zipfile.ZipFile(apk_path) as archive:
        manifest_data = archive.read("AndroidManifest.xml")
        manifest = parse_binary_manifest(manifest_data)
        zip_info = zip_summary(apk_data, archive)

        dex_reports = []
        for name in sorted(info.filename for info in archive.infolist() if re.fullmatch(r"classes(?:\d+)?\.dex", info.filename)):
            dex_reports.append(summarize_dex(name, archive.read(name)))

        native_reports = []
        with tempfile.TemporaryDirectory(prefix="spectron-native-audit-") as directory:
            for info in sorted(
                (item for item in archive.infolist() if re.fullmatch(r"lib/[^/]+/[^/]+\.so", item.filename)),
                key=lambda item: item.filename,
            ):
                data = archive.read(info.filename)
                native_path = Path(directory) / Path(info.filename).name
                native_path.write_bytes(data)
                native_reports.append(
                    {
                        "name": info.filename,
                        "size": len(data),
                        "sha256": sha256_bytes(data),
                        "elf": parse_readelf(native_path),
                        "native_strings": native_string_indicators(data),
                    }
                )

        certificates = {}
        if "res/raw/fabzat_com.crt" in archive.namelist():
            data = archive.read("res/raw/fabzat_com.crt")
            certificates["fabzat"] = certificate_record("res/raw/fabzat_com.crt", data, pem=True)
        if "META-INF/CERT.RSA" in archive.namelist():
            data = archive.read("META-INF/CERT.RSA")
            certificates["apk_v1"] = extract_v1_certificate(data, "META-INF/CERT.RSA")

        names = set(archive.namelist())
        signature_entries = sorted(
            name
            for name in names
            if name.upper().startswith("META-INF/")
            and Path(name).suffix.upper() in {".SF", ".RSA", ".DSA", ".EC"}
        )

    selected = selected_components(manifest)
    report = {
        "schema": "libqplay.spectron-apk-security-audit.v1",
        "tool": "tools/audit_spectron_apk.py",
        "tool_version": 1,
        "analysis_date": "2026-08-30",
        "analysis_scope": "offline static inventory of the supplied local APK",
        "network_contacted": False,
        "live_endpoint_tested": False,
        "input": {
            "name": apk_path.name,
            "sha256": sha256_bytes(apk_data),
            "bytes": len(apk_data),
        },
        "manifest": manifest,
        "component_security_selection": selected,
        "zip": zip_info,
        "dex": dex_reports,
        "native": native_reports,
        "signing": {
            "v1_signature_entries": signature_entries,
            "v1_signature_present": bool(signature_entries),
            "apk_signing_block": zip_info["apk_signing_block"],
            "certificates": certificates,
        },
    }
    report["findings"] = build_findings(manifest, dex_reports, native_reports, certificates)
    report["reproduction"] = {
        "command": "python3 tools/audit_spectron_apk.py /path/to/spectron_client_1.0.2.apk --output artifacts/spectron_apk_security_audit_20260830.json",
        "side_effects": "Reads the APK and writes only the requested JSON report. Temporary ELF and certificate files are removed on exit.",
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", nargs="?", type=Path, default=DEFAULT_APK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    apk_path = args.apk if args.apk.is_absolute() else Path.cwd() / args.apk
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if not apk_path.is_file():
        parser.error(f"APK does not exist: {apk_path}")
    report = audit(apk_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "input_sha256": report["input"]["sha256"],
                "findings": len(report["findings"]),
                "dex_files": len(report["dex"]),
                "native_files": len(report["native"]),
                "output": output.as_posix(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
