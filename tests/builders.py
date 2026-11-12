"""Builders that construct minimal PE, AXML, DEX and APK fixtures for tests."""
from __future__ import annotations

import hashlib
import io
import struct
import zipfile
import zlib

ANDROID_NS = "http://schemas.android.com/apk/res/android"


# --------------------------------------------------------------------------- PE

def build_minimal_pe64(entry_bytes: bytes = b"\xc3") -> bytes:
    """Build a minimal but parseable PE32+ (AMD64) executable image."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    magic = 0x20B
    entry_rva = 0x1000
    image_base = 0x140000000
    section_align = 0x1000
    file_align = 0x200
    size_of_headers = 0x200
    size_of_image = 0x2000

    optional = bytearray()
    optional += struct.pack("<HBBIIIII", magic, 14, 0, 0x200, 0x200, 0, entry_rva, 0x1000)
    optional += struct.pack(
        "<QIIHHHHHHIIIIHH",
        image_base, section_align, file_align,
        6, 0, 0, 0, 6, 0,
        0, size_of_image, size_of_headers, 0,
        3, 0x8160,
    )
    optional += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    optional += b"\x00" * (16 * 8)
    assert len(optional) == 240, len(optional)

    coff = struct.pack(
        "<HHIIIHH",
        0x8664, 1, 1700000000, 0, 0, len(optional), 0x0022,
    )

    pointer_to_raw = size_of_headers
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(entry_bytes), 0x1000, max(len(entry_bytes), file_align), pointer_to_raw,
        0, 0, 0, 0,
        0x60000020,
    )

    headers = b"PE\x00\x00" + coff + bytes(optional) + section
    blob = bytearray(dos) + headers
    if len(blob) > size_of_headers:
        raise ValueError("headers exceed SizeOfHeaders")
    blob.extend(b"\x00" * (size_of_headers - len(blob)))
    blob.extend(entry_bytes.ljust(file_align, b"\x00"))
    return bytes(blob)


# -------------------------------------------------------------------------- AXML

class AxmlBuilder:
    """Encode a minimal binary Android XML document (UTF-16 string pool)."""

    def __init__(self) -> None:
        self.strings: list[str] = []
        self.chunks: list[bytes] = []

    def _index(self, value: str) -> int:
        if value not in self.strings:
            self.strings.append(value)
        return self.strings.index(value)

    def start_ns(self, prefix: str, uri: str) -> None:
        body = struct.pack("<IIII", 1, 0xFFFFFFFF, self._index(prefix), self._index(uri))
        self.chunks.append(struct.pack("<HHI", 0x0100, 0x10, 8 + len(body)) + body)

    def end_ns(self, prefix: str, uri: str) -> None:
        body = struct.pack("<IIII", 1, 0xFFFFFFFF, self._index(prefix), self._index(uri))
        self.chunks.append(struct.pack("<HHI", 0x0101, 0x10, 8 + len(body)) + body)

    def start(self, tag: str, attrs: list[tuple[str, str, str]] | None = None) -> None:
        """attrs entries: (name, value, kind) where kind is 'str' | 'int' | 'bool'."""
        name_idx = self._index(tag)
        encoded: list[bytes] = []
        for name, value, kind in attrs or []:
            if ":" in name:
                prefix, local = name.split(":", 1)
            else:
                prefix, local = "", name
            attr_name_idx = self._index(local)
            if prefix:
                ns_idx = self._index(ANDROID_NS)
            else:
                ns_idx = 0xFFFFFFFF
            if kind == "int":
                raw_idx = 0xFFFFFFFF
                data_type = 0x10
                data = int(value)
            elif kind == "bool":
                raw_idx = 0xFFFFFFFF
                data_type = 0x12
                data = 1 if value.lower() == "true" else 0
            else:
                raw_idx = self._index(value)
                data_type = 0x03
                data = raw_idx
            encoded.append(
                struct.pack("<IIIHBBI", ns_idx, attr_name_idx, raw_idx, 8, 0, data_type, data)
            )
        attr_count = len(encoded)
        attr_ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_idx, 20, 20, attr_count, 0, 0, 0)
        body = struct.pack("<II", 1, 0xFFFFFFFF) + attr_ext + b"".join(encoded)
        self.chunks.append(struct.pack("<HHI", 0x0102, 0x10, 8 + len(body)) + body)

    def end(self, tag: str) -> None:
        name_idx = self._index(tag)
        body = struct.pack("<IIII", 1, 0xFFFFFFFF, 0xFFFFFFFF, name_idx)
        self.chunks.append(struct.pack("<HHI", 0x0103, 0x10, 8 + len(body)) + body)

    def build(self) -> bytes:
        pool = self._string_pool()
        payload = pool + b"".join(self.chunks)
        return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload

    def _string_pool(self) -> bytes:
        count = len(self.strings)
        offsets = []
        data = bytearray()
        for value in self.strings:
            offsets.append(len(data))
            encoded = value.encode("utf-16-le")
            data += struct.pack("<H", len(value))
            data += encoded
            data += b"\x00\x00"
        while len(data) % 4:
            data += b"\x00"
        strings_start = 28 + 4 * count
        header = struct.pack(
            "<HHIIIIII", 0x0001, 28, strings_start + len(data),
            count, 0, 0, strings_start, 0,
        )
        return header + b"".join(struct.pack("<I", off) for off in offsets) + bytes(data)


def build_demo_manifest_axml() -> bytes:
    axml = AxmlBuilder()
    axml.start_ns("android", ANDROID_NS)
    axml.start("manifest", [
        ("package", "com.revstudio.demo", "str"),
        ("versionCode", "21", "int"),
        ("versionName", "2.1.0", "str"),
    ])
    axml.start("uses-sdk", [
        ("android:minSdkVersion", "24", "int"),
        ("android:targetSdkVersion", "34", "int"),
    ])
    for permission in (
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.READ_EXTERNAL_STORAGE",
    ):
        axml.start("uses-permission", [("android:name", permission, "str")])
        axml.end("uses-permission")
    axml.start("uses-feature", [("android:name", "android.hardware.camera", "str")])
    axml.end("uses-feature")
    axml.start("application", [
        ("android:label", "RevDemo", "str"),
        ("android:icon", "@mipmap/ic_launcher", "str"),
        ("android:allowBackup", "false", "bool"),
    ])
    axml.start("activity", [
        ("android:name", "com.revstudio.demo.MainActivity", "str"),
        ("android:exported", "true", "bool"),
    ])
    axml.start("action", [("android:name", "android.intent.action.MAIN", "str")])
    axml.end("action")
    axml.start("category", [("android:name", "android.intent.category.LAUNCHER", "str")])
    axml.end("category")
    axml.end("activity")
    axml.start("service", [("android:name", "com.revstudio.demo.SyncService", "str")])
    axml.end("service")
    axml.start("receiver", [("android:name", "com.revstudio.demo.BootReceiver", "str")])
    axml.end("receiver")
    axml.start("provider", [
        ("android:name", "com.revstudio.demo.DataProvider", "str"),
        ("android:authorities", "com.revstudio.demo.provider", "str"),
    ])
    axml.end("provider")
    axml.end("application")
    axml.end("manifest")
    axml.end_ns("android", ANDROID_NS)
    return axml.build()


# --------------------------------------------------------------------------- DEX

def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dex(
    classes: list[dict] | None = None,
    extra_strings: list[str] | None = None,
) -> bytes:
    """Build a minimal DEX containing the given class definitions.

    Each class: {"name": "com/demo/Main", "super": "android/app/Activity",
                 "source": "Main.java", "methods": [(name, shorty, ret, [params], access)]}
    """
    classes = classes or [
        {
            "name": "com/revstudio/demo/MainActivity",
            "super": "android/app/Activity",
            "source": "MainActivity.java",
            "methods": [
                ("onCreate", "V", "V", ["Landroid/os/Bundle;"], 0x0001),
                ("onClick", "V", "V", [], 0x0001),
                ("<init>", "V", "V", [], 0x10001),
            ],
        },
        {
            "name": "com/revstudio/demo/api/ApiClient",
            "super": "java/lang/Object",
            "source": "ApiClient.java",
            "methods": [
                ("get", "Ljava/lang/String;", "Ljava/lang/String;", ["Ljava/lang/String;"], 0x0001),
                ("post", "Z", "Z", ["Ljava/lang/String;", "Ljava/lang/String;"], 0x0009),
            ],
        },
    ]

    strings: list[str] = []

    def sid(value: str) -> int:
        if value not in strings:
            strings.append(value)
        return strings.index(value)

    type_descriptors: list[str] = []

    def tid(descriptor: str) -> int:
        if descriptor not in type_descriptors:
            type_descriptors.append(descriptor)
        sid(descriptor)
        return type_descriptors.index(descriptor)

    for cls in classes:
        tid(f"L{cls['name']};")
        if cls.get("super"):
            tid(f"L{cls['super']};")
        if cls.get("source"):
            sid(cls["source"])
        for name, shorty, ret, params, _access in cls.get("methods", []):
            sid(name)
            sid(shorty)
            tid(ret)
            for param in params:
                tid(param)

    for value in extra_strings or []:
        sid(value)

    type_descriptors_sorted = sorted(type_descriptors)

    def tidx(descriptor: str) -> int:
        return type_descriptors_sorted.index(descriptor)

    string_index = {value: i for i, value in enumerate(strings)}

    # protos: (shorty, ret_desc, params_descs)
    proto_keys: list[tuple[str, str, tuple[str, ...]]] = []
    for cls in classes:
        for name, shorty, ret, params, _access in cls.get("methods", []):
            key = (shorty, ret, tuple(params))
            if key not in proto_keys:
                proto_keys.append(key)
            sid(name)
    proto_index = {key: i for i, key in enumerate(proto_keys)}

    # method ids: sorted by (class_idx, name_idx, proto_idx)
    method_records: list[tuple[int, int, int, str, int, tuple]] = []
    for cls in classes:
        class_desc = f"L{cls['name']};"
        for name, shorty, ret, params, access in cls.get("methods", []):
            method_records.append((
                tidx(class_desc), string_index[name], proto_index[(shorty, ret, tuple(params))],
                name, access, (shorty, ret, tuple(params)),
            ))
    method_records.sort(key=lambda rec: (rec[0], rec[1], rec[2]))

    # layout offsets
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * len(strings)
    proto_ids_off = type_ids_off + 4 * len(type_descriptors_sorted)
    method_ids_off = proto_ids_off + 12 * len(proto_keys)
    class_defs_off = method_ids_off + 8 * len(method_records)
    data_off = class_defs_off + 32 * len(classes)
    if data_off % 4:
        data_off += 4 - (data_off % 4)

    data = bytearray()
    string_data_offsets: list[int] = []
    for value in strings:
        string_data_offsets.append(data_off + len(data))
        encoded = value.encode("utf-8")
        data += _uleb128(len(value))
        data += encoded + b"\x00"

    type_list_offsets: dict[tuple[str, ...], int] = {}
    for _shorty, _ret, params in proto_keys:
        if not params:
            continue
        if params in type_list_offsets:
            continue
        while (data_off + len(data)) % 4:
            data += b"\x00"
        type_list_offsets[params] = data_off + len(data)
        data += struct.pack("<I", len(params))
        for descriptor in params:
            data += struct.pack("<H", tidx(descriptor))
        if len(params) % 2:
            data += b"\x00\x00"

    class_data_offsets: list[int] = []
    for cls in classes:
        class_desc = f"L{cls['name']};"
        own = [rec for rec in method_records if rec[0] == tidx(class_desc)]
        direct = [rec for rec in own if rec[3] in ("<init>", "<clinit>")]
        virtual = [rec for rec in own if rec not in direct]
        class_data_offsets.append(data_off + len(data))
        data += _uleb128(0) + _uleb128(0) + _uleb128(len(direct)) + _uleb128(len(virtual))
        for group in (direct, virtual):
            previous = 0
            for rec in group:
                absolute = method_records.index(rec)
                data += _uleb128(absolute - previous)
                data += _uleb128(rec[4])
                data += _uleb128(0)
                previous = absolute

    while (data_off + len(data)) % 4:
        data += b"\x00"
    map_off = data_off + len(data)
    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(type_descriptors_sorted), type_ids_off),
        (0x0003, len(proto_keys), proto_ids_off),
        (0x0005, len(method_records), method_ids_off),
        (0x0007, len(classes), class_defs_off),
        (0x2002, len(class_data_offsets), class_data_offsets[0] if class_data_offsets else 0),
        (0x2001, len(strings), string_data_offsets[0] if string_data_offsets else 0),
    ]
    data += struct.pack("<I", len(map_items))
    for type_code, size, offset in map_items:
        data += struct.pack("<HHII", type_code, 0, size, offset)

    file_size = data_off + len(data)
    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)
    struct.pack_into("<I", header, 36, 0x70)
    struct.pack_into("<I", header, 40, 0x12345678)
    struct.pack_into("<I", header, 52, map_off)
    struct.pack_into("<II", header, 56, len(strings), string_ids_off)
    struct.pack_into("<II", header, 64, len(type_descriptors_sorted), type_ids_off)
    struct.pack_into("<II", header, 72, len(proto_keys), proto_ids_off)
    struct.pack_into("<II", header, 80, 0, 0)
    struct.pack_into("<II", header, 88, len(method_records), method_ids_off)
    struct.pack_into("<II", header, 96, len(classes), class_defs_off)
    struct.pack_into("<II", header, 104, len(data), data_off)

    blob = bytearray(header)
    for offset in string_data_offsets:
        blob += struct.pack("<I", offset)
    for descriptor in type_descriptors_sorted:
        blob += struct.pack("<I", string_index[descriptor])
    for shorty, ret, params in proto_keys:
        blob += struct.pack(
            "<III",
            string_index[shorty],
            tidx(ret),
            type_list_offsets.get(params, 0),
        )
    for class_idx, name_idx, proto_idx, _name, _access, _proto in method_records:
        blob += struct.pack("<HHI", class_idx, proto_idx, name_idx)
    for i, cls in enumerate(classes):
        class_desc = f"L{cls['name']};"
        superclass = 0xFFFFFFFF if not cls.get("super") else tidx(f"L{cls['super']};")
        source_idx = string_index.get(cls.get("source", ""), 0xFFFFFFFF)
        blob += struct.pack(
            "<IIIIIIII",
            tidx(class_desc), 0x0001, superclass, 0,
            source_idx, 0, class_data_offsets[i], 0,
        )
    while len(blob) < data_off:
        blob += b"\x00"
    blob += data
    assert len(blob) == file_size, (len(blob), file_size)

    blob[12:32] = hashlib.sha1(bytes(blob[32:])).digest()
    struct.pack_into("<I", blob, 8, zlib.adler32(bytes(blob[12:])) & 0xFFFFFFFF)
    return bytes(blob)


# --------------------------------------------------------------------------- APK

def build_demo_apk() -> bytes:
    """Build a realistic demo APK: manifest + dex + assets + libs + signatures."""
    dex = build_dex()
    html = (
        "<!DOCTYPE html>\n<html>\n<head><title>RevDemo</title></head>\n"
        "<body><script src=\"app.js\"></script></body>\n</html>\n"
    )
    js = (
        "// RevDemo web shell\n"
        "const API_BASE = 'https://api.revstudio.example/v1';\n"
        "const api_key = 'demo-secret-key-12345';\n"
        "async function loadUser(id) {\n"
        "  const response = await fetch(`${API_BASE}/users/${id}`);\n"
        "  return response.json();\n"
        "}\n"
        "function render(data) {\n"
        "  document.querySelector('#app').innerHTML = data.name;\n"
        "}\n"
    )
    config = '{\n  "environment": "demo",\n  "featureFlags": ["beta_ui", "sync"]\n}\n'

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", build_demo_manifest_axml())
        archive.writestr("classes.dex", dex)
        archive.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 60)
        archive.writestr("assets/www/index.html", html)
        archive.writestr("assets/www/app.js", js)
        archive.writestr("assets/config.json", config)
        archive.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 120)
        archive.writestr("lib/armeabi-v7a/libnative.so", b"\x7fELF" + b"\x00" * 100)
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        archive.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
        archive.writestr("META-INF/CERT.RSA", b"\x30\x82" + b"\x00" * 80)
    return buffer.getvalue()
