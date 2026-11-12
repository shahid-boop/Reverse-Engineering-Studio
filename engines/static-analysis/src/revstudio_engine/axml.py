from __future__ import annotations

import struct

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
CHUNK_START_NAMESPACE = 0x0100
CHUNK_END_NAMESPACE = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103
CHUNK_CDATA = 0x0104
UTF8_FLAG = 0x100

RADIX_FRACTION_BITS = (0, 7, 15, 23)
DIMENSION_UNITS = ("px", "dp", "sp", "pt", "in", "mm", "", "")
FRACTION_UNITS = ("%", "%p", "", "", "", "", "", "")


class AxmlError(ValueError):
    """Raised when a binary Android XML document cannot be decoded."""


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _read_len8(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first & 0x80:
        return ((first & 0x7F) << 8) | buf[pos + 1], pos + 2
    return first, pos + 1


def _parse_string_pool(buf: bytes, off: int) -> list[str]:
    header_size = _u16(buf, off + 2)
    string_count = _u32(buf, off + 8)
    flags = _u32(buf, off + 16)
    strings_start = _u32(buf, off + 20)
    utf8 = bool(flags & UTF8_FLAG)
    strings: list[str] = []
    base = off + strings_start
    for i in range(string_count):
        str_off = _u32(buf, off + header_size + i * 4)
        pos = base + str_off
        if utf8:
            _, pos = _read_len8(buf, pos)
            byte_len, pos = _read_len8(buf, pos)
            strings.append(buf[pos:pos + byte_len].decode("utf-8", errors="replace"))
        else:
            char_len = _u16(buf, pos)
            pos += 2
            if char_len & 0x8000:
                char_len = ((char_len & 0x7FFF) << 16) | _u16(buf, pos)
                pos += 2
            strings.append(buf[pos:pos + char_len * 2].decode("utf-16-le", errors="replace"))
    return strings


def _signed32(value: int) -> int:
    return value - 0x100000000 if value >= 0x80000000 else value


def _complex_float(data: int) -> float:
    mantissa = _signed32(data & 0xFFFFFF00) >> 8
    radix = (data >> 4) & 0x0F
    fraction_bits = RADIX_FRACTION_BITS[radix] if radix < 4 else 0
    return mantissa / (1 << fraction_bits)


def _format_value(data_type: int, data: int, strings: list[str]) -> str:
    if data_type == 0x03:
        return strings[data] if 0 <= data < len(strings) else ""
    if data_type == 0x01:
        return f"@0x{data:08x}"
    if data_type == 0x02:
        return f"?0x{data:08x}"
    if data_type == 0x10:
        return str(_signed32(data))
    if data_type == 0x11:
        return f"0x{data:08x}"
    if data_type == 0x12:
        return "true" if data else "false"
    if data_type == 0x05:
        return struct.unpack("<f", struct.pack("<I", data))[0].__format__("g")
    if data_type == 0x04:
        unit = DIMENSION_UNITS[data & 0x0F]
        return f"{_complex_float(data):g}{unit}"
    if data_type == 0x06:
        unit = FRACTION_UNITS[data & 0x0F]
        return f"{_complex_float(data):g}{unit}"
    if data_type in (0x1C, 0x1D, 0x1E, 0x1F):
        width = 8 if data_type in (0x1C, 0x1D) else 4
        return f"#{data:0{width}x}"
    return f"0x{data:x}"


def _escape(text: str, attribute: bool = False) -> str:
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if attribute:
        text = text.replace('"', "&quot;")
    return text


def parse_axml(data: bytes) -> dict:
    """Decode a binary Android XML document into pretty XML plus components."""
    if not isinstance(data, bytes) or len(data) < 8:
        raise AxmlError("Buffer too small for an AXML document.")

    file_type, header_size, file_size = struct.unpack_from("<HHI", data, 0)
    if file_type != RES_XML_TYPE:
        raise AxmlError(f"Not an AXML document (chunk type 0x{file_type:04x}).")

    strings: list[str] = []
    events: list[dict] = []
    pending_ns: list[tuple[str, str]] = []
    uri_to_prefix: dict[str, str] = {}
    pos = header_size
    end = min(file_size, len(data))

    while pos + 8 <= end:
        chunk_type, _chunk_header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
        if chunk_size < 8 or pos + chunk_size > end:
            raise AxmlError(f"Corrupt chunk at offset {pos}.")

        if chunk_type == RES_STRING_POOL_TYPE:
            strings = _parse_string_pool(data, pos)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            pass
        elif chunk_type in (CHUNK_START_NAMESPACE, CHUNK_END_NAMESPACE):
            line = _u32(data, pos + 8)
            prefix = strings[_u32(data, pos + 16)] if _u32(data, pos + 16) < len(strings) else ""
            uri = strings[_u32(data, pos + 20)] if _u32(data, pos + 20) < len(strings) else ""
            if chunk_type == CHUNK_START_NAMESPACE:
                pending_ns.append((prefix, uri))
                uri_to_prefix[uri] = prefix
            events.append({
                "kind": "ns", "start": chunk_type == CHUNK_START_NAMESPACE,
                "prefix": prefix, "uri": uri, "line": line,
            })
        elif chunk_type == CHUNK_START_ELEMENT:
            line = _u32(data, pos + 8)
            name_idx = _u32(data, pos + 20)
            attr_start = _u16(data, pos + 24)
            attr_count = _u16(data, pos + 28)
            tag = strings[name_idx] if name_idx < len(strings) else "?"
            attrs: dict[str, str] = {}
            attr_pos = pos + 16 + attr_start
            for _ in range(attr_count):
                ns_idx = _u32(data, attr_pos)
                attr_name_idx = _u32(data, attr_pos + 4)
                raw_idx = _u32(data, attr_pos + 8)
                data_type = data[attr_pos + 15]
                value = _u32(data, attr_pos + 16)
                attr_name = strings[attr_name_idx] if attr_name_idx < len(strings) else "?"
                prefix = ""
                if ns_idx < len(strings):
                    prefix = uri_to_prefix.get(strings[ns_idx], "")
                key = f"{prefix}:{attr_name}" if prefix else attr_name
                if raw_idx < len(strings):
                    attrs[key] = strings[raw_idx]
                else:
                    attrs[key] = _format_value(data_type, value, strings)
                attr_pos += 20
            events.append({
                "kind": "start", "tag": tag, "attrs": attrs, "line": line,
                "xmlns": pending_ns,
            })
            pending_ns = []
        elif chunk_type == CHUNK_END_ELEMENT:
            line = _u32(data, pos + 8)
            name_idx = _u32(data, pos + 20)
            tag = strings[name_idx] if name_idx < len(strings) else "?"
            events.append({"kind": "end", "tag": tag, "line": line})
        elif chunk_type == CHUNK_CDATA:
            line = _u32(data, pos + 8)
            text_idx = _u32(data, pos + 16)
            text = strings[text_idx] if text_idx < len(strings) else ""
            if text:
                events.append({"kind": "text", "text": text, "line": line})
        pos += chunk_size

    return {
        "xml": events_to_xml(events),
        "components": extract_components(events),
        "string_count": len(strings),
        "event_count": len(events),
    }


def events_to_xml(events: list[dict]) -> str:
    lines = ['<?xml version="1.0" encoding="utf-8"?>']
    depth = 0
    buffered: list[str] | None = None

    def render(parts: list[str]) -> str:
        return "<" + " ".join(parts) + ">"

    for event in events:
        kind = event["kind"]
        if kind == "ns":
            continue
        if kind == "start":
            if buffered is not None:
                lines.append("  " * depth + render(buffered))
                depth += 1
            parts = [event["tag"]]
            for prefix, uri in event.get("xmlns", []):
                attr = f"xmlns:{prefix}" if prefix else "xmlns"
                parts.append(f'{attr}="{_escape(uri, attribute=True)}"')
            for key, value in event["attrs"].items():
                parts.append(f'{key}="{_escape(value, attribute=True)}"')
            buffered = parts
        elif kind == "end":
            if buffered is not None:
                lines.append("  " * depth + render(buffered) + f"</{event['tag']}>")
                buffered = None
            else:
                depth = max(0, depth - 1)
                lines.append("  " * depth + f"</{event['tag']}>")
        elif kind == "text":
            if buffered is not None:
                lines.append("  " * depth + render(buffered))
                depth += 1
                buffered = None
            lines.append("  " * depth + _escape(event["text"]))
    if buffered is not None:
        lines.append("  " * depth + render(buffered))
    return "\n".join(lines)


def _attr(attrs: dict[str, str], name: str, default=None):
    if name in attrs:
        return attrs[name]
    suffix = ":" + name
    for key, value in attrs.items():
        if key.endswith(suffix):
            return value
    return default


def _append_unique(target: list, value) -> None:
    if value and value not in target:
        target.append(value)


def extract_components(events: list[dict]) -> dict:
    comps: dict = {
        "package": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "compile_sdk": None,
        "application_label": None,
        "application_icon": None,
        "permissions": [],
        "features": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "instrumentations": [],
        "launchable_activity": None,
    }
    activity_ctx: dict | None = None

    for event in events:
        if event["kind"] == "end":
            if event["tag"] in ("activity", "activity-alias") and activity_ctx is not None:
                if activity_ctx.get("main") and activity_ctx.get("launcher"):
                    comps["launchable_activity"] = activity_ctx.get("name")
                activity_ctx = None
            continue
        if event["kind"] != "start":
            continue

        tag = event["tag"]
        attrs = event["attrs"]

        if tag == "manifest":
            comps["package"] = _attr(attrs, "package", comps["package"])
            comps["version_name"] = _attr(attrs, "versionName", comps["version_name"])
            comps["version_code"] = _attr(attrs, "versionCode", comps["version_code"])
        elif tag == "uses-sdk":
            comps["min_sdk"] = _attr(attrs, "minSdkVersion", comps["min_sdk"])
            comps["target_sdk"] = _attr(attrs, "targetSdkVersion", comps["target_sdk"])
            comps["compile_sdk"] = _attr(attrs, "compileSdkVersion", comps["compile_sdk"])
        elif tag in ("uses-permission", "uses-permission-sdk-23"):
            _append_unique(comps["permissions"], _attr(attrs, "name"))
        elif tag == "uses-feature":
            name = _attr(attrs, "name")
            if name:
                _append_unique(comps["features"], name)
        elif tag == "application":
            comps["application_label"] = _attr(attrs, "label", comps["application_label"])
            comps["application_icon"] = _attr(attrs, "icon", comps["application_icon"])
        elif tag in ("activity", "activity-alias"):
            name = _attr(attrs, "name")
            _append_unique(comps["activities"], name)
            activity_ctx = {"name": name, "main": False, "launcher": False}
        elif tag == "service":
            _append_unique(comps["services"], _attr(attrs, "name"))
        elif tag == "receiver":
            _append_unique(comps["receivers"], _attr(attrs, "name"))
        elif tag == "provider":
            _append_unique(comps["providers"], _attr(attrs, "name"))
        elif tag == "instrumentation":
            _append_unique(comps["instrumentations"], _attr(attrs, "name"))
        elif tag == "action" and activity_ctx is not None:
            if (_attr(attrs, "name") or "").endswith("intent.action.MAIN"):
                activity_ctx["main"] = True
        elif tag == "category" and activity_ctx is not None:
            if (_attr(attrs, "name") or "").endswith("intent.category.LAUNCHER"):
                activity_ctx["launcher"] = True

    return comps
