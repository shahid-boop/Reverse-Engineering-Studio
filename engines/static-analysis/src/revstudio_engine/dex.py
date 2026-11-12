from __future__ import annotations

import struct

MAX_CLASSES = 3000
MAX_METHODS_PER_CLASS = 300
MAX_STRING_SAMPLE = 400

DESCRIPTOR_PRIMS = {
    "V": "void", "Z": "boolean", "B": "byte", "S": "short",
    "C": "char", "I": "int", "J": "long", "F": "float", "D": "double",
}

ACC_FLAGS = (
    (0x0001, "public"), (0x0002, "private"), (0x0004, "protected"),
    (0x0008, "static"), (0x0010, "final"), (0x0020, "synchronized"),
    (0x0040, "volatile/bridge"), (0x0080, "transient/varargs"),
    (0x0100, "native"), (0x0200, "interface"), (0x0400, "abstract"),
    (0x0800, "strictfp"), (0x1000, "synthetic"), (0x2000, "annotation"),
    (0x4000, "enum"), (0x8000, "constructor"), (0x10000, "declared-synchronized"),
)


class DexError(ValueError):
    """Raised when a DEX document cannot be parsed."""


def access_flags_text(flags: int) -> str:
    return " ".join(name for bit, name in ACC_FLAGS if flags & bit)


def java_name(descriptor: str | None) -> str | None:
    if not descriptor:
        return None
    arrays = 0
    while descriptor.startswith("["):
        arrays += 1
        descriptor = descriptor[1:]
    if descriptor.startswith("L") and descriptor.endswith(";"):
        base = descriptor[1:-1].replace("/", ".")
    else:
        base = DESCRIPTOR_PRIMS.get(descriptor, descriptor)
    return base + "[]" * arrays


def _uleb128(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise DexError("Truncated ULEB128.")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 35:
            raise DexError("Malformed ULEB128.")


def parse_dex(data: bytes, name: str = "classes.dex") -> dict:
    if not isinstance(data, bytes) or len(data) < 0x70 or not data.startswith(b"dex\n"):
        raise DexError(f"{name}: not a DEX file (bad magic).")

    fields = struct.unpack_from("<8sI20s" + "I" * 20, data, 0)
    magic = fields[0]
    file_size = fields[3]
    header_size = fields[4]
    (string_ids_size, string_ids_off,
     type_ids_size, type_ids_off,
     proto_ids_size, proto_ids_off,
     field_ids_size, field_ids_off,
     method_ids_size, method_ids_off,
     class_defs_size, class_defs_off) = fields[9:21]

    if header_size != 0x70:
        raise DexError(f"{name}: unexpected header size {header_size}.")
    if file_size > len(data):
        raise DexError(f"{name}: header file size exceeds actual data.")

    version = magic[4:7].decode("ascii", errors="replace")

    def string_at(idx: int) -> str | None:
        if not 0 <= idx < string_ids_size:
            return None
        offset = struct.unpack_from("<I", data, string_ids_off + idx * 4)[0]
        _utf16_len, pos = _uleb128(data, offset)
        end = data.find(b"\x00", pos)
        if end < 0:
            end = len(data)
        return data[pos:end].decode("utf-8", errors="replace")

    types: list[str] = []
    for i in range(type_ids_size):
        idx = struct.unpack_from("<I", data, type_ids_off + i * 4)[0]
        types.append(string_at(idx) or "?")

    protos: list[tuple[int, int, int]] = []
    for i in range(proto_ids_size):
        protos.append(struct.unpack_from("<III", data, proto_ids_off + i * 12))

    method_ids: list[tuple[int, int, int]] = []
    for i in range(method_ids_size):
        method_ids.append(struct.unpack_from("<HHI", data, method_ids_off + i * 8))

    def proto_text(proto_idx: int) -> str:
        if not 0 <= proto_idx < len(protos):
            return "(?)"
        _shorty_idx, return_idx, params_off = protos[proto_idx]
        params: list[str] = []
        if params_off:
            count = struct.unpack_from("<I", data, params_off)[0]
            for k in range(min(count, 64)):
                type_idx = struct.unpack_from("<H", data, params_off + 4 + k * 2)[0]
                params.append(java_name(types[type_idx]) if type_idx < len(types) else "?")
        returns = java_name(types[return_idx]) if return_idx < len(types) else "void"
        return f"({', '.join(params)}) {returns}"

    def methods_for(class_data_off: int) -> list[dict]:
        if not class_data_off:
            return []
        pos = class_data_off
        static_fields_size, pos = _uleb128(data, pos)
        instance_fields_size, pos = _uleb128(data, pos)
        direct_methods_size, pos = _uleb128(data, pos)
        virtual_methods_size, pos = _uleb128(data, pos)
        for _ in range(static_fields_size + instance_fields_size):
            _diff, pos = _uleb128(data, pos)
            _acc, pos = _uleb128(data, pos)
        results: list[dict] = []
        for kind, count in (("direct", direct_methods_size), ("virtual", virtual_methods_size)):
            method_idx = 0
            for _ in range(count):
                diff, pos = _uleb128(data, pos)
                access, pos = _uleb128(data, pos)
                code_off, pos = _uleb128(data, pos)
                method_idx += diff
                if 0 <= method_idx < len(method_ids):
                    owner_idx, proto_idx, name_idx = method_ids[method_idx]
                    del owner_idx
                    results.append({
                        "name": string_at(name_idx) or "?",
                        "proto": proto_text(proto_idx),
                        "access": access_flags_text(access),
                        "kind": kind,
                        "has_code": bool(code_off),
                    })
                if len(results) >= MAX_METHODS_PER_CLASS:
                    break
            if len(results) >= MAX_METHODS_PER_CLASS:
                break
        return results

    classes: list[dict] = []
    classes_truncated = False
    for i in range(class_defs_size):
        if len(classes) >= MAX_CLASSES:
            classes_truncated = True
            break
        (class_idx, access, superclass_idx, _interfaces_off,
         source_idx, _annotations_off, class_data_off,
         _static_values_off) = struct.unpack_from("<IIIIIIII", data, class_defs_off + i * 32)
        descriptor = types[class_idx] if class_idx < len(types) else "?"
        superclass = None
        if superclass_idx != 0xFFFFFFFF and superclass_idx < len(types):
            superclass = java_name(types[superclass_idx])
        classes.append({
            "name": java_name(descriptor) or descriptor,
            "descriptor": descriptor,
            "superclass": superclass,
            "source": string_at(source_idx),
            "access": access_flags_text(access),
            "methods": methods_for(class_data_off),
        })

    string_sample: list[str] = []
    for i in range(min(string_ids_size, 4000)):
        if len(string_sample) >= MAX_STRING_SAMPLE:
            break
        value = string_at(i)
        if value and len(value) >= 4:
            string_sample.append(value[:300])

    return {
        "name": name,
        "size_bytes": len(data),
        "dex_version": version,
        "counts": {
            "strings": string_ids_size,
            "types": type_ids_size,
            "protos": proto_ids_size,
            "fields": field_ids_size,
            "methods": method_ids_size,
            "classes": class_defs_size,
        },
        "classes": classes,
        "classes_truncated": classes_truncated,
        "string_sample": string_sample,
    }
