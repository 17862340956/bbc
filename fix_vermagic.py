#!/usr/bin/env python3
"""Edit only the ELF .modinfo section; refuse overflow and signed modules."""
import hashlib
import struct
import sys
from pathlib import Path

TARGET = b"5.15.167-android13-8-o-01144-gb3f32e037fab"
REVISION = b"qilin-r3-20261027"
SIGNATURE = b"~Module signature appended~\n"


def section(data, wanted):
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected little-endian ELF64")
    if struct.unpack_from("<HH", data, 16) != (1, 183):
        raise ValueError("expected ET_REL / AArch64 module")
    offset = struct.unpack_from("<Q", data, 40)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", data, 58)
    if entry_size != 64 or not count or names_index >= count:
        raise ValueError("unsupported section headers")
    if offset + count * entry_size > len(data):
        raise ValueError("truncated section headers")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + i * entry_size)
               for i in range(count)]
    strings = headers[names_index]
    if strings[4] + strings[5] > len(data):
        raise ValueError("truncated section-name table")
    names = data[strings[4]:strings[4] + strings[5]]
    matches = []
    for header in headers:
        name_offset = header[0]
        end = names.find(b"\0", name_offset)
        if name_offset >= len(names) or end < 0:
            raise ValueError("bad section name")
        if names[name_offset:end] == wanted:
            start, size = header[4:6]
            if start + size > len(data):
                raise ValueError("truncated section")
            matches.append((start, size))
    if len(matches) != 1:
        raise ValueError("expected exactly one " + wanted.decode() + " section")
    return matches[0]


def entries(data):
    start, size = section(data, b".modinfo")
    block = data[start:start + size]
    if block and block[-1] != 0:
        raise ValueError("unterminated .modinfo")
    return [x for x in block.split(b"\0") if x]


def field(values, name):
    prefix = name + b"="
    matches = [x[len(prefix):] for x in values if x.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError("expected one field: " + name.decode())
    return matches[0]


def patched(data):
    if data.endswith(SIGNATURE):
        raise ValueError("signed module: changing bytes would invalidate signature")
    start, size = section(data, b".modinfo")
    before = entries(data)
    old = field(before, b"vermagic")
    if field(before, b"name") != b"cpuinfo_spoof":
        raise ValueError("unexpected module name")
    release, separator, flags = old.partition(b" ")
    if not separator or not release or not flags:
        raise ValueError("invalid vermagic")
    after = []
    for item in before:
        if item.startswith(b"vermagic="):
            after.append(b"vermagic=" + TARGET + b" " + flags)
        elif not item.startswith(b"qilin_modinfo_reserve="):
            after.append(item)
    block = b"\0".join(after) + b"\0"
    if len(block) > size:
        raise ValueError(f".modinfo capacity exceeded: {len(block)} > {size}")
    result = data[:start] + block.ljust(size, b"\0") + data[start + size:]
    assert len(result) == len(data)
    assert entries(result) == after
    assert result[:start] == data[:start] and result[start + size:] == data[start + size:]
    return result


def fix(path):
    path = Path(path)
    original = path.read_bytes()
    result = patched(original)  # validate completely before overwriting
    path.write_bytes(result)
    values = entries(result)
    print("vermagic:", field(values, b"vermagic").decode())
    print("name:", field(values, b"name").decode())
    print("sha256:", hashlib.sha256(result).hexdigest())
    print("size:", len(result))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fix_vermagic.py MODULE.ko")
    try:
        sys.exit(fix(sys.argv[1]))
    except Exception as exc:
        sys.exit("error: " + str(exc))
