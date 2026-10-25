#!/usr/bin/env python3
import sys
from pathlib import Path

TARGET = b"5.15.167-android13-8-o-01144-gb3f32e037fab"

def fix(path):
    pth = Path(path)
    data = bytearray(pth.read_bytes())

    vm = data.find(b"vermagic=")
    if vm < 0:
        raise RuntimeError("vermagic not found")

    value_start = vm + len(b"vermagic=")
    value_end = data.find(b"\0", value_start)
    if value_end < 0:
        raise RuntimeError("vermagic terminator not found")

    old_value = bytes(data[value_start:value_end])
    space = old_value.find(b" ")
    if space < 0:
        raise RuntimeError("vermagic flags not found")
    new_value = TARGET + old_value[space:]

    name_start = value_end + 1
    depends = data.find(b"depends=", name_start)
    if depends < 0:
        raise RuntimeError("depends field not found")
    depends_value = depends + len(b"depends=")
    content_end = data.find(b"\0", depends_value)
    if content_end < 0:
        raise RuntimeError("depends terminator not found")

    tail = bytes(data[name_start:content_end + 1])
    replacement = new_value + b"\0" + tail

    old_region_end = content_end + 1
    zero_end = old_region_end
    while zero_end < len(data) and data[zero_end] == 0:
        zero_end += 1
    capacity = zero_end - value_start
    if len(replacement) > capacity:
        raise RuntimeError(
            f"modinfo padding too small: need {len(replacement)}, have {capacity}"
        )

    for i in range(capacity):
        data[value_start + i] = replacement[i] if i < len(replacement) else 0

    pth.write_bytes(data)

    verify = pth.read_bytes()
    v0 = verify.find(b"vermagic=")
    v1 = verify.find(b"\0", v0)
    n0 = verify.find(b"name=")
    n1 = verify.find(b"\0", n0)
    vermagic = verify[v0:v1].decode("ascii")
    name = verify[n0:n1].decode("ascii")
    if TARGET.decode() not in vermagic:
        raise RuntimeError(f"verification failed: {vermagic}")
    if name != "name=cpuinfo_spoof":
        raise RuntimeError(f"name field damaged: {name}")
    print("vermagic:", vermagic)
    print("name:", name)
    print("size:", len(verify))
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} MODULE.ko", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(fix(sys.argv[1]))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
