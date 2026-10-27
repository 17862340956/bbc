#!/usr/bin/env python3
"""Post-build identity and DWARF callback ABI verification. Never loads a module."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from fix_vermagic import TARGET, REVISION, entries, field


def verify(path, require_dwarf=True):
    path = Path(path)
    data = path.read_bytes()
    values = entries(data)
    vm = field(values, b"vermagic")
    if vm.partition(b" ")[0] != TARGET:
        raise ValueError("vermagic release mismatch")
    if field(values, b"name") != b"cpuinfo_spoof":
        raise ValueError("wrong module name")
    if field(values, b"version") != REVISION:
        raise ValueError("old or unexpected revision; do not load")
    report = {"file": path.name, "revision": REVISION.decode(),
              "vermagic": vm.decode(), "size": len(data),
              "sha256": hashlib.sha256(data).hexdigest(), "callbacks": {}}
    # Fixture-only identity checks must not depend on installed optional packages.
    # The CLI always uses require_dwarf=True for actual module validation.
    if not require_dwarf:
        report["dwarf"] = "not_checked"
        return report
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("pyelftools is required for callback ABI verification") from exc
    expected = {"fake_available": ["cpufreq_policy *", "char *"],
                "fake_boost": ["cpufreq_policy *", "char *"],
                "fake_cpu_mask": ["device *", "device_attribute *", "char *"],
                "fake_topology": ["device *", "device_attribute *", "char *"]}
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if not elf.has_dwarf_info():
            raise ValueError("DWARF missing: upload unstripped .ko")
        dwarf = elf.get_dwarf_info()
        def describe(die):
            if die is None:
                return "void"
            name = die.attributes.get("DW_AT_name")
            if die.tag == "DW_TAG_pointer_type":
                target = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
                return describe(target) + " *"
            if die.tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
                return describe(die.get_DIE_from_attribute("DW_AT_type"))
            return name.value.decode() if name else die.tag
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                name = die.attributes.get("DW_AT_name")
                if die.tag != "DW_TAG_subprogram" or name is None:
                    continue
                name = name.value.decode(errors="replace")
                if name not in expected:
                    continue
                args = [describe(child.get_DIE_from_attribute("DW_AT_type"))
                        for child in die.iter_children() if child.tag == "DW_TAG_formal_parameter"]
                if not args:
                    continue
                if args != expected[name]:
                    raise ValueError(f"callback ABI mismatch: {name}: {args}")
                report["callbacks"][name] = args
        missing = set(expected) - set(report["callbacks"])
        if missing:
            raise ValueError("callback DWARF missing: " + ", ".join(sorted(missing)))
    report["dwarf"] = "passed"
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("module")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        result = verify(args.module)
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(text)
    except Exception as exc:
        sys.exit("verification failed: " + str(exc))
