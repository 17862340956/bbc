import struct
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import builtins
import importlib.util

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fix_vermagic import TARGET, REVISION, SIGNATURE, entries, field, patched, section
from verify_module import verify


def sample(values=None, capacity=384, machine=183):
    values = values or [b"name=cpuinfo_spoof", b"depends=", b"version=" + REVISION,
                        b"vermagic=5.15.202-test SMP preempt mod_unload modversions aarch64"]
    strings = b"\0.shstrtab\0.modinfo\0.text\0"
    modinfo = b"\0".join(values) + b"\0"
    if len(modinfo) > capacity:
        raise ValueError("fixture overflow")
    data = bytearray(64 + len(strings) + capacity + 8)
    data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    strings_at = 64
    info_at = strings_at + len(strings)
    text_at = info_at + capacity
    data[strings_at:info_at] = strings
    data[info_at:info_at + len(modinfo)] = modinfo
    data[text_at:text_at + 8] = b"TEXTMARK"
    headers_at = len(data)
    struct.pack_into("<HHI", data, 16, 1, machine, 1)
    struct.pack_into("<Q", data, 40, headers_at)
    struct.pack_into("<HHHHHH", data, 52, 64, 0, 0, 64, 4, 1)
    data.extend(b"\0" * (4 * 64))
    for idx, name, start, size, kind in [(1, 1, strings_at, len(strings), 3),
                                        (2, 11, info_at, capacity, 1),
                                        (3, 20, text_at, 8, 1)]:
        struct.pack_into("<IIQQQQIIQQ", data, headers_at + idx * 64,
                         name, kind, 0, 0, start, size, 0, 0, 1, 0)
    return bytes(data)


class BuildToolsTests(unittest.TestCase):
    def test_section_limited_and_idempotent(self):
        before = sample()
        after = patched(before)
        start, size = section(before, b".modinfo")
        self.assertEqual(before[:start], after[:start])
        self.assertEqual(before[start + size:], after[start + size:])
        self.assertEqual(len(before), len(after))
        self.assertEqual(after, patched(after))
        self.assertEqual(field(entries(after), b"name"), b"cpuinfo_spoof")
        self.assertTrue(field(entries(after), b"vermagic").startswith(TARGET + b" "))

    def test_unordered_fields_and_reserve(self):
        values = [b"qilin_modinfo_reserve=" + b"." * 96, b"depends=abc",
                  b"vermagic=x SMP preempt", b"name=cpuinfo_spoof", b"version=" + REVISION]
        after = entries(patched(sample(values)))
        self.assertEqual(field(after, b"depends"), b"abc")
        self.assertFalse(any(x.startswith(b"qilin_modinfo_reserve=") for x in after))

    def test_overflow_refused(self):
        with self.assertRaises(ValueError):
            patched(sample([b"name=cpuinfo_spoof", b"vermagic=x SMP"], capacity=40))

    def test_signed_module_refused(self):
        with self.assertRaises(ValueError):
            patched(sample() + SIGNATURE)

    def test_duplicate_vermagic_refused(self):
        with self.assertRaises(ValueError):
            patched(sample([b"name=cpuinfo_spoof", b"vermagic=x SMP", b"vermagic=y SMP"]))

    def test_unterminated_modinfo_refused(self):
        data = bytearray(sample())
        start, size = section(data, b".modinfo")
        data[start + size - 1] = ord('x')
        with self.assertRaisesRegex(ValueError, "unterminated"):
            patched(bytes(data))

    def test_architecture_refused(self):
        with self.assertRaises(ValueError):
            patched(sample(machine=62))

    def test_old_revision_refused(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample([b"name=cpuinfo_spoof", b"version=old", b"vermagic=x SMP"])))
            with self.assertRaisesRegex(ValueError, "revision"):
                verify(path, require_dwarf=False)

    def test_identity_fixture(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            report = verify(path, require_dwarf=False)
            self.assertEqual(report["revision"], REVISION.decode())
            self.assertEqual(report["dwarf"], "not_checked")

    def test_identity_never_imports_elftools(self):
        original_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name == "elftools" or name.startswith("elftools."):
                raise AssertionError("identity-only verification must not import pyelftools")
            return original_import(name, *args, **kwargs)
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            with patch("builtins.__import__", side_effect=guarded):
                self.assertEqual(verify(path, require_dwarf=False)["dwarf"], "not_checked")

    def test_strict_requires_elftools(self):
        original_import = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name == "elftools" or name.startswith("elftools."):
                raise ImportError("simulated missing pyelftools")
            return original_import(name, *args, **kwargs)
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            with patch("builtins.__import__", side_effect=unavailable):
                with self.assertRaisesRegex(RuntimeError, "pyelftools is required"):
                    verify(path)

    @unittest.skipUnless(importlib.util.find_spec("elftools"), "pyelftools not installed")
    def test_strict_rejects_fixture_without_dwarf(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "fixture.ko"
            path.write_bytes(patched(sample()))
            with self.assertRaisesRegex(ValueError, "DWARF missing"):
                verify(path)


if __name__ == "__main__":
    unittest.main()
