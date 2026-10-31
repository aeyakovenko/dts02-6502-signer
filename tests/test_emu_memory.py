"""Host-side emulator image loading must stay inside the 64 KiB memory array."""

import unittest
from unittest.mock import patch

from sim.emu import Machine


class TestMemoryLoading(unittest.TestCase):
    def test_load_boundaries(self):
        m = Machine()
        image = bytes(range(256)) * 256
        m.load(0, image)
        self.assertEqual(m.read(0, 65536), image)
        m.load(0, b"\xA5")
        m.load(65535, bytearray(b"\x5A"))
        self.assertEqual(m.read(0, 1), b"\xA5")
        self.assertEqual(m.read(65535, 1), b"\x5A")
        before = bytes(m.m)
        for addr in (0, 65535, 65536):
            m.load(addr, b"")
        self.assertEqual(bytes(m.m), before)

    def test_load_counts_bytes_in_typed_buffers(self):
        data = memoryview(b"\x11\x22\x33\x44").cast("H")
        m = Machine()
        m.load(65532, data)
        self.assertEqual(m.read(65532, 4), data.tobytes())

    def test_invalid_loads_never_reach_memmove(self):
        typed = memoryview(b"\x11\x22\x33\x44").cast("H")
        for addr, data in ((-1, b"x"), (-1, b""), (65535, b"xy"),
                           (65536, b"x"), (65537, b""), (0, bytes(65537)),
                           (65534, typed)):
            with self.subTest(addr=addr, size=len(bytes(data))):
                m = Machine()
                with patch("sim.emu.ctypes.memmove") as copy:
                    with self.assertRaises(ValueError):
                        m.load(addr, data)
                    copy.assert_not_called()

    def test_crossing_memory_end_preserves_memory_and_registers(self):
        m = Machine()
        m.load(65535, b"\x33")
        m.m.a = 0x5A
        before = bytes(m.m)
        # Without bounds checking, the second byte overwrites register A.
        with self.assertRaises(ValueError):
            m.load(65535, b"\x11\x22")
        self.assertEqual(bytes(m.m), before)

    def test_invalid_image_lengths_never_reach_memmove(self):
        for name, size in (("image64k", 65536), ("rom", 32768)):
            for n in (0, size - 1, size + 1):
                with self.subTest(image=name, size=n):
                    with patch("sim.emu.ctypes.memmove") as copy:
                        with self.assertRaises(ValueError):
                            Machine(**{name: bytes(n)})
                        copy.assert_not_called()

    def test_full_image_and_rom_overlay_accept_byte_buffers(self):
        image = bytes(range(256)) * 256
        rom = bytes(reversed(range(256))) * 128
        m = Machine(image64k=memoryview(image).cast("H"), rom=bytearray(rom))
        self.assertEqual(m.read(0, 65536), image[:32768] + rom)
        self.assertEqual((m.m.a, m.m.x, m.m.y, m.m.switches, m.m.p),
                         (0, 0, 0, 0xFF, 0x34))


if __name__ == "__main__":
    unittest.main()
