"""CPU core validation: Klaus Dormann functional tests on both cores, and
cycle-exact agreement between the Python core and the C emulator."""

import os
import unittest

from sim.cpu65c02 import Core
from sim.emu import Machine
from sim.asm import assemble
from sim.firmware import FONT, SCENARIOS, boot_rom

KLAUS = os.path.join(os.path.dirname(__file__), "..", "third_party", "klaus", "bin_files")
SUITES = {"65C02_extended_opcodes_test.bin": (0x24F1, 66907084),
          "6502_functional_test.bin": (0x3469, 96561324)}


def run_python(img, max_cycles=200_000_000):
    mem = bytearray(img)
    c = Core()
    c.pc = 0x400
    cyc = 0
    while cyc < max_cycles:
        g = c.step()
        req = next(g)
        pc0 = c.fetch_pc
        try:
            while True:
                cyc += 1
                rw, a, d, s = req
                if rw == "R":
                    req = g.send(mem[a])
                else:
                    mem[a] = d
                    req = g.send(None)
        except StopIteration:
            pass
        if c.pc == pc0:
            return pc0, cyc
    return None, cyc


@unittest.skipUnless(os.path.isdir(KLAUS), "run tools/fetch_klaus.sh first")
class TestKlaus(unittest.TestCase):
    def test_c_emulator(self):
        for name, (ok, cycles) in SUITES.items():
            with self.subTest(name):
                m = Machine(image64k=open(os.path.join(KLAUS, name), "rb").read())
                m.m.pc = 0x400
                self.assertEqual(m.run(max_cycles=300_000_000), Machine.TRAP)
                self.assertEqual(m.m.pc, ok)
                self.assertEqual(m.cycles, cycles)

    def test_python_core(self):
        for name, (ok, cycles) in SUITES.items():
            with self.subTest(name):
                pc, cyc = run_python(open(os.path.join(KLAUS, name), "rb").read())
                self.assertEqual(pc, ok)
                self.assertEqual(cyc, cycles)          # same count as the C emulator


class TestCrossCheck(unittest.TestCase):
    def test_signer_prefix_identical_on_both_cores(self):
        """Run the signing ROM for 300k cycles on both cores (ideal bus):
        identical cycle-by-cycle progress and memory."""
        import hashlib
        from sim import ed25519_ref as E, signer_fw as F
        from sim.signer_harness import build
        img, syms, _ = build()
        seed = hashlib.sha256(b"cross-check seed").digest()
        env = F.envelope(b"cross-check message", E.public_key(seed))
        mem = bytearray(65536)
        mem[0x8000:] = img
        mem[F.ENV:F.ENV + len(env)] = env
        mem[F.SEED:F.SEED + 32] = seed
        m = Machine(image64k=mem)
        m.m.s = 0xFD
        m.reset()
        core = Core()
        core.s = 0xFD
        core.pc = img[0x7FFC] | img[0x7FFD] << 8
        cyc = 7
        lock = 0
        while cyc < 300_000:
            g = core.step()
            req = next(g)
            try:
                while True:
                    cyc += 1
                    rw, a, d, s = req
                    if rw == "R":
                        if 0x7F00 <= a < 0x8000:      # I/O: switches $FF, status = locks
                            v = (lock << 5) if (a & 7) == 1 else 0xFF
                        else:
                            v = mem[a]
                        req = g.send(v)
                    else:
                        if a < 0x7F00:
                            mem[a] = d
                        elif a < 0x8000 and (a & 7) == 3:
                            lock = 1
                        req = g.send(None)
            except StopIteration:
                pass
        m.run(max_cycles=cyc - m.cycles)
        self.assertEqual(m.cycles, cyc)
        self.assertEqual(m.m.pc, core.pc)
        self.assertEqual(bytes(m.m.mem[:0x7F00]), bytes(mem[:0x7F00]))
        self.assertEqual(m.m.msg_lock, 1)                 # got past the freeze step


class TestDisplayInterlocks(unittest.TestCase):
    """Section 8 removes display power on FAULT or CPU RESET, without a
    firmware GPIO store. CPU RESET also clears U16, but preserves the locks."""

    @classmethod
    def setUpClass(cls):
        cls.rom, cls.syms = boot_rom()

    def lit_machine(self):
        m = Machine(rom=self.rom)
        m.load(0x3F80, b"DTS02SIM" + bytes([SCENARIOS["font"]]))
        m.reset()
        self.assertEqual(m.run(stop=self.syms["done"], max_cycles=100_000), Machine.STOP)
        self.assertEqual(m.display_masks(), FONT)
        return m

    def execute(self, m, source):
        # Execute real CPU stores; host-side loading only installs the test program.
        img, _ = assemble(source + "\nSTP", org=0x0200, size=256)
        m.load(0x0200, img)
        m.m.pc = 0x0200
        self.assertEqual(m.run(max_cycles=100), Machine.STP)

    def test_fault_blanks_display_without_gpio_write(self):
        for port, addr in ((0x7F03, 0x4000), (0x7F03, 0x5FFF),
                           (0x7F04, 0x6000), (0x7F04, 0x7EFF)):
            with self.subTest(port=hex(port), addr=hex(addr)):
                m = self.lit_machine()
                m.load(addr, b"\x5A")
                gpio, writes = m.m.gpio, m.m.gpio_writes
                self.execute(m, f"LDA #1\nSTA ${port:04X}\nLDA #$A5\nSTA ${addr:04X}")
                self.assertEqual((m.m.fault, m.m.blocked_writes), (1, 1))
                self.assertEqual(m.read(addr, 1), b"\x5A")
                self.assertEqual((m.m.gpio, m.m.gpio_writes), (gpio, writes))
                self.assertEqual(m.display_masks(), [0] * 16)
                # I/O remains writable, but cannot restore power while FAULT is set.
                self.execute(m, "LDA #$DC\nSTA $7F02")
                self.assertEqual(m.display_masks(), [0] * 16)

    def test_cpu_reset_blanks_display_and_preserves_locks(self):
        for msg_lock, res_lock, fault in ((0, 0, 0), (1, 0, 0), (0, 1, 0), (1, 1, 1)):
            with self.subTest(msg_lock=msg_lock, res_lock=res_lock, fault=fault):
                m = self.lit_machine()
                source = "LDA #1\n"
                if msg_lock:
                    source += "STA $7F03\n"
                if res_lock:
                    source += "STA $7F04\n"
                if fault:
                    source += "STA $4000\n"
                self.execute(m, source)
                before = m.read(0, 0x8000)
                cycles, instructions, writes = m.cycles, m.m.instructions, m.m.gpio_writes
                m.reset()
                self.assertEqual(m.display_masks(), [0] * 16)
                self.assertEqual((m.m.gpio, m.m.prev_gpio), (0, 0))
                self.assertEqual((m.m.msg_lock, m.m.res_lock, m.m.fault),
                                 (msg_lock, res_lock, fault))
                self.assertEqual(m.read(0, 0x8000), before)
                self.assertEqual((m.cycles, m.m.instructions, m.m.gpio_writes),
                                 (cycles + 7, instructions, writes))


if __name__ == "__main__":
    unittest.main()
