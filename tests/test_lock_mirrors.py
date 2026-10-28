"""F8 lock-mirror hygiene: firmware must write lock ports only at canonical
addresses ($7F03 / $7F04), never at a $7Fxx mirror (A3–A7 undecoded)."""

import hashlib
import re
import unittest

from sim import ed25519_ref as E, firmware as DIAG, signer_fw as F, solana as SOL
from sim.emu import Machine
from sim.runner import Bench
from sim.signer_harness import Fw

# Canonical I/O window: A3–A7 clear. Any other $7Fxx address is a mirror.
CANONICAL_IO = frozenset(range(0x7F00, 0x7F08))
LOCK_PORTS = frozenset({0x7F03, 0x7F04})  # MESSAGE_LOCK / RESULT_LOCK
# Diagnostic ROM intentionally probes $7F0B in scenario "mirrors" (FINDINGS F8 /
# tests/test_system.py::test_mirrors_and_undriven_ports).
DIAG_ALLOWED_LOCK_MIRRORS = frozenset({0x7F0B})


def _io_addrs_written(m):
    """Decode Machine.io_wr_bits into the set of $7Fxx addresses written."""
    out = set()
    bits = m.m.io_wr_bits
    for lo in range(256):
        if bits[lo >> 3] & (1 << (lo & 7)):
            out.add(0x7F00 | lo)
    return out


_EQU = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$([0-9A-Fa-f]+)\s*$", re.M)
_ABS_STORE_HEX = re.compile(r"\b(STA|STX|STY|STZ)\s+\$([0-9A-Fa-f]{2,4})\b", re.I)
_ABS_STORE_SYM = re.compile(r"\b(STA|STX|STY|STZ)\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.I)


def _abs_stores_to_io(src):
    """Absolute stores into $7F00–$7FFF in assembler source (hex or equate)."""
    equ = {n.upper(): int(h, 16) for n, h in _EQU.findall(src)}
    hits = []
    for i, line in enumerate(src.splitlines(), 1):
        code = line.split(";", 1)[0]
        for op, hexn in _ABS_STORE_HEX.findall(code):
            addr = int(hexn, 16)
            if 0x7F00 <= addr <= 0x7FFF:
                hits.append((i, op.upper(), addr, line.strip()))
        for op, name in _ABS_STORE_SYM.findall(code):
            addr = equ.get(name.upper())
            if addr is not None and 0x7F00 <= addr <= 0x7FFF:
                hits.append((i, op.upper(), addr, line.strip()))
    return hits


class TestLockMirrorHygiene(unittest.TestCase):
    def test_signer_source_uses_only_canonical_io_stores(self):
        src = F.source()
        hits = _abs_stores_to_io(src)
        addrs = {a for _, _, a, _ in hits}
        self.assertTrue(addrs, "expected at least GPIO/lock stores in signer source")
        bad = sorted(a for a in addrs if a not in CANONICAL_IO)
        self.assertEqual(bad, [], f"signer source stores to I/O mirrors: {hits}")
        self.assertIn(0x7F03, addrs)
        self.assertIn(0x7F04, addrs)

    def test_diagnostic_source_documents_intentional_mirror(self):
        _, syms = DIAG.boot_rom()
        hits = _abs_stores_to_io(DIAG.BOOT_SRC)
        lock_mirrors = sorted(
            a for _, _, a, _ in hits
            if (a & 7) in (3, 4) and a not in LOCK_PORTS
        )
        self.assertEqual(set(lock_mirrors), DIAG_ALLOWED_LOCK_MIRRORS)
        mirror_lines = [ln for _, _, a, ln in hits if a == 0x7F0B]
        self.assertEqual(len(mirror_lines), 1)
        self.assertIn("7F0B", mirror_lines[0])
        non_lock = [(op, a, ln) for _, op, a, ln in hits
                    if a not in LOCK_PORTS and a not in DIAG_ALLOWED_LOCK_MIRRORS]
        bad = [(op, a, ln) for op, a, ln in non_lock if a not in CANONICAL_IO]
        self.assertEqual(bad, [])
        self.assertIn("sc_mirrors", syms)

    def test_sign_flow_writes_only_canonical_io_ports(self):
        seed = hashlib.sha256(b"DTS-02 public test fixture seed - never fund").digest()
        pk = E.public_key(seed)
        to = E.public_key(hashlib.sha256(b"recipient").digest())
        bh = hashlib.sha256(b"blockhash").digest()
        msg = SOL.transfer_message(pk, to, 5000, bh)
        fw = Fw()
        fw.put(F.SEED, seed)
        fw.put(F.ENV, F.envelope(msg, pk))
        for i in range(32):
            fw.m.m.io_wr_bits[i] = 0
        fw.call("sign_main")
        written = _io_addrs_written(fw.m)
        self.assertTrue(written)
        bad = sorted(a for a in written if a not in CANONICAL_IO)
        self.assertEqual(
            bad, [], f"sign_main wrote I/O mirrors: {[hex(a) for a in bad]}"
        )
        self.assertIn(0x7F03, written)
        self.assertIn(0x7F04, written)
        self.assertEqual(fw.m.m.msg_lock, 1)
        self.assertEqual(fw.m.m.res_lock, 1)

    def test_negative_mirror_write_sets_lock_in_board_model(self):
        """Synthetic $7F0B write sets MESSAGE_LOCK — alias decode is real (F8)."""
        b = Bench(scenario="mirrors", seed=26)
        b.run_to("done")
        self.assertEqual(b.net("MESSAGE_LOCK"), 1)
        self.assertEqual(b.ram.mem[0x287] & 0xE0, 0x20)

    def test_negative_emu_records_mirror_and_sets_lock(self):
        """If firmware stored to $7F0B, the emulator would record it and lock."""
        rom = bytearray(32768)
        # $8000: LDA #$01; STA $7F0B; STP
        rom[0:6] = bytes([0xA9, 0x01, 0x8D, 0x0B, 0x7F, 0xDB])
        rom[0x7FFC] = 0x00
        rom[0x7FFD] = 0x80
        m = Machine(rom=bytes(rom))
        m.reset()
        self.assertEqual(m.run(max_cycles=50), Machine.STP)
        self.assertEqual(m.m.msg_lock, 1)
        written = _io_addrs_written(m)
        self.assertIn(0x7F0B, written)
        self.assertNotIn(0x7F03, written)


class TestLockMirrorFindingsNote(unittest.TestCase):
    def test_findings_f8_mentions_hygiene_test(self):
        from pathlib import Path
        text = Path("FINDINGS.md").read_text(encoding="utf-8")
        self.assertIn("### F8.", text)
        self.assertIn("test_lock_mirrors.py", text)
        self.assertIn("test_mirrors_and_undriven_ports", text)


if __name__ == "__main__":
    unittest.main()
