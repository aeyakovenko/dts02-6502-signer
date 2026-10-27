"""Document-level checks: hashes, crypto vector, ERC, placement, BOM, analog math."""

import re
import unittest

from sim import analog, checks, ed25519_ref, specdoc
from sim.asm import assemble
from sim.runner import Bench


class TestDocument(unittest.TestCase):
    def test_diagnostic_rom_hash_reproduces(self):
        rom = specdoc.diagnostic_rom()
        self.assertEqual(len(rom), 32768)
        self.assertEqual(specdoc.sha256(rom), specdoc.expected_diagnostic_hash())

    def test_diagnostic_rom_disassembly(self):
        rom = specdoc.diagnostic_rom()
        src = """
            .org $8000
            SEI
            CLD
            LDX #$FF
            TXS
            LDA #0
            STA $7F02
        loop: LDA $7F00
            STA $0200
            LDA $0200
            JMP loop
        trap: JMP trap
            .org $FFFA
            .word trap, $8000, trap
        """
        img, syms = assemble(src)
        self.assertEqual(syms["loop"], 0x800A)
        self.assertEqual(syms["trap"], 0x8016)
        self.assertEqual(img[:25], rom[:25])
        self.assertEqual(img[0x7FFA:], rom[0x7FFA:])

    def test_rfc8032_vector(self):
        t = specdoc.spec_text()
        sec = t[t.index("### 10.6"):t.index("## 11.")]
        v = {k: bytes.fromhex(h) for k, h in re.findall(r"^(seed|A|R|S)\s*=\s*([0-9a-f]+)", sec, re.M)}
        for k in "seed A R S".split():
            self.assertEqual(len(v[k]), 32, k)
        self.assertEqual(ed25519_ref.public_key(v["seed"]), v["A"])
        sig = ed25519_ref.sign(v["seed"], b"")
        self.assertEqual(sig, v["R"] + v["S"])
        self.assertTrue(ed25519_ref.verify(v["A"], b"", sig))
        self.assertFalse(ed25519_ref.verify(v["A"], b"", v["R"] + b"\x5f" + v["S"]))
        self.assertFalse(ed25519_ref.verify(v["A"], b"x", sig))

    def test_rfc8032_test2(self):
        seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pk = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        self.assertEqual(ed25519_ref.public_key(seed), pk)
        self.assertEqual(ed25519_ref.sign(seed, b"\x72"), sig)

    def test_placement_table(self):
        rows, problems = checks.placement()
        self.assertEqual(len(rows), 43)
        self.assertEqual(problems, [])


class TestAssemblerExpressions(unittest.TestCase):
    def byte(self, expr):
        return assemble(".byte " + expr, org=0, size=1)[0][0]

    def test_multiplication_binds_tighter(self):
        self.assertEqual(self.byte("2+3*4"), 14)
        self.assertEqual(self.byte("10-2*3"), 4)
        self.assertEqual(self.byte("3*4-2*5"), 2)

    def test_subtraction_left_to_right(self):
        self.assertEqual(self.byte("$10-$08-$02"), 6)

    def test_operator_character_literals(self):
        self.assertEqual(self.byte("'+'"), ord("+"))
        self.assertEqual(self.byte("'*'+1"), ord("*") + 1)


class TestNetlist(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bench = Bench(scenario="idle")

    def test_erc_clean(self):
        errors, notes = checks.erc(self.bench.sim)
        self.assertEqual(errors, [])
        self.assertEqual(notes, [])

    def test_bom_counts_match_netlist(self):
        for item, spec_qty, net_qty in checks.bom(self.bench.sim):
            self.assertEqual(spec_qty, net_qty, item)


class TestAnalog(unittest.TestCase):
    def test_pullup_numbers_in_spec(self):
        p = analog.pullup(4.7e3, 60)
        self.assertAlmostEqual(p["tau_ns"], 282, delta=1)
        self.assertAlmostEqual(p["rise_10_90_ns"], 620, delta=5)
        self.assertAlmostEqual(p["slew_ns_per_v_at_2v"], 94, delta=1)
        self.assertLess(p["t_to_4v_ns"], 460)
        c = analog.pullup(10e3, 45)
        self.assertAlmostEqual(c["rise_10_90_ns"], 990, delta=5)
        self.assertAlmostEqual(c["slew_ns_per_v_at_2v"], 150, delta=1)
        self.assertAlmostEqual((5.25 - 0.4) / 4.7e3 * 1e3, 1.03, delta=0.01)

    def test_rev02_pullup_violated_hct_slew_limit(self):
        self.assertGreater(analog.pullup(47e3, 60)["slew_ns_per_v_at_2v"], 500)

    def test_power_numbers_in_spec(self):
        pw = analog.power()
        self.assertAlmostEqual(pw["p_spec_w"], 2.2, delta=0.05)
        self.assertAlmostEqual(pw["rise_spec_c"], 45, delta=1)
        self.assertAlmostEqual(pw["cell_floor_8"], 0.99, delta=0.01)
        self.assertAlmostEqual(pw["cell_floor_6"], 1.3, delta=0.02)
        d = analog.display_current()
        self.assertAlmostEqual(d["panel_nom_ma"], 120, delta=1)
        self.assertAlmostEqual(d["panel_bound_ma"], 214.4, delta=0.1)

    def test_supervisor_margin(self):
        s = analog.supervisor_margin()
        self.assertAlmostEqual(s["margin_475_v"], 0.05, delta=1e-9)
        self.assertAlmostEqual(s["margin_460_v"], 0.20, delta=1e-9)

    def test_oscillator_spread_finding(self):
        # Finding F3: 10k/330p does not guarantee the spec's 400 kHz ceiling
        o = analog.oscillator()
        self.assertGreater(o["max_hz"], 400e3)
        self.assertLess(o["min_hz"], 300e3)


if __name__ == "__main__":
    unittest.main()
