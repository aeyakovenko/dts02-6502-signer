"""Power dip (supervisor reset) during an SRAM write strobe."""

import unittest

from sim import corners
from sim.brownout import dip_during_write


class TestBrownout(unittest.TestCase):
    def check_recovery(self, r):
        self.assertEqual(r["write_during_reset"], [])          # no strobe starts while held
        self.assertEqual(tuple(r["after"].values()), (0, 0, 0))  # locks / fault cleared
        # after recovery the fresh boot ran with no further violations
        self.assertEqual(r["violations_total"] - len(r["violations_at_dip"]), 0)

    def test_dip_typical_delays_clean(self):
        r = dip_during_write(40, seed=2)
        self.check_recovery(r)
        self.assertEqual(r["violations_at_dip"], [])
        self.assertEqual([(a, d) for _, a, d in r["interrupted_write"]], [(0x100, 0x55)])

    def test_dip_can_disturb_next_address_at_corner(self):
        # F12: the cold clear drops PHI2 before the SRAM write strobe ends, so
        # the next cycle's address can be written with indeterminate data.
        r = dip_during_write(40, seed=2, corner=corners.brownout_write_corner)
        self.check_recovery(r)
        kinds = {v.kind for v in r["violations_at_dip"]}
        self.assertIn("addr-during-write", kinds)


    def test_dip_during_signer_prefix_recovers(self):
        """Adversarial: power dip while signing firmware is writing toward MESSAGE_LOCK.

        Uses the signing ROM on the gate-level board (same path as
        TestGateLevel). Injects a cold clear during an SRAM write and checks
        F12 recovery: no WE while held, locks/FAULT clear after reboot path.
        """
        import hashlib

        from sim import signer_fw as F
        from sim import solana as SOL
        from sim import ed25519_ref as E
        from sim.runner import Bench
        from sim.signer_harness import build

        seed = hashlib.sha256(b"DTS-02 public test fixture seed - never fund").digest()
        a = E.public_key(seed)
        msg = SOL.transfer_message(a, E.public_key(b"\x03" * 32), 1000, bytes(32))
        env = F.envelope(msg, a)
        img, syms, _ = build()
        b = Bench(image=img, symbols=syms, seed=3)
        b.ram.mem[:] = [0] * 32768
        for i, v in enumerate(env):
            b.ram.mem[F.ENV + i] = v
        for i, v in enumerate(seed):
            b.ram.mem[F.SEED + i] = v
        b.watch_edges("RAM_WE_N", "COLD_CLEAR_N", "FAULT", "MESSAGE_LOCK", "RESULT_LOCK")

        writes = []

        def on_we(net, t, old, new):
            req = b.cpu.req
            if new == 0 and old == 1 and req[0] == "W":
                writes.append((t, req[1], req[2]))

        b.sim.nets["RAM_WE_N"].watchers.append(on_we)
        # Run until several SRAM writes have occurred (envelope copy / scratch).
        b.sim.run_until(b.sim.now + 200_000 * b.cpu_period,
                        stop=lambda: len(writes) >= 8)
        self.assertGreaterEqual(len(writes), 8)
        t_we = writes[7][0]
        b.sim.run_until(t_we + 40)          # into the write strobe
        viol_before = len(b.sim.violations)
        t_dip = b.sim.now
        low_ns = 20_000
        b.h.cold_clear(low_ns)
        t_release = t_dip + low_ns
        b.sim.run_until(t_release)
        cc_falls = [t for t, o, n in b.edge_log["COLD_CLEAR_N"] if n == 0 and t >= t_dip]
        self.assertTrue(cc_falls)
        cc_fall = cc_falls[0]
        we_during = [t for t in b.falling("RAM_WE_N", cc_fall + 1, t_release)]
        self.assertEqual(we_during, [])
        # Immediately after the POR pulse, locks/FAULT must be clear (F12).
        # Do not run far past release: signing firmware will re-parse the
        # envelope and may set MESSAGE_LOCK again on the new session.
        self.assertEqual(b.net("FAULT"), 0)
        self.assertEqual(b.net("MESSAGE_LOCK"), 0)
        self.assertEqual(b.net("RESULT_LOCK"), 0)
        # Confirm MESSAGE_LOCK actually fell during the dip if it had been set.
        msg_edges = [(t, o, n) for t, o, n in b.edge_log["MESSAGE_LOCK"] if t >= t_dip]
        if any(o == 1 for _, o, _ in msg_edges):
            self.assertTrue(any(n == 0 for _, _, n in msg_edges))
        _ = viol_before


if __name__ == "__main__":
    unittest.main()
