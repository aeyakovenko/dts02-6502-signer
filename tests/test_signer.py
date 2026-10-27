"""Signing firmware (sim/signer_fw.py) on the fast emulator, plus a gate-level
cross-check of its first phase on the board model."""

import hashlib
import random
import unittest
import zlib

from sim import ed25519_ref as E, signer_fw as F, solana as SOL
from sim.signer_harness import Fw, build

SEED = hashlib.sha256(b"DTS-02 public test fixture seed - never fund").digest()
A = E.public_key(SEED)
RFC = [("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", ""),
       ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72"),
       ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82")]


class TestPrimitives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fw = Fw()

    def test_field_ops(self):
        rnd = random.Random(1)
        P = F.P
        vals = [0, 1, P - 1, P, P + 1, 2**255, 2**256 - 1, 2**256 - 38, 19, 38] + \
               [rnd.getrandbits(256) for _ in range(10)]
        for i, a in enumerate(vals):
            b = vals[(7 * i + 3) % len(vals)]
            self.assertEqual(self.fw.fe_op("fe_mul", a, b)[0] % P, a * b % P)
            self.assertEqual(self.fw.fe_op("fe_add", a, b)[0] % P, (a + b) % P)
            self.assertEqual(self.fw.fe_op("fe_sub", a, b)[0] % P, (a - b) % P)
            self.fw.put(F.fe("TC"), F.le32(a))
            self.fw.setp("P3", F.fe("TC"))
            self.fw.call("fe_canon")
            self.assertEqual(int.from_bytes(self.fw.get(F.fe("TC"), 32), "little"), a % P)

    def test_all_multiply_variants(self):
        rnd = random.Random(7)
        P = F.P
        vals = [0, 1, P - 1, P, 2**255, 2**256 - 1, 2**256 - 38, 255, 256] + \
               [rnd.getrandbits(256) for _ in range(16)]
        for op, square in [("fe_mul_ct", False), ("fe_sq_ct", True), ("fe_mul_qs", False),
                           ("fe_sq_qs", True)]:
            for i, a in enumerate(vals):
                b = a if square else vals[(5 * i + 2) % len(vals)]
                with self.subTest(op=op, i=i):
                    r, _ = self.fw.fe_op(op, a, None if square else b)
                    self.assertEqual(r % P, a * b % P)

    def test_sha512_all_padding_boundaries(self):
        rnd = random.Random(2)
        for n in [0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 1232, 4096]:
            msg = bytes(rnd.getrandbits(8) for _ in range(n))
            self.fw.put(0x2000, msg)
            self.fw.call("sha_init")
            self.fw.setp("PTR", 0x2000)
            self.fw.put(F.ZP["LEN"], n.to_bytes(2, "little"))
            self.fw.call("sha_update")
            self.fw.setp("PTR", 0x3200)
            self.fw.call("sha_final")
            self.assertEqual(self.fw.get(0x3200, 64), hashlib.sha512(msg).digest(), n)

    def test_scalar_reduce(self):
        rnd = random.Random(3)
        for x in [0, F.L - 1, F.L, 2**512 - 1] + [rnd.getrandbits(512) for _ in range(8)]:
            self.fw.put(F.SCL["RED_IN"], x.to_bytes(64, "little"))
            self.fw.call("sc_reduce")
            self.assertEqual(int.from_bytes(self.fw.get(F.SCL["RED_R"], 32), "little"), x % F.L)

    def test_fixed_base_multiplication(self):
        rnd = random.Random(4)
        for s in [1, 2, 8, 9, 16, 255, F.L - 1, rnd.getrandbits(252), rnd.getrandbits(254) | 1 << 254]:
            self.fw.put(0x3100, s.to_bytes(32, "little"))
            self.fw.setp("P1", 0x3100)
            self.fw.call("recode")
            self.fw.call("base_mult")
            self.fw.setp("P4", 0x3200)
            self.fw.call("encode")
            self.assertEqual(self.fw.get(0x3200, 32), E._encode(E._mul(s, E.B)), hex(s))


class TestSignVerify(unittest.TestCase):
    def sign(self, seed, msg):
        fw = Fw()
        fw.put(F.SEED, seed)
        fw.put(F.MSG, msg)
        fw.put(F.META, len(msg).to_bytes(2, "little"))
        fw.setp("TT", F.SCL["SIG1"])
        fw.call("sign")
        return fw, fw.get(F.SCL["SIG1"], 64)

    def test_rfc8032_vectors(self):
        for seed_hex, msg_hex in RFC:
            seed, msg = bytes.fromhex(seed_hex), bytes.fromhex(msg_hex)
            fw, sig = self.sign(seed, msg)
            self.assertEqual(sig, E.sign(seed, msg))
            self.assertEqual(fw.get(F.SCL["A_BYTES"], 32), E.public_key(seed))

    def test_verifier_rejections(self):
        msg = b"fixture message"
        fw, sig = self.sign(SEED, msg)

        def ver(sig_, msg_=msg, a_=A):
            fw.put(F.SCL["SIG1"], sig_)
            fw.put(F.MSG, msg_)
            fw.put(F.META, len(msg_).to_bytes(2, "little"))
            fw.put(F.SCL["A_BYTES"], a_)
            fw.call("verify")
            return fw.get(F.ZP["STATUS"], 1)[0]
        s_plus_l = (int.from_bytes(sig[32:], "little") + F.L).to_bytes(32, "little")
        self.assertEqual(ver(sig), 0)
        self.assertEqual(ver(bytes([sig[0] ^ 1]) + sig[1:]), 1)
        self.assertEqual(ver(sig[:40] + bytes([sig[40] ^ 1]) + sig[41:]), 1)
        self.assertEqual(ver(sig[:32] + s_plus_l), 1)                 # malleability
        self.assertEqual(ver(sig, b"fixture messagf"), 1)             # k recomputed from M
        self.assertEqual(ver(sig, msg, E.public_key(b"\x02" * 32)), 1)
        self.assertEqual(ver(E.sign(SEED, b"other"), b"other"), 0)


class TestConstantTime(unittest.TestCase):
    """Secret-dependent code must have identical control flow and memory
    access patterns: the emulator hashes every bus address it touches."""

    def trace(self, routine, seed, msg=b"same public message"):
        fw = Fw()
        fw.put(F.SEED, seed)
        fw.put(F.MSG, msg)
        fw.put(F.META, len(msg).to_bytes(2, "little"))
        fw.setp("TT", F.SCL["SIG1"])
        cycles = fw.call(routine)
        return fw.m.m.trace, cycles

    def test_derive_and_sign_traces_independent_of_seed(self):
        for routine in ("derive", "sign"):
            with self.subTest(routine):
                a = self.trace(routine, hashlib.sha256(b"seed one").digest())
                b = self.trace(routine, hashlib.sha256(b"seed two").digest())
                self.assertEqual(a, b)

    def test_verify_restores_constant_time_multiply(self):
        fw = Fw()
        fw.put(F.SEED, SEED)
        fw.put(F.MSG, b"m")
        fw.put(F.META, (1).to_bytes(2, "little"))
        fw.setp("TT", F.SCL["SIG1"])
        fw.call("sign")
        good = fw.get(F.SCL["SIG1"], 64)
        for sig in (good, bytes(64)):                      # pass and fail paths
            fw.put(F.SCL["SIG1"], sig)
            fw.call("verify")
            vec = int.from_bytes(fw.m.read(F.ZP["MULV"], 2), "little")
            self.assertEqual(vec, fw.syms["fe_mul_ct"])


class TestSolanaFlow(unittest.TestCase):
    """Full spec flow (Sections 10.3-10.4) on Solana legacy messages."""

    def run_flow(self, msg):
        fw = Fw()
        fw.put(F.SEED, SEED)
        fw.put(F.ENV, F.envelope(msg, A))
        cycles = fw.call("sign_main")
        return fw, cycles

    def check(self, msg):
        fw, cycles = self.run_flow(msg)
        m = fw.m.m
        rec = fw.get(F.REC, 256)
        sig = rec[0x2C:0x6C]
        self.assertEqual(fw.get(F.ZP["STATUS"], 1)[0], 0)
        self.assertEqual((m.msg_lock, m.res_lock, m.fault, m.blocked_writes), (1, 1, 0, 0))
        self.assertEqual(rec, F.expected_record(msg, A, sig))
        self.assertEqual(sig, E.sign(SEED, msg))
        self.assertEqual(sig, SOL.openssl_sign(SEED, msg))
        self.assertTrue(SOL.openssl_verify(A, msg, sig))
        self.assertEqual(fw.get(F.MSG, len(msg)), msg)
        self.assertEqual(fw.get(0x0200, 0x3E00), bytes(0x3E00))      # secrets wiped
        return cycles

    def test_transfer(self):
        msg = SOL.transfer_message(A, E.public_key(b"\x03" * 32), 1_234_567_890,
                                   hashlib.sha256(b"blockhash").digest())
        cycles = self.check(msg)
        self.assertLess(cycles, 0.75e9)

    def test_durable_nonce_transfer(self):
        msg = SOL.transfer_message(A, E.public_key(b"\x03" * 32), 5, hashlib.sha256(b"nonce").digest(),
                                   nonce_account=E.public_key(b"\x04" * 32))
        self.check(msg)

    def test_max_legacy_message(self):
        self.check(bytes(range(256)) * 4 + bytes(143))        # 1,167 bytes

    def test_fail_closed(self):
        good = F.envelope(b"m", A)

        def reseal(body):
            return body + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")
        cases = {
            "bad crc": good[:-1] + bytes([good[-1] ^ 1]),
            "wrong expected key": F.envelope(b"m", E.public_key(b"\x01" * 32)),
            "profile 1 disabled": F.envelope(b"m", A, profile=1),
            "reserved set": reseal(good[:9] + b"\x01" + good[10:-4]),
            "length 4097": reseal(b"DTS02IN1" + bytes(2) + (4097).to_bytes(2, "little") + A + bytes(4097)),
            "bad magic": b"DTS02IN2" + good[8:],
        }
        for name, env in cases.items():
            with self.subTest(name):
                fw = Fw(double_sign=False, verify=False)
                fw.put(F.SEED, SEED)
                fw.put(F.ENV, env)
                fw.call("sign_main")
                self.assertEqual(fw.get(F.ZP["STATUS"], 1)[0], 0xEE)
                self.assertEqual(fw.m.m.res_lock, 0)
                self.assertEqual(fw.get(0x0200, 0x3E00), bytes(0x3E00))


    def test_malformed_envelope_truncated_and_oversize(self):
        """Adversarial: truncated / oversize envelopes must fail closed."""
        good = F.envelope(b"m", A)

        def run(env):
            fw = Fw(double_sign=False, verify=False)
            fw.put(F.SEED, SEED)
            fw.put(F.ENV, env)
            fw.call("sign_main")
            return fw

        cases = {
            "truncated before crc": good[:-4],
            "truncated mid header": good[:20],
            "empty": b"",
            "magic only": b"DTS02IN1",
            "length 0 with junk crc": (
                b"DTS02IN1" + bytes(2) + (0).to_bytes(2, "little") + A
                + (0).to_bytes(4, "little")  # wrong CRC
            ),
        }
        for name, env in cases.items():
            with self.subTest(name):
                fw = run(env)
                self.assertEqual(fw.get(F.ZP["STATUS"], 1)[0], 0xEE)
                self.assertEqual(fw.m.m.res_lock, 0)
                self.assertEqual(fw.get(0x0200, 0x3E00), bytes(0x3E00))

    def test_corrupted_signature_fails_full_flow_verify(self):
        """Negative: after a good sign, flipping a SIG1 byte must make verify fail.

        Confirms on-device verification is genuinely performed and rejects bad
        signatures (OpenSSL/RFC path still matches on the uncorrupted sig).
        """
        msg = SOL.transfer_message(A, E.public_key(b"\x03" * 32), 42,
                                   hashlib.sha256(b"blockhash-neg").digest())
        fw = Fw(double_sign=False, verify=True)
        fw.put(F.SEED, SEED)
        fw.put(F.ENV, F.envelope(msg, A))
        # Sign without going through sign_main so we can mutate SIG1, then verify.
        fw.put(F.MSG, msg)
        fw.put(F.META, len(msg).to_bytes(2, "little"))
        fw.setp("TT", F.SCL["SIG1"])
        fw.call("sign")
        good = bytearray(fw.get(F.SCL["SIG1"], 64))
        self.assertEqual(bytes(good), E.sign(SEED, msg))
        self.assertEqual(bytes(good), SOL.openssl_sign(SEED, msg))
        fw.call("verify")
        self.assertEqual(fw.get(F.ZP["STATUS"], 1)[0], 0)
        bad = bytearray(good)
        bad[10] ^= 0x01
        fw.put(F.SCL["SIG1"], bytes(bad))
        fw.call("verify")
        self.assertEqual(fw.get(F.ZP["STATUS"], 1)[0], 1)
        # Restore and confirm still accepts the good signature.
        fw.put(F.SCL["SIG1"], bytes(good))
        fw.call("verify")
        self.assertEqual(fw.get(F.ZP["STATUS"], 1)[0], 0)


class TestGateLevel(unittest.TestCase):
    def test_signer_runs_on_board_model_to_message_lock(self):
        from sim.runner import Bench
        img, syms, _ = build()
        msg = SOL.transfer_message(A, E.public_key(b"\x03" * 32), 1000, bytes(32))
        env = F.envelope(msg, A)
        b = Bench(image=img, symbols=syms, seed=5)
        b.ram.mem[:] = [0] * 32768
        for i, v in enumerate(env):
            b.ram.mem[F.ENV + i] = v
        for i, v in enumerate(SEED):
            b.ram.mem[F.SEED + i] = v
        b.sim.run_until(b.sim.now + 400_000 * b.cpu_period,
                        stop=lambda: b.sim.nets["MESSAGE_LOCK"].value == 1)
        self.assertEqual(b.sim.nets["MESSAGE_LOCK"].value, 1)
        self.assertEqual(b.violations(), [])
        fw = Fw()
        fw.put(F.ENV, env)
        fw.put(F.SEED, SEED)
        fw.m.m.s = 0xFD
        fw.m.reset()
        while not fw.m.m.msg_lock:
            fw.m.run(max_cycles=1)
        self.assertEqual(fw.m.m.instructions, b.cpu.core.instructions)
        self.assertEqual(bytes(b.ram.mem[:0x7F00]), fw.get(0, 0x7F00))


if __name__ == "__main__":
    unittest.main()
