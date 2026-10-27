#!/usr/bin/env python3
"""DTS-02 signing visualizer — live-style summary of a simulated signature.

Runs the existing fast-emulator signing harness (same path as
``python3 -m sim sign``), prints cycle count and wall-clock estimates at
88 kHz and 1 MHz, and reports the 16-digit seven-segment state from the
emulated HC595 storage registers when the firmware actually drives them.

Usage (from the repo root):
  ./dts02_visualizer.py
  ./dts02_visualizer.py --lamports 5000 --single
  ./dts02_visualizer.py --brownout   # board-model power-dip demo (F12)
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time


# Segment masks matching sim/firmware.py FONT (bit0=a .. bit6=g).
_FONT = [0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07,
         0x7F, 0x6F, 0x77, 0x7C, 0x39, 0x5E, 0x79, 0x71]
_GLYPH = {m: "0123456789AbCdEF"[i] for i, m in enumerate(_FONT)}
_GLYPH[0] = " "


def _fmt_duration(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:.2f} h"
    if seconds >= 60:
        return f"{seconds / 60:.2f} min"
    return f"{seconds:.2f} s"


def _masks_to_text(masks) -> str:
    return "".join(_GLYPH.get(m, "#") for m in masks)


def run_sign(lamports: int, single: bool) -> dict:
    """Run one signing flow via the existing harness; return a summary dict."""
    from sim import ed25519_ref as E
    from sim import signer_fw as F
    from sim import solana as SOL
    from sim.signer_harness import Fw

    seed_text = "DTS-02 public test fixture seed - never fund"
    seed = hashlib.sha256(seed_text.encode()).digest()
    pk = E.public_key(seed)
    to = E.public_key(hashlib.sha256(b"recipient").digest())
    bh = hashlib.sha256(b"blockhash").digest()
    msg = SOL.transfer_message(pk, to, lamports, bh)

    fw = Fw(double_sign=not single, verify=True)
    fw.put(F.SEED, seed)
    fw.put(F.ENV, F.envelope(msg, pk))

    t0 = time.perf_counter()
    cycles = fw.call("sign_main")
    wall = time.perf_counter() - t0

    m = fw.m.m
    rec = fw.get(F.REC, 256)
    sig = rec[0x2C:0x6C]
    status = fw.get(F.ZP["STATUS"], 1)[0]
    ok = (status == 0
          and sig == E.sign(seed, msg)
          and sig == SOL.openssl_sign(seed, msg)
          and rec == F.expected_record(msg, pk, sig))
    masks = fw.m.display_masks()
    return dict(
        cycles=cycles,
        wall=wall,
        ok=ok,
        status=status,
        msg_lock=m.msg_lock,
        res_lock=m.res_lock,
        fault=m.fault,
        gpio_writes=m.gpio_writes,
        masks=masks,
        sig_b58=SOL.b58encode(sig),
        pk_b58=SOL.b58encode(pk),
        msg_len=len(msg),
        lamports=lamports,
        single=single,
        seed_text=seed_text,
    )


def print_sign_summary(r: dict) -> None:
    mode = "single signature + verify" if r["single"] else "full double-sign + verify"
    cyc = r["cycles"]
    print("=" * 60)
    print(f"DTS-02 visualizer — {mode}")
    print("=" * 60)
    print(f"signer     {r['pk_b58']}")
    print(f"           (test seed {r['seed_text']!r}; never fund it)")
    print(f"message    {r['msg_len']} bytes, transfer {r['lamports']} lamports")
    print(f"status     {r['status']:#04x}  "
          f"MESSAGE_LOCK={r['msg_lock']} RESULT_LOCK={r['res_lock']} FAULT={r['fault']}")
    print(f"matches    RFC 8032 + OpenSSL + record: {r['ok']}")
    print(f"sig        {r['sig_b58']}")
    print()
    print("--- timing ---")
    print(f"cycles     {cyc:,}")
    print(f"host wall  {r['wall']:.2f} s (emulator, not target clock)")
    print(f"@ 88 kHz   {_fmt_duration(cyc / 88e3)}  "
          f"({cyc / 88e3:.1f} s)")
    print(f"@ 1 MHz    {_fmt_duration(cyc / 1e6)}  "
          f"({cyc / 1e6:.1f} s)")
    print()
    print("--- 16-digit seven-segment (HC595 storage) ---")
    masks = r["masks"]
    print(f"masks      {[f'{m:02X}' for m in masks]}")
    print(f"glyphs     [{_masks_to_text(masks)}]")
    print(f"gpio_writes {r['gpio_writes']}")
    if r["gpio_writes"] == 0 and all(m == 0 for m in masks):
        print("note       Signing firmware does not drive the display panel.")
        print("           The emulator exposes HC595 state (display_masks), but")
        print("           sim/signer_fw.py never clocks the 595 chain during")
        print("           sign_main — only the test ROM (sim/firmware.py) does.")
        print("           Blank masks above are the real post-sign state, not a fake.")
    print("=" * 60)


def run_brownout() -> int:
    """Board-model brownout demo using sim.brownout.dip_during_write (F12).

    This is the gate-level board + test ROM path, not the signing emulator.
    The signing emu has no supply/supervisor model, so fault injection there
    is not supported.
    """
    from sim.brownout import dip_during_write

    print("=" * 60)
    print("DTS-02 visualizer — brownout / power-dip (board model)")
    print("=" * 60)
    print("Injecting POR during an SRAM write strobe (sim.brownout).")
    print("This uses the gate-level board + test ROM, not the signing emu.")
    print()
    t0 = time.perf_counter()
    r = dip_during_write(40, seed=2)
    wall = time.perf_counter() - t0
    after = r["after"]
    print(f"offset_ns            {r['offset_ns']}")
    print(f"write_during_reset   {r['write_during_reset']}  (must be [])")
    print(f"interrupted_write    {r['interrupted_write'][:1]}")
    print(f"violations_at_dip    {len(r['violations_at_dip'])}")
    print(f"after recovery       FAULT={after['fault']} "
          f"MESSAGE_LOCK={after['msg']} RESULT_LOCK={after['res']}")
    print(f"violations_total     {r['violations_total']}")
    print(f"host wall            {wall:.2f} s")
    print()
    print("Per FINDINGS.md F12: cold clear clears locks/FAULT; firmware")
    print("performs a clean fresh boot. No write strobe starts while held.")
    print("=" * 60)
    ok = (r["write_during_reset"] == []
          and tuple(after.values()) == (0, 0, 0))
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="DTS-02 signing visualizer (stdlib + existing sim only)")
    p.add_argument("--lamports", type=int, default=5000,
                   help="transfer amount (default 5000)")
    p.add_argument("--single", action="store_true",
                   help="one signature + verify (skip duplicate sign)")
    p.add_argument("--brownout", action="store_true",
                   help="run board-model power-dip injection instead of signing "
                        "(sim.brownout; not available on the signing emulator)")
    args = p.parse_args(argv)

    if args.brownout:
        return run_brownout()

    print(f"[visualizer] starting sign "
          f"(lamports={args.lamports}, single={args.single}) …", flush=True)
    r = run_sign(args.lamports, args.single)
    print_sign_summary(r)
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
