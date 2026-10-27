#!/usr/bin/env python3
"""
DTS-02 Demo — side-by-side full vs single-signature comparison.

Run from the dts02-6502-signer repo root:
  python3 dts02_demo.py
  python3 dts02_demo.py --lamports 10000
"""

import argparse
import subprocess
import sys

def run(mode_args):
    cmd = [sys.executable, "-m", "sim", "sign"] + mode_args
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(1)
    return r.stdout

def extract(line_prefix, text):
    for line in text.splitlines():
        if line.startswith(line_prefix):
            return line
    return ""

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lamports", type=int, default=5000)
    args = p.parse_args()

    print(f"DTS-02 Demo — {args.lamports} lamports\n")

    print("=== Full flow (double sign + verify) ===")
    full = run(["--lamports", str(args.lamports)])
    print(extract("cycles", full))
    print(extract("matches", full))

    print("\n=== Single signature + verify ===")
    single = run(["--lamports", str(args.lamports), "--single"])
    print(extract("cycles", single))
    print(extract("matches", single))

    print("\nDone. Both modes match OpenSSL when the output says True.")

if __name__ == "__main__":
    main()
