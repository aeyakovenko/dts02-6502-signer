#!/usr/bin/env python3
"""
DTS-02 Companion Tool
Simple wrapper that runs the 6502 signer and prints a clean summary.

Usage (from the dts02-6502-signer repo root):
  python3 dts02_companion.py --lamports 5000
  python3 dts02_companion.py --lamports 5000 --single
"""

import argparse
import subprocess
import sys

def run_sign(lamports: int, single: bool) -> str:
    cmd = [sys.executable, "-m", "sim", "sign", "--lamports", str(lamports)]
    if single:
        cmd.append("--single")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout

def main():
    p = argparse.ArgumentParser(description="DTS-02 companion: clean signing summary")
    p.add_argument("--lamports", type=int, default=5000, help="lamports to transfer (default 5000)")
    p.add_argument("--single", action="store_true", help="use single-signature mode")
    args = p.parse_args()

    print(f"DTS-02 Companion — {'single' if args.single else 'full'} mode")
    print(f"Transfer: {args.lamports} lamports\n")

    output = run_sign(args.lamports, args.single)
    print(output)

    for line in output.splitlines():
        if line.startswith("cycles"):
            print("---")
            print(f"Highlight: {line}")
            break

if __name__ == "__main__":
    main()
