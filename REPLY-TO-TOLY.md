# Draft reply (do not post automatically)

Plain comment William can paste on the original thread / PRs. Not posted by the bot.

---

Follow-up measurements and tooling on top of the single-sign and visualizer work:

- Full double-sign + verify: **681,618,212** cycles (150-byte Solana transfer)
- Single signature + verify: **552,202,469** cycles (~19% less); OpenSSL / RFC 8032 match in both modes; on-device verification still runs
- PR #6 (single-sign measurement): https://github.com/aeyakovenko/dts02-6502-signer/pull/6
- PR #7 (visualizer + clock note, stacks on #6): https://github.com/aeyakovenko/dts02-6502-signer/pull/7
- This branch adds ASCII seven-segment rendering and a cycle progress bar in `dts02_visualizer.py`, expands `CLOCK-SPEED.md` with exact 88 kHz / 500 kHz / 1 MHz wall-clock tables and a Section 11.2 scope checklist, plus a few adversarial envelope/brownout tests

Fixed-base verification against `[k·a]B` (F11 option 4) was considered and left unimplemented: it would put a secret into the public verify path and weaken wrong-key rejection. Estimated savings remain ~0.1×10⁹ cycles per F11 if that policy were accepted.

