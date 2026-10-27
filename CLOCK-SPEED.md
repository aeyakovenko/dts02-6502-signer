# Clock speed and signature wall-clock time

Factual notes drawn from `FINDINGS.md` (especially F11) and `spec.md`
Section 11.2. Cycle counts are from the cycle-exact emulator on a 150-byte
Solana transfer (`python3 -m sim sign` / `--single`).

## What the findings claim

**Digital logic vs breadboard ceiling.** FINDINGS.md F11 states:

> The digital logic simulates cleanly with the CPU at roughly 1.3 MHz (an
> 8 MHz master), so the 100 kHz ceiling is a breadboard signal-integrity
> margin, not a logic limit.

That matches the F11 option list (“about 10× from 88 kHz to 1 MHz, which
the logic supports but a breadboard may not”) and the rev 0.4 oscillator
note in F2 (CPU about 13–88 kHz with 560 pF; acceptance PHI2 ≤ 100 kHz).
`spec.md` Section 5.3 says the same in substance: the logic simulates
cleanly far above the ceiling; the ceiling is a breadboard
signal-integrity margin.

**Verified in-repo figures**

| Claim | Source | Status |
|---|---|---|
| ~1.3 MHz CPU / 8 MHz master simulates clean | FINDINGS.md F11 (quoted above) | In FINDINGS.md |
| 100 kHz CPU ceiling is breadboard SI margin | FINDINGS.md F11; also F2 / F1 (100 kHz / 600 kHz master with six-state divider) | In FINDINGS.md |
| Full flow **681,618,212** cycles | FINDINGS.md F11 update (27 Oct 2026) | In FINDINGS.md |
| Single + verify **552,202,469** cycles | FINDINGS.md F11 update | In FINDINGS.md |
| Rev 0.4 CPU ~13–88 kHz (560 pF, master/6) | FINDINGS.md F2 | In FINDINGS.md |

No unverified frequency figures are introduced here. The ~1.3 MHz /
8 MHz pair is cited as FINDINGS.md’s claim, not re-derived in this note.

## Section 11.2 — what it actually requires

`spec.md` §11.2 is **bus-handoff acceptance checks on the assembled
core**, measured with an oscilloscope (a logic analyzer may trigger but
cannot substitute). The eight items cover:

1. RD_WIN_N vs PHI2 / RWB timing
2. P_D release / enable and quiet time between windows
3. U4 write-buffer enable / release
4. C_D hold through EARLY→MID and after PHI2 fall
5. Write→read pull-up quiet time on C_D
6. RWB_CYCLE changes only at PHI2 rise
7. Rise times of released P_D / C_D lines (≤ 3 µs, 10–90 %)
8. Contention signature (no sustained 0.8–2.0 V > 20 ns; rail step ≤ 50 mV)

FINDINGS.md “Limits of this verification” notes the simulation is digital
with ideal edges and **cannot** assess ringing, ground bounce, the 5 ns
PHI2 edge, supply droop, or HCT input-transition behavior — so the
Section 11.2 scope checks remain required. Raising the clock therefore
means re-passing those measurements at the new rate, not trusting the
digital sim alone.

### What to measure on a scope (checklist)

Quoted/paraphrased from `spec.md` §11.2 items 1–8. Do these on the
assembled core with an oscilloscope; a logic analyzer may trigger but
cannot substitute (`spec.md` §11.2 opening paragraph).

- [ ] **Item 1 — RD_WIN_N:** “RD_WIN_N (U18 pin 6) is low only while PHI2
  (U1 pin 37) is high and RWB is high; it falls within 100 ns of the PHI2
  rise and rises one master period (±100 ns) before PHI2 falls.”
- [ ] **Item 2 — P_D release/enable:** After RD_WIN_N rises, selected
  memory outputs release within 50 ns; next P_D driver enables no earlier
  than the next PHI2 rise; address changes at PHI2 fall happen with all
  P_D OEs inactive; between windows lines sit at pull-up for ≥ three
  master periods.
- [ ] **Item 3 — U4 write buffer:** “U4 outputs enable only while PHI2 is
  high in write cycles and release within 50 ns of PHI2 falling.”
- [ ] **Item 4 — C_D hold:** During a read, data at U1 pins 26–33 holds
  unchanged from the EARLY→MID edge until one master period after PHI2
  falls; during GAP and PRE the lines rise toward the pull-up level.
- [ ] **Item 5 — Write→read gap:** Between CPU releasing C_D (within 50 ns
  of PHI2 falling) and U44 enabling (next PHI2 rise), lines sit at
  pull-up for ≥ two master periods.
- [ ] **Item 6 — RWB_CYCLE:** “RWB_CYCLE (U45 pin 5) changes only at PHI2
  rising edges and equals RWB of the cycle just started.”
- [ ] **Item 7 — Rise times:** “Rise times of released lines, 10–90 %:
  every P_D line and every C_D line ≤3 µs” (HCT 500 ns/V limit). Expect
  roughly 0.7 µs (P_D) and 0.8 µs (C_D) when correctly wired.
- [ ] **Item 8 — Contention signature:** “no data line shows a sustained
  intermediate level (0.8–2.0 V) for more than 20 ns, and the 5 V rail
  shows no step larger than 50 mV at PHI2 edges.”

Any failed item is fixed and re-measured before step 4 of Section 11.1
proceeds (`spec.md` §11.2 closing paragraph).

## Practical changes to run faster

From FINDINGS.md F11 options and the layout / SI findings (F9, F10), in
rough order of effect:

1. **Soldered construction.** F11: “Qualify a faster clock on soldered
   construction.” Breadboard strip capacitance, long jumpers, and the
   ~400 mm PHI2 stub to U38 (F10) are the stated SI risks.
2. **Layout / stub removal.** F10’s fix (clock U38 from a spare U7 gate
   so PHI2 stays ~48 mm on BB1) removes a long clock stub. F9’s
   C_D / P_D length discussion is about capacitance budget, not a hard
   frequency gate, but shorter runs help edge integrity.
3. **Termination / edge control.** Spec §5.4 and F10 call out the
   ≤ 5 ns PHI2 edge and ringing risk. Better return paths and, where
   appropriate, series termination on long lines are the usual next
   steps once the board is soldered — qualify with a scope, do not
   assume.
4. **Oscilloscope validation per Section 11.2.** Re-run all eight
   handoff checks at the candidate CPU clock (and the matching master).
   Any failed item must be fixed and re-measured before trusting the
   higher rate (`spec.md` §11.2 closing paragraph).
5. **Firmware / policy levers (orthogonal to clock).** F11 also lists
   dropping the duplicate signature (~0.13 × 10⁹ cycles), table multiply
   for public verification data, and dedicated squaring — policy choices
   under Section 10.2, not hardware SI work.

## Wall-clock estimates

Cycle counts from FINDINGS.md F11 update (150-byte Solana transfer):

- Single signature + on-device verify: **552,202,469** cycles
- Full double-sign + verify: **681,618,212** cycles

Arithmetic: \(t = N / f\). Exact quotients below; wall-clock column rounds
for readability.

### Combined comparison (exact)

| Mode | Cycles | 88 kHz | 500 kHz | 1 MHz |
|---|---:|---:|---:|---:|
| Single | 552,202,469 | 6,275.028057 s (**1.7431 h**) | 1,104.404938 s (**18.407 min**) | 552.202469 s (**9.2034 min**) |
| Full | 681,618,212 | 7,745.661500 s (**2.1516 h**) | 1,363.236424 s (**22.721 min**) | 681.618212 s (**11.360 min**) |

### Single (552,202,469 cycles)

| Clock | Calculation | Wall-clock |
|---|---|---|
| 88 kHz (rev 0.4 max, reference) | \(552{,}202{,}469 / 88{,}000 = 6{,}275.028057\) s | **1.74 h** (104.6 min) |
| 500 kHz | \(552{,}202{,}469 / 500{,}000 = 1{,}104.404938\) s | **18.4 min** |
| 1 MHz | \(552{,}202{,}469 / 1{,}000{,}000 = 552.202469\) s | **9.2 min** |

### Full double-sign (681,618,212 cycles)

| Clock | Calculation | Wall-clock |
|---|---|---|
| 88 kHz (rev 0.4 max, reference) | \(681{,}618{,}212 / 88{,}000 = 7{,}745.661500\) s | **2.15 h** (129.1 min) |
| 500 kHz | \(681{,}618{,}212 / 500{,}000 = 1{,}363.236424\) s | **22.7 min** |
| 1 MHz | \(681{,}618{,}212 / 1{,}000{,}000 = 681.618212\) s | **11.4 min** |

(`python3 -m sim sign` prints the same 88 kHz / 1 MHz estimates rounded
as in FINDINGS.md’s table: ~2.1–2.2 h full at 88 kHz, ~11 min at 1 MHz.)

## Fixed-base verification attempt (not applied)

F11 option 4 suggests checking \([S]B = R + [k \cdot a]B\) with the
existing fixed-base tables, claiming about **0.1 × 10⁹** cycle savings,
because \(A = [a]B\) was already matched to the expected key.

**Not implemented** in this branch. Reasons (see also FINDINGS.md F11
note):

1. **Secret in verification.** `verify` currently calls `set_fast`
   (quarter-square ROM tables) because every operand is public. Using
   secret \(a\) under that multiply would be a secret-indexed table
   access on secret-influenced field elements — forbidden by
   `spec.md` §10.2. Switching to `set_ct` for that path would erase
   most of the estimated gain.
2. **Wrong-key rejection.** `tests/test_signer.py::test_verifier_rejections`
   requires `verify` to fail when `A_BYTES` is replaced by another
   public key. A `[k·a]B` check keyed only by the seed-derived scalar
   would ignore `A_BYTES` and accept that case — a security regression.
3. **Contract.** Firmware header and §10.2 treat verification as
   public-data confirmation of the signature equation against \(A\).

**Estimated savings (labeled estimate, from F11):** ~0.1 × 10⁹ cycles
(~15% of the 681M full flow) *if* the secret-in-verify policy were
accepted and constant-time multiply were kept for the secret path; real
savings would be lower once `set_ct` is forced. No cycle re-measurement
was performed because the code was not changed.

## Bottom line

The largest lever is clock rate: about **10×** from the 88 kHz rev 0.4
ceiling to 1 MHz if soldered construction and Section 11.2 scope checks
pass. The digital model already supports ~1.3 MHz CPU; the present
~100 kHz limit is a breadboard signal-integrity margin, not a logic
limit (FINDINGS.md F11).
