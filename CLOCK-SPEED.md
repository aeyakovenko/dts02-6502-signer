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

Arithmetic: \(t = N / f\).

### Single (552,202,469 cycles)

| Clock | Calculation | Wall-clock |
|---|---|---|
| 88 kHz (rev 0.4 max, reference) | \(552{,}202{,}469 / 88{,}000 = 6{,}275.028\) s | **1.74 h** (104.6 min) |
| 500 kHz | \(552{,}202{,}469 / 500{,}000 = 1{,}104.405\) s | **18.4 min** |
| 1 MHz | \(552{,}202{,}469 / 1{,}000{,}000 = 552.202\) s | **9.2 min** |

### Full double-sign (681,618,212 cycles)

| Clock | Calculation | Wall-clock |
|---|---|---|
| 88 kHz (rev 0.4 max, reference) | \(681{,}618{,}212 / 88{,}000 = 7{,}745.662\) s | **2.15 h** (129.1 min) |
| 500 kHz | \(681{,}618{,}212 / 500{,}000 = 1{,}363.236\) s | **22.7 min** |
| 1 MHz | \(681{,}618{,}212 / 1{,}000{,}000 = 681.618\) s | **11.4 min** |

(`python3 -m sim sign` prints the same 88 kHz / 1 MHz estimates rounded
as in FINDINGS.md’s table: ~2.1–2.2 h full at 88 kHz, ~11 min at 1 MHz.)

## Bottom line

The largest lever is clock rate: about **10×** from the 88 kHz rev 0.4
ceiling to 1 MHz if soldered construction and Section 11.2 scope checks
pass. The digital model already supports ~1.3 MHz CPU; the present
~100 kHz limit is a breadboard signal-integrity margin, not a logic
limit (FINDINGS.md F11).
