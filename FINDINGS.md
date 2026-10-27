# DTS-02 rev 0.3: verification findings

These results come from the simulation and checks in `sim/` (see `README.md`), run against revision 0.3 of `spec.md`. Each finding names the test that reproduces it.

**Status:** revision 0.4 of `spec.md` incorporates F1, F2, F3, F4, F5, F6, F7, F9 and F10. F11 and F12 came from the later firmware and brownout work. F11 is partly addressed by firmware optimization; the rest is an open decision. The simulator now models rev 0.4 by default; pass `--rev03` (or `mutations=["rev03"]`) to reproduce the rev 0.3 behavior described here. F8 is informational.

## Summary

The core architecture holds up. The spec's pin tables wire up into a working computer: it boots, runs the spec's diagnostic ROM, and drives the display through the full 595 chain to the right glyphs. The locks and fault latch behave exactly as Section 11.4 says. Every digital item in Section 11.2 passes under random datasheet delays, at every oscillator corner, with no contention and no setup or hold violation.

The one substantive issue is that rev 0.3's central claim is not fully guaranteed. Section 6.5 says chip selects change only while every output enable is inactive. At datasheet delay corners there is still a tens-of-nanoseconds race at the trailing edge of the read window (F1). It does not change function, but it does violate the spec's own acceptance limit. Moving one spare flip-flop and one spare gate already on the BOM fixes it, and that fix was verified in simulation.

The other findings are text and number corrections, plus two layout issues found by generating the hole-level wiring list (F9, F10). The added signing firmware shows the design can sign Solana transactions correctly, but at the specified clock one spec-compliant signature takes about two hours (F11).

## Findings

### F1. Medium: the read window can outlast the CPU's address hold

- **Spec reference:** Section 6.5, which says "A change of selection between ROM, RAM and a port buffer happens while every output enable is inactive". Section 11.2 item 8.
- **Mechanism:**
  - `RD_WIN_N = !(Q_A & RWB)` comes from raw Q_A through U10 (HCT00, up to 30 ns).
  - The CPU sees PHI2 fall one U7 (AC14) delay after raw Q_A, then changes its address tAH ≥ 10 ns later.
  - `ROM_CE_N` is a single HCT04 delay behind A15.
  - Worst case: 30 ns against 1.5 + 10 + 4 ns, so RD_WIN_N can still be low for about 15 ns after the new device is selected.
  - In that window the newly selected ROM, RAM or U14/U15 sees both CE and OE active while the old device is still driving P_D.
- **Evidence:** with delays forced to the datasheet corner (`sim/corners.py`), every ROM↔RAM and ROM↔U14 transition produces P_D overlaps of up to about 28 ns. They start 26–35 ns after PHI2 falls. This exceeds the 20 ns limit in Section 11.2 item 8. With random delays and matched Q//Q, the race did not appear in 60 runs, so it is a corner case.
  - Tests: `tests/test_bus.py::TestReadWindowRace::test_rev03_overlap_at_corner`; `python3 -m sim race`.
- **Impact:** no functional effect. U44 latched the data a full master period earlier, and every read and write in the simulation is correct. It is a short bus fight on each affected transition, and it contradicts the guarantee rev 0.3 was written to provide. The EPROM model turns its outputs on immediately because the AT27C256R gives no minimum, so the real overlap may be shorter.
- **Recommended fix (no new packages):** make the phase generator a three-stage Johnson counter, so the read window closes one full master period before PHI2 falls.
  - Use U45's unused flip-flop B as stage C: pin 12 D = Q_B, pin 11 CLK = MASTER_CLK, pin 13 /CLR = COLD_CLEAR_N, pin 10 /PRE = +5 V. Pin 9 = Q_C, pin 8 = /Q_C.
  - U6 pin 2 (D_A) takes /Q_C instead of /Q_B.
  - Generate RD_WIN_N from U18's spare 3-input NAND: pins 3, 4, 5 = Q_A, /Q_C, RWB; pin 6 = RD_WIN_N. U10 gate 3 becomes unused.
  - EARLY, HOLD_N, LATCH_OE_N, the U4 enables and the write strobes are unchanged.
  - The state sequence is 000→100→110→111→011→001, so PHI2 is high for three of six master periods. The CPU clock becomes master/6, so the 100 kHz CPU ceiling allows a 600 kHz master.
  - The read window covers states 100 and 110. P_D quiet time grows to three master periods.
  - Caveat: a three-stage Johnson counter has an illegal two-state loop (010↔101). COLD_CLEAR_N clears it at power-up; making it self-correcting takes one more gate.
  - Verified at the same corner: zero overlaps. All scenarios and Section 11.2 measurements pass (`python3 -m sim race`; `test_six_state_fix_has_no_overlap`).
- **Status:** fixed in rev 0.4. A 560 pF oscillator capacitor keeps the CPU clock at or below 100 kHz with the six-state divider.
- **Lower-margin alternative:** build U10 as a 74AC00. Its roughly 10 ns maximum makes the worst-case margin positive, but only by about 5 ns.

### F2. Low: the oscillator's stated range is a typical value, not a bound

- **Spec reference:** Section 5.3, which says "about 300–380 kHz … never above 400 kHz" (also in the change list).
- **Evidence:** SN74HC14 thresholds at 4.5 V are VT+ 1.55–3.15 V, VT− 0.9–2.45 V and ΔVT 0.4–2.1 V. With those, 5 % R and C tolerance, and stray capacitance, 10 kΩ / 330 pF gives **127–890 kHz**, and a third of the corners exceed 400 kHz (`python3 -m sim check`).
- **Impact:** the clock does not need the limit. The design simulates clean from 127 kHz up to an 8–12 MHz master (`TestMargins`, `TestDiagnosticRom.test_monte_carlo_delays_and_clock_corners`). The risk is that a stock part fails the Section 5.3 ≤ 400 kHz acceptance check, and that firmware debounce timing scales with the clock.
- **Fix:** either keep "measure and trim" as the stated rule and drop the range claim, or use 820 pF (worst case 52–363 kHz). With the F1 fix, the ceiling becomes 600 kHz master.
- **Status:** fixed in rev 0.4 with 560 pF: 76–530 kHz master, 13–88 kHz CPU.

### F3. Low: the P_D capacitance budget and rise-time acceptance are tighter than the design needs

- **Spec reference:** Section 6.5 (60 pF per P_D line), Section 11.2 item 7 (P_D ≤ 0.62 µs, C_D ≤ 1.0 µs).
- **Evidence:**
  - Seven loads on each P_D line come to about 35 pF typical and 85 pF maximum in pin capacitance alone. With breadboard strips and wire, a realistic line is about 60 pF typical and 112 pF worst case, so item 7 will likely fail on a real ten-board build.
  - Functionally, unmapped and write-only port reads still return $FF up to about 1,000 pF at 380 kHz, and about 400 pF at 890 kHz (`TestMargins.test_unmapped_reads_tolerate_large_p_d_capacitance`).
  - The binding limit is TI's 500 ns/V input-transition rate for HCT. That allows up to about 320 pF on P_D (4.7 kΩ) and about 150 pF on C_D (10 kΩ).
- **Fix:** set acceptance from the transition-rate limit: P_D 10–90 % ≤ about 3 µs, C_D ≤ about 3 µs. Keep 60 pF as a layout target, not a pass/fail gate. Rev 0.3's 47 kΩ → 4.7 kΩ change is justified: 47 kΩ gives 940 ns/V, which breaks the HCT limit (`test_rev02_pullup_violated_hct_slew_limit`).

### F4. Low (text): the reset-release delay range is understated

- **Spec reference:** Section 5.3, "about 70–90 ms".
- **Evidence:** with the HC14 VT+ spread and the unspecified tolerance of the 1 µF capacitor (±20 % assumed), the delay is 32–152 ms, about 74 ms at mid-threshold.
- **Impact:** none functionally. It is always far more than the two CPU clocks WDC requires (`TestPowerUp`). Fix the stated range.

### F5. Low (text): the Section 10.1 self-test scope contradicts itself

- Step 4 says "Fresh start only: self-test the stack region". But the abort (0 0 1) and review (0 1 x) states also need the stack and scratch RAM: they call the display routine and compute the CRC. The paragraph after the table also requires those states to write "only after the stack self-test of step 4 has passed in that boot".
- **Fix:** step 4 applies to every non-fault boot state. The test ROM does this, and the C0, C1 and C2 paths pass (`TestRecovery`).

### F6. Trivial (text): an invalid instruction in Section 10.1 step 2

`STA #$00 to $7F02` is not a 6502 instruction. It should read `LDA #$00` then `STA $7F02`.

### F7. Low: the regulator dissipation assumes 0.30 A

A worst-case current estimate comes to about 340 mA. That is the 214 mA display bound plus SRAM and EPROM active current, HCT ΔICC on the 16 P_D receivers at a 2.4 V high, pull-ups, the bleeder and the status LEDs. At 340 mA the regulator dissipates 2.5 W, a rise of about 51 °C instead of 45 °C. That is still acceptable with a ≤15 °C/W heatsink and the 500 mA fuse. Update the figure or replace it with a measurement.

### F8. Info: mirrored lock ports

A3–A7 are not decoded, so a write to any mirror of $7F03 or $7F04 (for example $7F0B) sets a lock. This matches the documented mirroring and fails closed, but a stray firmware store anywhere in $7Fxx can freeze a session (`test_mirrors_and_undriven_ports`).

### F9. Low: the Section 3.2 length targets can't be met with the Section 3.3 placement

The generated hole-level layout (`wiring/WIRING.md`) shows the C_D and P_D length targets are unreachable with the spec's own placement:

- **C_D:** about 280 mm against an "aim below 100 mm" target. The CPU data pins sit at BB1 rows 48–55, while U4/U44 sit at the top of BB10 (rows 2–23) and the C_D pull-ups at BB1 rows 2–11.
- **P_D:** about 530 mm against a 250 mm target. The P_D pins are spread over BB10, BB2 and BB4, and BB3 sits between BB2 and BB4.

Possible improvements:
- Put the C_D pull-ups at the CPU pins: C_D drops to 188 mm.
- Also move U4/U44/U45 level with the CPU data pins: C_D drops to 111 mm.
- No arrangement tried gets P_D under about 450 mm.

None of this matters electrically. The estimated load is about 70 pF per P_D line and 36 pF per C_D line. That is far inside the functional margin (about 1,000 pF, see F3), and the simulation passes on the netlist derived from the physical layout. Replace the length targets with the capacitance and rise-time criteria proposed in F3.

### F10. Low–medium: the CPU clock net runs to the far sidecar board

U38's clock is the CPU PHI2 net (Section 9.2, "PHI2 for U38 pin 3 is U7 pin 2"), and U38 sits on BB9 at the far end of the north row. In the generated layout PHI2 totals about 440 mm, of which only about 48 mm is the U7→U1 segment. That leaves a roughly 400 mm stub hanging off the net that must give the W65C02S a ≤5 ns edge, which is a ringing and edge-rate risk (Section 5.4).

**Fix (no new parts):** clock U38 from a spare U7 gate. U7 pin 3 = /Q_A (U6 pin 6), and pin 4 = PHI2_FAULT → U38 pin 3. The CPU PHI2 net then stays on BB1, about 48 mm. This was verified in simulation: the fault latch still works with the split clock (`test_phi2_buffer_variant_keeps_fault_latch_working`).

### F11. High (usability): a spec-compliant signature takes hours at the specified clock

### F11 update — single-signature measurement (27 Oct 2026)

Running with `--single` (one signature + on-device verification) uses **552,202,469** cycles versus **681,618,212** for the full double-sign flow on a 150-byte Solana transfer.

Savings: ~129 million cycles (~19%).
Both modes match OpenSSL and the result record format.
Verification is still performed. The second signature is a policy choice under Section 10.2.

The reference firmware (`sim/signer_fw.py`, below) implements Section 10.2 exactly as specified: constant time for secrets with no secret-indexed tables, two deterministic signatures compared byte-for-byte, and on-device verification before release. Measured on the cycle-exact emulator, signing a 150-byte Solana transfer took **1.17 × 10⁹ CPU cycles** in the first version and **0.68 × 10⁹** after optimization:

| Work | First version | Optimized | At 88 kHz (rev 0.4 max) | At 47 kHz (typical) | At 1 MHz |
|---|---:|---:|---:|---:|---:|
| One signature, no verify | 0.30 × 10⁹ | 0.26 × 10⁹ | 0.8 h | 1.5 h | 4 min |
| Spec flow: two signatures + verify | 1.17 × 10⁹ | 0.68 × 10⁹ | 2.1 h | 4.0 h | 11 min |

The optimized firmware stays inside spec Section 10.2 and adds no hardware:
- **Constant-time squaring.** Cross products are computed once above the diagonal and doubled. It takes 114k cycles against 147k for a general multiply, and squarings dominate inversions and doublings.
- **Table multiply for verification only.** A quarter-square multiply with 2 KB of ROM tables takes 88k cycles. It is used only inside verification, where every operand is public, through a dispatch vector that is switched back to constant time on every exit path (`test_verify_restores_constant_time_multiply`).
- **No duplicate [a]B.** The second signature reuses A, which was already checked byte-for-byte against the configured expected key.
- **Zero-page product buffer.** Every product byte is one cycle faster to store.

The emulator hashes every bus address it touches. `derive` and `sign` produce identical traces and cycle counts for different seeds (`TestConstantTime`), which demonstrates no secret-dependent branches or memory addresses.

Further speed needs a policy decision rather than more code tuning:
1. **Clock.** This is the largest lever: about 10× from 88 kHz to 1 MHz, which the logic supports but a breadboard may not.
2. **Secret-indexed tables.** Allowing the quarter-square tables for secret data, which spec Section 10.2 forbids, saves about 0.15 × 10⁹.
3. **Duplicate signature.** Dropping it saves about 0.13 × 10⁹; verification already detects computation faults.
4. **Verification against the key.** Checking [S]B = R + [k·a]B with the fixed-base tables saves about 0.1 × 10⁹. It is valid because A = [a]B was already checked against the expected key, but it uses a secret in verification.

The dominant costs:
- **Field multiplication:** about 155k cycles. The 6502 has no multiply instruction, and a constant-time shift-and-add over 256 bits is the price of avoiding secret-indexed tables.
- **Inversion:** about 41M cycles per point encoding.
- **Verification:** about 574M cycles, mostly in the variable-base [k]A.

The digital logic simulates cleanly with the CPU at roughly 1.3 MHz (an 8 MHz master), so the 100 kHz ceiling is a breadboard signal-integrity margin, not a logic limit.

Options, roughly in order of effect:
1. Qualify a faster clock on soldered construction.
2. Use a table-based multiply for verification only, which handles only public data.
3. Add a dedicated squaring routine; squarings dominate inversions and doublings.
4. Reconsider the duplicate signature, since verification already detects computation faults.

### F12. Info: a power dip during a write can disturb one extra SRAM byte

An asynchronous cold clear drops PHI2 within tens of nanoseconds. The SRAM write strobe ends through a longer gate chain, so at delay corners the CPU's next-cycle address reaches the SRAM while WE is still low, and that byte can be written with indeterminate data (`tests/test_brownout.py`). In every simulated dip:
- no write strobe starts while reset is held;
- locks and FAULT clear;
- the firmware performs a clean fresh boot.

This is harmless under Section 10.1, because a cold clear always starts a new session and RAM is never trusted afterwards. A live-key design must keep that rule.

## Signing firmware verification

The spec ships no signing firmware, so `sim/signer_fw.py` implements Sections 10.2–10.4 in 65C02 assembly (generated and assembled by `sim/asm.py`) to answer whether this computer can sign Solana transactions. It answers yes, slowly (F11).

- **Envelope:** validates magic, profile, reserved byte, length and CRC-32, then copies M to $4000 and the metadata to $5000, then sets MESSAGE_LOCK.
- **Signing:** derives A and refuses unless it equals the expected key. Signs twice and compares, verifies with k recomputed from the frozen message, writes the $6000 record with CRC-32, sets RESULT_LOCK and wipes $0200–$3FFF.
- **Correctness:** RFC 8032 vectors 1–3 match byte-for-byte. Solana legacy transfer, durable-nonce transfer and 1,167-byte messages are signed through the full flow. Each signature equals both the independent Python RFC 8032 implementation and **OpenSSL 3.0**, OpenSSL verifies it, and the result record matches Section 10.4 exactly.
- **Lock discipline:** the emulator enforces the Section 9 bank locks and FAULT, and the firmware never writes a locked bank (0 blocked writes).
- **Fail closed:** bad CRC, wrong expected key, disabled profile, nonzero reserved byte, oversize length and bad magic each refuse to sign, set no RESULT_LOCK and wipe scratch. The verifier rejects tampered R or S, S+L malleability, a different message and a different key.
- **On the board model:** the firmware runs on the gate-level board from reset through envelope validation to MESSAGE_LOCK with zero contention or timing violations. Instruction count and the whole SRAM image are identical to the fast emulator.
- **CPU validation:** both CPU models (Python bus model and C emulator) pass Klaus Dormann's 6502 functional test and 65C02 extended-opcode test with identical cycle counts.

Not covered: the review UI (field pages, NEXT/BACK/APPROVE), the Solana/Squads policy parser of profiles 1–2, and seed entry. In the simulation the seed is placed at $3F00 to stand in for the undefined local entry mechanism.

## Breadboard layout verification

`python3 -m sim wiring` generates a hole-for-hole build list from the spec. Chips go exactly where Section 3.3 places them; every passive part gets specific holes or a soldered-panel pad; every net is routed as point-to-point jumpers (669 wires, 285 between boards). The generator then rebuilds the netlist purely from what is physically joined — each 5-hole strip, each rail half (split at row 31/32, with explicit bridge wires) and each wire — and checks it:

- No hole used twice, no strip over 5 holes, no rail half over 25 holes, no part lead spanning over 30 mm.
- Physical connectivity equals the schematic: 0 shorts, 0 opens, ERC clean.
- Section 3.4 harness rules hold:
  - C_D stays on BB1/BB10;
  - P_D stays on BB10/BB2/BB4;
  - the BB9 harness is exactly the lock interface plus status returns;
  - each bank board carries only its own bank signals;
  - the LED panel return goes straight to the power fixture.
- The simulator runs the diagnostic ROM, unmapped reads, the lock/fault scenario and the font page on the **physical** netlist, with per-line capacitance taken from the layout. Zero violations.
- Injected build mistakes are caught:
  - a jumper one row off (A4/A5 short: CPU crashes in simulation);
  - an IC seated one row low;
  - a missing rail bridge (half a board unpowered: ERC);
  - a pull-up moved to the neighbouring strip. This one is caught by the connectivity check even though normal reads still work; only undriven reads expose it in simulation.

## Confirmed correct

| Item | How it was checked |
|---|---|
| Section 11.3 diagnostic ROM image hash | The generator was executed straight from `spec.md`: hash matches, and the disassembly and vectors are correct. |
| Section 10.6 RFC 8032 vector | An independent Ed25519 implementation reproduces A and R‖S (64 bytes). It also rejects the rev 0.2 65-byte string and passes RFC test 2. |
| Pinouts and wiring for all 43 DIPs | ERC: 0 errors. No undriven inputs, no output-to-output or output-to-rail shorts, and the only three-state-only nets (P_D, C_D) have pull-ups. |
| Placement table, Section 3.3 | 43 rows; row spans match pin counts, columns match package widths, no overlaps. |
| BOM quantities | ICs, digits, and the 3.3 k / 220 Ω / 4.7 k / 10 k / 100 nF / LED counts all match the netlist. |
| Johnson timing, write strobes, read latch | One WR_GPIO_N edge per $7F02 store, exactly one master period before PHI2 falls. C_D is held about 2.66 µs after PHI2 falls. RWB_CYCLE changes only at PHI2 rises. |
| Bus handoff (Section 11.2 items 1–6, 8) | At most one driver on P_D and C_D. P_D gap ≥ 2 master periods, C_D gap ≥ 1. Checked across Monte Carlo seeds at 127, 380 and 890 kHz. |
| Address decode and memory map | Diagnostic loop works. RAM probes at every bank boundary and walking address bit pass. $7F05, $7F02 and $7F0D read $FF; $7F08 mirrors $7F00. |
| Locks and fault (Section 11.4) | Protected writes blocked, FAULT set, FAULT blocks every SRAM write including scratch, panel hardware-blanked, status at $7F01 correct. After FAULT, CPU RESET reaches the ROM-only hold with RAM_WE_N never asserted. Cold clear restores a fresh state. |
| Reset and recovery (Section 10.1) | MESSAGE_LOCK → C0; valid result record → C2, with CRC-32 verified by the 6502 code; corrupted CRC → C1. No SRAM write above $3FFF in any recovery path. |
| Display chain | Shift order, bank split, QA–QH to segment mapping, the SC56-11 pinout and the font table together produce "0123456789AbCdEF". |
| Power and reset sequencing | COLD_CLEAR_N releases before CPU_RESET_N with many PHI2 clocks in between. GPIO is cleared and the display blanked at reset. |
| Arithmetic | Pull-up τ, rise times and slew; VOL current; regulator dissipation; battery end-of-life per cell; LED currents; supervisor margins (460: 200 mV, 475: 50 mV); MCP1x0-460 trip range of 4.35–4.60 V. |

Negative controls show the checks catch real faults. Rev 0.2-style OE wiring and an always-enabled write buffer are flagged as contention. Removing the reset qualification of EARLY_OK lets writes through during reset. A 16 MHz master produces timing violations.

## Limits of this verification

- The simulation is digital with ideal edges. It cannot assess ringing, ground bounce, the 5 ns PHI2 edge, supply droop or HCT input-transition behavior. The Section 11.2 oscilloscope checks are still required.
- Delays are representative datasheet ranges (`sim/timing.py`). Minimums are guesses, because most datasheets do not give them.
- The oscillator, supervisor, reset RC, switches and keys are behavioral. Their analog behavior is covered by closed-form calculation in `sim/analog.py`.
- The test ROM is test firmware only. No signing firmware exists to verify. For speed, the boot ROM zeroes $0000–$03FF; `boot_rom(zero_end_page=0x40)` builds the spec-compliant $0000–$3FFF version.
- The Solana and Squads sections (Section 10.5) and the live-key requirements (Section 12) are protocol and process material, outside a circuit simulation.
