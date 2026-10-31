# DTS-02: 65C02 Ed25519 desktop signer, with a simulation of the design

`spec.md` is the DTS-02 revision 0.5 breadboard specification. DTS-02 is a small 65C02 computer meant to be a third, offline Ed25519 signer in a 2-of-3 Squads multisig. It is built from:

- a W65C02S CPU
- a 32 KiB SRAM and a 32 KiB OTP ROM
- 74HC/HCT glue logic
- a 4×4 membrane keypad and pushbuttons
- sixteen raw seven-segment digits driven by two daisy-chained MAX7219 LED drivers
- hardware message and result bank locks, plus a fault latch

The spec covers the circuit, the breadboard layout, the bring-up plan and the firmware contract. It does not include signing firmware.

The `sim/` directory is a pure-Python (standard library only) simulation used to verify the spec. `FINDINGS.md` reports what the verification found.

## What the simulation models

- **Every IC at pin level.** `sim/board.py` copies the spec's DIP pin tables, so a wrong pin number in the spec becomes a wrong connection in the simulator. Models exist for HCT74, HCT541, HCT573, HCT138, HCT157, HCT273, HCT244, the MAX7219, the gate packages, the AS6C62256 SRAM, the AT27C256R EPROM, the SC56-11 digit, the display power switch, Schottky row diodes and a 4×4 keypad matrix (with ghosting).
- **Event-driven timing with three-state nets.** Signals take the values 0/1/X/Z. Each part instance gets a fixed propagation delay drawn from datasheet ranges (`sim/timing.py`), so different seeds give a Monte Carlo spread of path skews.
- **Checks that run automatically:**
  - bus contention (two drivers enabled on one net)
  - setup and hold at every flip-flop, latch, SRAM write and CPU read
  - invalid or floating samples
  - write-pulse width
  - address changes during a write
  - RESB held for fewer than two clocks
- **Pull-ups as an RC.** A released bus line stays indeterminate until it crosses the worst receiver threshold.
- **The CPU.** A cycle-accurate W65C02S bus model, including dummy reads and reset sequence, with tADS, tMDS, tDHW, tDSR and tDHR timing.
- **Firmware.**
  - The spec's own Section 11.3 diagnostic ROM, taken directly from the Python block in `spec.md`.
  - A test ROM (`sim/firmware.py`, built by `sim/asm.py`) that implements the spec's Section 10.1 boot and reset state machine and a display driver. On a fresh start it runs the test scenario the harness writes to the RAM mailbox at $3F80.
- **Signing firmware.** `sim/signer_fw.py` is an Ed25519 signer in 65C02 assembly that implements spec Sections 10.2–10.4: constant time for secrets, double signature, on-device verification, CRC'd result record and bank locks. It runs on a C emulator (`sim/emu65.c`, built automatically with `cc`) at hundreds of millions of cycles per second, and is checked against Python RFC 8032 and OpenSSL on real Solana transfer messages. Both CPU models pass Klaus Dormann's 6502/65C02 conformance tests with identical cycle counts.
- **Brownout.** `sim/brownout.py` injects supervisor resets into SRAM write strobes.
- **Static checks.** An electrical rule check of the netlist, a re-check of the Section 3.3 placement table, BOM quantities against the netlist, a closed-form analog analysis (`sim/analog.py`), and an independent RFC 8032 implementation (`sim/ed25519_ref.py`).

**The breadboard itself.** `sim/layout.py` places every IC per Section 3.3 and every passive part into a specific hole, then routes every net as point-to-point jumpers. The result is `wiring/WIRING.md`, a hole-by-hole build list. The netlist is then rebuilt from physical connectivity alone (5-hole strips, split rails, wires) and checked for shorts, opens, hole budget, harness rules and wire lengths. The simulator can run on this physical netlist (`Bench(physical=...)`), and tests inject typical build mistakes to confirm they're caught.

Some parts are behavioral stand-ins: the RC oscillator, the MCP130 supervisor, the reset RC, the display power switch, the keypad and the pushbuttons. The MAX7219 is modelled at register level (shift register, LOAD latch, power-up state) rather than as its 800 Hz multiplex scan. The simulation is digital. It does not cover ringing, ground bounce, edge rates or supply droop, which still need the oscilloscope checks in Section 11.2 of the spec.

## Running it

Requires Python 3.9 or later and a C compiler (`cc`) for the fast emulator. `python3 -m sim sign` and its tests also need the `openssl` CLI.

```sh
python3 -m sim check                        # static, document and analog checks (seconds)
python3 -m sim diag --columns 0x5          # run the spec's diagnostic ROM; press keypad keys in columns 1 and 3
python3 -m sim run font                     # boot the test ROM in a scenario (written to the $3F80 mailbox)
python3 -m sim run msg_fault --reset        # lock, fault, then press CPU RESET
python3 -m sim handoff                      # Section 11.2 bus-handoff measurements
python3 -m sim race                         # worst-case read-window corner: rev 0.3 vs rev 0.4
python3 -m sim wiring                       # regenerate wiring/WIRING.md + wiring.csv (hole-level build list) and check it
python3 -m sim sign --lamports 5000         # sign a Solana transfer on the emulated 65C02, check vs RFC 8032 + OpenSSL
python3 -m sim roms                         # write the prototype ROM images + SHA256SUMS to roms/
./tools/fetch_klaus.sh                      # optional: fetch Klaus Dormann's CPU test ROMs for tests/test_emu.py
python3 -m unittest discover -s tests -v    # full test suite: 100 tests, about 20 minutes
```

Scenarios for `run`: `idle`, `ram`, `msg_fault`, `res_fault`, `msg_frozen`, `record_ok`, `record_bad`, `mirrors`, `font` (`keypad` runs an endless key-echo loop and is driven from `tests/test_system.py`).

Options shared by `run`, `diag`, `handoff` and `race`:
- `--freq KHZ`: master clock, default 380
- `--seed N`: delay Monte Carlo draw
- `--rev03`: simulate the revision 0.3 wiring instead (to reproduce the findings that led to rev 0.4)
- `--vcd out.vcd`: write a waveform you can open in GTKWave

Throughput is about 1,500 simulated CPU cycles per second.

## Prototype ROMs

`python3 -m sim roms` writes the images to burn into the AT27C256R, with `roms/SHA256SUMS`. Read back all 32,768 bytes after programming and compare.

1. `DTS02_bus_diagnostic_32KiB.bin`: the spec's Section 11.3 bus diagnostic, for the first bring-up stage. It copies keypad port $7F00 to $0200 forever, with the display off.
2. `DTS02_test_rom_32KiB.bin`: the Section 10.1 boot state machine plus test scenarios. After a fresh start it shows `--0`. Press a digit to choose a scenario, then ENTER:

| Key | Scenario | What you should see |
|---|---|---|
| 0 | idle | Blank panel; FAULT/locks off |
| 1 | RAM test | Blank; RAM probes written (check with a logic analyzer) |
| 2 | message lock, then protected writes | Font page, then the panel goes dark (display power cut); red FAULT and yellow MESSAGE_LOCK LEDs on. CPU RESET stays in the fault hold |
| 3 | result lock, then protected write | FAULT and RESULT_LOCK LEDs on |
| 4 | freeze a message | MESSAGE_LOCK on; press CPU RESET and the panel shows `C0` |
| 5 / 6 | write a result record (valid / bad CRC), lock | RESULT_LOCK on; CPU RESET shows `C2` / `C1` |
| 7 | I/O mirrors | MESSAGE_LOCK on (set through mirror $7F0B) |
| 8 | font page | `0123456789AbCdEF` |
| 9 | keypad echo | Typed hex keys scroll in from the right (`*` = E, `#` = F) |

A cold clear (power cycle) returns to the menu. The signing ROM is not burnable yet: it has no keypad entry or review UI.

## Layout

```
spec.md            the design under test (rev 0.4; rev 0.3 is in git history)
FINDINGS.md        verification results and recommended changes
wiring/WIRING.md   generated hole-level breadboard build list (also wiring.csv)
sim/engine.py      event kernel, nets, contention and timing checks
sim/parts.py       pin-level IC models
sim/cpu65c02.py    W65C02S core (full instruction set) and bus-timing wrapper
sim/board.py       netlist transcribed from spec.md, plus fault-injection variants
sim/firmware.py    boot/test ROM source (Section 10.1 state machine, display driver, CRC-32)
sim/asm.py         two-pass 65C02 assembler (full instruction set, range-checked)
sim/analog.py      oscillator, reset RC, pull-up, power and display arithmetic
sim/checks.py      ERC, placement, BOM, waveform measurement helpers
sim/handoff.py     Section 11.2 measurements
sim/corners.py     forced worst-case delay corners
sim/layout.py      hole-level layout, jumper routing, physical connectivity
sim/signer_fw.py   Ed25519 signing firmware generator (65C02 assembly)
sim/emu65.c        fast C W65C02S emulator with the spec's I/O, locks and fault (sim/emu.py wraps it)
sim/solana.py      Solana legacy message construction, OpenSSL cross-check
sim/brownout.py    power-dip injection
tests/             unittest suite
```
