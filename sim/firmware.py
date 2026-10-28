"""Test firmware for the DTS-02 simulation.

boot_rom() implements the spec's Section 10.1 boot/reset state machine and,
on a fresh start, runs the test scenario whose number the harness wrote to
the RAM mailbox $3F80 (simulation), or that the operator selects on the
keypad: digit 0-9, then ENTER (real hardware).  This is test firmware for the
hardware model, not signing firmware.
"""

import hashlib
import zlib

from .asm import assemble

FONT = [0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07,
        0x7F, 0x6F, 0x77, 0x7C, 0x39, 0x5E, 0x79, 0x71]
GLYPH_C = 0x39

# RFC 8032 section 7.1 test 1 (public fixture; Section 10.6)
RFC_A = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

SCENARIOS = {
    "idle": 0, "ram": 1, "msg_fault": 2, "res_fault": 3, "msg_frozen": 4,
    "record_ok": 5, "record_bad": 6, "mirrors": 7, "font": 8, "keypad": 9,
}


def result_record(corrupt_crc=False):
    """256-byte public result record of Section 10.4 for the empty message."""
    r = bytearray(256)
    r[0:8] = b"DTS02OUT"
    r[8] = 1
    r[9] = 0
    r[10:12] = (0).to_bytes(2, "little")
    r[0x0C:0x2C] = RFC_A
    r[0x2C:0x6C] = RFC_SIG
    r[0x6C:0xAC] = hashlib.sha512(b"").digest()
    crc = zlib.crc32(bytes(r[0:0xAC])) & 0xFFFFFFFF
    r[0xAC:0xB0] = crc.to_bytes(4, "little")
    if corrupt_crc:
        r[0xAC] ^= 0xFF
    return bytes(r)


def crc_tables():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        t.append(c)
    return [bytes((v >> (8 * k)) & 0xFF for v in t) for k in range(4)]


def _bytes(b):
    return "\n".join("        .byte " + ", ".join(f"${x:02X}" for x in b[i:i + 16])
                     for i in range(0, len(b), 16))


BOOT_SRC = r"""
GPIO   = $7F02
STATUS = $7F01
SWITCH = $7F00
SETMSG = $7F03
SETRES = $7F04
MAILBOX = $3F80         ; harness: "DTS02SIM" at $3F80-$3F87, scenario at $3F88
SEL    = $2C            ; keypad menu selection
ENTCNT = $2D            ; ENTER debounce count
GSH    = $20            ; GPIO shadow: DISPLAY_ENABLE + idle keypad rows
MXA    = $21            ; MAX7219 word being sent (address, data)
MXD    = $22
MXA2   = $24            ; second chip's word (U22 receives first)
MXD2   = $25
CVT    = $26
KCNT   = $27
KRES   = $28
KLAST  = $29
KSTAB  = $2A
KBUF   = $30            ; 16 entered nibbles (zero page $30-$3F)
GPIO_IDLE = $DC         ; D6 DISPLAY_ENABLE, D7/D4/D3/D2 keypad rows released
ERRS   = $0F            ; zero-page error counter

        .org $8000
; ---------------- Section 10.1 steps 1-3: registers and I/O only ----------
reset:  SEI
        CLD
        LDX #$FF
        TXS
        LDA #$00
        STA GPIO
        LDA STATUS
        BMI hold                ; bit 7 FAULT -> ROM-only hold loop
        JMP selftest
hold:   JMP hold                ; no SRAM access, no stack

; ---------------- step 4: stack self-test, absolute stores only ------------
selftest:
        LDA #$AA
        STA $0100
        LDA #$55
        STA $01FF
        LDA $0100
        CMP #$AA
        BNE hold
        LDA $01FF
        CMP #$55
        BNE hold
        LDA #$55
        STA $0100
        LDA #$AA
        STA $01FF
        LDA $0100
        CMP #$55
        BNE hold
        LDA $01FF
        CMP #$AA
        BNE hold
        ; re-dispatch on the (unchanged) lock state
        LDA STATUS
        BMI hold
        ASL A
        BMI to_review
        ASL A
        BMI to_abort
        JMP fresh
to_review: JMP review
to_abort:  JMP abort

; ---------------- abort state (0 0 1): code C0, read-only above $3FFF -------
abort:  JSR display_init
        LDA #$3F                ; '0'
        JSR show_code
idle:   JMP idle

; ---------------- review state (0 1 x): verify record, C2 / C1 ------------
review: JSR display_init
        LDX #0
rv_mag: LDA $6000,X
        CMP magic,X
        BNE rv_bad
        INX
        CPX #8
        BNE rv_mag
        LDA $6008
        CMP #1
        BNE rv_bad
        ; CRC-32/IEEE over $6000-$60AB, table driven, state in $08-$0B
        LDA #$FF
        STA $08
        STA $09
        STA $0A
        STA $0B
        LDY #0
rv_crc: LDA $6000,Y
        EOR $0008
        TAX
        LDA $0009
        EOR crc0,X
        STA $08
        LDA $000A
        EOR crc1,X
        STA $09
        LDA $000B
        EOR crc2,X
        STA $0A
        LDA crc3,X
        STA $0B
        INY
        CPY #$AC
        BNE rv_crc
        LDA $0008
        EOR #$FF
        CMP $60AC
        BNE rv_bad
        LDA $0009
        EOR #$FF
        CMP $60AD
        BNE rv_bad
        LDA $000A
        EOR #$FF
        CMP $60AE
        BNE rv_bad
        LDA $000B
        EOR #$FF
        CMP $60AF
        BNE rv_bad
        LDA #$5B                ; '2'
        JSR show_code
        JMP idle
rv_bad: LDA #$06                ; '1'
        JSR show_code
        JMP idle

; ---------------- step 5: fresh start ------------------------------------
fresh:  LDA #0
        TAX
fz0:    STA $0000,X
        INX
        BNE fz0
        LDA #1
        STA $0D
        LDA #0
        STA $0C
        TAY
fz1:    STA ($0C),Y
        INY
        BNE fz1
        INC $0D
        LDX $0D
        CPX #ZERO_END
        BNE fz1
        JSR display_init
        LDX #7                  ; simulation harness mailbox present?
mbx:    LDA MAILBOX,X
        CMP simmagic,X
        BNE menu
        DEX
        BPL mbx
        LDA MAILBOX+8
        JMP dispatch

; ---------------- keypad menu: digit 0-9 selects, ENTER runs ----------------
menu:   STZ SEL
        STZ ENTCNT
        LDA #$FF
        STA KLAST
        STZ KSTAB
        JSR show_menu
mn_loop: JSR kscan
        CMP KLAST
        BEQ mn_same
        STA KLAST
        STZ KSTAB
        JMP mn_ent
mn_same: INC KSTAB
        LDA KSTAB
        CMP #3                  ; accept a key after 3 identical scans, once
        BNE mn_ent
        LDA KLAST
        CMP #10
        BCS mn_ent              ; A-F, none or several keys: ignored
        STA SEL
        JSR show_menu
mn_ent: LDA STATUS              ; ENTER is $7F01 bit 0
        AND #$01
        BEQ mn_rel
        INC ENTCNT
        LDA ENTCNT
        CMP #3
        BNE mn_loop
        LDA SEL
        JMP dispatch
mn_rel: STZ ENTCNT
        JMP mn_loop

show_menu:                      ; "--n" with n the selected scenario
        LDA #$40
        STA $10
        STA $11
        LDY SEL
        LDA font,Y
        STA $12
        LDX #3
        LDA #0
smz:    STA $10,X
        INX
        CPX #16
        BNE smz
        JMP show_page

dispatch:
        STA $07
        CMP #1
        BNE d2
        JMP sc_ram
d2:     CMP #2
        BNE d3
        JMP sc_msg_fault
d3:     CMP #3
        BNE d4
        JMP sc_res_fault
d4:     CMP #4
        BNE d5
        JMP sc_msg_frozen
d5:     CMP #5
        BNE d6
        JMP sc_record
d6:     CMP #6
        BNE d7
        JMP sc_record
d7:     CMP #7
        BNE d8
        JMP sc_mirrors
d8:     CMP #8
        BNE d9
        JMP sc_font
d9:     CMP #9
        BNE d10
        JMP sc_keypad
d10:    JMP done

done:   JMP done

; ---------------- scenario 1: RAM address/data test ------------------------
sc_ram: LDX #0
rw_w:   LDA ramtab,X
        STA $0C
        LDA ramtab+1,X
        STA $0D
        TXA
        EOR #$A5
        LDY #0
        STA ($0C),Y
        INX
        INX
        CPX #RAMTAB_LEN
        BNE rw_w
        LDX #0
rw_r:   LDA ramtab,X
        STA $0C
        LDA ramtab+1,X
        STA $0D
        TXA
        EOR #$A5
        STA $0E
        LDY #0
        LDA ($0C),Y
        CMP $000E
        BEQ rw_ok
        INC ERRS
rw_ok:  INX
        INX
        CPX #RAMTAB_LEN
        BNE rw_r
        ; walking data bits through one cell, plus JSR/RTS stack traffic
        LDA #1
wd:     STA $0300
        STA $0E
        LDA $0300
        CMP $000E
        BEQ wd_ok
        INC ERRS
wd_ok:  JSR nop_sub
        LDA $000E
        ASL A
        BNE wd
        LDA $000F
        STA $0280
        JMP done
nop_sub: PHA
        PLA
        RTS

; ---------------- scenario 2: message lock, then protected writes ----------
sc_msg_fault:
        JSR show_font
        LDA #$11
        STA $4000
        LDA #$12
        STA $5FFF
        LDA #$13
        STA $6000
        LDA #$14
        STA $7EFF
        STA SETMSG
        LDA #$99
        STA $4000               ; blocked, sets FAULT
        LDA #$98
        STA $5FFF               ; blocked
        LDA #$97
        STA $6000               ; unlocked bank but FAULT blocks every write
        LDA #$77
        STA $0300               ; scratch blocked
        LDA #$40
        STA GPIO                ; try to enable display: hardware blank
        LDA STATUS
        JMP done

; ---------------- scenario 3: result lock ---------------------------------
sc_res_fault:
        STA SETRES
        LDA #$21
        STA $4000               ; message bank still writable
        LDA #$22
        STA $5FFF
        LDA #$00
        STA GPIO                ; I/O write with RESULT_LOCK set: no fault
        STA $7F05               ; reserved port: no fault
        LDA STATUS
        STA $0281
        LDA #$23
        STA $6000               ; blocked, FAULT
        LDA #$24
        STA $7EFF
        LDA STATUS
        JMP done

; ---------------- scenario 4: freeze a message, wait for CPU RESET --------
sc_msg_frozen:
        LDX #0
mf:     LDA magic,X
        STA $4000,X
        INX
        CPX #8
        BNE mf
        LDA #8
        STA $5000
        STA SETMSG
        JMP done

; ---------------- scenarios 5/6: write result record, lock -----------------
sc_record:
        LDY #0
rc:     LDA record,Y
        STA $6000,Y
        INY
        BNE rc
        LDA $07
        CMP #6
        BNE rc_lock
        LDA $60AC
        EOR #$FF
        STA $60AC               ; corrupt the CRC before locking
rc_lock: STA SETRES
        JMP done

; ---------------- scenario 7: mirrors and undriven reads -------------------
sc_mirrors:
        LDA $7F08
        STA $0282
        LDA SWITCH
        STA $0283
        LDA $7F05
        STA $0284
        LDA GPIO
        STA $0285
        LDA $7F0D
        STA $0286
        STA $7F0B               ; mirror of $7F03: sets MESSAGE_LOCK
        LDA STATUS
        STA $0287
        JMP done

; ---------------- scenario 8: font page ------------------------------------
sc_font:
        JSR show_font
        JMP done

show_font:
        LDX #0
sf:     LDA font,X
        STA $0010,X
        INX
        CPX #16
        BNE sf
        JMP show_page

; ---------------- display driver: two MAX7219 in a chain (Section 8) -------
display_init:
        LDA #GPIO_IDLE
        STA GSH
        STA GPIO                ; switch the display rail on
        LDX #0
di_w:   NOP
        DEX
        BNE di_w                ; let DISP_V settle
        LDA #$0C
        LDX #$00
        JSR mx_both             ; shutdown (also the power-up state)
        LDA #$0F
        LDX #$00
        JSR mx_both             ; display test off
        LDA #$09
        LDX #$00
        JSR mx_both             ; no Code-B decode: raw segments
        LDA #$0B
        LDX #$07
        JSR mx_both             ; scan all 8 digits
        LDA #$0A
        LDX #$08
        JSR mx_both             ; intensity 9/32
        LDA #1
        STA $0E
di_d:   LDA $0E
        LDX #$00
        JSR mx_both             ; blank every digit register before display-on
        INC $0E
        LDA $0E
        CMP #9
        BNE di_d
        LDA #$0C
        LDX #$01
        JMP mx_both             ; normal operation

mx_both:                        ; same command (A = register, X = data) to both chips
        STA MXA
        STA MXA2
        STX MXD
        STX MXD2
mx_pair:                        ; U22 word (MXA2/MXD2) then U21 word (MXA/MXD), then LOAD
        LDA MXA2
        JSR mx_byte
        LDA MXD2
        JSR mx_byte
        LDA MXA
        JSR mx_byte
        LDA MXD
        JSR mx_byte
        LDA GSH
        ORA #$20
        STA GPIO                ; LOAD rising edge latches both chips
        LDA GSH
        STA GPIO
        RTS

mx_byte:                        ; shift A out MSB first on DIN (D0), clock on D1
        STA CVT
        LDY #8
mb:     LDA #0
        ASL CVT
        ROL A
        ORA GSH
        STA GPIO                ; DIN set, CLK low
        ORA #$02
        STA GPIO                ; CLK rising: MAX7219 samples DIN
        AND #$FD
        STA GPIO
        DEY
        BNE mb
        RTS

conv:                           ; A: bit0=a..bit6=g, bit7=dp -> MAX7219 D6=a..D0=g, D7=dp
        STA CVT
        LDA #0
        LDY #7
cv:     LSR CVT
        ROL A
        DEY
        BNE cv
        LSR CVT
        BCC cv2
        ORA #$80
cv2:    RTS

show_code:                      ; 'C' + glyph in A on digits 0,1; rest blank
        STA $11
        LDA #$39
        STA $10
        LDX #2
        LDA #0
scl:    STA $0010,X
        INX
        CPX #16
        BNE scl
show_page:                      ; display masks $10..$1F, digit 0 leftmost
        LDA #$0C
        LDX #$00
        JSR mx_both             ; blank while the page changes
        LDA #1
        STA $0E
sp_d:   LDX $0E
        LDA $000F,X             ; digit (n-1) -> U21 register n
        JSR conv
        STA MXD
        LDX $0E
        LDA $0017,X             ; digit (n+7) -> U22 register n
        JSR conv
        STA MXD2
        LDA $0E
        STA MXA
        STA MXA2
        JSR mx_pair
        INC $0E
        LDA $0E
        CMP #9
        BNE sp_d
        LDA #$0C
        LDX #$01
        JMP mx_both

; ---------------- keypad scan: A = key value 0-F, $FF none, $FE several -----
kscan:  STZ KCNT
        LDA #$FF
        STA KRES
        LDX #0
ks_r:   LDA GSH
        AND rowclr,X            ; pull this row's drive low
        STA GPIO
        NOP
        LDA SWITCH              ; columns, active low, in D0-D3
        EOR #$FF
        AND #$0F
        STA CVT
        LDY #0
ks_c:   LSR CVT
        BCC ks_n
        INC KCNT
        TXA
        ASL A
        ASL A
        STA $0E
        TYA
        CLC
        ADC $0E
        TAY
        LDA keyval,Y
        STA KRES
        TYA
        AND #3
        TAY
ks_n:   INY
        CPY #4
        BNE ks_c
        INX
        CPX #4
        BNE ks_r
        LDA GSH
        STA GPIO                ; release the rows
        LDA KCNT
        BEQ ks_none
        CMP #1
        BNE ks_many
        LDA KRES
        RTS
ks_none: LDA #$FF
        RTS
ks_many: LDA #$FE
        RTS

; ---------------- scenario 9: keypad echo -------------------------------------
sc_keypad:
        LDX #15
        LDA #16                 ; blank glyph
kz:     STA KBUF,X
        DEX
        BPL kz
        LDA #$FF
        STA KLAST
        STZ KSTAB
kp_loop: JSR kscan
        CMP KLAST
        BEQ kp_same
        STA KLAST
        STZ KSTAB
        JMP kp_loop
kp_same: LDA KSTAB
        CMP #3
        BCS kp_loop             ; already handled; keep the count from wrapping
        INC KSTAB
        LDA KSTAB
        CMP #3                  ; accept a key after 3 identical scans, once
        BNE kp_loop
        LDA KLAST
        CMP #16
        BCS kp_loop             ; none or several keys
        LDX #0
ksh:    LDA KBUF+1,X
        STA KBUF,X
        INX
        CPX #15
        BNE ksh
        LDA KLAST
        STA KBUF+15
        LDX #15
kr:     LDY KBUF,X
        LDA font,Y
        STA $10,X
        DEX
        BPL kr
        JSR show_page
kp_idle: JMP kp_loop

rowclr: .byte $FB, $F7, $EF, $7F        ; clear D2, D3, D4, D7
keyval: .byte 1, 2, 3, $A, 4, 5, 6, $B, 7, 8, 9, $C, $E, 0, $F, $D
magic:  .byte 'D', 'T', 'S', '0', '2', 'O', 'U', 'T'
simmagic: .byte 'D', 'T', 'S', '0', '2', 'S', 'I', 'M'
font:
{font}
        .byte $00               ; entry 16: blank
ramtab:
{ramtab}
RAMTAB_LEN = {ramtab_len}

        .org $9000
crc0:
{crc0}
crc1:
{crc1}
crc2:
{crc2}
crc3:
{crc3}
record:
{record}

        .org $FFFA
        .word hold, reset, hold
"""

# addresses probed by the RAM scenario: bank boundaries and walking address bits
RAM_PROBES = sorted({0x0300 ^ (1 << k) for k in range(15)} - {0x0100, 0x0200} |
                    {0x0300, 0x3FFF, 0x4000, 0x4FFF, 0x5000, 0x5FFF, 0x6000,
                     0x60FF, 0x6100, 0x7EFF})


def boot_rom(zero_end_page=0x04):
    """Assemble the boot/test ROM.  zero_end_page=$40 zeroes all of
    $0000-$3FFF as the spec requires; the default zeroes $0000-$03FF so the
    gate-level simulation stays fast."""
    t = crc_tables()
    ramtab = "\n".join(f"        .word ${a:04X}" for a in RAM_PROBES)
    src = (BOOT_SRC.replace("{font}", _bytes(FONT))
           .replace("{ramtab}", ramtab)
           .replace("{ramtab_len}", str(2 * len(RAM_PROBES)))
           .replace("{crc0}", _bytes(t[0])).replace("{crc1}", _bytes(t[1]))
           .replace("{crc2}", _bytes(t[2])).replace("{crc3}", _bytes(t[3]))
           .replace("{record}", _bytes(result_record())))
    img, syms = assemble(src, symbols={"ZERO_END": zero_end_page})
    return img, syms
