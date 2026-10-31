/* Fast functional W65C02S emulator for long firmware runs (signing).
 *
 * Mirrors sim/cpu65c02.py instruction semantics and cycle counts (verified
 * by tests/test_emu.py against the Python core and Klaus Dormann's 6502 and
 * 65C02 functional tests).  Memory map and I/O follow spec Section 4:
 * RAM $0000-$7EFF, I/O page $7F00-$7FFF (8 ports, A3-A7 undecoded), ROM
 * $8000-$FFFF.  The bank locks and fault latch follow Section 9.1: a write
 * into a locked bank is blocked and sets FAULT; FAULT blocks every SRAM write.
 *
 * Build: cc -O2 -shared -fPIC -o _emu65.so emu65.c
 */
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t mem[65536];
    uint8_t a, x, y, s, p;
    uint16_t pc;
    uint64_t cycles, instructions;
    uint8_t switches, keys, gpio;
    uint8_t msg_lock, res_lock, fault;
    uint32_t blocked_writes, gpio_writes;
    uint8_t halted;         /* 1 = STP/WAI or stop address reached */
    uint16_t last_pc;
    uint32_t sr[4];         /* MAX7219 shift registers (16 bits used), [0]=U21 [1]=U22 */
    uint32_t st[4];         /* bit0 = out of shutdown, bit1 = decode enabled */
    uint8_t prev_gpio;
    uint64_t trace;
    uint16_t mxdig[2][8];   /* MAX7219 digit registers, 0x100 = undefined */
    uint8_t io_writes[32];  /* bitmap: bit (a & 0xFF) set when $7Fxx is written */         /* FNV-1a over every bus address (instruction fetches,
                               operand/data reads and writes): equal traces mean
                               identical control flow and memory access patterns */
} M;

#define TRACE(m, a) ((m)->trace = ((m)->trace ^ (uint64_t)(a)) * 0x100000001B3ULL)

enum { FN = 0x80, FV = 0x40, FU = 0x20, FB = 0x10, FD = 0x08, FI = 0x04, FZ = 0x02, FC = 0x01 };

static uint8_t rd(M *m, uint16_t a) {
    TRACE(m, a);
    if (a >= 0x7F00 && a < 0x8000) {
        switch (a & 7) {
        case 0: return m->switches;
        case 1: return (m->keys & 0x1F) | (m->msg_lock << 5) | (m->res_lock << 6) | (m->fault << 7);
        default: return 0xFF;
        }
    }
    return m->mem[a];
}

/* GPIO $7F02 (spec rev 0.5): D0 DIN, D1 CLK, D5 LOAD, D6 DISPLAY_ENABLE (power),
 * D2/D3/D4/D7 keypad rows.  Two MAX7219 in a chain: sr[0] = U21, sr[1] = U22. */
static void mx_reset(M *m) {
    int c, i;
    for (c = 0; c < 2; c++) {
        m->sr[c] = 0;
        m->st[c] = 0;                /* bit0 = shutdown released */
        for (i = 0; i < 8; i++) m->mxdig[c][i] = 0x100;   /* undefined */
    }
}

static void gpio_write(M *m, uint8_t v) {
    uint8_t old = m->prev_gpio;
    int c;
    m->gpio = v;
    m->gpio_writes++;
    if (!(v & 0x40) || m->fault) {               /* display unpowered */
        mx_reset(m);
        m->prev_gpio = v;
        return;
    }
    if (!(old & 0x02) && (v & 0x02)) {           /* CLK rising: shift U21 -> U22 */
        uint32_t out21 = (m->sr[0] >> 15) & 1;
        m->sr[1] = ((m->sr[1] << 1) | out21) & 0xFFFF;
        m->sr[0] = ((m->sr[0] << 1) | (v & 1)) & 0xFFFF;
    }
    if (!(old & 0x20) && (v & 0x20)) {           /* LOAD rising: latch both */
        for (c = 0; c < 2; c++) {
            int addr = (m->sr[c] >> 8) & 0xF, data = m->sr[c] & 0xFF;
            if (addr >= 1 && addr <= 8) m->mxdig[c][addr - 1] = data;
            else if (addr == 0xC) m->st[c] = (m->st[c] & ~1u) | (data & 1);
            else if (addr == 0x9) m->st[c] = (m->st[c] & ~2u) | (data ? 2 : 0);
        }
    }
    m->prev_gpio = v;
}

static void wr(M *m, uint16_t a, uint8_t v) {
    TRACE(m, a | 0x10000);
    if (a >= 0x8000) return;
    if (a >= 0x7F00) {
        m->io_writes[(a & 0xFF) >> 3] |= (uint8_t)(1u << (a & 7));
        switch (a & 7) {
        case 2: gpio_write(m, v); break;
        case 3: m->msg_lock = 1; break;
        case 4: m->res_lock = 1; break;
        }
        return;
    }
    if (a >= 0x4000) {
        uint8_t lock = (a & 0x2000) ? m->res_lock : m->msg_lock;
        if (lock) {
            m->fault = 1;
            mx_reset(m);             /* FAULT removes display power independently of GPIO. */
            m->blocked_writes++;
            return;
        }
    }
    if (m->fault) { m->blocked_writes++; return; }
    m->mem[a] = v;
}

#define NZ(v) do { uint8_t _v = (v); m->p = (m->p & ~(FN | FZ)) | (_v & FN) | (_v ? 0 : FZ); } while (0)

static uint8_t fetch(M *m) { return rd(m, m->pc++); }

static void push(M *m, uint8_t v) { wr(m, 0x100 | m->s, v); m->s--; }
static uint8_t pull(M *m) { m->s++; return rd(m, 0x100 | m->s); }

/* modes */
enum { IMP, IMM, ZP, ZPX, ZPY, ABS, ABX, ABY, INX, INY, INZ, ACC, REL, IND, IAX, ZPR };
/* operation classes */
enum { O_LDA, O_LDX, O_LDY, O_AND, O_ORA, O_EOR, O_CMP, O_CPX, O_CPY, O_BIT, O_ADC, O_SBC,
       O_STA, O_STX, O_STY, O_STZ,
       O_ASL, O_LSR, O_ROL, O_ROR, O_INC, O_DEC, O_TSB, O_TRB,
       O_RMB, O_SMB, O_BBR, O_BBS, O_BR, O_JMP, O_JSR, O_RTS, O_RTI, O_BRK,
       O_PHA, O_PHP, O_PHX, O_PHY, O_PLA, O_PLP, O_PLX, O_PLY, O_NOP, O_STOP, O_IMPL };

typedef struct { uint8_t op, mode, arg, nb, nc; } Ent;   /* arg: bit no / branch cond / implied id */
static Ent T[256];
static int inited = 0;

static void set(int code, int op, int mode, int arg) { T[code].op = op; T[code].mode = mode; T[code].arg = arg; }

static void init(void) {
    static const struct { int op; int codes[9]; } alu[] = {
        {O_ORA, {0x09, 0x05, 0x15, 0x0D, 0x1D, 0x19, 0x01, 0x11, 0x12}},
        {O_AND, {0x29, 0x25, 0x35, 0x2D, 0x3D, 0x39, 0x21, 0x31, 0x32}},
        {O_EOR, {0x49, 0x45, 0x55, 0x4D, 0x5D, 0x59, 0x41, 0x51, 0x52}},
        {O_ADC, {0x69, 0x65, 0x75, 0x6D, 0x7D, 0x79, 0x61, 0x71, 0x72}},
        {O_LDA, {0xA9, 0xA5, 0xB5, 0xAD, 0xBD, 0xB9, 0xA1, 0xB1, 0xB2}},
        {O_CMP, {0xC9, 0xC5, 0xD5, 0xCD, 0xDD, 0xD9, 0xC1, 0xD1, 0xD2}},
        {O_SBC, {0xE9, 0xE5, 0xF5, 0xED, 0xFD, 0xF9, 0xE1, 0xF1, 0xF2}},
    };
    static const int am[9] = {IMM, ZP, ZPX, ABS, ABX, ABY, INX, INY, INZ};
    int i, k;
    for (i = 0; i < 256; i++) { set(i, O_NOP, IMP, 0); T[i].nb = 1; T[i].nc = 1; }
    for (i = 0; i < 7; i++) for (k = 0; k < 9; k++) set(alu[i].codes[k], alu[i].op, am[k], 0);
    {   int c[8] = {0x85, 0x95, 0x8D, 0x9D, 0x99, 0x81, 0x91, 0x92};
        int md[8] = {ZP, ZPX, ABS, ABX, ABY, INX, INY, INZ};
        for (k = 0; k < 8; k++) set(c[k], O_STA, md[k], 0); }
    {   int ops[4] = {O_ASL, O_ROL, O_LSR, O_ROR}, base[4] = {0x00, 0x20, 0x40, 0x60};
        for (k = 0; k < 4; k++) {
            set(base[k] + 0x0A, ops[k], ACC, 0); set(base[k] + 0x06, ops[k], ZP, 0);
            set(base[k] + 0x16, ops[k], ZPX, 0); set(base[k] + 0x0E, ops[k], ABS, 0);
            set(base[k] + 0x1E, ops[k], ABX, 0);
        } }
    set(0x86, O_STX, ZP, 0); set(0x96, O_STX, ZPY, 0); set(0x8E, O_STX, ABS, 0);
    set(0xA2, O_LDX, IMM, 0); set(0xA6, O_LDX, ZP, 0); set(0xB6, O_LDX, ZPY, 0);
    set(0xAE, O_LDX, ABS, 0); set(0xBE, O_LDX, ABY, 0);
    set(0xC6, O_DEC, ZP, 0); set(0xD6, O_DEC, ZPX, 0); set(0xCE, O_DEC, ABS, 0); set(0xDE, O_DEC, ABX, 0);
    set(0xE6, O_INC, ZP, 0); set(0xF6, O_INC, ZPX, 0); set(0xEE, O_INC, ABS, 0); set(0xFE, O_INC, ABX, 0);
    set(0x84, O_STY, ZP, 0); set(0x94, O_STY, ZPX, 0); set(0x8C, O_STY, ABS, 0);
    set(0xA0, O_LDY, IMM, 0); set(0xA4, O_LDY, ZP, 0); set(0xB4, O_LDY, ZPX, 0);
    set(0xAC, O_LDY, ABS, 0); set(0xBC, O_LDY, ABX, 0);
    set(0xC0, O_CPY, IMM, 0); set(0xC4, O_CPY, ZP, 0); set(0xCC, O_CPY, ABS, 0);
    set(0xE0, O_CPX, IMM, 0); set(0xE4, O_CPX, ZP, 0); set(0xEC, O_CPX, ABS, 0);
    set(0x89, O_BIT, IMM, 0); set(0x24, O_BIT, ZP, 0); set(0x34, O_BIT, ZPX, 0);
    set(0x2C, O_BIT, ABS, 0); set(0x3C, O_BIT, ABX, 0);
    set(0x64, O_STZ, ZP, 0); set(0x74, O_STZ, ZPX, 0); set(0x9C, O_STZ, ABS, 0); set(0x9E, O_STZ, ABX, 0);
    set(0x04, O_TSB, ZP, 0); set(0x0C, O_TSB, ABS, 0); set(0x14, O_TRB, ZP, 0); set(0x1C, O_TRB, ABS, 0);
    set(0x4C, O_JMP, ABS, 0); set(0x6C, O_JMP, IND, 0); set(0x7C, O_JMP, IAX, 0);
    set(0x20, O_JSR, ABS, 0); set(0x60, O_RTS, IMP, 0); set(0x40, O_RTI, IMP, 0); set(0x00, O_BRK, IMP, 0);
    set(0x48, O_PHA, IMP, 0); set(0x08, O_PHP, IMP, 0); set(0xDA, O_PHX, IMP, 0); set(0x5A, O_PHY, IMP, 0);
    set(0x68, O_PLA, IMP, 0); set(0x28, O_PLP, IMP, 0); set(0xFA, O_PLX, IMP, 0); set(0x7A, O_PLY, IMP, 0);
    set(0xCB, O_STOP, IMP, 0); set(0xDB, O_STOP, IMP, 0);
    {   /* implied ids */
        int c[] = {0xE8, 0xC8, 0xCA, 0x88, 0xAA, 0x8A, 0xA8, 0x98, 0x9A, 0xBA, 0x78, 0x58, 0xF8,
                   0xD8, 0x38, 0x18, 0xB8, 0x1A, 0x3A};
        for (k = 0; k < (int)(sizeof c / sizeof c[0]); k++) set(c[k], O_IMPL, IMP, k); }
    {   int c[] = {0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0, 0x80};
        for (k = 0; k < 9; k++) set(c[k], O_BR, REL, k); }
    for (k = 0; k < 8; k++) {
        set(0x07 + 0x10 * k, O_RMB, ZP, k); set(0x87 + 0x10 * k, O_SMB, ZP, k);
        set(0x0F + 0x10 * k, O_BBR, ZPR, k); set(0x8F + 0x10 * k, O_BBS, ZPR, k);
    }
    /* NOP shapes */
    T[0xEA].nb = 1; T[0xEA].nc = 2;
    { int c[] = {0x02, 0x22, 0x42, 0x62, 0x82, 0xC2, 0xE2};
      for (k = 0; k < 7; k++) { T[c[k]].nb = 2; T[c[k]].nc = 2; } }
    T[0x44].nb = 2; T[0x44].nc = 3;
    T[0x54].nb = 2; T[0x54].nc = 4; T[0xD4].nb = 2; T[0xD4].nc = 4; T[0xF4].nb = 2; T[0xF4].nc = 4;
    T[0x5C].nb = 3; T[0x5C].nc = 8; T[0xDC].nb = 3; T[0xDC].nc = 4; T[0xFC].nb = 3; T[0xFC].nc = 4;
    inited = 1;
}

/* effective address; returns cycles beyond the opcode fetch */
static uint16_t ea(M *m, int mode, int kind, int *cyc) {
    uint16_t b, e; uint8_t z;
    switch (mode) {
    case ZP: *cyc += 1; return fetch(m);
    case ZPX: *cyc += 2; return (uint8_t)(fetch(m) + m->x);
    case ZPY: *cyc += 2; return (uint8_t)(fetch(m) + m->y);
    case ABS: *cyc += 2; b = fetch(m); b |= fetch(m) << 8; return b;
    case ABX: case ABY:
        *cyc += 2; b = fetch(m); b |= fetch(m) << 8;
        e = b + (mode == ABX ? m->x : m->y);
        if (kind == 'w' || kind == '7' || ((e ^ b) & 0xFF00)) *cyc += 1;
        return e;
    case INX:
        *cyc += 4; z = fetch(m) + m->x;
        return rd(m, z) | (rd(m, (uint8_t)(z + 1)) << 8);
    case INY:
        *cyc += 3; z = fetch(m);
        b = rd(m, z) | (rd(m, (uint8_t)(z + 1)) << 8);
        e = b + m->y;
        if (kind == 'w' || ((e ^ b) & 0xFF00)) *cyc += 1;
        return e;
    case INZ:
        *cyc += 3; z = fetch(m);
        return rd(m, z) | (rd(m, (uint8_t)(z + 1)) << 8);
    }
    return 0;
}

static void cmpf(M *m, uint8_t r, uint8_t v) {
    m->p = (m->p & ~FC) | (r >= v ? FC : 0); NZ(r - v);
}

static int adc(M *m, uint8_t v) {
    int a = m->a, c = m->p & FC;
    if (!(m->p & FD)) {
        int r = a + v + c, ov = (~(a ^ v) & (a ^ r)) & 0x80;
        m->p = (m->p & ~(FC | FV)) | (r > 0xFF ? FC : 0) | (ov ? FV : 0);
        m->a = r; NZ(m->a); return 0;
    } else {
        int al = (a & 0x0F) + (v & 0x0F) + c, r, sa, sv, sr;
        if (al >= 0x0A) al = ((al + 0x06) & 0x0F) + 0x10;
        r = (a & 0xF0) + (v & 0xF0) + al;
        sa = (a & 0xF0) - ((a & 0x80) ? 0x100 : 0);
        sv = (v & 0xF0) - ((v & 0x80) ? 0x100 : 0);
        sr = sa + sv + al;
        if (r >= 0xA0) r += 0x60;
        m->p = (m->p & ~(FC | FV)) | (r >= 0x100 ? FC : 0) | ((sr < -128 || sr > 127) ? FV : 0);
        m->a = r; NZ(m->a); return 1;
    }
}

static int sbc(M *m, uint8_t v) {
    int a = m->a, c = m->p & FC, r = a - v - (1 - c), ov = ((a ^ v) & (a ^ r)) & 0x80;
    m->p = (m->p & ~(FC | FV)) | (r >= 0 ? FC : 0) | (ov ? FV : 0);
    if (!(m->p & FD)) { m->a = r; NZ(m->a); return 0; }
    {   int al = (a & 0x0F) - (v & 0x0F) + c - 1;
        if (r < 0) r -= 0x60;
        if (al < 0) r -= 0x06;
        m->a = r; NZ(m->a); return 1; }
}

static uint8_t rmw(M *m, int op, uint8_t v) {
    uint8_t c;
    switch (op) {
    case O_ASL: m->p = (m->p & ~FC) | (v >> 7); v <<= 1; NZ(v); return v;
    case O_LSR: m->p = (m->p & ~FC) | (v & 1); v >>= 1; NZ(v); return v;
    case O_ROL: c = m->p & FC; m->p = (m->p & ~FC) | (v >> 7); v = (v << 1) | c; NZ(v); return v;
    case O_ROR: c = m->p & FC; m->p = (m->p & ~FC) | (v & 1); v = (v >> 1) | (c << 7); NZ(v); return v;
    case O_INC: v++; NZ(v); return v;
    case O_DEC: v--; NZ(v); return v;
    case O_TSB: m->p = (m->p & ~FZ) | ((m->a & v) ? 0 : FZ); return v | m->a;
    case O_TRB: m->p = (m->p & ~FZ) | ((m->a & v) ? 0 : FZ); return v & ~m->a;
    }
    return v;
}

static int branch(M *m, int8_t off) {
    uint16_t t = m->pc + off;
    int c = 1 + (((t ^ m->pc) & 0xFF00) ? 1 : 0);
    m->pc = t;
    return c;
}

static int step(M *m) {
    uint8_t opc = fetch(m), v;
    Ent *e = &T[opc];
    int cyc = 1;
    uint16_t a, b;
    m->instructions++;
    switch (e->op) {
    case O_LDA: case O_LDX: case O_LDY: case O_AND: case O_ORA: case O_EOR:
    case O_CMP: case O_CPX: case O_CPY: case O_BIT: case O_ADC: case O_SBC:
        if (e->mode == IMM) { v = fetch(m); cyc += 1; }
        else { a = ea(m, e->mode, 'r', &cyc); v = rd(m, a); cyc += 1; }
        switch (e->op) {
        case O_LDA: m->a = v; NZ(v); break;
        case O_LDX: m->x = v; NZ(v); break;
        case O_LDY: m->y = v; NZ(v); break;
        case O_AND: m->a &= v; NZ(m->a); break;
        case O_ORA: m->a |= v; NZ(m->a); break;
        case O_EOR: m->a ^= v; NZ(m->a); break;
        case O_CMP: cmpf(m, m->a, v); break;
        case O_CPX: cmpf(m, m->x, v); break;
        case O_CPY: cmpf(m, m->y, v); break;
        case O_BIT:
            if (e->mode == IMM) m->p = (m->p & ~FZ) | ((m->a & v) ? 0 : FZ);
            else m->p = (m->p & ~(FN | FV | FZ)) | (v & (FN | FV)) | ((m->a & v) ? 0 : FZ);
            break;
        case O_ADC: cyc += adc(m, v); break;
        case O_SBC: cyc += sbc(m, v); break;
        }
        break;
    case O_STA: case O_STX: case O_STY: case O_STZ:
        a = ea(m, e->mode, 'w', &cyc);
        wr(m, a, e->op == O_STA ? m->a : e->op == O_STX ? m->x : e->op == O_STY ? m->y : 0);
        cyc += 1;
        break;
    case O_ASL: case O_LSR: case O_ROL: case O_ROR: case O_INC: case O_DEC: case O_TSB: case O_TRB:
        if (e->mode == ACC) { m->a = rmw(m, e->op, m->a); cyc += 1; break; }
        a = ea(m, e->mode, (e->op == O_INC || e->op == O_DEC) && e->mode == ABX ? '7' : 'm', &cyc);
        v = rd(m, a);
        wr(m, a, rmw(m, e->op, v));
        cyc += 3;
        break;
    case O_RMB: case O_SMB:
        a = fetch(m); v = rd(m, a);
        wr(m, a, e->op == O_SMB ? (v | (1 << e->arg)) : (v & ~(1 << e->arg)));
        cyc += 4;
        break;
    case O_BBR: case O_BBS:
        a = fetch(m); v = rd(m, a);
        { int8_t off = (int8_t)fetch(m); int bit = (v >> e->arg) & 1;
          cyc += 4;
          if (bit == (e->op == O_BBS)) cyc += branch(m, off); }
        break;
    case O_BR: {
        int8_t off = (int8_t)fetch(m); int t;
        static const uint8_t flag[8] = {FN, FN, FV, FV, FC, FC, FZ, FZ};
        cyc += 1;
        t = e->arg == 8 ? 1 : (((m->p & flag[e->arg]) != 0) == (e->arg & 1));
        if (t) cyc += branch(m, off);
        break; }
    case O_JMP:
        b = fetch(m); b |= fetch(m) << 8; cyc += 2;
        if (e->mode == ABS) m->pc = b;
        else {
            if (e->mode == IAX) b += m->x;
            m->pc = rd(m, b) | (rd(m, (uint16_t)(b + 1)) << 8);
            cyc += 3;
        }
        break;
    case O_JSR:
        b = fetch(m);
        push(m, m->pc >> 8); push(m, m->pc & 0xFF);
        b |= fetch(m) << 8; m->pc = b; cyc += 5;
        break;
    case O_RTS:
        m->pc = pull(m); m->pc |= pull(m) << 8; m->pc++; cyc += 5; break;
    case O_RTI:
        m->p = pull(m) | FU | FB; m->pc = pull(m); m->pc |= pull(m) << 8; cyc += 5; break;
    case O_BRK:
        m->pc++; push(m, m->pc >> 8); push(m, m->pc & 0xFF); push(m, m->p | FB | FU);
        m->pc = rd(m, 0xFFFE) | (rd(m, 0xFFFF) << 8); m->p = (m->p | FI) & ~FD; cyc += 6;
        break;
    case O_PHA: push(m, m->a); cyc += 2; break;
    case O_PHP: push(m, m->p | FB | FU); cyc += 2; break;
    case O_PHX: push(m, m->x); cyc += 2; break;
    case O_PHY: push(m, m->y); cyc += 2; break;
    case O_PLA: m->a = pull(m); NZ(m->a); cyc += 3; break;
    case O_PLP: m->p = pull(m) | FU | FB; cyc += 3; break;
    case O_PLX: m->x = pull(m); NZ(m->x); cyc += 3; break;
    case O_PLY: m->y = pull(m); NZ(m->y); cyc += 3; break;
    case O_NOP:
        m->pc += e->nb - 1; cyc = e->nc; break;
    case O_STOP: m->halted = 2; m->pc--; break;
    case O_IMPL:
        cyc += 1;
        switch (e->arg) {
        case 0: m->x++; NZ(m->x); break;          case 1: m->y++; NZ(m->y); break;
        case 2: m->x--; NZ(m->x); break;          case 3: m->y--; NZ(m->y); break;
        case 4: m->x = m->a; NZ(m->x); break;     case 5: m->a = m->x; NZ(m->a); break;
        case 6: m->y = m->a; NZ(m->y); break;     case 7: m->a = m->y; NZ(m->a); break;
        case 8: m->s = m->x; break;               case 9: m->x = m->s; NZ(m->x); break;
        case 10: m->p |= FI; break;               case 11: m->p &= ~FI; break;
        case 12: m->p |= FD; break;               case 13: m->p &= ~FD; break;
        case 14: m->p |= FC; break;               case 15: m->p &= ~FC; break;
        case 16: m->p &= ~FV; break;
        case 17: m->a++; NZ(m->a); break;         case 18: m->a--; NZ(m->a); break;
        }
        break;
    }
    return cyc;
}

/* Reset sequence (7 cycles) as in the Python core. */
void emu_reset(M *m) {
    if (!inited) init();
    m->gpio = m->prev_gpio = 0;      /* CPU_RESET_N clears U16, but not the bank/fault latches. */
    mx_reset(m);
    m->s = (uint8_t)(m->s - 3);
    m->pc = m->mem[0xFFFC] | (m->mem[0xFFFD] << 8);
    m->p = (m->p | FI | FU) & ~FD;
    m->cycles += 7;
}

/* Run until PC == stop (checked before each instruction), a self-jump trap,
 * STP/WAI, or max_cycles.  Returns the halt reason: 1 stop address, 2 STP/WAI,
 * 3 trap (instruction branching to itself), 0 cycle limit. */
int emu_run(M *m, int stop, uint64_t max_cycles) {
    uint64_t limit = m->cycles + max_cycles;
    if (!inited) init();
    m->halted = 0;
    while (m->cycles < limit) {
        uint16_t pc = m->pc;
        if (stop >= 0 && pc == (uint16_t)stop) { m->halted = 1; return 1; }
        m->last_pc = pc;
        m->cycles += step(m);
        if (m->halted) return m->halted;
        if (m->pc == pc) { m->halted = 3; return 3; }
    }
    return 0;
}

int emu_sizeof(void) { return (int)sizeof(M); }
