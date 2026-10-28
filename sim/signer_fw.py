"""DTS-02 signing firmware: Ed25519 (RFC 8032) for the W65C02S, generated as
assembly by this module and assembled with sim/asm.py.

Spec contract (Section 10): plain Ed25519 over raw message bytes; no
secret-dependent branches and no secret-indexed table lookups; two
deterministic signatures compared byte-for-byte and the signature equation
verified before release; result record at $6000 with CRC-32; bank locks set
through $7F03/$7F04.

Arithmetic choices
- Field elements: 32 bytes little-endian, any value < 2^256 (2^256 = 38 mod p),
  fully reduced only for encoding/comparison.
- fe_mul: constant-time schoolbook product by masked row additions: for
  each of the 256 multiplier bits, (a << k) & mask is added at byte offset j.
  Shifted copies a<<0..7 are interleaved (AKS[8*i+k]) so the inner loop uses
  only public indices.  Reduction folds the high half with x38.
- [s]B: radix-16 signed digits (branch-free recoding), 8 tables of 8 Niels
  points m*16^(8k)*B in ROM, every entry of a table scanned with masks.
- Verification uses only public data, so it may branch on public values.

Memory: zero page $10-$5F, buffers $0200-$1BFF, envelope $2000-$3EFF,
seed $3F00 (stands in for the future local seed-entry mechanism), message
$4000, metadata $5000, result record $6000.
"""

import hashlib
import zlib

from . import ed25519_ref as E
from .asm import assemble

P = E.p
L = E.L

# ---------------------------------------------------------------------------
# memory map
# ---------------------------------------------------------------------------
ZP = dict(P1=0x10, P2=0x12, P3=0x14, P4=0x16, MASK=0x18, BJ=0x19, JJ=0x1A, KK=0x1B,
          T0=0x1C, T1=0x1D, T2=0x1E, T3=0x1F, CL=0x20, CH=0x21, II=0x22, NN=0x23,
          SGN=0x24, ABSD=0x25, EQ=0x26, LEN=0x27, BUFPOS=0x29, PTR=0x2A, CNT=0x2C,
          TOTAL=0x2E, PTR2=0x31, STATUS=0x33, DIGIT=0x34, PROF=0x35, FAILC=0x36,
          SPTR=0x38, KPTR=0x3A, WPTR=0x3C, TT=0x3E,
          BI=0x48, BK=0x49, VJ=0x4A,        # loop counters of base_mult / verify (fe_mul owns JJ)
          MULV=0x4C, SQV=0x4E, ENTV=0x50,   # multiply dispatch vectors, fe_sq_ct row entry
          QP0=0x52, QP1=0x54, QP2=0x56, QP3=0x58,   # table-multiply row pointers
          REUSEA=0x5A)
AKS = 0x0200          # 264 bytes, page aligned
T64 = 0x0080          # 64-byte product in zero page ($80-$BF): zp,X forms are faster and wrap
                      # inside page 0, so indexing never adds a data-dependent cycle
W33 = 0x0440          # 33-byte shift buffer
FE_BASE = 0x0480      # field-element slots, 32 bytes each, up to $13FF
SHA = 0x1400          # SHA-512 state and buffers, up to $17FF
SC = 0x1800           # scalars and signature buffers, up to $1BFF
ENV = 0x2000          # input envelope
SEED = 0x3F00
MSG = 0x4000
META = 0x5000
REC = 0x6000
MAX_MSG = 4096

SHA_H = SHA            # 64
SHA_W = SHA + 0x40     # 80 * 8 = 640 -> SHA+0x2C0
SHA_WV = SHA + 0x2C0   # a..h working vars, 64
SHA_BUF = SHA + 0x300  # 128
SHA_X = SHA + 0x380    # temporaries: 8 words
SHA_LEN = SHA + 0x3C0  # 3-byte message length counter

# scalar area
SCL = {name: SC + 64 * i for i, name in enumerate(
    ["H", "A_BYTES", "PREFIXH", "R_SC", "K_SC", "S_SC", "SIG1", "SIG2", "DIG", "RED_IN",
     "RED_R", "RED_T", "EXPECT", "HASH", "TMP64", "RBYTES", "VK"])}


class FE:
    """Allocator for 32-byte field-element slots."""

    def __init__(self):
        self.next = FE_BASE
        self.names = {}

    def __call__(self, name, n=1):
        if name not in self.names:
            self.names[name] = self.next
            self.next += 32 * n
            assert self.next <= SHA, "field-element area overflow"
        return self.names[name]


fe = FE()
# point = 4 consecutive fe (X, Y, Z, T); niels = 3 (ypx, ymx, xy2d); cached = 4 (ypx, ymx, Z, T2d)
for _n in ["Q", "PP", "R2", "CB"]:
    fe(_n, 4)
fe("SEL", 3)
for _n in ["NEGT", "I0", "I1", "I2", "I3", "EX", "EY", "EZI", "DU", "DV", "DV3", "DVXX", "DCHK",
           "DX", "DY", "TA", "TB", "TC", "TD"]:
    fe(_n)
fe("NEGA", 4)
fe("VTAB", 4 * 15)   # cached multiples 1..15 of -A for verification


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
def le32(x):
    return (x % (1 << 256)).to_bytes(32, "little")


D = E.d
D2 = 2 * D % P
SQRTM1 = E.SQRT_M1


def to_affine(Pt):
    zi = pow(Pt[2], P - 2, P)
    return Pt[0] * zi % P, Pt[1] * zi % P


def niels(Pt):
    x, y = to_affine(Pt)
    return le32((y + x) % P) + le32((y - x) % P) + le32(2 * D * x * y % P)


def base_tables():
    """T_k[m-1] = m * 16^(8k) * B, k = 0..7, m = 1..8, Niels form."""
    out = bytearray()
    for k in range(8):
        base = E._mul(16 ** (8 * k), E.B)
        for m in range(1, 9):
            out += niels(E._mul(m, base))
    return bytes(out)


def sha_k():
    # SHA-512 round constants (FIPS 180-4), stored little-endian per word
    primes = []
    n = 2
    while len(primes) < 80:
        if all(n % q for q in primes if q * q <= n):
            primes.append(n)
        n += 1

    def frac_cbrt(q):
        # floor(frac(q^(1/3)) * 2^64) via integer cube root
        lo, hi = 0, 1 << 100
        target = q << 192
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if mid ** 3 <= target:
                lo = mid
            else:
                hi = mid - 1
        return lo & ((1 << 64) - 1)
    return [frac_cbrt(q) for q in primes]


def sha_h0():
    primes = [2, 3, 5, 7, 11, 13, 17, 19]

    def frac_sqrt(q):
        import math
        r = math.isqrt(q << 128)
        return r & ((1 << 64) - 1)
    return [frac_sqrt(q) for q in primes]


# ---------------------------------------------------------------------------
# code generation helpers
# ---------------------------------------------------------------------------
class G:
    def __init__(self):
        self.lines = []
        self.n = 0

    def __call__(self, *lines):
        self.lines.extend(lines)

    def lab(self, base="L"):
        self.n += 1
        return f"_{base}{self.n}"

    def text(self):
        return "\n".join(self.lines)


def ptr(g, zp, addr):
    g(f"LDA #<{addr}", f"STA {zp}", f"LDA #>{addr}", f"STA {zp}+1")


def call3(g, fn, r, a, b=None):
    """(P3) = fn((P1), (P2))"""
    ptr(g, "P1", a)
    if b is not None:
        ptr(g, "P2", b)
    ptr(g, "P3", r)
    g(f"JSR {fn}")


def loop_ne(g, target):
    """Branch back to target if Z=0, for loop bodies longer than 127 bytes."""
    l = g.lab("ln")
    g(f"BEQ {l}", f"JMP {target}", f"{l}:")


def mask_from_carry(g):
    """A = $FF if C=1 else $00 (branch-free)."""
    g("LDA #0", "ADC #$FF", "EOR #$FF")


def mask_from_borrow(g):
    """A = $FF if C=0 (borrow) else $00 (branch-free)."""
    g("LDA #0", "SBC #0")


# ---------------------------------------------------------------------------
# field arithmetic
# ---------------------------------------------------------------------------
def gen_field(g):
    # ---- fe_add: (P3) = (P1) + (P2) mod 2^256 folded with 38
    g("fe_add:", "CLC")
    for i in range(32):
        g(f"LDY #{i}", "LDA (P1),Y", "ADC (P2),Y", "STA (P3),Y")
    g("JMP fold_add")
    # fold: carry C -> add 38*C to (P3), twice
    g("fold_add:")
    for _ in range(2):
        mask_from_carry(g)
        g("AND #38", "LDY #0", "CLC", "ADC (P3),Y", "STA (P3),Y")
        for i in range(1, 32):
            g(f"LDY #{i}", "LDA (P3),Y", "ADC #0", "STA (P3),Y")
    g("RTS")
    # ---- fe_sub: (P3) = (P1) - (P2), borrow folded with -38
    g("fe_sub:", "SEC")
    for i in range(32):
        g(f"LDY #{i}", "LDA (P1),Y", "SBC (P2),Y", "STA (P3),Y")
    g("fold_sub:")
    for _ in range(2):
        mask_from_borrow(g)
        g("AND #38", "STA T0", "LDY #0", "LDA (P3),Y", "SEC", "SBC T0", "STA (P3),Y")
        for i in range(1, 32):
            g(f"LDY #{i}", "LDA (P3),Y", "SBC #0", "STA (P3),Y")
    g("RTS")
    # ---- fe_copy: (P3) = (P1)
    g("fe_copy:", "LDY #31")
    l = g.lab("cp")
    g(f"{l}: LDA (P1),Y", "STA (P3),Y", "DEY", f"BPL {l}", "RTS")
    # ---- fe_cmov: (P3) ^= ((P3) ^ (P1)) & MASK   (constant time)
    g("fe_cmov:", "LDY #31")
    l = g.lab("cm")
    g(f"{l}: LDA (P1),Y", "EOR (P3),Y", "AND MASK", "EOR (P3),Y", "STA (P3),Y", "DEY", f"BPL {l}", "RTS")
    # ---- fe_canon: (P3) reduced to [0, p): two masked subtractions of p
    g("fe_canon:")
    pb = le32(P)
    for _ in range(2):
        g("SEC")
        for i in range(32):
            g(f"LDY #{i}", "LDA (P3),Y", f"SBC #${pb[i]:02X}", f"STA {W33 + i}")
        mask_from_carry(g)          # no borrow -> take the difference
        g("STA MASK")
        ptr(g, "P1", W33)
        g("JSR fe_cmov")
    g("RTS")
    gen_mul_family(g)


A32 = 0x0310          # copy of the multiplicand (32 bytes)
DIAG = 0x0340         # 64-byte diagonal of a square
NB = 0x0380           # complemented multiplier bytes (table multiply)
ROWB = 0x03A0         # 33-byte row product (table multiply)
HIMASK = [(0xFF << k) & 0xFF for k in range(8)]


def gen_mul_family(g):
    """fe_mul / fe_sq dispatch through MULV / SQV:
    *_ct  constant time, no secret-indexed tables (signing)
    *_qs  quarter-square tables, public data only (verification)"""
    g("fe_mul: JMP (MULV)", "fe_sq: JMP (SQV)")
    g("set_ct:", "LDA #<fe_mul_ct", "STA MULV", "LDA #>fe_mul_ct", "STA MULV+1",
      "LDA #<fe_sq_ct", "STA SQV", "LDA #>fe_sq_ct", "STA SQV+1", "RTS")
    g("set_fast:", "LDA #<fe_mul_qs", "STA MULV", "LDA #>fe_mul_qs", "STA MULV+1",
      "LDA #<fe_sq_qs", "STA SQV", "LDA #>fe_sq_qs", "STA SQV+1", "RTS")

    # ---- build_aks: AKS[8i+k] = byte i of ((P1) << k), A32 = (P1)
    g("build_aks:", "LDY #31")
    l = g.lab("ld")
    g(f"{l}: LDA (P1),Y", f"STA {W33},Y", f"STA {A32},Y", "DEY", f"BPL {l}", f"STZ {W33 + 32}", "LDX #0")
    lk = g.lab("k")
    g(f"{lk}:")
    for i in range(33):
        g(f"LDA {W33 + i}", f"STA {AKS + 8 * i},X")
    g("ASL " + str(W33))
    for i in range(1, 33):
        g(f"ROL {W33 + i}")
    g("INX", "CPX #8")
    loop_ne(g, lk)
    g("LDX #63")
    lz = g.lab("z")
    g(f"{lz}: STZ {T64},X", "DEX", f"BPL {lz}", "RTS")

    # ---- fe_mul_ct: rows of (a<<k) & mask(bit k of b_j) added at byte offset j
    g("fe_mul_ct:", "JSR build_aks", "STZ JJ")
    lj = g.lab("j")
    g(f"{lj}: LDY JJ", "LDA (P2),Y", "STA BJ", "LDY #0")
    lb = g.lab("b")
    g(f"{lb}: LSR BJ")
    mask_from_carry(g)
    g("STA MASK", "LDX JJ", "CLC")
    for i in range(33):
        g(f"LDA {AKS + 8 * i},Y", "AND MASK", f"ADC {T64 + i},X", f"STA {T64 + i},X")
    g("INY", "CPY #8")
    loop_ne(g, lb)
    g("INC JJ", "LDA JJ", "CMP #32")
    loop_ne(g, lj)
    g("JMP reduce64")

    # ---- fe_sq_ct: cross terms above the diagonal once, doubled, plus diagonal
    # Row j adds bit k of a_j times (A_hi(j) << k), A_hi(j) = bytes > j of a.
    # Byte j+1 of that row is (a_{j+1} << k) & $FF = AKS[8(j+1)+k] & HIMASK[k];
    # bytes j+2..32 equal AKS[8i+k].  Entry into the unrolled adder depends only
    # on the public row index j.
    #
    # Diagonal a_j^2 is accumulated in the same bit loop (SH = a_j<<k, CT masks),
    # so the separate 32-byte diagonal pass is only needed for j=31. Cached
    # J8=JJ<<3 and J2=JJ<<1 cut ZP spills on the hot path.
    J8, J2 = 0x5B, 0x5C
    SHLO, SHHI = 0x5D, 0x5E
    DLO, DHI = 0x5F, 0x60
    g("fe_sq_ct:", "JSR build_aks", "STZ JJ", f"STZ {J8}", f"STZ {J2}")
    g("LDX #63")
    lz = g.lab("dz")
    g(f"{lz}: STZ {DIAG},X", "DEX", f"BPL {lz}")
    lj = g.lab("sj")
    g(f"{lj}: LDY JJ", f"LDA {A32},Y", "STA BJ", f"STA {SHLO}", f"STZ {SHHI}",
      f"STZ {DLO}", f"STZ {DHI}", "STZ KK",
      "LDX JJ", "LDA SQENT_LO,X", "STA ENTV", "LDA SQENT_HI,X", "STA ENTV+1")
    lb = g.lab("sb")
    g(f"{lb}: LSR BJ")
    mask_from_carry(g)
    g("STA MASK")
    g(f"LDA {SHLO}", "AND MASK", "CLC", f"ADC {DLO}", f"STA {DLO}",
      f"LDA {SHHI}", "AND MASK", f"ADC {DHI}", f"STA {DHI}",
      f"ASL {SHLO}", f"ROL {SHHI}")
    g(f"LDA {J8}", "CLC", "ADC #8", "ADC KK", "TAY",
      f"LDA {AKS},Y", "LDX KK", "AND HIMASKT,X", "AND MASK",
      f"LDX {J2}", "CLC", f"ADC {T64 + 1},X", f"STA {T64 + 1},X",
      "LDY KK", "LDX JJ", "JMP (ENTV)")
    g("sq_rows:")
    for i in range(2, 33):
        g(f"sqe{i}: LDA {AKS + 8 * i},Y", "AND MASK", f"ADC {T64 + i},X", f"STA {T64 + i},X")
    g("INC KK", "LDA KK", "CMP #8")
    loop_ne(g, lb)
    g(f"LDX {J2}", f"LDA {DLO}", f"STA {DIAG},X", f"LDA {DHI}", f"STA {DIAG + 1},X",
      "INC JJ", f"LDA {J2}", "CLC", "ADC #2", f"STA {J2}",
      f"LDA {J8}", "CLC", "ADC #8", f"STA {J8}",
      "LDA JJ", "CMP #31")
    loop_ne(g, lj)
    g(f"LDA {A32 + 31}", "STA BJ", "STA T0", "STZ T1", "STZ T2", "STZ T3", "LDY #8")
    lq = g.lab("dq")
    g(f"{lq}: LSR BJ")
    mask_from_carry(g)
    g("STA MASK", "LDA T0", "AND MASK", "CLC", "ADC T2", "STA T2",
      "LDA T1", "AND MASK", "ADC T3", "STA T3", "ASL T0", "ROL T1", "DEY", f"BNE {lq}")
    g(f"LDA T2", f"STA {DIAG + 62}", "LDA T3", f"STA {DIAG + 63}")
    g(f"ASL {T64}")
    for i in range(1, 64):
        g(f"ROL {T64 + i}")
    g("CLC")
    for i in range(64):
        g(f"LDA {T64 + i}", f"ADC {DIAG + i}", f"STA {T64 + i}")
    g("JMP reduce64")

    # ---- fe_mul_qs (public data): a*b = SQ[a+b] - NSQ[a + ~b], row by row
    g("fe_mul_qs:", "LDY #31")
    l = g.lab("nb")
    g(f"{l}: LDA (P2),Y", f"STA {A32},Y", "EOR #$FF", f"STA {NB},Y", "DEY", f"BPL {l}")
    g("LDX #63")
    lz = g.lab("qz")
    g(f"{lz}: STZ {T64},X", "DEX", f"BPL {lz}", "STZ JJ")
    lr = g.lab("qr")
    g(f"{lr}: LDY JJ", "LDA (P1),Y")
    _qs_setrow(g)
    g("STZ T2")                                # previous high byte
    for j in range(32):
        _qs_product(g, f"{A32 + j}", f"{NB + j}")
        # ROWB[j] = lo + previous hi (+carry folded through T2 chain)
        g("CLC", "ADC T2", f"STA {ROWB + j}", "LDA T3", "ADC #0", "STA T2")
    g(f"LDA T2", f"STA {ROWB + 32}")
    g("LDX JJ", "CLC")
    for i in range(33):
        g(f"LDA {ROWB + i}", f"ADC {T64 + i},X", f"STA {T64 + i},X")
    g("INC JJ", "LDA JJ", "CMP #32")
    loop_ne(g, lr)
    g("JMP reduce64")

    # ---- fe_sq_qs (public data): products above the diagonal, doubled, + squares
    g("fe_sq_qs:", "LDY #31")
    l = g.lab("sn")
    g(f"{l}: LDA (P1),Y", f"STA {A32},Y", "EOR #$FF", f"STA {NB},Y", "DEY", f"BPL {l}")
    g("LDX #63")
    lz = g.lab("sz")
    g(f"{lz}: STZ {T64},X", "DEX", f"BPL {lz}", "STZ JJ")
    lr = g.lab("sr")
    g(f"{lr}: LDY JJ", f"LDA {A32},Y")
    _qs_setrow(g)
    g("STZ T2", "LDX JJ", "INX")                 # columns j = i+1 .. 31
    lc = g.lab("sc")
    g(f"{lc}: LDY {A32},X", "LDA (QP0),Y", "STA T0", "LDA (QP2),Y", "STA T1",
      f"LDY {NB},X", "LDA T0", "SEC", "SBC (QP1),Y", "STA T0", "LDA T1", "SBC (QP3),Y", "STA T3",
      "LDA T0", "CLC", "ADC T2", f"STA {ROWB},X", "LDA T3", "ADC #0", "STA T2",
      "INX", "CPX #32", f"BNE {lc}")
    g("LDA T2", f"STA {ROWB + 32}")
    # T64[i + j] += ROWB[j] for j = i+1 .. 32, via PT = T64 + i; DEX keeps C
    g("CLC", f"LDA #<{T64}", "ADC JJ", "STA PTR2", f"LDA #>{T64}", "ADC #0", "STA PTR2+1",
      "LDA #32", "SEC", "SBC JJ", "TAX", "LDY JJ", "INY", "CLC")
    la = g.lab("sa")
    g(f"{la}: LDA {ROWB},Y", "ADC (PTR2),Y", "STA (PTR2),Y", "INY", "DEX", f"BNE {la}")
    g("INC JJ", "LDA JJ", "CMP #31", f"BEQ {lr}_x", f"JMP {lr}", f"{lr}_x:")
    g(f"ASL {T64}")
    for i in range(1, 64):
        g(f"ROL {T64 + i}")
    # diagonal squares a_j^2 = SQ[2 a_j]
    g("LDX #0")
    ld = g.lab("qd")
    g(f"{ld}: LDA {A32},X", "ASL A", "TAY", f"BCS {ld}_h",
      "LDA SQL,Y", "STA T0", "LDA SQH,Y", f"JMP {ld}_s",
      f"{ld}_h: LDA SQL+256,Y", "STA T0", "LDA SQH+256,Y")
    g(f"{ld}_s: STA T1", "TXA", "ASL A", "TAY", "LDA T0", f"STA {DIAG},Y", "LDA T1", f"STA {DIAG + 1},Y",
      "INX", "CPX #32", f"BNE {ld}")
    g("CLC")
    for i in range(64):
        g(f"LDA {T64 + i}", f"ADC {DIAG + i}", f"STA {T64 + i}")
    g("JMP reduce64")

    # ---- reduce64: (P3) = T64 mod p  (lo + 38*hi, 16-bit carry, folds)
    g("reduce64:", "STZ CL", "STZ CH", "LDX #0")
    lr = g.lab("r")
    g(f"{lr}:")
    g(f"LDA {T64 + 32},X", "ASL A", "STA T0", "LDA #0", "ROL A", "STA T1")      # 2v
    g("LDA T0", "ASL A", "STA T2", "LDA T1", "ROL A", "STA T3")                 # 4v
    g("CLC", "LDA T0", "ADC T2", "STA T0", "LDA T1", "ADC T3", "STA T1")        # 6v
    g("ASL T2", "ROL T3", "ASL T2", "ROL T3", "ASL T2", "ROL T3")               # 32v
    g("CLC", "LDA T0", "ADC T2", "STA T0", "LDA T1", "ADC T3", "STA T1")        # 38v
    g("CLC", f"LDA {T64},X", "ADC T0", "STA T0", "LDA T1", "ADC #0", "STA T1")  # + lo
    g("CLC", "LDA T0", "ADC CL", "STA T0", "LDA T1", "ADC CH", "STA CH")        # + carry
    g("TXA", "TAY", "LDA T0", "STA (P3),Y")
    g("LDA CH", "STA CL", "STZ CH")
    g("INX", "CPX #32", f"BNE {lr}")
    g("LDA CL", "ASL A", "STA T0", "LDA #0", "ROL A", "STA T1")
    g("LDA T0", "ASL A", "STA T2", "LDA T1", "ROL A", "STA T3")
    g("CLC", "LDA T0", "ADC T2", "STA T0", "LDA T1", "ADC T3", "STA T1")
    g("ASL T2", "ROL T3", "ASL T2", "ROL T3", "ASL T2", "ROL T3")
    g("CLC", "LDA T0", "ADC T2", "STA T0", "LDA T1", "ADC T3", "STA T1")        # 38c
    g("LDY #0", "CLC", "LDA (P3),Y", "ADC T0", "STA (P3),Y")
    g("LDY #1", "LDA (P3),Y", "ADC T1", "STA (P3),Y")
    for i in range(2, 32):
        g(f"LDY #{i}", "LDA (P3),Y", "ADC #0", "STA (P3),Y")
    g("JMP fold_add")


def _qs_setrow(g):
    """QP0..QP3 = SQL+a, NSQL+a, SQH+a, NSQH+a for the row multiplicand in A."""
    g("STA T0")
    for zp, tab in [("QP0", "SQL"), ("QP1", "NSQL"), ("QP2", "SQH"), ("QP3", "NSQH")]:
        g("CLC", f"LDA #<{tab}", "ADC T0", f"STA {zp}", f"LDA #>{tab}", "ADC #0", f"STA {zp}+1")


def _qs_product(g, b_addr, nb_addr):
    """A = low byte, T3 = high byte of row_a * b (public data only)."""
    g(f"LDY {b_addr}", "LDA (QP2),Y", "TAX", "LDA (QP0),Y", f"LDY {nb_addr}", "SEC",
      "SBC (QP1),Y", "STA T0", "TXA", "SBC (QP3),Y", "STA T3", "LDA T0")


def gen_field_high(g):
    """Squaring chains: inversion and (p-5)/8 power (ref10 addition chains)."""
    I0, I1, I2, I3 = fe("I0"), fe("I1"), fe("I2"), fe("I3")

    def sq(r, a, n=1):
        call3(g, "fe_sq", r, a)
        if n > 1:
            g(f"LDA #{n - 1}", "STA NN")
            l = g.lab("sq")
            g(f"{l}:")
            call3(g, "fe_sq", r, r)
            g("DEC NN", f"BNE {l}")

    def mul(r, a, b):
        call3(g, "fe_mul", r, a, b)

    def chain(name, tail):
        # input in ZIN (copied to EZI by caller convention), output to I0 / I1
        g(f"{name}:")
        z = fe("EZI")
        sq(I0, z)              # z^2
        sq(I1, I0, 2)          # z^8
        mul(I1, z, I1)         # z^9
        mul(I0, I0, I1)        # z^11
        sq(I2, I0)             # z^22
        mul(I1, I1, I2)        # 2^5-1
        sq(I2, I1, 5)
        mul(I1, I2, I1)        # 2^10-1
        sq(I2, I1, 10)
        mul(I2, I2, I1)        # 2^20-1
        sq(I3, I2, 20)
        mul(I2, I3, I2)        # 2^40-1
        sq(I2, I2, 10)
        mul(I1, I2, I1)        # 2^50-1
        sq(I2, I1, 50)
        mul(I2, I2, I1)        # 2^100-1
        sq(I3, I2, 100)
        mul(I2, I3, I2)        # 2^200-1
        sq(I2, I2, 50)
        mul(I1, I2, I1)        # 2^250-1
        tail()
        g("RTS")

    def inv_tail():
        sq(I1, I1, 5)          # 2^255-32
        mul(I0, I1, I0)        # 2^255-21 = p-2   -> I0

    def p58_tail():
        sq(I1, I1, 2)          # 2^252-4
        mul(I0, I1, z_())      # 2^252-3 -> I0

    def z_():
        return fe("EZI")

    chain("fe_invert", inv_tail)        # I0 = EZI^(p-2)
    chain("fe_pow2523", p58_tail)       # I0 = EZI^((p-5)/8)


# ---------------------------------------------------------------------------
# group arithmetic (extended coordinates, ref10 formulas)
# ---------------------------------------------------------------------------
def X_(pt):
    return pt


def Y_(pt):
    return pt + 32


def Z_(pt):
    return pt + 64


def T_(pt):
    return pt + 96


def gen_group(g):
    Q, PP, SEL, NEGT = fe("Q"), fe("PP"), fe("SEL"), fe("NEGT")
    TA = fe("TA")
    add, sub, mul = (lambda r, a, b: call3(g, "fe_add", r, a, b),
                     lambda r, a, b: call3(g, "fe_sub", r, a, b),
                     lambda r, a, b: call3(g, "fe_mul", r, a, b))
    # ---- p1p1 (PP) -> p3 (Q)
    g("p1p1_to_p3:")
    mul(X_(Q), X_(PP), T_(PP))
    mul(Y_(Q), Y_(PP), Z_(PP))
    mul(Z_(Q), Z_(PP), T_(PP))
    mul(T_(Q), X_(PP), Y_(PP))
    g("RTS")
    g("p1p1_to_p2:")
    mul(X_(Q), X_(PP), T_(PP))
    mul(Y_(Q), Y_(PP), Z_(PP))
    mul(Z_(Q), Z_(PP), T_(PP))
    g("RTS")
    # ---- PP = 2*Q (Q as p2: X, Y, Z)
    g("p2_dbl:")
    sq = lambda r, a: call3(g, "fe_sq", r, a)
    sq(X_(PP), X_(Q))                    # XX
    sq(Z_(PP), Y_(Q))                    # YY
    sq(T_(PP), Z_(Q))
    add(T_(PP), T_(PP), T_(PP))          # B = 2 Z^2
    add(Y_(PP), X_(Q), Y_(Q))            # A = X + Y
    sq(TA, Y_(PP))                       # AA
    add(Y_(PP), Z_(PP), X_(PP))          # Y3 = YY + XX
    sub(Z_(PP), Z_(PP), X_(PP))          # Z3 = YY - XX
    sub(X_(PP), TA, Y_(PP))              # X3 = AA - Y3
    sub(T_(PP), T_(PP), Z_(PP))          # T3 = B - Z3
    g("RTS")
    # ---- PP = Q + SEL (Niels: ypx, ymx, xy2d), ref10 ge_madd
    g("madd:")
    add(X_(PP), Y_(Q), X_(Q))
    sub(Y_(PP), Y_(Q), X_(Q))
    mul(Z_(PP), X_(PP), SEL)
    mul(Y_(PP), Y_(PP), SEL + 32)
    mul(T_(PP), SEL + 64, T_(Q))
    sub(X_(PP), Z_(PP), Y_(PP))
    add(Y_(PP), Z_(PP), Y_(PP))
    add(TA, Z_(Q), Z_(Q))
    add(Z_(PP), TA, T_(PP))
    sub(T_(PP), TA, T_(PP))
    g("RTS")
    # ---- PP = Q + C (cached in CPTR: ypx, ymx, Z, T2d), ref10 ge_add
    g("gadd:")
    g("LDA CPTR", "STA SPTR", "LDA CPTR+1", "STA SPTR+1")
    add(X_(PP), Y_(Q), X_(Q))
    sub(Y_(PP), Y_(Q), X_(Q))
    _mul_s(g, Z_(PP), X_(PP), 0)
    _mul_s(g, Y_(PP), Y_(PP), 32)
    _mul_s(g, T_(PP), T_(Q), 96)
    _mul_s(g, X_(PP), Z_(Q), 64)
    add(TA, X_(PP), X_(PP))
    sub(X_(PP), Z_(PP), Y_(PP))
    add(Y_(PP), Z_(PP), Y_(PP))
    add(Z_(PP), TA, T_(PP))
    sub(T_(PP), TA, T_(PP))
    g("RTS")
    # ---- Q -> cached form at CPTR: (Y+X, Y-X, Z, 2d*T)
    g("to_cached:")
    for off, (fn, a, b) in [(0, ("fe_add", Y_(Q), X_(Q))), (32, ("fe_sub", Y_(Q), X_(Q)))]:
        ptr(g, "P1", a)
        ptr(g, "P2", b)
        _p3_from_cptr(g, off)
        g(f"JSR {fn}")
    ptr(g, "P1", Z_(Q))
    _p3_from_cptr(g, 64)
    g("JSR fe_copy")
    ptr(g, "P1", T_(Q))
    ptr(g, "P2", "C_D2")
    _p3_from_cptr(g, 96)
    g("JSR fe_mul")
    g("RTS")
    # ---- Q = neutral
    g("q_zero:")
    for c, off in [("C_ZERO", 0), ("C_ONE", 32), ("C_ONE", 64), ("C_ZERO", 96)]:
        ptr(g, "P1", c)
        ptr(g, "P3", Q + off)
        g("JSR fe_copy")
    g("RTS")
    # ---- Q = 2^n * Q  (n in NN >= 1), via p2 doublings
    g("q_dbln:")
    l = g.lab("dn")
    g(f"{l}: JSR p2_dbl", "DEC NN", f"BEQ {l}_last", "JSR p1p1_to_p2", f"JMP {l}")
    g(f"{l}_last: JSR p1p1_to_p3", "RTS")

    # ---- constant-time select: SEL = sign(d) * T[|d|], table base in KPTR
    # d (signed, -8..8) in DIGIT
    g("select:")
    for c, off in [("C_ONE", 0), ("C_ONE", 32), ("C_ZERO", 64)]:
        ptr(g, "P1", c)
        ptr(g, "P3", SEL + off)
        g("JSR fe_copy")
    # SGN = $FF if d < 0 ; ABSD = |d|
    g("LDA DIGIT", "ASL A")
    mask_from_carry(g)
    g("STA SGN", "EOR DIGIT", "SEC", "SBC SGN", "STA ABSD")
    g("LDA KPTR", "STA SPTR", "LDA KPTR+1", "STA SPTR+1")
    g("LDA #1", "STA II")
    ls = g.lab("sel")
    g(f"{ls}:")
    # MASK = (ABSD == II) ? FF : 00
    g("LDA ABSD", "EOR II", "CMP #1")          # C = 0 iff equal
    mask_from_borrow(g)
    g("STA MASK", "LDY #95")
    lc = g.lab("cmv")
    g(f"{lc}: LDA (SPTR),Y", f"EOR {SEL},Y", "AND MASK", f"EOR {SEL},Y", f"STA {SEL},Y", "DEY", f"BPL {lc}")
    g("CLC", "LDA SPTR", "ADC #96", "STA SPTR", "LDA SPTR+1", "ADC #0", "STA SPTR+1")
    g("INC II", "LDA II", "CMP #9", f"BNE {ls}")
    # conditional negation: swap ypx/ymx and negate xy2d under SGN
    g("LDY #31")
    lw = g.lab("sw")
    g(f"{lw}: LDA {SEL},Y", f"EOR {SEL + 32},Y", "AND SGN", "STA T0",
      f"LDA {SEL},Y", "EOR T0", f"STA {SEL},Y", f"LDA {SEL + 32},Y", "EOR T0", f"STA {SEL + 32},Y",
      "DEY", f"BPL {lw}")
    sub(NEGT, "C_ZERO", SEL + 64)
    g("LDA SGN", "STA MASK")
    ptr(g, "P1", NEGT)
    ptr(g, "P3", SEL + 64)
    g("JSR fe_cmov", "RTS")

    # ---- Q = [s]B for the 64 signed digits at DIG (constant time)
    g("base_mult:", "JSR q_zero", "LDA #7", "STA BI")
    lo = g.lab("bo")
    g(f"{lo}:")
    g("LDA BI", "CMP #7", f"BEQ {lo}_nd", "LDA #4", "STA NN", "JSR q_dbln", f"{lo}_nd:")
    g("STZ BK")
    lk = g.lab("bk")
    g(f"{lk}:")
    # digit index 8*BK + BI
    g("LDA BK", "ASL A", "ASL A", "ASL A", "CLC", "ADC BI", "TAX", f"LDA {SCL['DIG']},X", "STA DIGIT")
    # table pointer = BTAB + BK*768
    g("LDA BK", "STA T0", "ASL A", "CLC", "ADC T0", "ASL A", "ASL A", "STA T1",   # BK*12 (high bytes / 64)
      "LDA #0", "STA T0")
    # 768*BK = BK*3*256 -> high byte add BK*3
    g("LDA BK", "ASL A", "CLC", "ADC BK", "STA T1",
      "LDA #<BTAB", "STA KPTR", "LDA #>BTAB", "CLC", "ADC T1", "STA KPTR+1")
    g("JSR select", "JSR madd", "JSR p1p1_to_p3")
    g("INC BK", "LDA BK", "CMP #8", f"BEQ {lk}_e", f"JMP {lk}", f"{lk}_e:")
    g("DEC BI", f"BMI {lo}_e", f"JMP {lo}", f"{lo}_e: RTS")

    # ---- encode Q to 32 bytes at (P4)
    g("encode:")
    ptr(g, "P1", Z_(Q))
    ptr(g, "P3", fe("EZI"))
    g("JSR fe_copy", "JSR fe_invert")
    mul(fe("EX"), X_(Q), fe("I0"))
    mul(fe("EY"), Y_(Q), fe("I0"))
    for v in ("EX", "EY"):
        ptr(g, "P3", fe(v))
        g("JSR fe_canon")
    g("LDY #31")
    l = g.lab("en")
    g(f"{l}: LDA {fe('EY')},Y", "STA (P4),Y", "DEY", f"BPL {l}")
    g(f"LDA {fe('EX')}", "AND #1", "ROR A", "ROR A", "AND #$80", "LDY #31", "ORA (P4),Y", "STA (P4),Y", "RTS")


def _p3_from_cptr(g, off):
    g("CLC", "LDA CPTR", f"ADC #{off}", "STA P3", "LDA CPTR+1", "ADC #0", "STA P3+1")


def _mul_s(g, r, a, off):
    """(r) = (a) * (SPTR + off)"""
    ptr(g, "P1", a)
    g("CLC", "LDA SPTR", f"ADC #{off}", "STA P2", "LDA SPTR+1", "ADC #0", "STA P2+1")
    ptr(g, "P3", r)
    g("JSR fe_mul")


# ---------------------------------------------------------------------------
# scalar arithmetic mod L
# ---------------------------------------------------------------------------
def gen_scalar(g):
    RIN, RR, RT = SCL["RED_IN"], SCL["RED_R"], SCL["RED_T"]
    lb = le32(L) + b"\x00"
    # sc_reduce: RR[0..31] = RED_IN (64 bytes) mod L, bit-serial, constant time
    g("sc_reduce:", "LDX #32")
    l0 = g.lab("rz")
    g(f"{l0}: STZ {RR},X", "DEX", f"BPL {l0}")
    g("LDA #63", "STA JJ")                     # byte index (public)
    lj = g.lab("rj")
    g(f"{lj}: LDX JJ", f"LDA {RIN},X", "STA BJ", "LDA #8", "STA KK")
    lk = g.lab("rk")
    g(f"{lk}: ASL BJ")                         # C = next bit (MSB first)
    g(f"ROL {RR}")
    for i in range(1, 33):
        g(f"ROL {RR + i}")
    g("SEC")
    for i in range(33):
        g(f"LDA {RR + i}", f"SBC #${lb[i]:02X}", f"STA {RT + i}")
    mask_from_carry(g)
    g("STA MASK", "LDX #32")
    lc = g.lab("rc")
    g(f"{lc}: LDA {RT},X", f"EOR {RR},X", "AND MASK", f"EOR {RR},X", f"STA {RR},X", "DEX", f"BPL {lc}")
    g("DEC KK", f"BEQ {lk}_e", f"JMP {lk}", f"{lk}_e:")
    g("DEC JJ", f"BMI {lj}_e", f"JMP {lj}", f"{lj}_e: RTS")
    # sc_muladd: RED_IN = (P1) * (P2) + (P4) (64 bytes), then RR = mod L
    g("sc_muladd:")
    # product via fe_mul's front half: reuse by computing into T64
    g("JSR prod64")
    g("LDX #0", "CLC")
    for i in range(32):
        g(f"LDY #{i}", f"LDA {T64 + i}", "ADC (P4),Y", f"STA {RIN + i}")
    for i in range(32, 64):
        g(f"LDA {T64 + i}", "ADC #0", f"STA {RIN + i}")
    g("JMP sc_reduce")


def gen_prod64(g):
    """T64 = (P1) * (P2), 64-byte product (same core as fe_mul, no reduction)."""
    g("prod64:", "LDY #31")
    l = g.lab("ld")
    g(f"{l}: LDA (P1),Y", f"STA {W33},Y", "DEY", f"BPL {l}", f"STZ {W33 + 32}", "LDX #0")
    lk = g.lab("k")
    g(f"{lk}:")
    for i in range(33):
        g(f"LDA {W33 + i}", f"STA {AKS + 8 * i},X")
    g("ASL " + str(W33))
    for i in range(1, 33):
        g(f"ROL {W33 + i}")
    g("INX", "CPX #8")
    loop_ne(g, lk)
    g("LDX #63")
    lz = g.lab("z")
    g(f"{lz}: STZ {T64},X", "DEX", f"BPL {lz}", "STZ JJ")
    lj = g.lab("j")
    g(f"{lj}: LDY JJ", "LDA (P2),Y", "STA BJ", "LDY #0")
    lb = g.lab("b")
    g(f"{lb}: LSR BJ")
    mask_from_carry(g)
    g("STA MASK", "LDX JJ", "CLC")
    for i in range(33):
        g(f"LDA {AKS + 8 * i},Y", "AND MASK", f"ADC {T64 + i},X", f"STA {T64 + i},X")
    g("INY", "CPY #8")
    loop_ne(g, lb)
    g("INC JJ", "LDA JJ", "CMP #32")
    loop_ne(g, lj)
    g("RTS")


def gen_recode(g):
    """DIG[0..63] = signed radix-16 digits of the 32-byte scalar at (P1),
    scalar < 2^255 (ref10 ge_scalarmult_base recoding, branch-free)."""
    DIG = SCL["DIG"]
    g("recode:", "LDY #0", "LDX #0")
    l = g.lab("rc")
    g(f"{l}: LDA (P1),Y", "AND #$0F", f"STA {DIG},X", "INX", "LDA (P1),Y",
      "LSR A", "LSR A", "LSR A", "LSR A", f"STA {DIG},X", "INX", "INY", "CPY #32", f"BNE {l}")
    g("STZ T0", "LDX #0")
    l2 = g.lab("rc2")
    g(f"{l2}: LDA {DIG},X", "CLC", "ADC T0", f"STA {DIG},X",    # e += carry
      "CLC", "ADC #8", "LSR A", "LSR A", "LSR A", "LSR A", "STA T0",   # carry = (e+8)>>4
      "ASL A", "ASL A", "ASL A", "ASL A", "STA T1", f"LDA {DIG},X", "SEC", "SBC T1", f"STA {DIG},X",
      "INX", "CPX #63", f"BNE {l2}")
    g(f"LDA {DIG + 63}", "CLC", "ADC T0", f"STA {DIG + 63}", "RTS")


# ---------------------------------------------------------------------------
# SHA-512
# ---------------------------------------------------------------------------
def gen_sha512(g):
    H, W, WV, BUF, X, LENB = SHA_H, SHA_W, SHA_WV, SHA_BUF, SHA_X, SHA_LEN
    A_, B_, C_, D_, E_, F_, G_, H_ = (WV + 8 * i for i in range(8))
    S0, S1, T1w, T2w, CHw, Xa, Xb = (X + 8 * i for i in range(7))

    def copy(dst, src):
        for i in range(8):
            g(f"LDA {src + i}", f"STA {dst + i}")

    def add_to(dst, src):
        g("CLC")
        for i in range(8):
            g(f"LDA {dst + i}", f"ADC {src + i}", f"STA {dst + i}")

    def rotr(dst, src, n):
        q, r = divmod(n, 8)
        for i in range(8):
            g(f"LDA {src + (i + q) % 8}", f"STA {dst + i}")
        for _ in range(r):
            g(f"LDA {dst}", "LSR A")
            for i in range(7, -1, -1):
                g(f"ROR {dst + i}")

    def shr(dst, src, n):
        copy(dst, src)
        for _ in range(n):
            g(f"LSR {dst + 7}")
            for i in range(6, -1, -1):
                g(f"ROR {dst + i}")

    def xor_into(dst, src):
        for i in range(8):
            g(f"LDA {dst + i}", f"EOR {src + i}", f"STA {dst + i}")

    # sha_init
    g("sha_init:")
    for w, v in enumerate(sha_h0()):
        b = v.to_bytes(8, "little")
        for i in range(8):
            g(f"LDA #${b[i]:02X}", f"STA {H + 8 * w + i}")
    g("STZ BUFPOS", f"STZ {LENB}", f"STZ {LENB + 1}", f"STZ {LENB + 2}", "RTS")
    # sha_byte: append A
    g("sha_byte:", "LDX BUFPOS", f"STA {BUF},X", "INC BUFPOS",
      f"INC {LENB}", "BNE _sb1", f"INC {LENB + 1}", "BNE _sb1", f"INC {LENB + 2}",
      "_sb1: LDA BUFPOS", "CMP #128", "BNE _sb2", "JSR sha_block", "_sb2: RTS")
    # sha_update: PTR, LEN (16-bit)
    g("sha_update:")
    l = g.lab("su")
    g(f"{l}: LDA LEN", "ORA LEN+1", f"BEQ {l}_d",
      "LDA (PTR)", "JSR sha_byte", "INC PTR", f"BNE {l}_a", "INC PTR+1",
      f"{l}_a: LDA LEN", f"BNE {l}_b", "DEC LEN+1", f"{l}_b: DEC LEN", f"JMP {l}", f"{l}_d: RTS")
    # sha_final: digest to (PTR) as 64 big-endian bytes
    g("sha_final:")
    for i in range(3):
        g(f"LDA {LENB + i}", f"STA {Xb + i}")
    g("LDA #$80", "JSR sha_pad")
    lp = g.lab("pd")
    g(f"{lp}: LDA BUFPOS", "CMP #112", f"BEQ {lp}_d", "LDA #0", "JSR sha_pad", f"JMP {lp}", f"{lp}_d:")
    # 128-bit big-endian bit length: bytes 112..127; value = len*8 (<= 27 bits)
    for _ in range(12):
        g("LDA #0", "JSR sha_pad")              # sha_pad returns with A = BUFPOS
    g(f"LDA {Xb}", "STA T0", f"LDA {Xb + 1}", "STA T1", f"LDA {Xb + 2}", "STA T2", "STZ T3")
    for _ in range(3):
        g("ASL T0", "ROL T1", "ROL T2", "ROL T3")
    for zp in ("T3", "T2", "T1", "T0"):
        g(f"LDA {zp}", "JSR sha_pad")
    # output big-endian
    g("LDY #0", "LDX #0")
    lo = g.lab("so")
    g(f"{lo}: TXA", "ORA #7", "STA T0")          # T0 = 8w+7
    for i in range(8):
        g("LDX T0", f"LDA {H},X", "STA (PTR),Y", "INY", "DEC T0")
    g("LDX T0", "INX", "INX", "INX", "INX", "INX", "INX", "INX", "INX", "INX", "CPY #64", f"BNE {lo}", "RTS")
    # sha_pad: append A without counting it in the message length
    g("sha_pad:", "LDX BUFPOS", f"STA {BUF},X", "INC BUFPOS", "LDA BUFPOS", "CMP #128",
      "BNE _sp1", "JSR sha_block", "_sp1: RTS")
    # sha_block: compress BUF
    g("sha_block:", "STZ BUFPOS")
    # W[0..15] from BUF (big-endian words)
    g("LDX #0")
    lw = g.lab("w")
    g(f"{lw}:")
    for i in range(8):
        g(f"LDA {BUF + 7 - i},X", f"STA {W + i},X")
    g("TXA", "CLC", "ADC #8", "TAX", "CPX #128", f"BNE {lw}")
    # W[16..79]
    g("LDA #<" + str(W + 128), "STA WPTR", "LDA #>" + str(W + 128), "STA WPTR+1", "LDA #64", "STA CNT")
    ls = g.lab("ws")
    g(f"{ls}:")

    def load_rel(dst, back):
        # dst = W[t - back]  (WPTR points at W[t])
        g("SEC", "LDA WPTR", f"SBC #{8 * back}", "STA PTR2", "LDA WPTR+1", "SBC #0", "STA PTR2+1", "LDY #7")
        l2 = g.lab("lr")
        g(f"{l2}: LDA (PTR2),Y", f"STA {dst},Y", "DEY", f"BPL {l2}")
    load_rel(Xa, 2)
    rotr(S1, Xa, 19)
    rotr(T2w, Xa, 61)
    xor_into(S1, T2w)
    shr(T2w, Xa, 6)
    xor_into(S1, T2w)                      # sigma1
    load_rel(Xa, 15)
    rotr(S0, Xa, 1)
    rotr(T2w, Xa, 8)
    xor_into(S0, T2w)
    shr(T2w, Xa, 7)
    xor_into(S0, T2w)                      # sigma0
    add_to(S1, S0)
    load_rel(Xa, 7)
    add_to(S1, Xa)
    load_rel(Xa, 16)
    add_to(S1, Xa)
    g("LDY #7")
    l3 = g.lab("st")
    g(f"{l3}: LDA {S1},Y", "STA (WPTR),Y", "DEY", f"BPL {l3}")
    g("CLC", "LDA WPTR", "ADC #8", "STA WPTR", f"BCC {ls}_a", "INC WPTR+1", f"{ls}_a: DEC CNT",
      f"BEQ {ls}_e", f"JMP {ls}", f"{ls}_e:")
    # working variables
    for i in range(64):
        g(f"LDA {H + i}", f"STA {WV + i}")
    g("LDA #<SHAK", "STA KPTR", "LDA #>SHAK", "STA KPTR+1",
      f"LDA #<{W}", "STA WPTR", f"LDA #>{W}", "STA WPTR+1", "LDA #80", "STA CNT")
    lr = g.lab("rd")
    g(f"{lr}:")
    rotr(S1, E_, 14)
    rotr(T2w, E_, 18)
    xor_into(S1, T2w)
    rotr(T2w, E_, 41)
    xor_into(S1, T2w)                      # Sigma1(e)
    for i in range(8):                     # ch = (e & f) ^ (~e & g)
        g(f"LDA {E_ + i}", f"AND {F_ + i}", "STA T0", f"LDA {E_ + i}", "EOR #$FF", f"AND {G_ + i}",
          "EOR T0", f"STA {CHw + i}")
    copy(T1w, H_)
    add_to(T1w, S1)
    add_to(T1w, CHw)
    g("LDY #0", "CLC")
    for i in range(8):
        g(f"LDA {T1w + i}", "ADC (KPTR),Y", "STA " + str(T1w + i), "INY") if False else None
    # T1 += K[t] + W[t]
    g("LDY #0", "CLC")
    for i in range(8):
        g(f"LDA {T1w + i}", "ADC (KPTR),Y", f"STA {T1w + i}", "INY")
    g("LDY #0", "CLC")
    for i in range(8):
        g(f"LDA {T1w + i}", "ADC (WPTR),Y", f"STA {T1w + i}", "INY")
    rotr(S0, A_, 28)
    rotr(T2w, A_, 34)
    xor_into(S0, T2w)
    rotr(T2w, A_, 39)
    xor_into(S0, T2w)                      # Sigma0(a)
    for i in range(8):                     # maj = (a & b) ^ (a & c) ^ (b & c)
        g(f"LDA {A_ + i}", f"AND {B_ + i}", "STA T0", f"LDA {A_ + i}", f"AND {C_ + i}", "EOR T0", "STA T0",
          f"LDA {B_ + i}", f"AND {C_ + i}", "EOR T0", f"STA {T2w + i}")
    add_to(T2w, S0)
    # rotate h..a
    for dst, src in [(H_, G_), (G_, F_), (F_, E_)]:
        copy(dst, src)
    copy(E_, D_)
    add_to(E_, T1w)
    for dst, src in [(D_, C_), (C_, B_), (B_, A_)]:
        copy(dst, src)
    copy(A_, T1w)
    add_to(A_, T2w)
    g("CLC", "LDA KPTR", "ADC #8", "STA KPTR", f"BCC {lr}_a", "INC KPTR+1",
      f"{lr}_a: CLC", "LDA WPTR", "ADC #8", "STA WPTR", f"BCC {lr}_b", "INC WPTR+1",
      f"{lr}_b: DEC CNT", f"BEQ {lr}_e", f"JMP {lr}", f"{lr}_e:")
    for w in range(8):
        add_to(H + 8 * w, WV + 8 * w)
    g("RTS")


# ---------------------------------------------------------------------------
# Ed25519 sign / verify, envelope, record
# ---------------------------------------------------------------------------
def sha_ptr_len(g, addr, n):
    ptr(g, "PTR", addr)
    g(f"LDA #<{n}", "STA LEN", f"LDA #>{n}", "STA LEN+1", "JSR sha_update")


def sha_msg(g):
    """Hash the frozen message at MSG with the length stored at META."""
    ptr(g, "PTR", MSG)
    g(f"LDA {META}", "STA LEN", f"LDA {META + 1}", "STA LEN+1", "JSR sha_update")


def gen_ed25519(g):
    S = SCL
    Q = fe("Q")
    # derive: H = SHA512(seed); a = clamp(H[0:32]); prefix = H[32:64]; A = [a]B
    g("derive:", "JSR derive_h")
    ptr(g, "P1", S["H"])
    g("JSR recode", "JSR base_mult")
    ptr(g, "P4", S["A_BYTES"])
    g("JSR encode", "RTS")
    g("derive_h:", "JSR set_ct", "JSR sha_init")
    sha_ptr_len(g, SEED, 32)
    ptr(g, "PTR", S["H"])
    g("JSR sha_final")
    g(f"LDA {S['H']}", "AND #$F8", f"STA {S['H']}",
      f"LDA {S['H'] + 31}", "AND #$3F", "ORA #$40", f"STA {S['H'] + 31}", "RTS")
    # sign into (SPTR... ) -> buffer given in PTR2? use fixed: signature to (P4) region via SIGP
    # sign: signature -> (TT).  REUSEA != 0 reuses A_BYTES (already checked
    # byte-for-byte against the expected key) instead of recomputing [a]B.
    g("sign:", "JSR set_ct", "LDA REUSEA", "BNE _sg_reuse", "JSR derive", "JMP _sg_go",
      "_sg_reuse: JSR derive_h", "_sg_go:")
    # r = SHA512(prefix || M) mod L
    g("JSR sha_init")
    sha_ptr_len(g, S["H"] + 32, 32)
    sha_msg(g)
    ptr(g, "PTR", S["RED_IN"])
    g("JSR sha_final", "JSR sc_reduce")
    g("LDX #31")
    l = g.lab("cr")
    g(f"{l}: LDA {S['RED_R']},X", f"STA {S['R_SC']},X", "DEX", f"BPL {l}")
    ptr(g, "P1", S["R_SC"])
    g("JSR recode", "JSR base_mult")
    ptr(g, "P4", S["RBYTES"])
    g("JSR encode")
    # k = SHA512(R || A || M) mod L
    g("JSR sha_init")
    sha_ptr_len(g, S["RBYTES"], 32)
    sha_ptr_len(g, S["A_BYTES"], 32)
    sha_msg(g)
    ptr(g, "PTR", S["RED_IN"])
    g("JSR sha_final", "JSR sc_reduce")
    g("LDX #31")
    l = g.lab("ck")
    g(f"{l}: LDA {S['RED_R']},X", f"STA {S['K_SC']},X", "DEX", f"BPL {l}")
    # S = (k*a + r) mod L
    ptr(g, "P1", S["K_SC"])
    ptr(g, "P2", S["H"])
    ptr(g, "P4", S["R_SC"])
    g("JSR sc_muladd")
    # signature = R || S  -> (TT)
    g("LDY #31")
    l = g.lab("sg")
    g(f"{l}: LDA {S['RBYTES']},Y", "STA (TT),Y", "DEY", f"BPL {l}", "LDY #63")
    l = g.lab("sg2")
    g(f"{l}: LDA {S['RED_R'] - 32},Y", "STA (TT),Y", "DEY", "CPY #31", f"BNE {l}", "RTS")


def gen_verify(g):
    """Public-data verification of SIG1 against A_BYTES and the frozen message.
    Sets STATUS = 0 on success, nonzero on failure."""
    S = SCL
    Q, PP = fe("Q"), fe("PP")
    DU, DV, DV3, DVXX, DCHK, DX, DY = (fe(n) for n in ["DU", "DV", "DV3", "DVXX", "DCHK", "DX", "DY"])
    NEGA, VTAB, R2, CB = fe("NEGA"), fe("VTAB"), fe("R2"), fe("CB")
    add, sub, mul = (lambda r, a, b: call3(g, "fe_add", r, a, b),
                     lambda r, a, b: call3(g, "fe_sub", r, a, b),
                     lambda r, a, b: call3(g, "fe_mul", r, a, b))
    g("verify:", "JSR set_fast", "LDA #1", "STA STATUS")
    # k = SHA512(R || A || M) mod L, recomputed here from the signature under
    # test and the frozen message (never reused from the signing pass)
    g("JSR sha_init")
    sha_ptr_len(g, S["SIG1"], 32)
    sha_ptr_len(g, S["A_BYTES"], 32)
    sha_msg(g)
    ptr(g, "PTR", S["RED_IN"])
    g("JSR sha_final", "JSR sc_reduce", "LDX #31")
    lk0 = g.lab("vk")
    g(f"{lk0}: LDA {S['RED_R']},X", f"STA {S['VK']},X", "DEX", f"BPL {lk0}")
    # S < L check (public): compare S against L, big end first
    lb = le32(L)
    sbytes = S["SIG1"] + 32
    g("LDX #31")
    lc = g.lab("sl")
    g(f"{lc}: LDA {sbytes},X", "CMP SCL_L,X", f"BCC {lc}_ok", f"BNE {lc}_f", "DEX", f"BPL {lc}",
      f"{lc}_f: JMP vfail", f"{lc}_ok:")              # S >= L rejected
    # decode -A (ref10 ge_frombytes_negate_vartime)
    g("LDY #31")
    l = g.lab("dy")
    g(f"{l}: LDA {S['A_BYTES']},Y", f"STA {DY},Y", "DEY", f"BPL {l}", f"LDA {DY + 31}", "AND #$7F", f"STA {DY + 31}")
    sq = lambda r, a: call3(g, "fe_sq", r, a)
    sq(DU, DY)
    mul(DV, DU, "C_D")
    sub(DU, DU, "C_ONE")            # u = y^2 - 1
    add(DV, DV, "C_ONE")            # v = d y^2 + 1
    sq(DV3, DV)
    mul(DV3, DV3, DV)               # v^3
    sq(DX, DV3)
    mul(DX, DX, DV)
    mul(DX, DX, DU)                 # u v^7
    ptr(g, "P1", DX)
    ptr(g, "P3", fe("EZI"))
    g("JSR fe_copy", "JSR fe_pow2523")
    mul(DX, fe("I0"), DV3)
    mul(DX, DX, DU)                 # x = u v^3 (u v^7)^((p-5)/8)
    sq(DVXX, DX)
    mul(DVXX, DVXX, DV)             # v x^2
    sub(DCHK, DVXX, DU)
    ptr(g, "P3", DCHK)
    g("JSR fe_canon", "JSR fe_iszero", "BEQ _v_rootok")
    add(DCHK, DVXX, DU)
    ptr(g, "P3", DCHK)
    g("JSR fe_canon", "JSR fe_iszero", "BEQ _v_m1", "JMP vfail", "_v_m1:")
    mul(DX, DX, "C_SQRTM1")
    g("_v_rootok:")
    # negate: if (x & 1) == sign(A) then x = -x   (gives -A)
    ptr(g, "P3", DX)
    g("JSR fe_canon")
    g(f"LDA {S['A_BYTES'] + 31}", "ROL A", "LDA #0", "ROL A", f"EOR {DX}", "AND #1", "BNE _v_noneg")
    sub(DX, "C_ZERO", DX)
    g("_v_noneg:")
    # NEGA = (x, y, 1, x*y)
    for c, off in [(DX, 0), (DY, 32), ("C_ONE", 64)]:
        ptr(g, "P1", c)
        ptr(g, "P3", NEGA + off)
        g("JSR fe_copy")
    mul(NEGA + 96, DX, DY)
    # VTAB[m-1] = cached(m * NEGA), m = 1..15
    for c, off in [(NEGA, 0)]:
        pass
    for i in range(4):
        ptr(g, "P1", NEGA + 32 * i)
        ptr(g, "P3", Q + 32 * i)
        g("JSR fe_copy")
    g(f"LDA #<{VTAB}", "STA CPTR", f"LDA #>{VTAB}", "STA CPTR+1", "JSR to_cached")
    g("LDA #14", "STA CNT")
    lt = g.lab("vt")
    g(f"{lt}:", "JSR gadd_neg_a", "JSR p1p1_to_p3",
      "CLC", "LDA CPTR", "ADC #128", "STA CPTR", "LDA CPTR+1", "ADC #0", "STA CPTR+1",
      "JSR to_cached", "DEC CNT", "BNE " + lt)
    # Q = [k](-A): 4-bit windows, MSB first (public scalar)
    g("JSR q_zero", "LDA #63", "STA VJ")
    lw = g.lab("vw")
    g(f"{lw}:", "LDA #4", "STA NN", "JSR q_dbln")
    g("LDA VJ", "LSR A", "TAX", f"LDA {S['VK']},X", "STA T0", "LDA VJ", "AND #1", f"BEQ {lw}_lo",
      "LSR T0", "LSR T0", "LSR T0", "LSR T0", f"{lw}_lo: LDA T0", "AND #$0F", f"BNE {lw}_go", f"JMP {lw}_n", f"{lw}_go:")
    # CPTR = VTAB + (nib-1)*128
    g("SEC", "SBC #1", "LSR A", "STA T1", "LDA #0", "ROR A", "CLC", f"ADC #<{VTAB}", "STA CPTR",
      "LDA T1", f"ADC #>{VTAB}", "STA CPTR+1", "JSR gadd", "JSR p1p1_to_p3")
    g(f"{lw}_n: DEC VJ", f"BMI {lw}_e", f"JMP {lw}", f"{lw}_e:")
    # R2 = Q (save), Q = [S]B, then Q = Q + cached(R2)
    for i in range(4):
        ptr(g, "P1", Q + 32 * i)
        ptr(g, "P3", R2 + 32 * i)
        g("JSR fe_copy")
    ptr(g, "P1", S["SIG1"] + 32)
    g("JSR recode", "JSR base_mult")
    # CB = cached(R2): temporarily swap Q and R2 through to_cached
    for i in range(4):
        ptr(g, "P1", Q + 32 * i)
        ptr(g, "P3", PP + 32 * i)
        g("JSR fe_copy")
        ptr(g, "P1", R2 + 32 * i)
        ptr(g, "P3", Q + 32 * i)
        g("JSR fe_copy")
    g(f"LDA #<{CB}", "STA CPTR", f"LDA #>{CB}", "STA CPTR+1", "JSR to_cached")
    for i in range(4):
        ptr(g, "P1", PP + 32 * i)
        ptr(g, "P3", Q + 32 * i)
        g("JSR fe_copy")
    g("JSR gadd", "JSR p1p1_to_p3")
    ptr(g, "P4", S["TMP64"])
    g("JSR encode")
    g("LDX #31")
    lr = g.lab("vr")
    g(f"{lr}: LDA {S['TMP64']},X", f"CMP {S['SIG1']},X", "BNE vfail", "DEX", f"BPL {lr}")
    g("STZ STATUS", "JMP set_ct")
    g("vfail:", "LDA #1", "STA STATUS", "JMP set_ct")
    # gadd with CPTR = VTAB (1 * -A cached) while Q holds the running multiple
    g("gadd_neg_a:", "LDA CPTR", "PHA", "LDA CPTR+1", "PHA",
      f"LDA #<{VTAB}", "STA CPTR", f"LDA #>{VTAB}", "STA CPTR+1", "JSR gadd",
      "PLA", "STA CPTR+1", "PLA", "STA CPTR", "RTS")
    # fe_iszero: (P3) canonical -> Z flag set if zero
    g("fe_iszero:", "LDY #31", "LDA #0")
    l = g.lab("iz")
    g(f"{l}: ORA (P3),Y", "DEY", f"BPL {l}", "CMP #0", "RTS")


def gen_main(g, double_sign=True, verify=True):
    """Spec Section 10.3 envelope -> Section 10.4 record, with bank locks."""
    S = SCL
    g("sign_main:", "JSR set_ct", "LDA #0", "STA FAILC", "STZ REUSEA")
    # ---- envelope: magic, profile 0, reserved 0, length <= 4096, CRC
    g("LDX #7")
    l = g.lab("mg")
    g(f"{l}: LDA {ENV},X", "CMP IN_MAGIC,X", f"BEQ {l}_o", "JMP fail", f"{l}_o: DEX", f"BPL {l}")
    g(f"LDA {ENV + 8}", "BEQ _m_p", "JMP fail", "_m_p:")          # profile 0 only in this build
    g(f"LDA {ENV + 9}", "BEQ _m_r", "JMP fail", "_m_r:")          # reserved
    g(f"LDA {ENV + 11}", "CMP #$10", "BCC _m_l", "BNE _m_lf", f"LDA {ENV + 10}", "BEQ _m_l",
      "_m_lf: JMP fail", "_m_l:")
    # total = 44 + length; CRC over [ENV, ENV+total)
    g("CLC", f"LDA {ENV + 10}", "ADC #44", "STA TOTAL", f"LDA {ENV + 11}", "ADC #0", "STA TOTAL+1")
    ptr(g, "PTR", ENV)
    g("LDA TOTAL", "STA LEN", "LDA TOTAL+1", "STA LEN+1", "JSR crc32")
    # compare with trailing CRC at ENV + total
    g("CLC", f"LDA #<{ENV}", "ADC TOTAL", "STA PTR", f"LDA #>{ENV}", "ADC TOTAL+1", "STA PTR+1", "LDY #3")
    l = g.lab("cc")
    g(f"{l}: LDA (PTR),Y", "CMP CRC,Y", f"BEQ {l}_o", "JMP fail", f"{l}_o: DEY", f"BPL {l}")
    # ---- freeze: message -> $4000, metadata -> $5000, then MESSAGE_LOCK
    ptr(g, "PTR", ENV + 44)
    ptr(g, "PTR2", MSG)
    g(f"LDA {ENV + 10}", "STA LEN", f"LDA {ENV + 11}", "STA LEN+1", "JSR memcpy")
    g(f"LDA {ENV + 10}", f"STA {META}", f"LDA {ENV + 11}", f"STA {META + 1}", f"LDA {ENV + 8}", f"STA {META + 2}")
    g("LDX #31")
    l = g.lab("ek")
    g(f"{l}: LDA {ENV + 12},X", f"STA {META + 3},X", f"STA {S['EXPECT']},X", "DEX", f"BPL {l}")
    g("STA $7F03")                                       # MESSAGE_LOCK
    # ---- signature 1
    g(f"LDA #<{S['SIG1']}", "STA TT", f"LDA #>{S['SIG1']}", "STA TT+1", "JSR sign")
    # derived public key must equal the expected key
    g("LDX #31")
    l = g.lab("pk")
    g(f"{l}: LDA {S['A_BYTES']},X", f"CMP {S['EXPECT']},X", f"BEQ {l}_o", "JMP fail", f"{l}_o: DEX", f"BPL {l}")
    if double_sign:
        g("LDA #1", "STA REUSEA")
        g(f"LDA #<{S['SIG2']}", "STA TT", f"LDA #>{S['SIG2']}", "STA TT+1", "JSR sign", "STZ REUSEA")
        g("LDX #63")
        l = g.lab("ds")
        g(f"{l}: LDA {S['SIG1']},X", f"CMP {S['SIG2']},X", f"BEQ {l}_o", "JMP fail", f"{l}_o: DEX", f"BPL {l}")
    if verify:
        g("JSR verify", "LDA STATUS", "BEQ _m_v", "JMP fail", "_m_v:")
    # ---- result record at $6000, then RESULT_LOCK
    g("LDX #0")
    l = g.lab("rz")
    g(f"{l}: STZ {REC},X", "INX", f"BNE {l}")
    g("LDX #7")
    l = g.lab("om")
    g(f"{l}: LDA OUT_MAGIC,X", f"STA {REC},X", "DEX", f"BPL {l}")
    g("LDA #1", f"STA {REC + 8}", f"LDA {META + 2}", f"STA {REC + 9}",
      f"LDA {META}", f"STA {REC + 10}", f"LDA {META + 1}", f"STA {REC + 11}")
    g("LDX #31")
    l = g.lab("oa")
    g(f"{l}: LDA {S['A_BYTES']},X", f"STA {REC + 0x0C},X", "DEX", f"BPL {l}", "LDX #63")
    l = g.lab("os")
    g(f"{l}: LDA {S['SIG1']},X", f"STA {REC + 0x2C},X", "DEX", f"BPL {l}")
    g("JSR sha_init")
    sha_msg(g)
    ptr(g, "PTR", REC + 0x6C)
    g("JSR sha_final")
    ptr(g, "PTR", REC)
    g("LDA #$AC", "STA LEN", "STZ LEN+1", "JSR crc32", "LDX #3")
    l = g.lab("oc")
    g(f"{l}: LDA CRC,X", f"STA {REC + 0xAC},X", "DEX", f"BPL {l}")
    g("STA $7F04")                                       # RESULT_LOCK
    g("JSR wipe", "LDA #0", "STA STATUS", "RTS")
    g("fail:", "JSR wipe", "LDA #$EE", "STA STATUS", "RTS")
    # wipe: zero $0200-$3FFF (secret scratch); zero page and stack are left to the caller
    g("wipe:", "LDA #$02", "STA PTR+1", "STZ PTR", "LDA #0", "LDY #0")
    l = g.lab("wp")
    g(f"{l}: STA (PTR),Y", "INY", f"BNE {l}", "INC PTR+1", "LDX PTR+1", "CPX #$40", f"BNE {l}", "RTS")
    # memcpy (PTR) -> (PTR2), LEN bytes
    g("memcpy:")
    l = g.lab("mc")
    g(f"{l}: LDA LEN", "ORA LEN+1", f"BNE {l}_g", "RTS", f"{l}_g: LDA (PTR)", "STA (PTR2)",
      "INC PTR", f"BNE {l}_a", "INC PTR+1", f"{l}_a: INC PTR2", f"BNE {l}_b", "INC PTR2+1",
      f"{l}_b: LDA LEN", f"BNE {l}_c", "DEC LEN+1", f"{l}_c: DEC LEN", f"JMP {l}")
    # crc32 over (PTR), LEN -> CRC (little-endian)
    g("crc32:", "LDA #$FF", "STA CRC", "STA CRC+1", "STA CRC+2", "STA CRC+3")
    l = g.lab("cr")
    g(f"{l}: LDA LEN", "ORA LEN+1", "BEQ " + l + "_d",
      "LDA (PTR)", "EOR CRC", "TAX",
      "LDA CRC+1", "EOR CRCT0,X", "STA CRC", "LDA CRC+2", "EOR CRCT1,X", "STA CRC+1",
      "LDA CRC+3", "EOR CRCT2,X", "STA CRC+2", "LDA CRCT3,X", "STA CRC+3",
      "INC PTR", f"BNE {l}_a", "INC PTR+1", f"{l}_a: LDA LEN", f"BNE {l}_b", "DEC LEN+1", f"{l}_b: DEC LEN", f"JMP {l}")
    g(f"{l}_d: LDX #3")
    l2 = g.lab("cx")
    g(f"{l2}: LDA CRC,X", "EOR #$FF", "STA CRC,X", "DEX", f"BPL {l2}", "RTS")


def gen_data(g):
    def bytes_(b):
        for i in range(0, len(b), 16):
            g("        .byte " + ", ".join(f"${x:02X}" for x in b[i:i + 16]))
    g(".align 256", "BTAB:")
    bytes_(base_tables())
    # quarter-square tables (public-data multiply): SQ[x] = x^2/4, NSQ[x] = (255-x)^2/4
    for name, fn in [("SQL", lambda x: (x * x // 4) & 0xFF), ("SQH", lambda x: (x * x // 4) >> 8),
                     ("NSQL", lambda x: ((255 - x) ** 2 // 4) & 0xFF),
                     ("NSQH", lambda x: ((255 - x) ** 2 // 4) >> 8)]:
        g(".align 256", f"{name}:")
        bytes_(bytes(fn(x) for x in range(512)))
    g("HIMASKT:")
    bytes_(bytes(HIMASK))
    g("SQENT_LO:")
    g("        .byte " + ", ".join(f"<sqe{j + 2}" for j in range(31)))
    g("SQENT_HI:")
    g("        .byte " + ", ".join(f">sqe{j + 2}" for j in range(31)))
    g("SHAK:")
    for k in sha_k():
        bytes_(k.to_bytes(8, "little"))
    for name, v in [("C_ZERO", 0), ("C_ONE", 1), ("C_D", D), ("C_D2", D2), ("C_SQRTM1", SQRTM1)]:
        g(f"{name}:")
        bytes_(le32(v))
    g("SCL_L:")
    bytes_(le32(L))
    g("IN_MAGIC:")
    bytes_(b"DTS02IN1")
    g("OUT_MAGIC:")
    bytes_(b"DTS02OUT")
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        t.append(c)
    for k in range(4):
        g(f".align 256", f"CRCT{k}:")
        bytes_(bytes((v >> (8 * k)) & 0xFF for v in t))


def source(double_sign=True, verify=True):
    g = G()
    for k, v in ZP.items():
        g(f"{k} = ${v:02X}")
    g("CPTR = $40", "CRC = $42")
    g(".org $8000")
    g("reset:", "SEI", "CLD", "LDX #$FF", "TXS", "LDA #0", "STA $7F02", "JSR sign_main", "STP")
    # test stubs: harness sets PC to one of these
    for name in ["fe_mul", "fe_sq", "fe_add", "fe_sub", "fe_canon", "fe_invert", "fe_pow2523",
                 "sc_reduce", "sc_muladd", "recode", "base_mult", "encode", "derive", "sign",
                 "sha_init", "sha_update", "sha_final", "crc32", "sign_main", "prod64",
                 "fe_mul_ct", "fe_sq_ct", "fe_mul_qs", "fe_sq_qs"]:
        g(f"t_{name}: JSR set_ct", f"JSR {name}", "STP")
    g("t_verify: JSR verify", "STP")
    g("t_sha:", "JSR sha_init", "JSR sha_update", "JSR sha_final", "STP")
    gen_main(g, double_sign, verify)
    gen_ed25519(g)
    gen_verify(g)
    gen_group(g)
    gen_recode(g)
    gen_scalar(g)
    gen_prod64(g)
    gen_field(g)
    gen_field_high(g)
    gen_sha512(g)
    gen_data(g)
    g(".org $FFFA", ".word reset, reset, reset")
    return g.text()


def build(double_sign=True, verify=True):
    src = source(double_sign, verify)
    img, syms = assemble(src)
    return img, syms, src


# ---------------------------------------------------------------------------
# host-side helpers
# ---------------------------------------------------------------------------
def envelope(message, expected_pk, profile=0):
    body = (b"DTS02IN1" + bytes([profile, 0]) + len(message).to_bytes(2, "little")
            + expected_pk + message)
    return body + (zlib.crc32(body) & 0xFFFFFFFF).to_bytes(4, "little")


def expected_record(message, pk, sig, profile=0):
    r = bytearray(256)
    r[0:8] = b"DTS02OUT"
    r[8] = 1
    r[9] = profile
    r[10:12] = len(message).to_bytes(2, "little")
    r[0x0C:0x2C] = pk
    r[0x2C:0x6C] = sig
    r[0x6C:0xAC] = hashlib.sha512(message).digest()
    r[0xAC:0xB0] = (zlib.crc32(bytes(r[:0xAC])) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(r)
