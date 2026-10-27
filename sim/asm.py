"""Two-pass 65C02 assembler for the test and signing firmware.

The opcode table is derived from sim/cpu65c02.OPTABLE, the same table the
Klaus-Dormann-validated CPU core executes, so assembler and core cannot
disagree about an encoding.

Syntax: one statement per line, `label:` prefixes, `;` comments,
`.org $8000`, `.byte a, b, ...`, `.word x`, `.res n` (n zero bytes),
`.align n`, `NAME = expr`.
Operands: #imm, zp, zp,X, zp,Y, abs, abs,X, abs,Y, (zp,X), (zp),Y, (zp),
(abs) and (abs,X) for JMP, A or nothing for accumulator shifts, and
`zp,target` for BBRn/BBSn.  Zero page is chosen automatically when the
operand is known on the first pass to be below $100 and the instruction has
a zero-page form, except that a 4-digit hex literal ($0012) forces absolute;
the choice is frozen so both passes agree on sizes.  INC A / DEC A assemble
to the 65C02 accumulator forms.
Expressions: $hex, %bin, decimal, 'c', labels/constants, + - * with the
usual precedence (* before + and -, then left to right), and a leading
<expr / >expr (low / high byte).  Parentheses are not supported.

Every operand and data value is range-checked on the final pass: values
that do not fit their encoding raise AsmError instead of being truncated.
(Credit: the silent-truncation bug was reported in PR #1.)
"""

import re

from .cpu65c02 import OPTABLE

SIZE = {"imp": 1, "acc": 1, "imm": 2, "zp": 2, "zpx": 2, "zpy": 2, "abs": 3, "absx": 3,
        "absy": 3, "indx": 2, "indy": 2, "indz": 2, "ind": 3, "indabsx": 3, "rel": 2,
        "zprel": 3}

OPS = {}
for _code, (_m, _mode) in OPTABLE.items():
    if _m in ("NOP",) and _code != 0xEA:
        continue                       # undefined-opcode NOPs are not assemblable
    OPS.setdefault(_m, {})[_mode] = _code
ZP_TWIN = {"abs": "zp", "absx": "zpx", "absy": "zpy"}


class AsmError(Exception):
    pass


class Assembler:
    def __init__(self, source, org=0x8000, size=0x8000, fill=0xEA, symbols=None):
        self.source = source
        self.base = org
        self.size = size
        self.fill = fill
        self.symbols = dict(symbols or {})
        self.mode_choice = {}

    # ---- expressions ---------------------------------------------------------
    def eval(self, expr, final):
        expr = expr.strip()
        if expr.startswith("<"):
            return self.eval(expr[1:], final) & 0xFF
        if expr.startswith(">"):
            return (self.eval(expr[1:], final) >> 8) & 0xFF
        # Tokenise so character literals such as '+' stay intact, then apply
        # normal precedence: * binds tighter than + and -.
        toks = re.findall(r"'.'|[+\-*]|[^\s+\-*']+", expr)
        if not toks:
            raise AsmError(f"empty expression {expr!r}")
        total, op, prod, pending = 0, "+", None, None
        for tok in toks + ["+"]:
            if tok in ("+", "-", "*"):
                if prod is None:
                    if tok == "*":
                        raise AsmError(f"bad expression {expr!r}")
                    op = "-" if (op == "-") != (tok == "-") else "+"
                    continue
                if tok == "*":
                    pending = "*"
                    continue
                total += prod if op == "+" else -prod
                prod, op = None, tok
                continue
            v = self.atom(tok, final)
            if pending == "*":
                prod *= v
                pending = None
            elif prod is None:
                prod = v
            else:
                raise AsmError(f"bad expression {expr!r}")
        if pending:
            raise AsmError(f"bad expression {expr!r}")
        return total

    def atom(self, tok, final):
        if tok.startswith("$"):
            return int(tok[1:], 16)
        if tok.startswith("%"):
            return int(tok[1:], 2)
        if tok.startswith("'") and tok.endswith("'") and len(tok) == 3:
            return ord(tok[1])
        if tok.isdigit():
            return int(tok)
        if tok in self.symbols:
            return self.symbols[tok]
        if final:
            raise AsmError(f"undefined symbol {tok!r}")
        raise _Unresolved()

    def try_eval(self, expr, final):
        try:
            return self.eval(expr, final), True
        except _Unresolved:
            return 0x8000, False

    # ---- operand modes ---------------------------------------------------------
    def mode(self, mnem, arg, final, key):
        arg = arg.strip()
        forms = OPS[mnem]
        if arg == "" or arg.upper() == "A":
            if "acc" in forms:
                return "acc", None
            if "imp" in forms:
                return "imp", None
        if arg.startswith("#"):
            v, _ = self.try_eval(arg[1:], final)
            return "imm", v
        m = re.fullmatch(r"\((.+)\s*,\s*[xX]\)", arg)
        if m:
            v, _ = self.try_eval(m.group(1), final)
            return ("indabsx" if "indabsx" in forms else "indx"), v
        m = re.fullmatch(r"\((.+)\)\s*,\s*[yY]", arg)
        if m:
            v, _ = self.try_eval(m.group(1), final)
            return "indy", v
        m = re.fullmatch(r"\((.+)\)", arg)
        if m:
            v, _ = self.try_eval(m.group(1), final)
            return ("ind" if "ind" in forms else "indz"), v
        m = re.fullmatch(r"(.+?)\s*,\s*([xXyY])", arg)
        if m:
            v, known = self.try_eval(m.group(1), final)
            mode = "absx" if m.group(2) in "xX" else "absy"
        else:
            v, known = self.try_eval(arg, final)
            mode = "abs"
        if not final:
            zp = ZP_TWIN[mode]
            base = m.group(1) if m else arg
            forced_abs = re.fullmatch(r"\$[0-9A-Fa-f]{4}", base.strip()) is not None
            use_zp = zp in forms and (mode not in forms or
                                      (known and 0 <= v < 0x100 and not forced_abs))
            self.mode_choice[key] = zp if use_zp else mode
        return self.mode_choice[key], v

    # ---- passes ------------------------------------------------------------------
    def assemble(self):
        for final in (False, True):
            out = bytearray([self.fill] * self.size)
            pc = self.base
            for lineno, raw in enumerate(self.source.splitlines(), 1):
                line = raw.split(";", 1)[0].strip()
                try:
                    pc = self._line(line, pc, out, final, lineno)
                except AsmError as e:
                    raise AsmError(f"line {lineno}: {raw.strip()}: {e}") from None
        self.image = out
        return out

    def _put(self, out, pc, b):
        off = pc - self.base
        if not 0 <= off < self.size:
            raise AsmError(f"address ${pc:04X} outside image")
        out[off] = b & 0xFF

    @staticmethod
    def _check(v, bits, what):
        if not 0 <= v < (1 << bits):
            raise AsmError(f"{what} out of range ({v}; expected 0..{(1 << bits) - 1})")

    def _line(self, line, pc, out, final, key):
        while True:
            m = re.match(r"([A-Za-z_]\w*):\s*(.*)", line)
            if not m:
                break
            if not final and m.group(1) in self.symbols:
                raise AsmError(f"duplicate label {m.group(1)}")
            self.symbols[m.group(1)] = pc
            line = m.group(2)
        if not line:
            return pc
        m = re.fullmatch(r"([A-Za-z_]\w*)\s*=\s*(.+)", line)
        if m:
            v, known = self.try_eval(m.group(2), final)
            if known or final:
                self.symbols[m.group(1)] = v
            return pc
        parts = line.split(None, 1)
        mnem = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        if mnem == ".ORG":
            return self.eval(arg, True)
        if mnem == ".RES":
            n = self.eval(arg, True)
            for i in range(n):
                self._put(out, pc + i, 0)
            return pc + n
        if mnem == ".ALIGN":
            n = self.eval(arg, True)
            return (pc + n - 1) // n * n
        if mnem in (".BYTE", ".WORD"):
            for item in [a.strip() for a in arg.split(",") if a.strip()]:
                v, _ = self.try_eval(item, final)
                if final:
                    self._check(v, 8 if mnem == ".BYTE" else 16, mnem)
                self._put(out, pc, v)
                if mnem == ".BYTE":
                    pc += 1
                else:
                    self._put(out, pc + 1, v >> 8)
                    pc += 2
            return pc
        if mnem not in OPS:
            raise AsmError(f"unknown mnemonic {mnem}")
        if mnem in ("INC", "DEC") and arg.strip().upper() == "A":
            mnem, arg = ("INA" if mnem == "INC" else "DEA"), ""
        forms = OPS[mnem]
        if "rel" in forms:
            tgt, _ = self.try_eval(arg, final)
            off = tgt - (pc + 2)
            if final and not -128 <= off <= 127:
                raise AsmError(f"branch out of range ({off})")
            self._put(out, pc, forms["rel"])
            self._put(out, pc + 1, off & 0xFF)
            return pc + 2
        if "zprel" in forms:
            zp_s, tgt_s = [x.strip() for x in arg.split(",", 1)]
            zp, _ = self.try_eval(zp_s, final)
            tgt, _ = self.try_eval(tgt_s, final)
            off = tgt - (pc + 3)
            if final:
                self._check(zp, 8, "zero-page operand")
                if not -128 <= off <= 127:
                    raise AsmError(f"branch out of range ({off})")
            self._put(out, pc, forms["zprel"])
            self._put(out, pc + 1, zp)
            self._put(out, pc + 2, off & 0xFF)
            return pc + 3
        mode, v = self.mode(mnem, arg, final, key)
        if mode not in forms:
            raise AsmError(f"{mnem} has no {mode} mode")
        n = SIZE[mode]
        if final and n > 1:
            self._check(v, 8 * (n - 1), f"{mode} operand")
        self._put(out, pc, forms[mode])
        if n > 1:
            self._put(out, pc + 1, v)
        if n == 3:
            self._put(out, pc + 2, v >> 8)
        return pc + n


class _Unresolved(Exception):
    pass


def assemble(source, **kw):
    a = Assembler(source, **kw)
    img = a.assemble()
    return bytes(img), a.symbols
