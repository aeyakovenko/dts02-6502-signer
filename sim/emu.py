"""ctypes wrapper around emu65.c (built on first use with the system C compiler)."""

import ctypes
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "emu65.c")
BUILD = os.path.join(HERE, "_build")
LIB = os.path.join(BUILD, "_emu65.so")


class M(ctypes.Structure):
    _fields_ = [("mem", ctypes.c_uint8 * 65536),
                ("a", ctypes.c_uint8), ("x", ctypes.c_uint8), ("y", ctypes.c_uint8),
                ("s", ctypes.c_uint8), ("p", ctypes.c_uint8),
                ("pc", ctypes.c_uint16),
                ("cycles", ctypes.c_uint64), ("instructions", ctypes.c_uint64),
                ("switches", ctypes.c_uint8), ("keys", ctypes.c_uint8), ("gpio", ctypes.c_uint8),
                ("msg_lock", ctypes.c_uint8), ("res_lock", ctypes.c_uint8), ("fault", ctypes.c_uint8),
                ("blocked_writes", ctypes.c_uint32), ("gpio_writes", ctypes.c_uint32),
                ("halted", ctypes.c_uint8),
                ("last_pc", ctypes.c_uint16),
                ("sr", ctypes.c_uint32 * 4), ("st", ctypes.c_uint32 * 4),
                ("prev_gpio", ctypes.c_uint8),
                ("trace", ctypes.c_uint64),
                ("mxdig", (ctypes.c_uint16 * 8) * 2),
                ("io_writes", ctypes.c_uint8 * 32)]


_lib = None


def lib():
    global _lib
    if _lib is None:
        os.makedirs(BUILD, exist_ok=True)
        if not os.path.exists(LIB) or os.path.getmtime(LIB) < os.path.getmtime(SRC):
            subprocess.check_call(["cc", "-O2", "-shared", "-fPIC", "-o", LIB, SRC])
        _lib = ctypes.CDLL(LIB)
        _lib.emu_run.restype = ctypes.c_int
        _lib.emu_run.argtypes = [ctypes.POINTER(M), ctypes.c_int, ctypes.c_uint64]
        _lib.emu_reset.argtypes = [ctypes.POINTER(M)]
        assert _lib.emu_sizeof() == ctypes.sizeof(M), "struct layout mismatch"
    return _lib


class Machine:
    """A W65C02S + DTS-02 memory map, locks and fault latch, running at full speed."""

    STOP, STP, TRAP, LIMIT = 1, 2, 3, 0

    def __init__(self, rom=None, image64k=None):
        self.m = M()
        if image64k is not None:
            image64k = bytes(image64k)
            if len(image64k) != 65536:
                raise ValueError("image64k must contain exactly 65536 bytes")
            self.load(0, image64k)
        if rom is not None:
            rom = bytes(rom)
            if len(rom) != 32768:
                raise ValueError("rom must contain exactly 32768 bytes")
            self.load(0x8000, rom)
        self.m.switches = 0xFF
        self.m.p = 0x34

    def reset(self):
        lib().emu_reset(ctypes.byref(self.m))

    def run(self, stop=-1, max_cycles=10**10):
        return lib().emu_run(ctypes.byref(self.m), stop, max_cycles)

    def load(self, addr, data):
        """Load host-provided bytes without writing outside the memory array."""
        data = bytes(data)
        if not 0 <= addr <= 65536 - len(data):
            raise ValueError("load must fit within the 65536-byte address space")
        ctypes.memmove(ctypes.addressof(self.m.mem) + addr, data, len(data))

    def read(self, addr, n):
        return bytes(self.m.mem[addr:addr + n])

    @property
    def cycles(self):
        return self.m.cycles

    def io_addresses_written(self):
        """Every $7Fxx address stored to since the bitmap was last cleared."""
        return {0x7F00 | i for i in range(256) if self.m.io_writes[i >> 3] & (1 << (i & 7))}

    def clear_io_log(self):
        for i in range(32):
            self.m.io_writes[i] = 0

    def display_masks(self):
        """Segment masks (bit0=a .. bit6=g, bit7=dp) of the 16 digits from the
        emulated MAX7219 registers; None for a digit never written."""
        out = []
        for c in range(2):
            on = self.m.st[c] & 1
            for i in range(8):
                d = self.m.mxdig[c][i]
                if not on:
                    out.append(0)
                elif d > 0xFF:
                    out.append(None)
                else:
                    m = d & 0x80
                    for seg in range(7):
                        if d & (1 << (6 - seg)):
                            m |= 1 << seg
                    out.append(m)
        return out
