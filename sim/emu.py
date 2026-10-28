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
                ("io_wr_bits", ctypes.c_uint8 * 32)]


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
            ctypes.memmove(self.m.mem, bytes(image64k), 65536)
        if rom is not None:
            assert len(rom) == 32768
            ctypes.memmove(ctypes.addressof(self.m.mem) + 0x8000, bytes(rom), 32768)
        self.m.switches = 0xFF
        self.m.p = 0x34

    def reset(self):
        lib().emu_reset(ctypes.byref(self.m))

    def run(self, stop=-1, max_cycles=10**10):
        return lib().emu_run(ctypes.byref(self.m), stop, max_cycles)

    def load(self, addr, data):
        ctypes.memmove(ctypes.addressof(self.m.mem) + addr, bytes(data), len(data))

    def read(self, addr, n):
        return bytes(self.m.mem[addr:addr + n])

    @property
    def cycles(self):
        return self.m.cycles

    def display_masks(self):
        """Segment masks of the 16 digits, from the emulated 595 storage registers."""
        out = []
        for b in range(4):
            st = self.m.st[b]
            for j in range(4):
                out.append((st >> (8 * j)) & 0xFF)
        return out
