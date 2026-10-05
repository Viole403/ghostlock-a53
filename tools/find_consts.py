#!/usr/bin/env python3
"""Print every 64-bit constant materialised in a disassembly listing.

Clang builds large addresses out of a `mov`/`movz` plus a run of `movk`
instructions, each carrying one 16-bit field. Grepping a single immediate is
not a usable test for "does this binary contain address X": an unrelated
instruction can carry the same 16-bit value by chance, which is exactly what
happened when the A53 gate grepped for `#0x800` and matched the VA48 build.

This replays the listing instead, reconstructing the register state so whole
64-bit constants can be compared exactly. Output is one `0x...` value per
line, suitable for `grep -qx`.

Usage:
    python3 tools/find_consts.py <disassembly>
"""

import re
import sys

MASK64 = (1 << 64) - 1

# Accepts decimal and 0x spellings; llvm-objdump prints the former and clang
# prints both depending on the path that produced the listing.
_NUM = r"-?(?:0x[0-9a-f]+|[0-9]+)"
_MOVZ = re.compile(rf"^\s*movz\s+x(\d+),\s*#({_NUM})")
_MOV = re.compile(rf"^\s*mov\s+x(\d+),\s*#({_NUM})")
_MOVK = re.compile(rf"^\s*movk\s+x(\d+),\s*#({_NUM}),\s*lsl\s+#(\d+)")


def constants(path):
    """Yield every 64-bit value that a mov/movk sequence materialises."""
    registers = {}
    for line in open(path, errors="replace"):
        line = line.split("//", 1)[0]
        movk = _MOVK.match(line)
        if movk:
            register, imm, shift = (
                movk.group(1),
                int(movk.group(2), 0),
                int(movk.group(3)),
            )
            previous = registers.get(register, 0)
            value = (previous | (imm << shift)) & MASK64
            registers[register] = value
            yield value
            continue
        moved = _MOVZ.match(line) or _MOV.match(line)
        if moved:
            register, imm = moved.group(1), int(moved.group(2), 0)
            registers[register] = imm & MASK64
            yield registers[register]


def main():
    if len(sys.argv) != 2:
        sys.exit(main.__doc__ or __doc__)
    for value in constants(sys.argv[1]):
        print(f"0x{value:016x}")


if __name__ == "__main__":
    main()
