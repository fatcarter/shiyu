import sys
from macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def disas(path, va, count):
    m = MachO(path)
    off = m.va_to_off(va)
    code = m.data[off:off + 4 * count]
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    for i in md.disasm(code, va):
        out.append(f"{i.address:#012x}: {i.mnemonic:<10} {i.op_str}")
    return out, m

if __name__ == '__main__':
    path, va, count = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3])
    lines, m = disas(path, va, count)
    # annotate string refs
    import re
    for ln in lines:
        addr = int(ln.split(':')[0], 16)
        print(ln)
