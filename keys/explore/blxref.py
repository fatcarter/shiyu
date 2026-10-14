"""Find BL call sites targeting a given function VA."""
import struct, sys
from macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def callers(m, targets):
    d = m.data
    text = m.sections_named('__text')
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    tset = set(targets)
    out = {t: [] for t in targets}
    for (seg, name, addr, size, offset) in text:
        code = d[offset:offset+size]
        for i in md.disasm(code, addr):
            if i.mnemonic == 'bl':
                try:
                    t = int(i.op_str.lstrip('#'), 16)
                except ValueError:
                    continue
                if t in tset:
                    out[t].append(i.address)
    return out

if __name__ == '__main__':
    m = MachO(sys.argv[1])
    tgts = [int(x, 0) for x in sys.argv[2:]]
    res = callers(m, tgts)
    for t, lst in res.items():
        print(f"callers of {hex(t)}: {len(lst)}")
        for a in lst[:20]:
            print("   ", hex(a))
