"""Find ADRP+ADD (and ADRP+LDR) code references to a target VA in an arm64 Mach-O."""
import struct, sys
from macho import MachO

def sign_extend(v, bits):
    if v & (1 << (bits - 1)):
        return v - (1 << bits)
    return v

def scan_adrp_add(m, ranges=None):
    """Yield (insn_va, target_va, kind) for ADRP+ADD/LDR pairs."""
    d = m.data
    text = m.sections_named('__text')
    for (seg, name, addr, size, offset) in text:
        end = offset + size
        o = offset
        prev = None  # (va, page_target, rd)
        while o + 8 <= end:
            w1 = struct.unpack_from('<I', d, o)[0]
            va1 = m.off_to_va(o)
            if (w1 & 0x9F000000) == 0x90000000:  # ADRP
                immlo = (w1 >> 29) & 3
                immhi = (w1 >> 5) & 0x7FFFF
                rd = w1 & 0x1F
                imm = sign_extend((immhi << 2) | immlo, 21) << 12
                page = (va1 & ~0xFFF) + imm
                prev = (va1, page, rd)
            elif prev is not None:
                w2 = w1
                pva, page, rd = prev
                # ADD (imm), 64-bit
                if (w2 & 0xFF000000) in (0x91000000, 0x91400000):
                    rn = (w2 >> 5) & 0x1F
                    rd2 = w2 & 0x1F
                    sh = (w2 >> 22) & 1
                    imm12 = (w2 >> 10) & 0xFFF
                    if rn == rd:
                        tgt = page + (imm12 << (12 if sh else 0))
                        yield (pva, tgt, 'add')
                # LDR (imm) / LDRB etc: 64-bit unsigned offset
                elif (w2 & 0xFFC00000) == 0xF9400000:
                    rn = (w2 >> 5) & 0x1F
                    if rn == rd:
                        imm12 = (w2 >> 10) & 0xFFF
                        yield (pva, page + imm12 * 8, 'ldr')
                prev = None
            else:
                prev = None
            o += 4

def find_xrefs(m, target_va, tol=0):
    hits = []
    for (pva, tgt, kind) in scan_adrp_add(m):
        if tgt == target_va or (tol and abs(tgt - target_va) <= tol):
            hits.append((pva, tgt, kind))
    return hits

if __name__ == '__main__':
    path = sys.argv[1]
    m = MachO(path)
    for s in sys.argv[2:]:
        sva = m.find_string_va(s)
        print(f"\n### string {s!r}: {len(sva)} occurrence(s)")
        for (fo, va) in sva[:6]:
            print(f"  at file {hex(fo)} va {hex(va)}")
            for (pva, tgt, kind) in find_xrefs(m, va)[:12]:
                print(f"     xref {kind} @ {hex(pva)}")
