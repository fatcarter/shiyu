"""Minimal Mach-O helper: segment mapping + string/xref location."""
import struct

class MachO:
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        d = self.data
        magic = struct.unpack_from('<I', d, 0)[0]
        assert magic in (0xfeedfacf, 0xfeedface), hex(magic)
        self.is64 = magic == 0xfeedfacf
        ncmds = struct.unpack_from('<I', d, 16)[0]
        off = 32 if self.is64 else 28
        self.segments = []   # (name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot)
        self.sections = []   # (segname, sectname, addr, size, offset)
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<II', d, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                (segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot,
                 nsects, flags) = struct.unpack_from('<16sQQQQIIII', d, off + 8)
                name = segname.rstrip(b'\0').decode()
                self.segments.append((name, vmaddr, vmsize, fileoff, filesize, initprot))
                so = off + 72
                for _ in range(nsects):
                    (sn, sgn, addr, size, offset) = struct.unpack_from('<16s16sQQI', d, so)
                    self.sections.append((sgn.rstrip(b'\0').decode(), sn.rstrip(b'\0').decode(),
                                          addr, size, offset))
                    so += 80
            off += cmdsize
        self.text = [(n, va, vs, fo, fs, ip) for (n, va, vs, fo, fs, ip) in self.segments]
        self.base = min(va for (_, va, vs, fo, fs, ip) in self.segments if vs > 0)

    def va_to_off(self, va):
        for (name, vmaddr, vmsize, fileoff, filesize, ip) in self.segments:
            if vmaddr <= va < vmaddr + vmsize:
                return fileoff + (va - vmaddr)
        return None

    def off_to_va(self, o):
        for (name, vmaddr, vmsize, fileoff, filesize, ip) in self.segments:
            if fileoff <= o < fileoff + filesize:
                return vmaddr + (o - fileoff)
        return None

    def find_string_va(self, s):
        """Return list of (file_offset, va) for occurrences of s in __TEXT."""
        out = []
        b = s.encode() if isinstance(s, str) else s
        i = self.data.find(b)
        while i >= 0:
            va = self.off_to_va(i)
            if va is not None:
                out.append((i, va))
            i = self.data.find(b, i + 1)
        return out

    def sections_named(self, name):
        return [s for s in self.sections if s[1] == name]

if __name__ == '__main__':
    import sys
    m = MachO(sys.argv[1])
    print("base", hex(m.base))
    for s in m.segments:
        print("SEG", s[0], hex(s[1]), hex(s[2]), "fileoff", hex(s[3]), hex(s[4]), "prot", s[5])
    print("sections:", len(m.sections))
    for s in m.sections[:20]:
        print("  ", s[0], s[1], hex(s[2]), hex(s[3]), hex(s[4]))
