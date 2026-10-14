"""wxSQLite3 AES-128 KCV verifier: test a candidate raw key against an observed DB header."""
import hashlib, struct, base64, sys
from Crypto.Cipher import AES

def _modmult(a, b, c, m, s):
    q = s // a
    s = b * (s - a * q) - c * q
    if s < 0:
        s += m
    return s

def generate_iv(page_no):
    z = page_no + 1
    ik = bytearray(16)
    for idx in range(4):
        z = _modmult(52774, 40692, 3791, 2147483399, z)
        ik[idx*4:idx*4+4] = struct.pack('<I', z & 0xFFFFFFFF)
    return hashlib.md5(bytes(ik)).digest()

def page_key(raw16, page_no):
    return hashlib.md5(raw16 + struct.pack('<I', page_no) + b'sAlT').digest()

def kcv(raw16):
    ct = AES.new(page_key(raw16, 1), AES.MODE_CBC, generate_iv(1)).encrypt(b'SQLite format 3\x00')
    return ct[:8]

def check(raw16, target_hex):
    return kcv(raw16).hex() == target_hex

# 说明: 账号 ID 与 Profile 名已匿名化(仅保留形态), KCV 为库文件前 8 字节。
TARGETS = {
  '1000000000000001': 'c2ca3db61c4ba469',
  '1000000000000002': '539069ad16dc7e3e',
  '1000000000000003': 'f60b3454349e76ff',
}

if __name__ == '__main__':
    cands = []
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            try: cands.append(bytes.fromhex(a))
            except ValueError: cands.append(base64.b64decode(a))
    else:
        b64 = 'fASm4zyA6UaoTlQbuGig7ajFhc7BzpXF3KAvAtCVXVY='
        d = base64.b64decode(b64)
        cands = [d, d[:16], d[16:], d[:16][::-1], hashlib.md5(d).digest(), hashlib.sha256(d).digest()[:16]]
    print("iv1 =", generate_iv(1).hex())
    for c in cands:
        if len(c) != 16:
            print(f"  {c.hex()} (len {len(c)}, skip)")
            continue
        row = [f"{c.hex()}  kcv={kcv(c).hex()}"]
        for vid, t in TARGETS.items():
            if check(c, t): row.append(f"  <<< MATCH {vid}")
        print(" ".join(row))
