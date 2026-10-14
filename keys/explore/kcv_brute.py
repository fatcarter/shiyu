"""Brute-force candidate (key derivation, cipher) pairs against the per-account KCV."""
import hashlib, hmac, itertools, struct
from Crypto.Cipher import AES, DES, DES3, ARC4, ChaCha20
try:
    from Crypto.Cipher import Blowfish, CAST
except Exception:
    Blowfish = CAST = None

# 说明: 账号 ID 与 Profile 名已匿名化(仅保留形态), KCV 为库文件前 8 字节。
PAIRS = [
    ("1000000000000001", bytes.fromhex("c2ca3db61c4ba469")),
    ("1000000000000002", bytes.fromhex("539069ad16dc7e3e")),
    ("1000000000000003", bytes.fromhex("f60b3454349e76ff")),
]
PLAINS = [b"SQLite f", b"SQLite format 3\0", b"\0"*16, b"\0"*8, b"SQLite"]

def key_candidates(vid_s):
    v = int(vid_s)
    out = {}
    out['ascii'] = vid_s.encode()
    for endian in ('little', 'big'):
        b8 = v.to_bytes(8, endian)
        out['vid8_' + endian] = b8
        out['md5_vid8_' + endian] = hashlib.md5(b8).digest()
        out['sha256_vid8_' + endian] = hashlib.sha256(b8).digest()
        out['sha1_vid8_' + endian] = hashlib.sha1(b8).digest()
        out['vid8le_hex_' + endian] = b8.hex().encode()
    a = vid_s.encode()
    for h in ('md5', 'sha1', 'sha256', 'sha512'):
        d = hashlib.new(h, a).digest()
        out[h + '_ascii'] = d
        out[h + '_ascii_hex'] = d.hex().encode()
    return out

def expand(k):
    """Produce plausible key lengths by padding/truncating."""
    outs = {}
    outs['raw'] = k
    for n in (8, 16, 24, 32):
        if len(k) >= n:
            outs[f'trunc{n}'] = k[:n]
        else:
            outs[f'zero{n}'] = (k + b'\0' * n)[:n]
            outs[f'rep{n}'] = (k * ((n // len(k)) + 1))[:n]
    return outs

def try_encrypts(key, plain):
    res = []
    for kname, k in expand(key).items():
        for bits in (16, 24, 32):
            if len(k) != bits: continue
            try:
                c = AES.new(k, AES.MODE_ECB); res.append((f'AES-{bits*8}-ECB/{kname}', c.encrypt(plain[:16])))
            except Exception: pass
            try:
                c = AES.new(k, AES.MODE_CBC, iv=b'\0'*16); res.append((f'AES-{bits*8}-CBC0/{kname}', c.encrypt(plain[:16])))
            except Exception: pass
        if len(k) == 8:
            try:
                c = DES.new(k, DES.MODE_ECB); res.append((f'DES-ECB/{kname}', c.encrypt(plain[:8])))
            except Exception: pass
            try:
                c = ARC4.new(k); res.append((f'RC4/{kname}', c.encrypt(plain[:16])))
            except Exception: pass
        if len(k) == 16:
            try:
                c = DES3.new(k, DES3.MODE_ECB); res.append((f'3DES-ECB/{kname}', c.encrypt(plain[:8])))
            except Exception: pass
        if Blowfish and len(k) in (16, 24, 32):
            try:
                c = Blowfish.new(k, Blowfish.MODE_ECB); res.append((f'BF-ECB/{kname}', c.encrypt(plain[:8])))
            except Exception: pass
    return res

hits = []
for vid, target in PAIRS:
    for kname, k in key_candidates(vid).items():
        for pname, p in [('SQLiteF', b"SQLite f"), ('SQLiteAll', b"SQLite format 3\0")]:
            for cname, ct in try_encrypts(k, p):
                if ct[:8] == target:
                    hits.append((vid, kname, pname, cname))
print("raw hits:", hits)

# hash-only candidates (no cipher)
for vid, target in PAIRS:
    for kname, k in key_candidates(vid).items():
        if k[:8] == target or k[-8:] == target:
            print("hash hit", vid, kname)
print("done")
