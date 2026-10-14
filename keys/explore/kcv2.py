import hashlib, hmac, itertools
from Crypto.Cipher import AES, DES, DES3, ARC4, Blowfish

# 说明: 账号 ID 与 Profile 名已匿名化(仅保留形态), KCV 为库文件前 8 字节。
PAIRS = [
    ("1000000000000001", bytes.fromhex("c2ca3db61c4ba469")),
    ("1000000000000002", bytes.fromhex("539069ad16dc7e3e")),
    ("1000000000000003", bytes.fromhex("f60b3454349e76ff")),
]

def key_material(vs):
    v = int(vs); a = vs.encode()
    out = {}
    out['ascii'] = a
    out['upper'] = a            # digits only, same
    out['md5'] = hashlib.md5(a).digest()
    out['md5hex'] = hashlib.md5(a).hexdigest().encode()
    out['md5HEX'] = hashlib.md5(a).hexdigest().upper().encode()
    out['sha1'] = hashlib.sha1(a).digest()
    out['sha256'] = hashlib.sha256(a).digest()
    out['sha256hex'] = hashlib.sha256(a).hexdigest().encode()
    for e in ('little', 'big'):
        b8 = v.to_bytes(8, e)
        out['vid8_' + e] = b8
        out['md5_vid8_' + e] = hashlib.md5(b8).digest()
        out['sha1_vid8_' + e] = hashlib.sha1(b8).digest()
        out['sha256_vid8_' + e] = hashlib.sha256(b8).digest()
        out['md5hex_vid8_' + e] = hashlib.md5(b8).hexdigest().encode()
    # double hashes
    for base in ('md5', 'sha1', 'sha256'):
        for h in ('md5', 'sha1', 'sha256'):
            out[f'{h}({base})'] = hashlib.new(h, out[base]).digest()
            out[f'{h}hex({base})'] = hashlib.new(h, out[base]).hexdigest().encode()
    return out

def sizes(k):
    r = {}
    for n in (8, 16, 24, 32):
        if len(k) == n: r[f'exact{n}'] = k
        if len(k) > n: r[f'trunc{n}'] = k[:n]
        else:
            r[f'zero{n}'] = (k + bytes(n))[:n]
            r[f'rep{n}'] = (k * (n // max(1,len(k)) + 1))[:n]
    return r

PLAINS = [b'SQLite f', b'SQLite format 3\0', bytes(16), bytes(8)]

def encs(key, pt):
    for bits, n in ((16,16),(24,24),(32,32)):
        if len(key)!=n: continue
        yield f'AES{bits*8}ecb', AES.new(key, AES.MODE_ECB).encrypt(pt[:16])
        yield f'AES{bits*8}cbc0', AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(pt[:16])
    if len(key)==8:
        yield 'desecb', DES.new(key, DES.MODE_ECB).encrypt(pt[:8])
        yield 'rc4', ARC4.new(key).encrypt(pt[:16])
    if len(key)==16:
        yield '3desecb', DES3.new(key, DES3.MODE_ECB).encrypt(pt[:8])
        yield 'bf8', Blowfish.new(key, Blowfish.MODE_ECB).encrypt(pt[:8])
    if len(key)==24:
        yield 'bf24', Blowfish.new(key, Blowfish.MODE_ECB).encrypt(pt[:8])
    if len(key)==32:
        yield 'bf32', Blowfish.new(key, Blowfish.MODE_ECB).encrypt(pt[:8])

hits=[]
vals = {vs: key_material(vs) for vs,_ in PAIRS}
names = list(vals[PAIRS[0][0]].keys())
for name in names:
    ok_all = True
    detail=[]
    for vs, target in PAIRS:
        km = vals[vs][name]
        found=False
        for sn, k in sizes(km).items():
            for pt in PLAINS:
                try:
                    for cn, ct in encs(k, pt):
                        if ct[:8]==target:
                            detail.append((vs,name,sn,cn,pt[:12])); found=True
                except Exception: pass
        if not found: ok_all=False
    if ok_all and detail:
        hits.append(detail)
print("hits:", hits[:5] if hits else "NONE")
# also pure-hash KCV
for vs, t in PAIRS:
    for name, km in vals[vs].items():
        if km[:8]==t or km[-8:]==t:
            print("hashKCV", vs, name)
print("done")
