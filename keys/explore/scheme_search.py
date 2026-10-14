"""用已知候选 key 反推加密方案: 找到能把 raw key 映射到观测 KCV 的组合。"""
import hashlib, struct, itertools, sys
from Crypto.Cipher import AES

# 说明: 账号 ID 与 Profile 名已匿名化(仅保留形态), KCV 为库文件前 8 字节。
OBS = {
 'Data/1000000000000001': 'c2ca3db61c4ba469',
 'profiles/A(messages)': 'f466330dbb5529cf',
 'profiles/A(Contact)': '5c67e632826eee7a',
 'profiles/B': 'a45cb229f49e70c4',
 'profiles/C': '41be6d610ff4a274',
 'acct/1000000000000002': '539069ad16dc7e3e',
 'acct/1000000000000003': 'f60b3454349e76ff',
}

CAND_KEYS = [
 '5c0a73c8418f0687c40143fded22874b',
]

def modmult(a,b,c,m,s):
    q=s//a; s=b*(s-a*q)-c*q
    return s+m if s<0 else s

def lcg_iv(page):
    z=page+1; ik=bytearray(16)
    for i in range(4):
        z=modmult(52774,40692,3791,2147483399,z)
        ik[i*4:i*4+4]=struct.pack('<I', z & 0xFFFFFFFF)
    return hashlib.md5(bytes(ik)).digest()

def key_variants(hexstr):
    k = bytes.fromhex(hexstr)
    out = {'hex16': k, 'ascii32': hexstr.encode()}
    for name, base in list(out.items()):
        out[name+'_md5'] = hashlib.md5(base).digest()
        out[name+'_sha256'] = hashlib.sha256(base).digest()
        for h in ('sha256','sha1','md5'):
            out[f'{name}_{h}_16'] = hashlib.new(h, base).digest()[:16]
    # 两次哈希
    for name, base in list(out.items()):
        out[name+'_md5x2'] = hashlib.md5(hashlib.md5(base).digest()).digest()
    return {k:v for k,v in out.items() if len(v) in (16,32)}

def pk_variants(K, page=1, extra=b''):
    out = {}
    p32 = struct.pack('<I', page)
    p32b = struct.pack('>I', page)
    out['md5(K+LE+vmSAlT)'] = hashlib.md5(K+p32+b'sAlT').digest()
    out['md5(K+LE+salt)'] = hashlib.md5(K+p32+b'salt').digest()
    out['md5(K+LE)'] = hashlib.md5(K+p32).digest()
    out['md5(LE+K+vmSAlT)'] = hashlib.md5(p32+K+b'sAlT').digest()
    out['md5(K+BE+vmSAlT)'] = hashlib.md5(K+p32b+b'sAlT').digest()
    out['K'] = K
    out['md5(K)'] = hashlib.md5(K).digest()
    out['sha256(K)'] = hashlib.sha256(K).digest()
    out['sha256(K)_16'] = hashlib.sha256(K).digest()[:16]
    # PBKDF2 家族
    for salt in (b'sAlT', b'', K[:8], p32, b'salt'):
        for it in (1, 1000, 4000, 64000):
            for h in ('sha1','sha256'):
                try:
                    out[f'pbkdf2-{h}-{it}-{salt[:4]!r}'] = hashlib.pbkdf2_hmac(h, K, salt, it, 16)
                except Exception: pass
    return out

def iv_variants(K, page=1):
    out = {}
    out['lcg(page)'] = lcg_iv(page)
    out['zeros'] = bytes(16)
    out['md5(K)'] = hashlib.md5(K).digest()
    out['K16'] = (K+bytes(16))[:16]
    out['md5(page)'] = hashlib.md5(struct.pack('<I',page)).digest()
    return out

P0 = b'SQLite format 3\x00'

def main():
    hits = []
    for hexstr in CAND_KEYS:
        for kname, K in key_variants(hexstr).items():
            for pname, pk in pk_variants(K).items():
                pklen = len(pk)
                if pklen not in (16,32): continue
                for iname, iv in iv_variants(K).items():
                    for mode in ('cbc','ecb'):
                        try:
                            if mode=='cbc':
                                ct = AES.new(pk, AES.MODE_CBC, iv).encrypt(P0)
                            else:
                                ct = AES.new(pk, AES.MODE_ECB).encrypt(P0)
                        except Exception: continue
                        kcv = ct[:8].hex()
                        for oname, obs in OBS.items():
                            if kcv == obs:
                                hits.append((kname,pname,iname,mode,oname))
                        # 也试解密方向
                        try:
                            if mode=='cbc':
                                pt = AES.new(pk, AES.MODE_CBC, iv).decrypt(P0)
                            else:
                                pt = AES.new(pk, AES.MODE_ECB).decrypt(P0)
                            kcv2 = pt[:8].hex()
                            for oname, obs in OBS.items():
                                if kcv2 == obs:
                                    hits.append((kname,pname,iname,mode+'/dec',oname))
                        except Exception: pass
    print("hits:", hits)
    # 也检查 KCV 是否直接是 key 的哈希
    for hexstr in CAND_KEYS:
        K = bytes.fromhex(hexstr)
        cands = {}
        for h in ('md5','sha1','sha256','sha512','blake2b','blake2s'):
            d = hashlib.new(h, K).digest()
            cands[h]=d; cands[h+'_hex']=d.hex().encode()
        for n,v in cands.items():
            for oname, obs in OBS.items():
                if v.hex().startswith(obs) or v.hex().endswith(obs):
                    print("hash-prefix hit", n, oname)
        print("md5(key)=",hashlib.md5(K).hexdigest(), "sha256(key)=", hashlib.sha256(K).hexdigest())
main()
