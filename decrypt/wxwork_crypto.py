#!/usr/bin/env python3
"""企业微信(macOS) wxSQLite3/SQLite3MultipleCiphers AES-128-CBC 解密核心。

算法参数经由对真实库的验证确定, 并与开源实现 tzwkb/wecom-agent
(https://github.com/tzwkb/wecom-agent, MIT)的结论一致:
  - 页 size 4096; 页 key = md5(raw_key[16] || 页号<u32 LE> || b"sAlT")
  - IV = sqlite3mcGenerateInitialVector(页号): LCG(modmult) 生成 16B → md5
  - AES-128-CBC, 无 HMAC, reserve=0
  - 页1 变体: 文件偏移 0-7 = "密钥指纹"KCV(= AES-CBC-Enc(pk1,iv1,"SQLite format 3\\0")[0:8]);
    偏移 8-15 是被搬走的原 16-23 字节; 偏移 16-23 为明文 SQLite 头片段。
    解密: data[16:24]=data[8:16] → 从 16 起 CBC 解密 → 校验片段 → data[:16]="SQLite format 3\\0"
  - WAL: 32B 头为明文; 每帧 = 24B 帧头(页号/提交后大小/盐/校验) + 4096B 加密页;
    帧内页与主库同一套页加密(页1 同样走上面的变体)。

本模块只做密码学与页/帧解析, 不做业务解析。
"""
from __future__ import annotations

import hashlib
import struct

PAGE_SZ = 4096
SQLITE_HDR = b"SQLite format 3\x00"
WXSQLITE3_SALT = b"sAlT"
WAL_HDR_SZ = 32
WAL_FRAME_HDR_SZ = 24

# AES 后端: cryptography(本机已装) 优先, 退 pycryptodome
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _aes_cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return d.update(data) + d.finalize()

    def _aes_cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return e.update(data) + e.finalize()
except ImportError:  # pragma: no cover
    from Crypto.Cipher import AES

    def _aes_cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    def _aes_cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def _modmult(a: int, b: int, c: int, m: int, s: int) -> int:
    """SQLite3MultipleCiphers 的 LCG 单步(与 C 端 modmult 完全一致)。"""
    q = s // a
    s = b * (s - a * q) - c * q
    if s < 0:
        s += m
    return s


def generate_initial_vector(page_no: int) -> bytes:
    """对齐 sqlite3mcGenerateInitialVector(page_no)。"""
    z = page_no + 1
    ik = bytearray(16)
    for i in range(4):
        z = _modmult(52774, 40692, 3791, 2147483399, z)
        ik[i * 4 : i * 4 + 4] = struct.pack("<I", z & 0xFFFFFFFF)
    return hashlib.md5(bytes(ik)).digest()


def derive_page_key(raw_key: bytes, page_no: int) -> bytes:
    if len(raw_key) != 16:
        raise ValueError("raw key 必须 16 字节")
    return hashlib.md5(raw_key + struct.pack("<I", page_no) + WXSQLITE3_SALT).digest()


def has_plain_header_fragment(page: bytes) -> bool:
    """页1 偏移16-23 是否为明文 SQLite 头片段(页大小/保留字节特征)。"""
    if len(page) < 24:
        return False
    h = page[16:24]
    page_size = (h[0] << 8) | h[1]
    if page_size == 1:
        page_size = 65536
    return (
        512 <= page_size <= 65536
        and (page_size & (page_size - 1)) == 0
        and h[5] == 0x40
        and h[6] == 0x20
        and h[7] == 0x20
    )


def kcv_of(raw_key: bytes) -> bytes:
    """密钥指纹(8B): = 加密库文件的前 8 字节, 同 key 的所有库相同。"""
    pk, iv = derive_page_key(raw_key, 1), generate_initial_vector(1)
    return _aes_cbc_enc(pk, iv, SQLITE_HDR[:16])[:8]


def decrypt_page(raw_key: bytes, page: bytes, page_no: int) -> bytes:
    """解密单页(含页1 变体)。返回 4096B 明文页。"""
    if len(page) != PAGE_SZ:
        raise ValueError(f"页必须为 {PAGE_SZ} 字节, 实际 {len(page)}")
    if page_no == 1 and has_plain_header_fragment(page):
        data = bytearray(page)
        frag = bytes(data[16:24])
        data[16:24] = data[8:16]
        data[16:] = _aes_cbc_dec(
            derive_page_key(raw_key, 1), generate_initial_vector(1), bytes(data[16:])
        )
        if bytes(data[16:24]) != frag:
            raise ValueError("页1 校验失败(密钥不正确)")
        data[:16] = SQLITE_HDR
        return bytes(data)
    return _aes_cbc_dec(
        derive_page_key(raw_key, page_no), generate_initial_vector(page_no), page
    )


def looks_like_page1(page: bytes) -> bool:
    return (
        page[: len(SQLITE_HDR)] == SQLITE_HDR
        and len(page) >= 108
        and page[100] in (0x02, 0x05, 0x0A, 0x0D)
    )


def verify_key(raw_key: bytes, page1: bytes) -> bool:
    """解密整张页1 并校验 SQLite 头 + b-tree 类型(排除假阳性)。"""
    if len(raw_key) != 16 or len(page1) < PAGE_SZ:
        return False
    try:
        return looks_like_page1(decrypt_page(raw_key, page1[:PAGE_SZ], 1))
    except Exception:
        return False


def file_kcv(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read(8)


def is_plaintext_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(len(SQLITE_HDR)) == SQLITE_HDR
    except OSError:
        return False


# ── WAL ────────────────────────────────────────────────────────────────
def wal_frames(path: str):
    """迭代 WAL 中**已提交**的帧: yield (page_no, page_bytes, db_size_pages)。

    只取到最后一个 db_size!=0 的提交帧为止(之后的未提交帧一律忽略);
    每帧页数据 4096B 仍为密文, 由调用方按页号解密。

    世代过滤: WAL 文件是**复用**的 —— checkpoint 后 SQLite 从文件头重新写当前世代,
    盐值(salt)递增, 上一世代的旧帧仍残留在文件尾部。只有盐与 WAL 头一致的帧属于
    当前世代, 遇到盐不匹配即停止扫描(同 SQLite walIndexRecover 的语义)。若不过滤,
    残留的旧帧会把旧页覆盖到新解密出的主库上, 得到 "database disk image is malformed"。
    """
    import os

    size = os.path.getsize(path)
    if size < WAL_HDR_SZ + WAL_FRAME_HDR_SZ + PAGE_SZ:
        return
    with open(path, "rb") as f:
        hdr = f.read(WAL_HDR_SZ)
        magic = struct.unpack(">I", hdr[0:4])[0]
        if magic not in (0x377F0682, 0x377F0683):  # 非 WAL 文件
            return
        salt = hdr[16:24]
        frame_sz = WAL_FRAME_HDR_SZ + PAGE_SZ
        # 先定位最后一个提交帧(其帧头 db_size 字段 != 0), 扫描范围止于当前世代末尾
        last_commit_end = 0
        off = WAL_HDR_SZ
        while off + frame_sz <= size:
            f.seek(off)
            fh = f.read(WAL_FRAME_HDR_SZ)
            if len(fh) < WAL_FRAME_HDR_SZ:
                break
            page_no, db_size = struct.unpack(">II", fh[0:8])
            if page_no == 0:  # 帧头损坏, 停止
                break
            if fh[8:16] != salt:  # 上一世代的残留帧, 当前世代到此结束
                break
            off += frame_sz
            if db_size != 0:
                last_commit_end = off
        if last_commit_end == 0:
            return
        off = WAL_HDR_SZ
        while off < last_commit_end:
            f.seek(off)
            fh = f.read(WAL_FRAME_HDR_SZ)
            page = f.read(PAGE_SZ)
            if len(fh) < WAL_FRAME_HDR_SZ or len(page) < PAGE_SZ:
                return
            page_no, db_size = struct.unpack(">II", fh[0:8])
            yield page_no, page, db_size
            off += frame_sz


# ── 离线自测(用合成页验证算法移植, 不碰企业微信) ────────────────────────
def _encrypt_page1(raw_key: bytes, plain_page: bytes) -> bytes:
    data = bytearray(plain_page)
    db_header = bytes(data[16:24])
    pk, iv = derive_page_key(raw_key, 1), generate_initial_vector(1)
    data[:16] = _aes_cbc_enc(pk, iv, bytes(data[:16]))
    data[16:] = _aes_cbc_enc(pk, iv, bytes(data[16:]))
    data[8:16] = data[16:24]
    data[16:24] = db_header
    return bytes(data)


def _selftest() -> None:
    import os as _os

    raw_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    page = bytearray(PAGE_SZ)
    page[:16] = SQLITE_HDR
    page[16:24] = bytes.fromhex("1000020200402020")
    page[100] = 0x0D
    enc = _encrypt_page1(raw_key, bytes(page))
    assert has_plain_header_fragment(enc)
    assert verify_key(raw_key, enc)
    assert not verify_key(_os.urandom(16), enc)
    assert decrypt_page(raw_key, enc, 1) == bytes(page)
    assert kcv_of(raw_key) == enc[:8], "KCV 定义应与加密库前 8 字节一致"
    print("self-test PASS: 页1 变体/KCV/verify_key 均正确")


if __name__ == "__main__":
    _selftest()
