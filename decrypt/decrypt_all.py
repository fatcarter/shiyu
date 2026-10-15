#!/usr/bin/env python3
"""企业微信(macOS) 加密库全量离线解密。

流程:
  1) 用 KCV(文件前 8 字节)在容器里认出所有加密库, 按密钥分组;
  2) 先把 库+WAL 以 APFS 克隆方式快照到 raw_snapshot/(避免读到 checkpoint 中途的半个库);
  3) 多进程按 4096B 页解密(含页1 变体), 再叠加 WAL 已提交帧;
  4) 输出明文库到 plaintext/, 并写 manifest.json(记录每个库的密钥/页数/WAL 帧数)。

用法:
  decrypt_all.py [--src <容器Data目录>] [--keys keys/wxwork_keys.json] [--out data/plaintext] \
                 [--raw-snapshot data/raw_snapshot] [--jobs 8] [--only <正则>] [--keep-raw]

路径默认按 ../wwconfig.py 自动发现(换机器不用改代码)。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from urllib.parse import quote

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.dirname(_HERE))
from wwconfig import paths  # noqa: E402
from wxwork_crypto import (  # noqa: E402
    PAGE_SZ,
    SQLITE_HDR,
    decrypt_page,
    derive_page_key,
    generate_initial_vector,
    is_plaintext_sqlite,
    wal_frames,
)

_P = paths()

CHUNK_PAGES = 8192  # 每任务 32MB
_W = {}             # worker 局部状态(派生密钥缓存)


def _decrypt_chunk(job):
    """解一段连续的页: 对每页按页号派生 key/IV 后 AES-CBC 解密并写回同偏移。"""
    src, dst, raw_key, first_page, npages = job
    key = bytes.fromhex(raw_key)
    with open(src, "rb") as fi, open(dst, "r+b") as fo:
        fi.seek((first_page - 1) * PAGE_SZ)
        buf = fi.read(npages * PAGE_SZ)
        out = bytearray(len(buf))
        for i in range(0, len(buf), PAGE_SZ):
            page_no = first_page + i // PAGE_SZ
            page = buf[i : i + PAGE_SZ]
            if len(page) < PAGE_SZ:  # 尾部不足一页: 补零
                page = page + b"\x00" * (PAGE_SZ - len(page))
            try:
                out[i : i + PAGE_SZ] = decrypt_page(key, page, page_no)
            except Exception as e:  # 单页失败不中断整库(留空页并记录)
                out[i : i + PAGE_SZ] = b"\x00" * PAGE_SZ
                print(f"    警告: 页 {page_no} 解密失败: {e}", file=sys.stderr)
        fo.seek((first_page - 1) * PAGE_SZ)
        fo.write(bytes(out))
    return len(buf)


def decrypt_db(src: str, dst: str, raw_key: str, jobs: int) -> dict:
    """解密主库文件(不含 WAL), 返回统计。"""
    size = os.path.getsize(src)
    total_pages = (size + PAGE_SZ - 1) // PAGE_SZ
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    # 目标文件预分配为源大小(明文与密文等长, reserve=0)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        shutil.copyfileobj(fi, fo, length=8 * 1024 * 1024)
    tasks = []
    for p in range(1, total_pages + 1, CHUNK_PAGES):
        n = min(CHUNK_PAGES, total_pages - p + 1)
        tasks.append((src, dst, raw_key, p, n))
    done = 0
    if jobs <= 1:
        for t in tasks:
            done += _decrypt_chunk(t)
    else:
        with ProcessPoolExecutor(max_workers=jobs) as ex:
            for n in ex.map(_decrypt_chunk, tasks):
                done += n
    return {"pages": total_pages, "bytes": done}


def apply_wal(db_path: str, wal_path: str, raw_key: str) -> dict:
    """把 WAL 中已提交帧解密后覆盖到明文库上(使最新消息不丢)。"""
    key = bytes.fromhex(raw_key)
    frames = 0
    last_page = 0
    db_size_pages = 0
    max_page = os.path.getsize(db_path) // PAGE_SZ
    with open(db_path, "r+b") as fo:
        for page_no, page, db_size in wal_frames(wal_path):
            try:
                plain = decrypt_page(key, page, page_no)
            except Exception as e:
                print(f"    警告: WAL 页 {page_no} 解密失败: {e}", file=sys.stderr)
                continue
            fo.seek((page_no - 1) * PAGE_SZ)
            fo.write(plain)
            frames += 1
            last_page = max(last_page, page_no)
            if db_size:
                db_size_pages = db_size
        if db_size_pages and db_size_pages * PAGE_SZ != os.path.getsize(db_path):
            fo.truncate(db_size_pages * PAGE_SZ)  # 按最后一次提交的页数对齐文件大小
        elif last_page > max_page:
            fo.truncate(last_page * PAGE_SZ)
    return {"wal_frames": frames, "wal_last_page": last_page, "db_size_pages": db_size_pages}


def finalize_plaintext(db_path: str) -> bool:
    """WAL 合并完后把明文库从 WAL 模式改为回滚日志模式。

    原因: 明文副本不再有配对的 -wal/-shm, 若头里仍写着"读写版本=2(WAL)", 只读打开会
    因无法创建 -shm 而 SQLITE_CANTOPEN。合并已完成, 改回 1 与真实状态一致, 且任何
    SQLite 工具都能直接打开。
    """
    with open(db_path, "r+b") as f:
        hdr = bytearray(f.read(100))
        if len(hdr) >= 20 and hdr[:16] == SQLITE_HDR and hdr[18] == 2 and hdr[19] == 2:
            hdr[18] = 1
            hdr[19] = 1
            f.seek(0)
            f.write(bytes(hdr))
            return True
    return False


def snapshot_pair(src: str, snap: str) -> bool:
    """APFS 克隆出 库+WAL 快照, 返回"这一对是否同代"(一致)。

    竞态: 应用边写边 checkpoint 时, 库与 WAL 若取自不同时刻, 合并后会不一致。
    判定: 先克隆 WAL, 再克隆库, 期间 WAL 的 size/mtime/inode 未变 → 两者同代。
    跨卷或不支持克隆时退化为普通拷贝。
    """
    os.makedirs(os.path.dirname(snap) or ".", exist_ok=True)

    def _clone(s: str, d: str) -> None:
        if os.path.exists(d):
            os.unlink(d)
        if subprocess.run(["cp", "-c", "--", s, d], capture_output=True).returncode != 0:
            shutil.copy2(s, d)

    def _stat(p: str):
        try:
            st = os.stat(p)
            return (st.st_size, st.st_mtime_ns, st.st_ino)
        except OSError:
            return None

    wal = src + "-wal"
    before = _stat(wal)
    if before is not None:
        _clone(wal, snap + "-wal")
    _clone(src, snap)
    after = _stat(wal)
    return before == after


def _quick_check(path: str) -> str:
    """对明文库跑 PRAGMA quick_check, 返回 "ok" 或第一条问题文案。

    用进程内 sqlite3 而非 sqlite3 CLI: CLI 会把错误包成 "Parse error in 3rd command
    line argument: ...", 前缀随 CLI 版本变化, 判定文案会被污染。
    """
    try:
        conn = sqlite3.connect("file:" + quote(os.path.abspath(path)) + "?mode=ro", uri=True)
    except sqlite3.Error as e:
        return f"check-error: {e}"
    try:
        rows = conn.execute("PRAGMA quick_check").fetchall()
    except sqlite3.Error as e:
        return str(e).strip() or type(e).__name__
    except Exception as e:  # noqa: BLE001
        return f"check-error: {e}"
    finally:
        conn.close()
    out = [str(r[0]).strip() for r in rows if r and r[0] is not None]
    return out[0] if out else "unknown"


# SQLite 内置分词器; 其余(icu / 企业微信 WWFts5Tokenizer 等)都要外部注册
_BUILTIN_TOKENIZERS = {"unicode61", "ascii", "porter", "trigram"}
_TOKENIZER_RX = re.compile(
    r"USING\s+fts[3-5]\s*\([^)]*?tokenize\s*=?\s*'?([A-Za-z0-9_]+)", re.I | re.S
)


def _has_foreign_tokenizer(path: str) -> bool:
    """库中是否存在声明了非内置分词器的 FTS 虚表。"""
    try:
        conn = sqlite3.connect("file:" + quote(os.path.abspath(path)) + "?mode=ro", uri=True)
    except sqlite3.Error:
        return False
    try:
        for (sql,) in conn.execute(
            "SELECT sql FROM sqlite_master WHERE sql LIKE '%USING FTS%'"
            " OR sql LIKE '%USING fts%'"
        ).fetchall():
            m = _TOKENIZER_RX.search(sql or "")
            if m and m.group(1).lower() not in _BUILTIN_TOKENIZERS:
                return True
    except sqlite3.Error:
        return False
    finally:
        conn.close()
    return False


def check_ok(path: str, chk: str) -> bool:
    """quick_check 文案是否可接受。

    "ok"=结构完好。另有一类是**本机环境限制**而非库损坏: 企业微信的 FTS 虚表声明了
    外部分词器(icu / 自研 WWFts5Tokenizer), 本机 SQLite 注册表里没有, quick_check
    遍历这些虚表必然失败 —— 报 "unknown tokenizer: xxx", 或 FTS5 加载失败时抬升的
    通用 "SQL logic error"(不带分词器名)。两者都只在库里确实有外部分词器时放行,
    真正的损坏("database disk image is malformed" / "*** in database main ***")照旧被判失败。
    """
    if chk == "ok":
        return True
    if chk != "SQL logic error" and "unknown tokenizer" not in chk:
        return False
    return _has_foreign_tokenizer(path)


def decrypt_one(src: str, dst: str, raw_key: str, jobs: int, snap: str,
                use_wal: bool, attempts: int = 3) -> dict:
    """带校验与重试的单个库解密: 直到 quick_check 通过或重试耗尽。

    顺序很关键: **先叠加 WAL, 再整体校验**。WAL 里是比主库更新的已提交数据, 主库
    自身完好并不代表数据是最新的 —— 先校验主库、通过就跳过 WAL 会静默丢掉最新消息。

    竞态兜底: 快照的库与 WAL 若取自不同时刻(应用边写边 checkpoint), 合并后会校验
    不过; 此时退回"只解主库"的版本(稍旧但自洽), 不把损坏副本交给下游。

    校验口径见 check_ok(): "ok"=结构完好; 缺外部分词器的报错同样算通过。
    """
    size = os.path.getsize(src)
    best = None
    for i in range(1, attempts + 1):
        stable = snapshot_pair(src, snap)
        st = decrypt_db(snap, dst, raw_key, jobs)
        finalize_plaintext(dst)
        rec = {"size": size, **st, "snapshot_stable": stable, "attempts": i}
        if use_wal and stable and os.path.exists(snap + "-wal"):
            rec.update(apply_wal(dst, snap + "-wal", raw_key))
            finalize_plaintext(dst)
            chk = _quick_check(dst)
            if check_ok(dst, chk):
                best = {**rec, "wal_applied": True, "quick_check": chk, "check_ok": True}
                break
            print(f"    警告: {os.path.basename(dst)} 合并 WAL 后校验不过"
                  f"({chk}), 退回未合并版本", file=sys.stderr)
            for k in ("wal_frames", "wal_last_page", "db_size_pages"):
                rec.pop(k, None)
            st = decrypt_db(snap, dst, raw_key, jobs)  # 重新解出主库, 丢弃已合并的改动
            finalize_plaintext(dst)
            rec.update({**st, "wal_applied": False})
        chk = _quick_check(dst)
        rec.update({"quick_check": chk, "check_ok": check_ok(dst, chk)})
        best = rec  # 记录最后一次(失败)结果
        if rec["check_ok"]:
            break
    return best or {}


def kcv_of_file(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(8)
    except OSError:
        return b""


def find_encrypted_dbs(root: str, kcv_map: dict, only: str | None) -> dict:
    """遍历 root 认出加密库: {kcv_hex: [path, ...]}。"""
    found: dict[str, list[str]] = {}
    rx = re.compile(only) if only else None
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if fn.endswith(("-shm", "-journal")):
                continue
            p = os.path.join(dirpath, fn)
            if rx and not rx.search(p):
                continue
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            k = kcv_of_file(p)
            if len(k) == 8 and k.hex() in kcv_map:
                found.setdefault(k.hex(), []).append(p)
    for v in found.values():
        v.sort()
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=_P.container, help="容器 Data 根目录(默认自动发现)")
    ap.add_argument("--keys", default=_P.keys_file)
    ap.add_argument("--out", default=_P.plaintext)
    ap.add_argument("--raw-snapshot", default=_P.raw_snapshot)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--only", default=None, help="只处理路径匹配该正则的库")
    ap.add_argument("--no-wal", action="store_true")
    args = ap.parse_args()
    if not os.path.isdir(args.src):
        raise SystemExit(f"找不到容器 Data 目录: {args.src}\n"
                         f"(用 --src 或用 $WEWORK_CONTAINER 指定)")

    raw_keys = json.load(open(args.keys, encoding="utf-8"))
    # 统一成 {kcv_hex: (key_hex, 描述)}
    kcv_map = {}
    for name, v in raw_keys.items():
        key = v["key"] if isinstance(v, dict) else v
        kcv = v["kcv"] if isinstance(v, dict) else None
        if kcv is None:
            from wxwork_crypto import kcv_of

            kcv = kcv_of(bytes.fromhex(key)).hex()
        kcv_map[kcv] = (key, name)

    print(f"密钥表: {len(kcv_map)} 个 → " + ", ".join(f"{k}({n})" for k, (_, n) in kcv_map.items()))
    found = find_encrypted_dbs(args.src, kcv_map, args.only)
    total = sum(len(v) for v in found.values())
    print(f"认出加密库 {total} 个:")
    for kcv, paths in sorted(found.items(), key=lambda kv: -len(kv[1])):
        print(f"  {kcv} ({kcv_map[kcv][1]}): {len(paths)} 个")

    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.raw_snapshot, exist_ok=True)
    manifest = []
    t0 = time.time()

    for kcv, paths in sorted(found.items(), key=lambda kv: -os.path.getsize(kv[1][0])):
        key, desc = kcv_map[kcv]
        for src in paths:
            rel = os.path.relpath(src, args.src)
            dst = os.path.join(args.out, rel)
            snap = os.path.join(args.raw_snapshot, rel)
            rec = decrypt_one(src, dst, key, args.jobs, snap, use_wal=not args.no_wal)
            rec.update({"src": src, "out": dst, "kcv": kcv, "key_name": desc})
            manifest.append(rec)
            mark = "✅" if rec.get("check_ok") else "⚠️"
            print(f"  {mark} {rel}  {rec.get('size',0)/1048576:.1f}MB 页{rec.get('pages')} "
                  f"WAL{rec.get('wal_frames',0)}帧 stable={rec.get('snapshot_stable')} "
                  f"试{rec.get('attempts')}次 quick_check={rec.get('quick_check')}  ({time.time()-t0:.0f}s)",
                  flush=True)

    mf = os.path.join(args.out, "manifest.json")
    json.dump(manifest, open(mf, "w"), ensure_ascii=False, indent=2)
    ok = sum(1 for r in manifest if r.get("check_ok"))
    print(f"\n完成: {len(manifest)} 个库, {ok} 个通过/跳过校验, 用时 {time.time()-t0:.0f}s")
    print(f"manifest: {mf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
