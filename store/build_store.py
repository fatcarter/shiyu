#!/usr/bin/env python3
"""企业微信结构化导出: 解密后的库 + 媒体目录 → 可检索 SQLite(wecom.sqlite)。

数据来源(均为解密后的明文库, 见 ../data/plaintext/):
  A. 新库(主): Profiles/<hash>/Messages1/Info.db   MESSAGE/CONVERSATION
     Profiles/<hash>/Messages1/Session.db          USER(姓名/职务/头像)
  B. 老库(补): WXWork/Data/<vid>/Data/message.db   仅导入新库没有的历史
     .../session.db  conversation_table(会话名/数字ID映射)、user.db、file.db(file_table4)
  C. 媒体:    Profiles/<hash>/Caches/{Images,Files,Videos,Emotions,...}
              (目录名即文件内容 md5, 与消息 content 里的 md5 直接对应)

产出表:
  meta/account/conv/sender/msg/msg_fts/media/msg_media/legacy_file
  msg_fts 用 fts5 trigram 分词 → 支持中文子串检索(2 字以下回退 LIKE)。

所有路径由 ../wwconfig.py 自动发现 —— 换机器不用改代码(见该模块文档)。

用法: build_store.py [--jobs 8] [--no-legacy]
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import multiprocessing as mp
import os
import pickle
import re
import shutil
import tempfile
import sqlite3
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
from wwconfig import paths  # noqa: E402
from parse_proto import extract_md5s, extract_reply_text, extract_urls, walk  # noqa: E402

P = paths()
PLAIN = P.plaintext
OUT_DB = P.store_db
MEDIA_BACKUP = P.media_backup                # 全量媒体备份(可长期保存的那一份)
CONTAINER = P.container
SELF_VID = int(P.legacy_vid) if P.legacy_vid.isdigit() else 0   # 本人 vid, 老库会话映射要用

INFO_DB = P.info_db
SESSION_DB = P.session_db
LEGACY_MSG_DB = P.legacy_msg_db
LEGACY_SESSION_DB = P.legacy_session_db
LEGACY_USER_DB = P.legacy_user_db
LEGACY_FILE_DB = P.legacy_file_db

# 媒体目录: 键=备份目录(media/)下的相对路径, 值=容器内的对应子路径。
# 实际索引以**备份**为准(备份才是长期可用的那一份), 容器里新增、备份里没有的文件
# 也一并收录(rel_path 留空, 只记容器路径), 这样既完整又不丢最新文件。
MEDIA_DIRS = P.media_scan_pairs()

# content_type → 展示标签(据真实样本归纳; 未知类型保留原编号)
TYPE_LABEL = {
    0: "文本", 2: "文本", 80: "富文本", 29: "图片", 14: "文件", 15: "文件",
    13: "文档", 101: "链接", 123: "复合/引用", 38: "系统", 1002: "系统",
    1011: "卡片", 1005: "卡片", 4: "小程序", 561: "卡片", 565: "卡片", 106: "语音",
}
_TEXT_LIKE = {0, 2, 80}
_FILE_LIKE = {14, 15, 123}
_IMAGE_LIKE = {29}
_LINK_LIKE = {13, 101}
_FILENAME_RX = re.compile(r"^[^/\\\x00-\x1f]{1,180}\.[A-Za-z0-9]{1,8}$")


def _leaf_texts(blob: bytes):
    """收集文本叶子: [(深度, 路径, 文本)], 过滤掉 server_id/md5 之类的长 hex。"""
    out = []
    for path, kind, val in walk(blob):
        if kind != "text":
            continue
        t = val.strip("\x00 \t\r\n")
        if not t or re.fullmatch(r"[0-9a-fA-F]{24,}", t):
            continue
        out.append((path.count("."), path, t))
    return out


def _size_for(blob: bytes, name_path: str) -> int:
    """文件大小: 同层里字段号 +2 的那个整数字段。

    样本规律: 文件名在 .2 → 大小在 .4(ct=14/15); 文件名在 .103.2 → 大小在 .103.4(ct=123)。
    文件名也可能直接落在顶层字段(路径不带点), 这时同样按 +2 找。
    """
    if not name_path:
        return 0
    head, _, tail = name_path.rpartition(".")
    if not tail.isdigit():
        return 0
    want = f"{head}.{int(tail) + 2}" if head else str(int(tail) + 2)
    if not want:
        return 0
    for path, kind, val in walk(blob):
        if kind == "int" and path == want and 0 < val < 2**40:
            return int(val)
    return 0


def analyze(ct: int, blob: bytes) -> dict:
    """按 content_type 抽取展示正文/URL/文件名/大小/md5 列表。"""
    if not blob:
        return {"text": "", "url": "", "file_name": "", "file_size": 0, "md5s": []}
    leaves = _leaf_texts(blob)
    urls = extract_urls(blob)
    md5s = extract_md5s(blob)
    url = urls[0] if urls else ""
    fname_leaf = next((l for l in leaves if _FILENAME_RX.match(l[2]) and not l[2].startswith("http")), None)
    file_name = fname_leaf[2] if fname_leaf else ""
    file_size = _size_for(blob, fname_leaf[1] if fname_leaf else "")
    text = ""
    if ct in _TEXT_LIKE or ct not in TYPE_LABEL:
        # 文本类: 按段落取"最后一个非空白文本段"(即本次回复, 而不是它引用的内容)
        text = extract_reply_text(blob)
    elif ct in _FILE_LIKE:
        others = sorted((l for l in leaves if l[2] != file_name), key=lambda x: -len(x[2]))
        quote = others[0][2] if others and len(others[0][2]) > 6 else ""
        label = TYPE_LABEL.get(ct, "文件")
        head = f"[{label}] {file_name}" if file_name else f"[{label}]"
        text = f"{head}｜引用: {quote[:200]}" if quote else head
    elif ct in _IMAGE_LIKE:
        cap = next((t for _, _, t in leaves if not t.startswith("http")), "")
        text = f"[图片] {cap}" if cap else "[图片]"
    elif ct in _LINK_LIKE:
        title = sorted((l[2] for l in leaves if not l[2].startswith("http")), key=len, reverse=True)
        text = f"[链接] {title[0]}" if title else (f"[链接] {url}" if url else "[链接]")
    else:
        cand = sorted(leaves, key=lambda x: (x[0], -len(x[2])))
        text = cand[0][2] if cand else f"[{TYPE_LABEL.get(ct, '类型' + str(ct))}]"
    return {"text": text[:8000], "url": url, "file_name": file_name,
            "file_size": file_size, "md5s": md5s[:8]}


def _msg_worker(args):
    """子进程: 解一段 LID 区间的消息, 结果**写文件**, 只回传条数。

    为什么不用 mp.Pool 直接回传结果: 单批结果可达上百 MB, 走进程间管道时实测会让
    父进程永久阻塞在 IMapIterator 上(worker 侧报 BrokenPipeError), 而且没有任何
    报错线索。改成落盘后, 管道里只有整数, 还能按文件数看进度、失败后按批重跑。
    """
    db, lo, hi, out = args
    rows = []
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        for lid, rid, seq, conv, snd, ct, ts, url_col, blob, isread, flag in c.execute(
            "SELECT LID,RID,seq,conv_id,sender_id,content_type,send_time,url,content,isread,flag "
            "FROM MESSAGE WHERE LID>=? AND LID<? ORDER BY LID", (lo, hi)):
            a = analyze(ct, blob)
            rows.append((lid, rid, seq, conv, snd, ct, ts, a["text"], a["url"] or (url_col or ""),
                         a["file_name"], a["file_size"], ",".join(a["md5s"]), isread, flag))
    finally:
        c.close()
    with open(out, "wb") as f:
        pickle.dump(rows, f, protocol=pickle.HIGHEST_PROTOCOL)
    return len(rows)


def _read_parts(paths):
    """按顺序读回各批结果, 读完即删(省磁盘)。"""
    for p in paths:
        if not os.path.exists(p):
            continue
        with open(p, "rb") as f:
            yield pickle.load(f)
        os.unlink(p)


def _legacy_conv_id(cid: str | None) -> int | None:
    """老库会话文本 id → 新库 conv_id。

    "R:12345"          → 12345                                  (群/客户会话, 数字即新库 RID)
    "S:1688..._1688..." → 非本人那个 vid                          (单人会话, 新库用对方 vid 作 RID)
    其它                → None(无法对应, 该会话的消息只留旧 id)

    本人 vid 取自 wwconfig(老库目录名), 认不出来时不做 S: 映射 —— 宁可少导入也不认错人。
    """
    if not cid:
        return None
    if cid.startswith("R:"):
        try:
            return int(cid[2:])
        except ValueError:
            return None
    if cid.startswith("S:") and SELF_VID:
        vids = [v for v in cid[2:].split("_") if v.isdigit() and int(v) != SELF_VID]
        return int(vids[0]) if len(vids) == 1 else None
    return None


def _legacy_worker(args):
    """子进程: 解一段 message_id 区间的老库消息, 结果同样落盘(老库单表 135 万行, 要并行)。"""
    db, lo, hi, out = args
    rows = []
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        for mid, seq, snd, cid, ct, ts, blob, extra in c.execute(
            "SELECT message_id,sequence,sender_id,conversation_id,content_type,send_time,"
            "content,extra_content FROM message_table WHERE message_id>=? AND message_id<?",
            (lo, hi)):
            a = analyze(ct, blob or extra or b"")
            rows.append((mid, seq, snd, cid, ct, ts, a))
    finally:
        c.close()
    with open(out, "wb") as f:
        pickle.dump(rows, f, protocol=pickle.HIGHEST_PROTOCOL)
    return len(rows)


SCHEMA = """
-- 设计约定(遵循项目数据库硬线):
--   1) 主键 id 只标识行, 不承载业务唯一性; 业务键(lid/rid/conv_id/md5...)一律用普通索引;
--   2) 所有表带 deleted_at(0=有效, 非 0=软删除时间戳), 检索一律过滤 deleted_at=0;
--   3) 无任何 UNIQUE 索引/约束 —— 幂等与去重由应用层(本脚本)保证。
CREATE TABLE meta(id INTEGER PRIMARY KEY, key TEXT, value TEXT, deleted_at INTEGER DEFAULT 0);
CREATE TABLE account(id INTEGER PRIMARY KEY, vid INTEGER, name TEXT, corp_id TEXT, corp_name TEXT,
                     deleted_at INTEGER DEFAULT 0);
CREATE TABLE conv(id INTEGER PRIMARY KEY, conv_id INTEGER, conv_key TEXT, name TEXT, conv_type INTEGER,
                  member_count INTEGER, create_time INTEGER, last_msg_time INTEGER, src TEXT,
                  deleted_at INTEGER DEFAULT 0);
CREATE TABLE sender(id INTEGER PRIMARY KEY, rid INTEGER, name TEXT, alias TEXT, job TEXT, mobile TEXT,
                    email TEXT, full TEXT, eng TEXT, corpid INTEGER, src TEXT,
                    deleted_at INTEGER DEFAULT 0);
CREATE TABLE msg(id INTEGER PRIMARY KEY, lid INTEGER, src TEXT, rid INTEGER, seq INTEGER,
                 conv_id INTEGER, conv_key TEXT, sender_rid INTEGER, content_type INTEGER,
                 send_time INTEGER, text TEXT, url TEXT, file_name TEXT, file_size INTEGER,
                 md5s TEXT, isread INTEGER DEFAULT 0, flag INTEGER DEFAULT 0,
                 deleted_at INTEGER DEFAULT 0);
CREATE TABLE media(id INTEGER PRIMARY KEY, md5 TEXT, kind TEXT, name TEXT, size INTEGER,
                   mtime INTEGER, rel_path TEXT, src_path TEXT, deleted_at INTEGER DEFAULT 0);
CREATE TABLE msg_media(id INTEGER PRIMARY KEY, msg_id INTEGER, md5 TEXT, kind TEXT, via TEXT,
                       deleted_at INTEGER DEFAULT 0);
CREATE TABLE legacy_file(id INTEGER PRIMARY KEY, message_id INTEGER, message_type INTEGER,
                         name TEXT, size INTEGER, md5 TEXT, conversation_id TEXT,
                         sender_id INTEGER, receive_time INTEGER, server_id TEXT, url TEXT,
                         deleted_at INTEGER DEFAULT 0);
CREATE VIRTUAL TABLE msg_fts USING fts5(text, conv_name, sender_name, tokenize='trigram');
CREATE INDEX idx_meta_key ON meta(key);
CREATE INDEX idx_conv_id ON conv(conv_id);
CREATE INDEX idx_conv_time ON conv(last_msg_time);
CREATE INDEX idx_sender_rid ON sender(rid);
CREATE INDEX idx_msg_lid ON msg(lid);
CREATE INDEX msg_conv_time ON msg(conv_id, send_time);
CREATE INDEX msg_time ON msg(send_time);
CREATE INDEX msg_ct ON msg(content_type);
CREATE INDEX msg_sender ON msg(sender_rid);
CREATE INDEX idx_msg_media_msg ON msg_media(msg_id);
CREATE INDEX msg_media_md5 ON msg_media(md5);
CREATE INDEX idx_media_md5 ON media(md5);
CREATE INDEX media_kind ON media(kind);
CREATE INDEX idx_legacy_file_md5 ON legacy_file(md5);
CREATE INDEX idx_legacy_file_conv ON legacy_file(conversation_id, receive_time);
"""

MSG_INSERT = ("INSERT INTO msg(id,lid,src,rid,seq,conv_id,conv_key,sender_rid,content_type,"
              "send_time,text,url,file_name,file_size,md5s,isread,flag)"
              " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
FTS_INSERT = "INSERT INTO msg_fts(rowid,text,conv_name,sender_name) VALUES(?,?,?,?)"
MSG_COLS = 17


def _scan_dir(base: str, skip: set | None = None):
    """遍历目录, yield (所在目录, 相对 base 的路径, 绝对路径)。skip 命中的相对路径跳过。"""
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if fn.startswith("."):
                continue
            p = os.path.join(dirpath, fn)
            r = os.path.relpath(p, base)
            if skip and r in skip:
                continue
            yield dirpath, r, p


def _media_row(kind: str, dirpath: str, path: str, rel_path: str, src_path: str):
    """组装一行 media。失败返回 None。

    md5 = 所在目录名(企业微信缓存目录名就是文件内容 md5, 与消息 content 里的 md5 直接对应);
    不是 32hex 目录的(如 UserAvatarUrl)用路径摘要占位, 只作为文件索引, 不参与消息关联。
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    m = re.match(r"^([0-9a-f]{32})(_HD)?$", os.path.basename(dirpath))
    md5 = m.group(1) if m else "path:" + hashlib.md5(src_path.encode()).hexdigest()
    return (md5, kind, os.path.basename(path), st.st_size, int(st.st_mtime), rel_path, src_path)


def build_media(conn) -> dict:
    """索引媒体: 以备份(media/)为准, 再补上备份之后新增、备份里还没有的文件。"""
    t0 = time.time()
    rows, nmd5 = [], 0
    for kind, (back_rel, cont_rel) in MEDIA_DIRS.items():
        seen = set()
        for dirpath, r, p in _scan_dir(os.path.join(MEDIA_BACKUP, back_rel)):
            seen.add(r)
            row = _media_row(kind, dirpath, p, f"{back_rel}/{r}",
                             os.path.join(CONTAINER, cont_rel, r))
            if row:
                rows.append(row)
        # 容器里比备份新的文件: 一样收录, 只是 rel_path 留空(备份内没有这一份)
        for dirpath, r, p in _scan_dir(os.path.join(CONTAINER, cont_rel), seen):
            row = _media_row(kind, dirpath, p, "", p)
            if row:
                rows.append(row)
    for i in range(0, len(rows), 20000):
        conn.executemany("INSERT INTO media(md5,kind,name,size,mtime,rel_path,src_path)"
                         " VALUES(?,?,?,?,?,?,?)", rows[i:i + 20000])
    conn.commit()
    nmd5 = conn.execute("SELECT count(*) FROM media WHERE md5 NOT LIKE 'path:%'").fetchone()[0]
    return {"media_files": len(rows), "media_with_md5": nmd5,
            "media_secs": round(time.time() - t0, 1)}


def _self_account(conn) -> tuple:
    """本人账号信息: vid 取老库目录名, 姓名取老库 user_table 里本人那一行(退而求其次用联系人表)。

    企业微信的字符串 corp_id(`ww…`)只散落在若干库里, 没有稳定的表可查, 新库 Session.db
    的 USER 也只存数字 corpid, 所以公司信息靠 $WECOM_CORP_ID / $WECOM_CORP_NAME 补,
    没给就留空(account 表只是备注, 检索不依赖它)。
    """
    vid, name = SELF_VID, ""
    if vid and os.path.exists(LEGACY_USER_DB):
        c = sqlite3.connect(f"file:{LEGACY_USER_DB}?mode=ro", uri=True)
        try:
            r = c.execute("SELECT name FROM user_table WHERE id=?", (vid,)).fetchone()
            name = (r[0] or "") if r else ""
        finally:
            c.close()
    if not name and vid:
        r = conn.execute("SELECT name FROM sender WHERE rid=? AND deleted_at=0", (vid,)).fetchone()
        name = (r[0] or "") if r else ""
    return vid, name, os.environ.get("WECOM_CORP_ID", ""), os.environ.get("WECOM_CORP_NAME", "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--no-legacy", action="store_true", help="跳过老库补充")
    args = ap.parse_args()
    t0 = time.time()
    # 清理上次异常退出(被 kill)留下的中间结果目录
    for d in glob.glob(os.path.join(tempfile.gettempdir(), "build_store_*")):
        shutil.rmtree(d, ignore_errors=True)
    if os.path.exists(OUT_DB):
        os.unlink(OUT_DB)
    conn = sqlite3.connect(OUT_DB)
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    stats: dict = {}

    # ── 1. 媒体索引 ────────────────────────────────────────────────
    stats.update(build_media(conn))
    print(f"[1/6] 媒体索引 {stats['media_files']} 个文件 ({stats['media_secs']}s)", flush=True)

    # ── 2. 会话 / 成员 ────────────────────────────────────────────
    info = sqlite3.connect(f"file:{INFO_DB}?mode=ro", uri=True)
    conv_rows, conv_names, conv_types = [], {}, {}
    for cid, rid, name, ctype, ctime, lmt, hd, members in info.execute(
        "SELECT LID,RID,name,conversationtype,create_time,modify_time,hidden,"
        "length(member_bin) FROM CONVERSATION"):
        conv_rows.append((rid, None, name, ctype, members, ctime, lmt, "info"))
        conv_names[rid] = name
        conv_types[rid] = ctype
    conn.executemany("INSERT INTO conv(conv_id,conv_key,name,conv_type,member_count,create_time,"
                     "last_msg_time,src) VALUES(?,?,?,?,?,?,?,?)", conv_rows)
    stats["convs_info"] = len(conv_rows)

    senders = {}
    if os.path.exists(SESSION_DB):
        s = sqlite3.connect(f"file:{SESSION_DB}?mode=ro", uri=True)
        for rid, name, alias, job, mobile, email, full, eng, corpid in s.execute(
            "SELECT RID,name,alias,job,mobile,email,full,eng,corpid FROM USER"):
            senders[rid] = name
            conn.execute("INSERT INTO sender(rid,name,alias,job,mobile,email,full,eng,corpid,src)"
                         " VALUES(?,?,?,?,?,?,?,?,?,?)",
                         (rid, name, alias, job, mobile, email, full, eng, corpid, "info"))
        s.close()
    stats["senders_info"] = len(senders)

    # 老库: 会话 id 映射 + 用户
    #
    # 关键: 老库 conversation_table 有两个 id ——
    #   con_numeric_id: 老库**自己**的连续编号(1..535), 与新库毫无关系, 用它做映射
    #                   会让 120 万条本已存在的消息被当成"新消息"重复导入;
    #   id:            "R:<数字>" 或 "S:<vid>_<vid>" —— 其中 R: 后面的数字**就是**
    #                   新库 CONVERSATION.RID; S: 单人会话则取非本人那个 vid
    #                   (新库单人会话的 RID 就是对方 vid)。
    # 所以映射必须从 id 解出, 不能碰 con_numeric_id。
    legacy_conv = {}
    n_lc_mapped = n_lc_added = 0
    if not args.no_legacy and os.path.exists(LEGACY_SESSION_DB):
        s = sqlite3.connect(f"file:{LEGACY_SESSION_DB}?mode=ro", uri=True)
        for cid, name, ctime, lmt in s.execute(
                "SELECT id,name,create_time,last_message_time FROM conversation_table"):
            num = _legacy_conv_id(cid)
            legacy_conv[cid] = (num, name)
            if num is None:
                continue
            n_lc_mapped += 1
            if num not in conv_names:
                conn.execute("INSERT INTO conv(conv_id,conv_key,name,conv_type,member_count,"
                             "create_time,last_msg_time,src) VALUES(?,?,?,?,?,?,?,?)",
                             (num, cid, name, 0, 0, ctime, lmt, "legacy"))
                conv_names[num] = name
                n_lc_added += 1
        s.close()
    if not args.no_legacy and os.path.exists(LEGACY_USER_DB):
        s = sqlite3.connect(f"file:{LEGACY_USER_DB}?mode=ro", uri=True)
        for uid, name, en, email, mobile, position, avatar in s.execute(
            "SELECT id,name,english_name,email,mobile,position,avator_url FROM user_table"):
            if uid not in senders:
                senders[uid] = name
                conn.execute("INSERT INTO sender(rid,name,alias,job,mobile,email,full,eng,corpid,src)"
                             " VALUES(?,?,?,?,?,?,?,?,?,?)",
                             (uid, name, "", position, mobile, email, en, "", 0, "legacy"))
        s.close()
    conn.commit()
    stats["legacy_convs"] = len(legacy_conv)
    stats["legacy_convs_mapped"] = n_lc_mapped
    stats["legacy_convs_added"] = n_lc_added
    stats["senders_total"] = len(senders)
    print(f"[2/6] 会话 {len(conv_rows)}(新) + 老库 {len(legacy_conv)} 个"
          f"(对上号 {n_lc_mapped}, 其中新库没有的 {n_lc_added} 个已补入), 人 {len(senders)}",
          flush=True)

    # ── 3. 消息(新库, 多进程解析) ─────────────────────────────────
    lo, hi = info.execute("SELECT min(LID),max(LID)+1 FROM MESSAGE").fetchone()
    step = max(1, (hi - lo) // (args.jobs * 8))
    tmpdir = tempfile.mkdtemp(prefix="build_store_")
    tasks = [(INFO_DB, x, min(x + step, hi), os.path.join(tmpdir, f"m{i:05d}.pkl"))
             for i, x in enumerate(range(lo, hi, step))]
    nmsg = 0
    next_id = 1          # msg.id 由本进程统一分配: FTS 的 rowid 必须与之一致
    # 跨库去重键: 新老两库都用 (会话, 消息序号 seq) 标识同一条消息, 实测老库
    # 可映射会话里 91.7% 的消息能在此对上号。不用正文做键 —— 老的引用消息正文里
    # 混着被引用内容, 同一个 seq 两库文本可能不同, 正文比对会漏掉大量重复。
    seen = set()         # conv_id<<32 | seq
    seen_seq = set()     # 仅 seq(部分老会话 id 无法映射到新库时的兜底)
    with mp.Pool(args.jobs) as pool:
        for done, _n in enumerate(pool.imap(_msg_worker, tasks, chunksize=1), 1):
            if done % 64 == 0:
                print(f"      ...已解析 {done}/{len(tasks)} 批", flush=True)
    # 结果按批序读回写库: 顺序即 LID 顺序, msg.id 与 FTS rowid 才能一一对应
    for rows in _read_parts(t[3] for t in tasks):
        batch, fts = [], []
        for r in rows:
            mid = next_id
            next_id += 1
            nmsg += 1
            batch.append((mid, r[0], "info", r[1], r[2], r[3], None, r[4], r[5],
                          r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13]))
            fts.append((mid, r[7], conv_names.get(r[3], ""), senders.get(r[4], "")))
            if r[3] is not None and r[2] is not None:
                seen.add((r[3] << 32) | (r[2] & 0xFFFFFFFF))
            if r[2] is not None:
                seen_seq.add(r[2])
            if len(batch) >= 20000:
                conn.executemany(MSG_INSERT, batch)
                conn.executemany(FTS_INSERT, fts)
                batch, fts = [], []
        if batch:
            conn.executemany(MSG_INSERT, batch)
            conn.executemany(FTS_INSERT, fts)
    conn.commit()
    stats["msgs_info"] = nmsg
    print(f"[3/6] 新库消息 {nmsg} 条, 解析用时 {time.time()-t0:.0f}s", flush=True)

    # ── 4. 老库补充(只导新库没有的) ────────────────────────────────
    if not args.no_legacy and os.path.exists(LEGACY_MSG_DB):
        lm = sqlite3.connect(f"file:{LEGACY_MSG_DB}?mode=ro", uri=True)
        lmin, lmax = lm.execute("SELECT min(message_id),max(message_id)+1 FROM message_table").fetchone()
        lm.close()
        lid0 = int(info.execute("SELECT max(LID) FROM MESSAGE").fetchone()[0]) + 1
        lstep = max(1, (lmax - lmin) // (args.jobs * 8))
        ltasks = [(LEGACY_MSG_DB, x, min(x + lstep, lmax),
                   os.path.join(tmpdir, f"l{i:05d}.pkl"))
                  for i, x in enumerate(range(lmin, lmax, lstep))]
        nadd, lid, batch = 0, lid0, []

        def _flush():
            nonlocal nadd, batch
            if not batch:
                return
            conn.executemany(MSG_INSERT, batch)
            conn.executemany(FTS_INSERT,
                             [(b[0], b[10], conv_names.get(b[5], ""), senders.get(b[7], ""))
                              for b in batch])
            nadd += len(batch)
            batch = []

        with mp.Pool(args.jobs) as pool:
            for done, _n in enumerate(pool.imap(_legacy_worker, ltasks, chunksize=1), 1):
                if done % 16 == 0:
                    print(f"      ...老库已解析 {done}/{len(ltasks)} 批", flush=True)
        for rows in _read_parts(t[3] for t in ltasks):
            for src_mid, seq, snd, cid, ct, ts, a in rows:
                num = legacy_conv.get(cid, (None, ""))[0]
                dup = False
                if seq is not None:
                    # 会话能映射: 用 (会话, seq) 精确判定
                    if num is not None and ((num << 32) | (seq & 0xFFFFFFFF)) in seen:
                        dup = True
                    # 会话映射不出来(老库有 3% 会话在新库里没有对应 id), 但 seq 在
                    # 新库出现过 —— seq 近似全局唯一(1.24M 行里仅 3 处重复), 视为重复。
                    elif num is None and seq in seen_seq:
                        dup = True
                if dup:
                    continue
                batch.append((next_id, lid, "legacy", src_mid, seq, num, cid, snd, ct, ts,
                              a["text"], a["url"], a["file_name"], a["file_size"],
                              ",".join(a["md5s"]), 0, 0))
                next_id += 1
                lid += 1
                if len(batch) >= 20000:
                    _flush()
                    conn.commit()
        _flush()
        conn.commit()
        stats["msgs_legacy_added"] = nadd

        # (会话, seq) 去重能挡住 91.7% 的重复, 剩下的是**两库 seq 漂移**的同一条消息
        # (同一会话/发送人/同一秒/正文完全相同, 但 seq 差几个数)。这里再按内容精确匹配
        # 清理一遍 —— 用软删除(置 deleted_at)而不是 DELETE: 硬删会让 msg 与 msg_fts
        # 的 rowid 错位, 而检索层本来就只看 deleted_at=0 的行。
        cur = conn.execute(
            "UPDATE msg SET deleted_at=strftime('%s','now') WHERE src='legacy' AND deleted_at=0 "
            "AND EXISTS (SELECT 1 FROM msg i WHERE i.src='info' AND i.deleted_at=0 "
            "  AND i.conv_id=msg.conv_id AND i.send_time=msg.send_time "
            "  AND i.sender_rid=msg.sender_rid AND substr(i.text,1,120)=substr(msg.text,1,120))")
        stats["msgs_legacy_deduped_by_content"] = cur.rowcount
        conn.commit()
        print(f"[4/6] 老库补充 {nadd} 条, 其中按内容判定为重复已软删除 {cur.rowcount} 条", flush=True)
    shutil.rmtree(tmpdir, ignore_errors=True)

    # ── 5. 消息↔媒体关联 ─────────────────────────────────────────
    # 关联在 Python 里做: media.md5 建字典后逐条消息查表。
    # 不用 SQL JOIN —— instr() 无法走索引, 消息×媒体会退化成千亿次比较。
    md5map = {}
    for md5, kind, rel, src in conn.execute(
            "SELECT md5,kind,rel_path,src_path FROM media WHERE md5 NOT LIKE 'path:%' AND deleted_at=0"):
        md5map.setdefault(md5, (kind, rel, src))
    links, batch = 0, []
    for mid, md5s in conn.execute(
            "SELECT id,md5s FROM msg WHERE md5s<>'' AND deleted_at=0"):
        for md5 in set(md5s.split(",")):
            if md5 in md5map:
                batch.append((mid, md5, md5map[md5][0], "content_md5"))
                if len(batch) >= 20000:
                    conn.executemany("INSERT INTO msg_media(msg_id,md5,kind,via) VALUES(?,?,?,?)", batch)
                    links += len(batch)
                    batch.clear()
    if batch:
        conn.executemany("INSERT INTO msg_media(msg_id,md5,kind,via) VALUES(?,?,?,?)", batch)
        links += len(batch)
    conn.commit()
    stats["msg_media_links"] = links
    print(f"[5/6] 消息-媒体关联 {links} 条", flush=True)

    # ── 6. 老库 file_table4 + meta ────────────────────────────────
    if not args.no_legacy and os.path.exists(LEGACY_FILE_DB):
        lf = sqlite3.connect(f"file:{LEGACY_FILE_DB}?mode=ro", uri=True)
        rows = lf.execute(
            "SELECT message_id,message_type,name,size,md5,conversation_id,sender_id,receive_time,"
            "server_id,url FROM file_table4").fetchall()
        conn.executemany("INSERT INTO legacy_file(message_id,message_type,name,size,md5,"
                         "conversation_id,sender_id,receive_time,server_id,url)"
                         " VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
        lf.close()
        stats["legacy_file_rows"] = len(rows)
    conn.execute("INSERT INTO meta(key,value) VALUES('built_at', datetime('now','localtime'))")
    conn.execute("INSERT INTO meta(key,value) VALUES('sources', ?)", (json.dumps(
        {"info_db": INFO_DB, "session_db": SESSION_DB, "legacy_msg_db": LEGACY_MSG_DB,
         "legacy_file_db": LEGACY_FILE_DB, "media_dirs": MEDIA_DIRS,
         "media_backup": MEDIA_BACKUP, "container": CONTAINER},
        ensure_ascii=False),))
    conn.execute("INSERT INTO meta(key,value) VALUES('stats', ?)", (json.dumps(stats, ensure_ascii=False),))
    conn.execute("INSERT INTO account(vid,name,corp_id,corp_name) VALUES(?,?,?,?)", _self_account(conn))
    conn.commit()
    conn.execute("INSERT INTO msg_fts(msg_fts) VALUES('optimize')")
    conn.commit()
    n = conn.execute("SELECT count(*) FROM msg").fetchone()[0]
    conn.close()
    size = os.path.getsize(OUT_DB) / 1048576
    print(f"[6/6] 完成: msg={n} 条, 库大小 {size:.0f}MB, 总耗时 {time.time()-t0:.0f}s")
    print("统计:", json.dumps(stats, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
