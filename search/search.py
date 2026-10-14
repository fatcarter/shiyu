#!/usr/bin/env python3
"""企业微信聊天记录检索 CLI —— 查询 data/wecom.sqlite。

子命令:
  search  "关键词"      全文检索(FTS5 trigram 子串匹配, <3 字回退 LIKE)
  convs   [关键词]      会话列表(按最后消息时间倒序)
  show    <会话>        某会话的消息流(时间正序)
  around  <消息id>      某条消息的上下文(-n 条)
  media   <消息id>      某条消息的附件(含本地备份文件路径)
  export  <会话>        把该会话的附件导出到目录
  stats                 库统计

通用选项: --from/--to YYYY-MM-DD[ HH:MM], --limit N, --json, --conv, --sender, --type N

设计: 只读访问, 所有查询强制 deleted_at=0; 附件路径优先给备份副本(data/media 下)。
路径由 wwconfig 自动发现, 可用 $WECOM_DB / $WECOM_MEDIA_ROOT 覆盖。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
from wwconfig import paths  # noqa: E402

_P = paths()
DB = _P.store_db
MEDIA_ROOT = _P.media_backup

TYPE_LABEL = {
    0: "文本", 2: "文本", 80: "富文本", 29: "图片", 14: "文件", 15: "文件",
    13: "文档", 101: "链接", 123: "复合", 38: "系统", 1002: "系统",
    1011: "卡片", 1005: "卡片", 4: "小程序", 561: "卡片", 565: "卡片", 106: "语音",
}


def label(ct) -> str:
    return TYPE_LABEL.get(ct, f"类型{ct}")


def backup_path(rel_path: str, src_path: str = "") -> str:
    """media 表 → 可读的本地文件路径: 优先备份副本, 回退容器原路径。"""
    if rel_path:
        p = os.path.join(MEDIA_ROOT, rel_path)
        if os.path.exists(p):
            return p
    return src_path if src_path and os.path.exists(src_path) else ""


def best_media_path(md5: str, conn) -> str:
    """同一 md5 常有两份: 压缩版与 `_HD` 高分辨率版(实测 _HD 那份才等于消息里记的原始大小),
    展示/导出时优先给 _HD。"""
    rows = conn.execute(
        "SELECT rel_path,src_path FROM media WHERE md5=? AND deleted_at=0", (md5,)).fetchall()
    paths = [(r["rel_path"], r["src_path"]) for r in rows]
    paths.sort(key=lambda t: (0 if (t[0] and "_HD" in t[0]) else 1))
    for rel, src in paths:
        p = backup_path(rel, src)
        if p:
            return p
    return ""


def parse_time(s: str, end: bool = False) -> int:
    """'YYYY-MM-DD' / 'YYYY-MM-DD HH:MM' / 'YYYY-MM-DDTHH:MM:SS' → unix 秒。"""
    s = s.strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            t = time.strptime(s, fmt)
        except ValueError:
            continue
        ts = int(time.mktime(t))
        if end and fmt == "%Y-%m-%d":
            ts += 86399
        return ts
    raise SystemExit(f"时间格式无法识别: {s}(应为 YYYY-MM-DD 或 'YYYY-MM-DD HH:MM')")


def ts_str(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""


def fts_phrase(kw: str) -> str:
    """FTS5 短语查询: 双引号包裹实现子串匹配, 内部引号用重复引号转义。"""
    return '"' + kw.replace('"', '""') + '"'


class Store:
    """只读封装: 会话名/发送人名一次载入内存(表小), 消息按需查。

    连接按线程各持一份: Web UI 用 ThreadingHTTPServer 并发处理请求, 而 sqlite3
    连接默认不允许跨线程使用(直接在别的线程用会抛 "SQLite objects created in a
    thread can only be used in that same thread")。会话名/联系人字典初始化后只读,
    多线程共享没问题。
    """

    def __init__(self, path: str = DB):
        if not os.path.exists(path):
            raise SystemExit(f"找不到 {path}, 请先运行 store/build_store.py")
        self.path = path
        self._local = threading.local()
        self.convs = {}     # conv_id → 会话名
        for r in self.conn.execute(
                "SELECT conv_id,name FROM conv WHERE deleted_at=0 ORDER BY (src='info') DESC"):
            if r["conv_id"] is not None and not self.convs.get(r["conv_id"]):
                self.convs[r["conv_id"]] = r["name"] or ""
        self.senders = {}
        for r in self.conn.execute(
                "SELECT rid,name FROM sender WHERE deleted_at=0 ORDER BY (src='info') DESC"):
            if r["rid"] is not None and not self.senders.get(r["rid"]):
                self.senders[r["rid"]] = r["name"] or ""

    @property
    def conn(self) -> sqlite3.Connection:
        """当前线程的连接(懒建)。"""
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
            c.row_factory = sqlite3.Row
            self._local.conn = c
        return c

    def conv_name(self, cid) -> str:
        return self.convs.get(cid) or f"#{cid}"

    def sender_name(self, rid) -> str:
        return self.senders.get(rid) or f"#{rid}"

    def resolve_conv(self, spec: str) -> list[int]:
        """会话标识 → conv_id 列表: 支持数字 ID、精确名、子串名。"""
        spec = spec.strip()
        if re.fullmatch(r"\d+", spec):
            return [int(spec)]
        exact = [c for c, n in self.convs.items() if n == spec]
        if exact:
            return exact
        return sorted(c for c, n in self.convs.items() if spec in (n or ""))

    def conv_ids_by_sender(self, spec: str) -> list[int]:
        rids = [r for r, n in self.senders.items() if spec in (n or "")]
        if not rids:
            return []
        qs = ",".join("?" * len(rids))
        return [r[0] for r in self.conn.execute(
            f"SELECT DISTINCT conv_id FROM msg WHERE sender_rid IN ({qs}) AND deleted_at=0", rids)]

    def sender_rids(self, spec: str) -> list[int]:
        return [r for r, n in self.senders.items() if spec in (n or "")]


STORE: Store = None  # main 里初始化; 下面按名字解析会话/发送人要用


def _where(args, alias: str = "m") -> tuple[str, list]:
    """把 --from/--to/--conv/--sender/--type 变成 SQL 片段。"""
    sql, p = [f"{alias}.deleted_at=0"], []
    if getattr(args, "from_", None):
        sql.append(f"{alias}.send_time>=?"); p.append(parse_time(args.from_))
    if getattr(args, "to", None):
        sql.append(f"{alias}.send_time<=?"); p.append(parse_time(args.to, end=True))
    if getattr(args, "type", None) is not None:
        sql.append(f"{alias}.content_type=?"); p.append(args.type)
    if getattr(args, "conv", None):
        ids = STORE.resolve_conv(args.conv)
        if not ids:
            raise SystemExit(f"没有匹配的会话: {args.conv}")
        sql.append(f"{alias}.conv_id IN ({','.join('?' * len(ids))})"); p += ids
    if getattr(args, "sender", None):
        rids = STORE.sender_rids(args.sender)
        if not rids:
            raise SystemExit(f"没有匹配的发送人: {args.sender}")
        sql.append(f"{alias}.sender_rid IN ({','.join('?' * len(rids))})"); p += rids
    return " AND ".join(sql), p


def fmt_row(r: sqlite3.Row, with_conv: bool = True) -> str:
    who = STORE.sender_name(r["sender_rid"])
    head = f"{ts_str(r['send_time'])}  {who:<10}"
    if with_conv:
        head += f" @{STORE.conv_name(r['conv_id'])[:24]:<24}"
    text = (r["text"] or "").replace("\n", " ⏎ ")
    if len(text) > 300:
        text = text[:300] + "…"
    # 非文本类的正文本身就以 "[文件] xxx" 这种带标签的形式生成, 此时不必再打一次类型标签
    tag = label(r["content_type"])
    tagpart = "" if text.startswith("[") else f"[{tag}] "
    extra = ""
    if r["file_name"] and r["file_name"] not in text:
        sz = f" {r['file_size']/1024:.0f}KB" if r["file_size"] else ""
        extra = f" 📎{r['file_name']}{sz}"
    return f"{head} {tagpart}{extra}{text}  (id={r['id']})"


# ── 子命令 ────────────────────────────────────────────────────────────
def cmd_search(args) -> int:
    where, params = _where(args)
    kws = [k for k in args.keyword if k.strip()]
    if not kws:
        raise SystemExit("请给出检索关键词")
    joins, conds = [], []
    short = [k for k in kws if len(k) < 3]
    long_ = [k for k in kws if len(k) >= 3]
    if long_:
        # trigram 分词: 短语查询实现子串匹配, 多条短语空格相连 = FTS5 隐含 AND
        # (FTS5 对同一表只允许一个 MATCH, 所以必须合成单条表达式)
        joins.append("JOIN msg_fts f ON f.rowid=m.id")
        conds.append("msg_fts MATCH ?")
        params.append(" ".join(fts_phrase(k) for k in long_))
    if short:
        # 1-2 字无法进 trigram 索引, 回退 LIKE(全表扫, 但配合时间/会话过滤可接受)
        for k in short:
            conds.append("m.text LIKE ?")
            params.append(f"%{k}%")
    sql = (f"SELECT m.* FROM msg m {' '.join(joins)} WHERE {where}"
           + (" AND " + " AND ".join(conds) if conds else "")
           + f" ORDER BY m.send_time DESC LIMIT ?")
    params.append(args.limit)
    rows = STORE.conn.execute(sql, params).fetchall()
    if args.json:
        print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=1))
    else:
        print(f"命中 {len(rows)} 条(最多显示 {args.limit} 条):\n")
        for r in rows:
            print(fmt_row(r))
    return 0


def cmd_convs(args) -> int:
    sql = ("SELECT m.conv_id, count(*) n, min(m.send_time) t0, max(m.send_time) t1 "
           "FROM msg m WHERE m.deleted_at=0")
    p = []
    if args.keyword:
        sql += " AND m.conv_id IN (SELECT conv_id FROM conv WHERE deleted_at=0 AND name LIKE ?)"
        p.append(f"%{args.keyword[0]}%")
    sql += " GROUP BY m.conv_id ORDER BY t1 DESC LIMIT ?"
    p.append(args.limit)
    rows = STORE.conn.execute(sql, p).fetchall()
    if args.json:
        print(json.dumps([{**dict(r), "name": STORE.conv_name(r["conv_id"])} for r in rows],
                         ensure_ascii=False, indent=1))
    else:
        print(f"{'会话':<34} {'消息数':>8}  {'首条':<12} {'末条':<12} ID")
        for r in rows:
            print(f"{STORE.conv_name(r['conv_id'])[:32]:<34} {r['n']:>8}  "
                  f"{ts_str(r['t0'])[:10]:<12} {ts_str(r['t1'])[:10]:<12} {r['conv_id']}")
    return 0


def _dump(rows, args) -> None:
    if args.json:
        print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=1))
    else:
        for r in rows:
            print(fmt_row(r))


def cmd_show(args) -> int:
    where, params = _where(args, "m")
    sql = f"SELECT m.* FROM msg m WHERE {where} ORDER BY m.send_time ASC LIMIT ?"
    params.append(args.limit)
    _dump(STORE.conn.execute(sql, params).fetchall(), args)
    return 0


def cmd_around(args) -> int:
    row = STORE.conn.execute("SELECT conv_id,send_time FROM msg WHERE id=?", (args.msg_id,)).fetchone()
    if not row:
        raise SystemExit(f"没有 id={args.msg_id} 的消息")
    rows = STORE.conn.execute(
        "SELECT * FROM msg WHERE conv_id=? AND deleted_at=0 AND id<>? "
        "AND (send_time<? OR (send_time=? AND id<?)) ORDER BY send_time DESC, id DESC LIMIT ?",
        (row["conv_id"], args.msg_id, row["send_time"], row["send_time"], args.msg_id, args.n)
    ).fetchall()
    after = STORE.conn.execute(
        "SELECT * FROM msg WHERE conv_id=? AND deleted_at=0 AND id<>? "
        "AND (send_time>? OR (send_time=? AND id>?)) ORDER BY send_time ASC, id ASC LIMIT ?",
        (row["conv_id"], args.msg_id, row["send_time"], row["send_time"], args.msg_id, args.n)
    ).fetchall()
    mid = STORE.conn.execute("SELECT * FROM msg WHERE id=?", (args.msg_id,)).fetchone()
    print(f"会话: {STORE.conv_name(row['conv_id'])}\n")
    for r in reversed(rows):
        print("  " + fmt_row(r, with_conv=False))
    print("▶ " + fmt_row(mid, with_conv=False))
    for r in after:
        print("  " + fmt_row(r, with_conv=False))
    return 0


def cmd_media(args) -> int:
    rows = STORE.conn.execute(
        "SELECT md.md5, md.kind, md.name, md.size, md.rel_path, md.src_path "
        "FROM msg_media mm JOIN media md ON md.md5=mm.md5 "
        "WHERE mm.msg_id=? AND mm.deleted_at=0 AND md.deleted_at=0", (args.msg_id,)).fetchall()
    seen, out = set(), []
    for r in rows:
        if r["md5"] in seen:
            continue
        seen.add(r["md5"])
        out.append({**dict(r), "local": best_media_path(r["md5"], STORE.conn)})
    msg = STORE.conn.execute("SELECT * FROM msg WHERE id=?", (args.msg_id,)).fetchone()
    if msg:
        print(fmt_row(msg) + "\n")
    if not out:
        print("该消息没有可定位的附件(或附件不在本次备份目录内)")
        return 0
    for o in out:
        sz = f"{o['size']/1048576:.2f}MB" if o["size"] and o["size"] > 1048576 else f"{o['size']/1024:.0f}KB"
        print(f"  [{o['kind']}] {o['name']}  {sz}  md5={o['md5']}\n      {o['local'] or '(未找到本地文件)'}")
    return 0


def cmd_export(args) -> int:
    where, params = _where(args, "m")
    sql = (f"SELECT DISTINCT md.md5, md.kind, md.name, md.rel_path, md.src_path FROM msg m "
           f"JOIN msg_media mm ON mm.msg_id=m.id JOIN media md ON md.md5=mm.md5 "
           f"WHERE {where} AND mm.deleted_at=0 AND md.deleted_at=0")
    rows = STORE.conn.execute(sql, params).fetchall()
    os.makedirs(args.out, exist_ok=True)
    n = 0
    for r in rows:
        src = backup_path(r["rel_path"], r["src_path"])
        if not src:
            continue
        dst = os.path.join(args.out, f"{r['kind']}_{r['name']}")
        if os.path.exists(dst):
            dst = os.path.join(args.out, f"{r['kind']}_{r['md5'][:8]}_{r['name']}")
        shutil.copy2(src, dst)
        n += 1
    print(f"导出 {n}/{len(rows)} 个附件 → {args.out}")
    return 0


def cmd_stats(args) -> int:
    c = STORE.conn
    stats = {
        "媒体文件": c.execute("SELECT count(*) FROM media WHERE deleted_at=0").fetchone()[0],
        "媒体占用GB": round(c.execute("SELECT sum(size) FROM media WHERE deleted_at=0").fetchone()[0] / 2**30, 1),
        "媒体已关联消息": c.execute("SELECT count(*) FROM msg_media WHERE deleted_at=0").fetchone()[0],
        "会话": c.execute("SELECT count(*) FROM conv WHERE deleted_at=0").fetchone()[0],
        "联系人": c.execute("SELECT count(*) FROM sender WHERE deleted_at=0").fetchone()[0],
        "消息总数": c.execute("SELECT count(*) FROM msg WHERE deleted_at=0").fetchone()[0],
    }
    for src, n in c.execute("SELECT src,count(*) FROM msg WHERE deleted_at=0 GROUP BY src"):
        stats[f"消息({src})"] = n
    t0, t1 = c.execute("SELECT min(send_time),max(send_time) FROM msg WHERE deleted_at=0").fetchone()
    stats["时间跨度"] = f"{ts_str(t0)[:10]} ~ {ts_str(t1)[:10]}"
    print("消息类型分布:")
    for ct, n in c.execute("SELECT content_type,count(*) n FROM msg WHERE deleted_at=0 "
                           "GROUP BY content_type ORDER BY n DESC LIMIT 12"):
        print(f"  {label(ct):<8} ct={ct:<6} {n:>9}")
    print()
    for k, v in stats.items():
        print(f"{k:<16} {v}")
    return 0


def main() -> int:
    global STORE
    # 过滤选项挂在每个子命令上(而不是顶层), 这样 `search.py search 预算 --conv X` 里
    # 选项能写在关键词后面, 符合直觉。
    def with_filters(p):
        p.add_argument("--db", default=DB)
        p.add_argument("--from", dest="from_", help="起始时间 YYYY-MM-DD[ HH:MM]")
        p.add_argument("--to", help="结束时间(含当天)")
        p.add_argument("--limit", type=int, default=50)
        p.add_argument("--conv", help="限定会话(名称子串或数字 ID)")
        p.add_argument("--sender", help="限定发送人(名称子串)")
        p.add_argument("--type", type=int, help="限定 content_type")
        p.add_argument("--json", action="store_true", help="输出 JSON")
        return p

    ap = argparse.ArgumentParser(description="企业微信聊天记录检索")
    with_filters(ap)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("search", help="全文检索")
    p.add_argument("keyword", nargs="+")
    p.set_defaults(func=cmd_search)
    p = sub.add_parser("convs", help="会话列表")
    p.add_argument("keyword", nargs="*")
    p.set_defaults(func=cmd_convs)
    p = sub.add_parser("show", help="某会话的消息流")
    p.add_argument("conv", help="会话名或 ID")
    p.set_defaults(func=cmd_show)
    p = sub.add_parser("around", help="某条消息的上下文")
    p.add_argument("msg_id", type=int)
    p.add_argument("-n", type=int, default=10, help="前后各取几条(默认 10)")
    p.set_defaults(func=cmd_around)
    p = sub.add_parser("media", help="某条消息的附件")
    p.add_argument("msg_id", type=int)
    p.set_defaults(func=cmd_media)
    p = sub.add_parser("export", help="导出会话附件")
    p.add_argument("conv", help="会话名或 ID")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_export)
    p = sub.add_parser("stats", help="库统计")
    p.set_defaults(func=cmd_stats)
    for p in sub.choices.values():
        with_filters(p)
    # 省略子命令时按"全文检索"理解: `search.py 预算 审批` 等价于 `search.py search 预算 审批`
    CMDS = {"search", "convs", "show", "around", "media", "export", "stats"}
    argv = sys.argv[1:]
    if not argv:
        argv = ["--help"]
    elif not CMDS.intersection(argv[:8]):
        argv = ["search"] + argv
    args = ap.parse_args(argv)
    STORE = Store(args.db)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
