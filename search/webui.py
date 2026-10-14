#!/usr/bin/env python3
"""企业微信聊天记录检索 Web UI —— 本地只读浏览 data/wecom.sqlite。

用法: webui.py [--port 8765] [--host 127.0.0.1]
打开 http://127.0.0.1:8765

路径由 wwconfig 自动发现; 容器化部署时用 $WECOM_DB / $WECOM_MEDIA_ROOT 指定,
监听地址可用 $WECOM_WEBUI_HOST / $WECOM_WEBUI_PORT 覆盖(容器内需绑 0.0.0.0)。

安全: 默认只监听回环地址; 附件只按 media 表里的 md5 反查路径提供, 不接受任意路径。
"""
from __future__ import annotations

import argparse
import html
import os
import re
import sqlite3
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from search import DB, Store, best_media_path, label, ts_str  # noqa: E402

STORE: Store = None
PAGE = 200

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c1e21;--mut:#7a8290;--line:#e3e6ea;--me:#0b6bcb}
@media(prefers-color-scheme:dark){:root{--bg:#16181c;--card:#1e2126;--fg:#e6e8ea;
--mut:#9aa3b0;--line:#2c3036;--me:#4a9eff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.55 -apple-system,"PingFang SC",system-ui,sans-serif}
header{position:sticky;top:0;background:var(--card);border-bottom:1px solid var(--line);
padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;z-index:9}
h1{font-size:15px;margin:0;font-weight:600}
input,button,select{font:inherit;padding:6px 10px;border:1px solid var(--line);
border-radius:8px;background:var(--card);color:var(--fg)}
input[type=text]{min-width:260px}
button{cursor:pointer}
main{max-width:1000px;margin:0 auto;padding:16px}
.msg{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:8px 12px;margin-bottom:8px}
.meta{color:var(--mut);font-size:12px;margin-bottom:3px;display:flex;
gap:8px;flex-wrap:wrap;align-items:center}
.who{font-weight:600;color:var(--fg)}
.tag{background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:0 5px}
.txt{white-space:pre-wrap;word-break:break-word}
.txt img{max-width:320px;max-height:240px;border-radius:8px;display:block;margin-top:4px}
a{color:var(--me);text-decoration:none}
a:hover{text-decoration:underline}
.conv{display:flex;justify-content:space-between;gap:12px;padding:7px 12px;
background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:6px}
.mut{color:var(--mut);font-size:12px;white-space:nowrap}
.pg{margin:16px 0;text-align:center;color:var(--mut)}
mark{background:#ffe58f;color:#000;border-radius:3px}
"""


def esc(s) -> str:
    return html.escape(str(s or ""))


# 企业微信缓存里的图片扩展名经常与真实格式不符(见过 .png 实为 JPEG),
# 所以按魔数判定类型, 扩展名只作兜底。
_MAGIC = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"RIFF", "image/webp"),          # 近似: RIFF....WEBP
    (b"%PDF", "application/pdf"),
    (b"\x1aE\xdf\xa3", "video/webm"),
]


def sniff_ctype(path: str, data: bytes) -> str:
    for magic, ct in _MAGIC:
        if data.startswith(magic):
            return ct
    if len(data) > 12 and data[4:8] == b"ftyp":
        return "video/mp4"
    if data[4:12] in (b"ftypisom", b"ftypmp42"):
        return "video/mp4"
    ext = os.path.splitext(path)[1].lower()
    return {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".gif": "image/gif", ".webp": "image/webp", ".mp4": "video/mp4",
            ".pdf": "application/pdf", ".amr": "audio/amr"}.get(
                ext, "application/octet-stream")


def hl(text: str, kws: list[str]) -> str:
    """关键词高亮(先转义再插 mark, 避免 XSS)。"""
    out = esc(text)
    for k in sorted({k for k in kws if k}, key=len, reverse=True):
        if not k:
            continue
        out = re.sub(re.escape(esc(k)), lambda m: f"<mark>{m.group(0)}</mark>", out, flags=re.I)
    return out


def page(title: str, body: str, q: str = "") -> bytes:
    return f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>{CSS}</style>
<header><h1>💬 企业微信记录</h1>
<form action="/search" method="get">
<input type="text" name="q" value="{esc(q)}" placeholder="搜索聊天内容…" autofocus>
<button>检索</button></form>
<a href="/">会话</a><a href="/stats">统计</a></header>
<main>{body}</main></html>""".encode()


def render_msgs(rows, kws=(), with_conv=True, img=True) -> str:
    out = []
    for r in rows:
        who = STORE.sender_name(r["sender_rid"])
        bits = [f'<span class="who">{esc(who)}</span>', esc(ts_str(r["send_time"]))]
        if with_conv:
            bits.append(f'<a href="/conv/{r["conv_id"]}">#{esc(STORE.conv_name(r["conv_id"]))}</a>')
        if not (r["text"] or "").startswith("["):
            bits.append(f'<span class="tag">{esc(label(r["content_type"]))}</span>')
        if r["file_name"] and r["file_name"] not in (r["text"] or ""):
            sz = f" {r['file_size'] / 1024:.0f}KB" if r["file_size"] else ""
            bits.append(f"📎 {esc(r['file_name'])}{sz}")
        bits.append(f'<a href="/around/{r["id"]}">id={r["id"]}</a>')
        body = hl(r["text"] or "", list(kws))
        # 图片/表情消息直接内嵌本地附件(按 media.kind 判定, 不猜 content_type)
        if img:
            row = STORE.conn.execute(
                "SELECT md5 FROM msg_media WHERE msg_id=? AND deleted_at=0 "
                "AND kind IN ('image','emotion','emotion_thumb') LIMIT 1", (r["id"],)).fetchone()
            if row:
                body += f'<img loading="lazy" src="/file/{row[0]}">'
        out.append(f'<div class="msg"><div class="meta">{" ".join(bits)}</div>'
                   f'<div class="txt">{body}</div></div>')
    return "".join(out) or '<p class="mut">没有结果</p>'


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):  # 静音访问日志
        pass

    def send(self, data: bytes, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def qs(self):
        return urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

    def do_GET(self):  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        q = self.qs()
        try:
            if path == "/":
                return self.home()
            if path == "/search":
                return self.search(q.get("q", [""])[0])
            if path.startswith("/conv/"):
                return self.conv(path.split("/")[2], q)
            if path.startswith("/around/"):
                return self.around(path.split("/")[2])
            if path.startswith("/file/"):
                return self.file(path.split("/")[2])
            if path == "/stats":
                return self.stats()
            self.send(page("404", "<p>没有这个页面</p>"), code=404)
        except Exception as e:  # 检索期任何异常都回显, 便于排查
            self.send(page("错误", f"<pre>{esc(e)}</pre>"), code=500)

    def home(self):
        rows = STORE.conn.execute(
            "SELECT m.conv_id, count(*) n, max(m.send_time) t1 FROM msg m WHERE m.deleted_at=0 "
            "GROUP BY m.conv_id ORDER BY t1 DESC LIMIT 300").fetchall()
        items = "".join(
            f'<a class="conv" href="/conv/{r["conv_id"]}">'
            f'<span>{esc(STORE.conv_name(r["conv_id"]))}</span>'
            f'<span class="mut">{r["n"]} 条 · {esc(ts_str(r["t1"])[:16])}</span></a>'
            for r in rows)
        self.send(page("企业微信记录", f"<p class='mut'>最近活跃的 {len(rows)} 个会话</p>{items}"))

    def search(self, kw):
        kw = kw.strip()
        if not kw:
            return self.send(page("检索", "<p>请输入关键词</p>"))
        kws = kw.split()
        params, conds = [], []
        long_ = ['"' + k.replace('"', '""') + '"' for k in kws if len(k) >= 3]
        if long_:
            conds.append("msg_fts MATCH ?")
            params.append(" ".join(long_))       # FTS5 空格短语 = 隐含 AND
        for k in (k for k in kws if len(k) < 3):
            conds.append("m.text LIKE ?")
            params.append(f"%{k}%")
        rows = STORE.conn.execute(
            "SELECT m.* FROM msg m JOIN msg_fts f ON f.rowid=m.id "
            f"WHERE m.deleted_at=0 AND {' AND '.join(conds)} "
            "ORDER BY m.send_time DESC LIMIT 300", params).fetchall()
        body = (f'<p class="mut">“{esc(kw)}” 命中 {len(rows)} 条(最多 300)</p>'
                + render_msgs(rows, kws))
        self.send(page(f"检索 {kw}", body, kw))

    def conv(self, cid, q):
        cid = int(cid)
        before = q.get("before", [None])[0]
        sql = "SELECT * FROM msg WHERE conv_id=? AND deleted_at=0"
        p = [cid]
        if before:
            sql += " AND send_time<?"; p.append(int(before))
        rows = STORE.conn.execute(sql + " ORDER BY send_time DESC, id DESC LIMIT ?",
                                  p + [PAGE]).fetchall()
        rows = list(reversed(rows))
        nav = ""
        if rows:
            nav = (f'<div class="pg"><a href="/conv/{cid}?before={rows[0]["send_time"]}">'
                   f'↑ 更早的 {PAGE} 条</a></div>')
        body = (f'<h2 style="font-size:15px">{esc(STORE.conv_name(cid))}</h2>'
                + nav + render_msgs(rows, with_conv=False))
        self.send(page(STORE.conv_name(cid), body))

    def around(self, mid):
        mid = int(mid)
        row = STORE.conn.execute("SELECT conv_id,send_time FROM msg WHERE id=?", (mid,)).fetchone()
        if not row:
            return self.send(page("404", "<p>没有这条消息</p>"), code=404)
        cid, ts = row["conv_id"], row["send_time"]
        rows = STORE.conn.execute(
            "SELECT * FROM msg WHERE conv_id=? AND deleted_at=0 AND send_time BETWEEN ? AND ? "
            "ORDER BY send_time, id LIMIT 200", (cid, ts - 3600, ts + 3600)).fetchall()
        body = render_msgs(rows, with_conv=False)
        self.send(page("上下文", f'<h2 style="font-size:15px">'
                                 f'{esc(STORE.conv_name(cid))} 上下文 · 目标消息 id={mid}</h2>{body}'))

    def file(self, md5):
        if not re.fullmatch(r"[0-9a-f]{32}", md5):
            return self.send(b"bad md5", "text/plain", 400)
        r = STORE.conn.execute(
            "SELECT rel_path,src_path,name FROM media WHERE md5=? AND deleted_at=0 LIMIT 1",
            (md5,)).fetchone()
        p = best_media_path(md5, STORE.conn) if r else ""
        if not p or not os.path.isfile(p):
            return self.send("附件不在本次备份目录内".encode(), "text/plain; charset=utf-8", 404)
        with open(p, "rb") as f:
            data = f.read()
        self.send(data, sniff_ctype(p, data))

    def stats(self):
        c = STORE.conn
        n = c.execute("SELECT count(*) FROM msg WHERE deleted_at=0").fetchone()[0]
        t0, t1 = c.execute("SELECT min(send_time),max(send_time) FROM msg WHERE deleted_at=0").fetchone()
        m = c.execute("SELECT count(*),sum(size) FROM media WHERE deleted_at=0").fetchone()
        types = "".join(f"<li>{esc(label(ct))}: {k}</li>" for ct, k in c.execute(
            "SELECT content_type,count(*) k FROM msg WHERE deleted_at=0 GROUP BY 1 ORDER BY k DESC LIMIT 12"))
        body = (f"<ul><li>消息总数: {n}</li><li>时间跨度: {esc(ts_str(t0)[:10])} ~ {esc(ts_str(t1)[:10])}</li>"
                f"<li>媒体文件: {m[0]} 个, {(m[1] or 0) / 2**30:.1f} GB</li></ul>"
                f"<h3 style='font-size:14px'>消息类型</h3><ul>{types}</ul>")
        self.send(page("统计", body))


def main() -> int:
    global STORE
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB)
    ap.add_argument("--host", default=os.environ.get("WECOM_WEBUI_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("WECOM_WEBUI_PORT", "8765")))
    args = ap.parse_args()
    STORE = Store(args.db)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"检索服务已启动: http://{args.host}:{args.port}  (Ctrl-C 退出)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
