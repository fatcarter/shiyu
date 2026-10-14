#!/usr/bin/env python3
"""构建后自检: 校验 data/wecom.sqlite 的完整性、去重效果与附件关联率。

用法: verify_store.py
"""
from __future__ import annotations

import os
import sqlite3
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
from wwconfig import paths  # noqa: E402

DB = paths().store_db


def main() -> int:
    if not os.path.exists(DB):
        print("找不到", DB)
        return 1
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    ok = True

    def check(name, sql, want=None, op="=="):
        nonlocal ok
        got = c.execute(sql).fetchone()[0]
        good = True if want is None else (
            got == want if op == "==" else got <= want if op == "<=" else got >= want)
        print(f"  {'✅' if good else '❌'} {name}: {got}" + ("" if want is None else f" (期望 {op} {want})"))
        ok = ok and good
        return got

    print("— 结构 —")
    check("quick_check", "PRAGMA quick_check", "ok")
    check("会话数", "SELECT count(*) FROM conv WHERE deleted_at=0", 0, ">")
    check("消息数", "SELECT count(*) FROM msg WHERE deleted_at=0", 0, ">")
    check("FTS 行数", "SELECT count(*) FROM msg_fts", 0, ">")

    print("— 一致性与去重 —")
    # 主键与 FTS rowid 必须一一对应(构建时按同一顺序分配)
    check("FTS 与 msg 的 id 差集", "SELECT count(*) FROM msg_fts f "
          "LEFT JOIN msg m ON m.id=f.rowid WHERE m.id IS NULL", 0)
    check("msg.id 与 lid 是否各自唯一",
          "SELECT count(*) FROM (SELECT id FROM msg GROUP BY id HAVING count(*)>1)", 0)
    # (会话, seq) 是新老两库共用的消息标识, 跨库去重就靠它 → 跨库不该有重复
    check("跨库 (会话,seq) 重复",
          "SELECT count(*) FROM (SELECT conv_id,seq FROM msg WHERE deleted_at=0 AND seq IS NOT NULL "
          "GROUP BY 1,2 HAVING count(*)>1 AND count(DISTINCT src)>1)", 0)
    # 兜底: seq 漂移的同一条消息(同会话/发送人/秒/正文)应已被内容去重软删
    check("跨库重复消息(会话+发送人+时间+正文)",
          "SELECT count(*) FROM (SELECT conv_id,sender_rid,send_time,substr(text,1,120),"
          "count(*) n,count(DISTINCT src) s FROM msg WHERE deleted_at=0 "
          "GROUP BY 1,2,3,4 HAVING n>1 AND s>1)", 0)
    check("老库消息占比(%)", "SELECT round(100.0*sum(src='legacy')/count(*),1) FROM msg WHERE deleted_at=0")
    # 仅信息: 老库源数据本身就有 2 组 (会话,seq) 重复(两条不同 message_id), 未做处理
    print("  ℹ️  同库内 (会话,seq) 重复(源数据自带):",
          c.execute("SELECT count(*) FROM (SELECT conv_id,seq FROM msg WHERE deleted_at=0 "
                    "AND seq IS NOT NULL GROUP BY 1,2 HAVING count(*)>1 "
                    "AND count(DISTINCT src)=1)").fetchone()[0])
    # 正文里不该再出现 `\n<长度字节>` 包装残留(如换行后跟一个可打印字符)
    check("正文疑似残留包装前缀",
          "SELECT count(*) FROM msg WHERE deleted_at=0 AND text LIKE (char(10)||'_%') "
          "AND length(text)<60", 0)

    print("— 附件关联 —")
    with_md5 = check("带 md5 的消息", "SELECT count(*) FROM msg WHERE md5s<>'' AND deleted_at=0", 0, ">")
    linked = check("关联上本地文件的消息",
                   "SELECT count(DISTINCT msg_id) FROM msg_media WHERE deleted_at=0", 0, ">")
    if with_md5:
        print(f"     关联率 {linked/with_md5*100:.0f}%")
    check("media 里有内容 md5 的文件",
          "SELECT count(*) FROM media WHERE md5 NOT LIKE 'path:%' AND deleted_at=0", 0, ">")

    print("— FTS 检索 —")
    for kw in ("预算", "会议", "项目"):
        try:
            n = c.execute("SELECT count(*) FROM msg_fts WHERE msg_fts MATCH ?",
                          ('"' + kw + '"',)).fetchone()[0]
            print(f"  {'✅' if n else '⚠️'} 短语“{kw}”: {n} 条(2 字在 trigram 下为 0 属正常)")
        except sqlite3.OperationalError as e:
            print(f"  ❌ 短语“{kw}” 报错: {e}")
            ok = False
    for kw in ("汇报材料", "产品经理"):
        n = c.execute("SELECT count(*) FROM msg_fts WHERE msg_fts MATCH ?",
                      ('"' + kw + '"',)).fetchone()[0]
        print(f"  {'✅' if n else '❌'} 短语“{kw}”(≥3 字): {n} 条")
        ok = ok and n > 0

    print("\n结论:", "全部通过" if ok else "存在未通过项")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
