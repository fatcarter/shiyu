#!/usr/bin/env python3
"""企业微信消息 content(BLOB) protobuf 解析。

MESSAGE.content 是 Tencent protobuf(ant 序列化), 布局随 content_type 变化, 没有公开
的 .proto。本模块不做"猜 schema", 而是:
  1) 结构化遍历: 把长度分隔字段按 (可解为子消息 / 可解为文本) 分类递归;
  2) 文本抽取: 取"最内层可读文本"作为正文(跳过框架字节与二进制);
  3) 附件引用: 抽取 32-hex 的 md5(企业微信附件目录名就是 md5)、URL、文件名。

自测: 直接跑本文件 = 对合成样本验证遍历/文本/哈希抽取逻辑。
"""
from __future__ import annotations

import re
from typing import Iterator

_HEX32 = re.compile(rb"^[0-9a-fA-F]{32}$")
_URL = re.compile(rb"https?://[\x21-\x7e]{6,500}")
_PRINT = re.compile(rb"[\x20-\x7e\xc2-\xf4][\x20-\x7e\x80-\xbf]*")


def _is_text(b: bytes) -> bool:
    """可读文本判定: UTF-8 合法, 且不含除换行/回车/制表以外的控制字符。

    严格到"零控制字符"是刻意的: content 里真正的人类文本几乎不会夹控制字节,
    而把二进制子消息误判成文本会污染正文抽取(实测放过 5% 控制字符就会中招)。
    """
    if not b:
        return False
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not s.strip():
        return False
    return all(ord(ch) >= 0x20 or ch in "\n\r\t" for ch in s)


def _read_varint(b: bytes, i: int) -> tuple[int, int]:
    v = 0
    shift = 0
    while i < len(b):
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        shift += 7
        if not (c & 0x80):
            return v, i
        if shift > 63:
            break
    raise ValueError("varint 越界")


def parse_fields(b: bytes) -> list[tuple[int, int, object]]:
    """解析一层 protobuf: 返回 [(field_no, wire_type, value)]。

    wire_type: 0=varint(int), 1/5=定长(hex str), 2=长度分隔(bytes)。
    解析失败(不是合法 protobuf)时抛 ValueError。
    """
    out = []
    i = 0
    n = len(b)
    while i < n:
        key, i = _read_varint(b, i)
        fno, wt = key >> 3, key & 7
        if fno == 0:
            raise ValueError("字段号 0")
        if wt == 0:
            v, i = _read_varint(b, i)
            out.append((fno, wt, v))
        elif wt == 2:
            ln, i = _read_varint(b, i)
            if ln < 0 or i + ln > n:
                raise ValueError("长度越界")
            out.append((fno, wt, b[i : i + ln]))
            i += ln
        elif wt == 5:
            if i + 4 > n:
                raise ValueError("i32 越界")
            out.append((fno, wt, b[i : i + 4].hex()))
            i += 4
        elif wt == 1:
            if i + 8 > n:
                raise ValueError("i64 越界")
            out.append((fno, wt, b[i : i + 8].hex()))
            i += 8
        else:
            raise ValueError(f"未知 wire type {wt}")
    return out


def _encode_field(fno: int, payload: bytes) -> bytes:
    """按 protobuf 重新编码一个长度分隔字段(用于校验"恰好一层包装")。"""
    ln = len(payload)
    out = bytearray([(fno << 3) | 2])
    while True:
        b = ln & 0x7F
        ln >>= 7
        out.append(b | (0x80 if ln else 0))
        if not ln:
            break
    return bytes(out) + payload


def _parses_as_message(b: bytes) -> bool:
    try:
        return bool(parse_fields(b))
    except ValueError:
        return False


def unwrap_text_wrapper(b: bytes) -> bytes | None:
    """正文叶子常被一层 protobuf 头包着: 0a <len> <正文>。

    例: b"\n9没有的话，就别部署了，没有效果图就算了" 里 '\n'(0x0a) 是字段标记,
    '9'(0x39=57) 是长度 —— 其后 57 字节才是真正正文(正好 19 个汉字 x 3 = 57)。
    因为 0x0a 是合法 UTF-8(换行), 这类值会被判成"文本", 不剥掉就会在正文里留下
    "\n9" 这类前缀, 还会让同一条消息在新老库里文本不一致, 跨库去重因此失效。

    返回内层载荷; 不是"恰好一层包装"时返回 None。
    """
    if len(b) < 3:
        return None
    try:
        fields = parse_fields(b)
    except ValueError:
        return None
    if len(fields) != 1:
        return None
    fno, wt, payload = fields[0]
    if wt != 2 or not isinstance(payload, bytes) or not payload:
        return None
    if _encode_field(fno, payload) != b:   # 必须正好用尽整个 buffer, 否则不是纯包装
        return None
    return payload if (_is_text(payload) or _parses_as_message(payload)) else None


def peel_text_wrapper(b: bytes) -> bytes | None:
    """反复剥掉 0a<len> 包装(实测最多两层), 返回最内层; 没剥过返回 None。"""
    cur = b
    for _ in range(4):
        nxt = unwrap_text_wrapper(cur)
        if nxt is None:
            break
        cur = nxt
    return cur if cur is not b else None


def walk(b: bytes, path: str = "", depth: int = 0) -> Iterator[tuple[str, str, object]]:
    """递归遍历: yield (字段路径, 类型, 值)。类型 ∈ {int, text, bytes, hex, raw}。"""
    if depth > 8:
        yield (path, "raw", b)
        return
    try:
        fields = parse_fields(b)
    except ValueError:
        yield (path, "raw", b)
        return
    if not fields:
        yield (path, "raw", b)
        return
    for fno, wt, v in fields:
        p = f"{path}.{fno}" if path else str(fno)
        if wt == 0:
            yield (p, "int", v)
        elif wt in (1, 5):
            yield (p, "hex", v)
        else:
            # 顺序要紧: 32 位 hex 也是合法 UTF-8 文本, 若先判文本就永远走不到 md5 分支
            if _HEX32.match(v):
                yield (p, "md5", v.decode("ascii").lower())
                continue
            sub = _parses_as_message(v) if len(v) >= 2 else False
            if sub and not _is_text(v):
                yield from walk(v, p, depth + 1)
            elif _is_text(v):
                inner = peel_text_wrapper(v)
                if inner is None:
                    yield (p, "text", v.decode("utf-8"))
                elif _is_text(inner):      # 剥掉 0a<len> 包装后的真正正文
                    yield (p + ".1", "text", inner.decode("utf-8"))
                else:
                    yield from walk(inner, p + ".1", depth + 1)
            else:
                yield (p, "bytes", v)


def text_segments(b: bytes) -> list[dict]:
    """把 content 拆成"段落"序列: [{"type": int, "text": str|None}]。

    企业微信把一条消息切成若干段, 每段自带一个类型(段内字段 1):
      type 0 文本段   1 其他   5 引用对象的发送人 id
    引用别人的消息时, 结构是:
      [0: "“张三：\n"] [0: 被引用的正文] [0: "”\n------\n"] [0: 本次回复]
      [5: 张三的 id] [0: " "]
    ——被引用内容排在前面, **本次回复是最后一个非空白文本段**, 末尾还会跟一个
    空白段。只按"最长的文本"或"第一个文本"取正文会把引用内容当成正文(实测如此),
    所以必须按段落类型和顺序来定。
    """
    segs: list[dict] = []
    cur: dict | None = None
    for path, kind, val in walk(b):
        parts = path.split(".")
        if kind == "int" and len(parts) == 2 and parts[1] == "1":
            cur = {"type": val, "text": None}
            segs.append(cur)
        elif kind == "text" and cur is not None and len(parts) >= 3 \
                and parts[1] == "2" and parts[-1] == "1":
            cur["text"] = val
    return segs


def extract_reply_text(b: bytes) -> str:
    """取消息的正文: 最后一个非空白的文本段; 取不到时退回"最长的文本叶子"。"""
    texts = [s["text"] for s in text_segments(b)
             if s["type"] == 0 and s["text"] and s["text"].strip()]
    if texts:
        return texts[-1].strip("\x00 \t\r\n")
    return extract_text(b)


def extract_text(b: bytes) -> str:
    """取"最内层文本"拼成正文: 深度优先收集 text 叶子, 取最长的一条(正文通常最长)。"""
    texts = []
    for path, kind, val in walk(b):
        if kind == "text":
            texts.append(val)
    if not texts:
        return ""
    # 企业微信正文常见前缀: 一个前导空格/制表 + 结构标记, 去掉前导空白
    best = max(texts, key=len)
    return best.strip("\x00 \t\r\n")


def extract_md5s(b: bytes) -> list[str]:
    """抽取附件 md5: 只认"整个字段值就是 32 位 hex"的叶子。

    绝不对整个 blob 做 hex 正则兜底 —— 企业微信会把内层 ant 消息以 **hex 字符串**形式
    再存一份(字段 1), 里面全是 0123456789abcdef, 一旦按原始字节扫 32 位窗口, 会从这串
    hex 里切出成千上万个假 md5(实测把 3.5 万条真实附件关系污染成 29 万个)。
    """
    found = []
    for path, kind, val in walk(b):
        if kind == "md5" and val not in found:
            found.append(val)
    return found


def extract_urls(b: bytes) -> list[str]:
    out = []
    for m in _URL.finditer(b):
        u = m.group().decode("utf-8", "replace")
        if u not in out:
            out.append(u)
    return out


def extract_strings(b: bytes, min_len: int = 2) -> list[str]:
    """所有可读字符串(含文件名等), 用于结构化兜底。"""
    out = []
    for m in _PRINT.finditer(b):
        try:
            s = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        s = s.strip("\x00 \t")
        if len(s) >= min_len and s not in out:
            out.append(s)
    return out


def _selftest() -> None:
    def ld(fno: int, payload: bytes) -> bytes:  # 长度分隔字段
        ln = len(payload)
        assert ln < 128
        return bytes([(fno << 3) | 2, ln]) + payload

    # 子消息: 一个短文本 + 一段二进制(二进制不参与正文, 但应被递归进去而不是当成文本)
    inner = ld(1, "你好世界".encode()) + ld(2, b"\xff\xfe\x00\x01" * 3)
    blob = (
        ld(1, " 这是一段足够长的正文文本内容".encode())
        + b"\x10\xe8\x07"          # f2 varint 1000
        + ld(3, inner)             # f3 嵌套消息
        + ld(4, b"https://x.cn/a")  # f4 url
    )
    fields = parse_fields(blob)
    assert [f[0] for f in fields] == [1, 2, 3, 4], fields
    assert extract_text(blob) == "这是一段足够长的正文文本内容", repr(extract_text(blob))
    # extract_text 取"最长的文本叶子"
    assert extract_text(ld(1, "短".encode()) + ld(2, "这是一段更长的正文".encode())) == "这是一段更长的正文"
    # 整个字段是 32 位 hex → 识别为 md5(必须在文本判定之前, 否则会被当成普通文本)
    assert extract_md5s(ld(2, b"a" * 32)) == ["a" * 32]
    # 0a<len> 包装必须剥掉: '\n' + chr(len) + 正文
    body = "没有的话，就别部署了，没有效果图就算了"
    assert len(body.encode()) == 57
    wrapped = ld(2, b"\n" + bytes([57]) + body.encode())
    assert extract_text(wrapped) == body, repr(extract_text(wrapped))
    # 32 位 hex 叶子不再混进正文
    assert extract_text(ld(1, "正文".encode()) + ld(2, b"b" * 32)) == "正文"
    # hex 编码的子消息(全是 0123456789abcdef)不得被切出假 md5
    fake = ld(1, ("306902010204623060020100020473f32d9f02030f42410204eb" * 2).encode())
    assert extract_md5s(fake) == [], extract_md5s(fake)
    assert extract_urls(blob) == ["https://x.cn/a"]
    # 非 protobuf 输入不应抛异常
    assert extract_text(b"\xff\xfe\x00garbage") == ""
    # 含控制字符的串不算文本(否则二进制子消息会被当成正文)
    assert not _is_text(inner)
    print("self-test PASS: protobuf 遍历/文本/md5/URL 抽取正常")


if __name__ == "__main__":
    _selftest()
