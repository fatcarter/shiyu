#!/bin/bash
# 重建用于取密钥的 App 副本: 复制 /Applications/企业微信.app → keys/WeCom-dev.app 并重签名。
#
# 为什么要这么绕(见 README 第四节):
#   读活进程内存需要 task_for_pid, 而原版 App 没有 get-task-allow 权限, 读不了;
#   给副本加上该权限**并且不加 --options runtime**(硬化运行时)才能读。
#   原版 App 全程只读, 不会被本脚本改动。
#
# 用法: make_dev_app.sh [原版App路径] [副本输出路径]
#       默认 /Applications/企业微信.app → keys/WeCom-dev.app
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-${WEWORK_APP:-/Applications/企业微信.app}}"
DST="${2:-$HERE/WeCom-dev.app}"
ENT="$HERE/wecom_dev_entitlements.plist"

[[ -d "$SRC" ]] || { echo "找不到原版 App: $SRC" >&2; exit 1; }
[[ -f "$ENT" ]] || { echo "找不到权限文件: $ENT" >&2; exit 1; }
if [[ -e "$DST" ]]; then
  echo "目标已存在: $DST" >&2
  echo "要重建请先手动删除(脚本不替你 rm -rf)" >&2
  exit 1
fi

echo "复制 $SRC"
echo "  →  $DST"
# APFS 克隆: 秒级完成且不额外占盘; 卷不支持克隆时退回普通复制
cp -cR "$SRC" "$DST" 2>/dev/null || cp -R "$SRC" "$DST"

echo "重签名(adhoc, 带 get-task-allow, 不加 --options runtime)"
codesign --force --sign - --entitlements "$ENT" "$DST"

# ── 断言: 三条都过才算副本可用 ────────────────────────────────
# 用 bash 字符串匹配而不是 `codesign ... | grep -q`: grep -q 命中即退出会让 codesign
# 吃 SIGPIPE, 在 set -o pipefail 下整条管道被判成失败, 断言就会无故报错。
SIG="$(codesign -dv "$DST" 2>&1 || true)"
ENTINFO="$(codesign -d --entitlements - "$DST" 2>/dev/null || true)"
fail=0
if ! codesign --verify "$DST" 2>/dev/null; then
  echo "❌ 签名校验失败" >&2; fail=1
fi
if [[ "$SIG" != *"flags=0x2(adhoc)"* ]]; then
  echo "❌ 不是 adhoc 签名" >&2; fail=1
fi
if [[ "$SIG" == *"runtime"* ]]; then
  echo "❌ 签名带了运行时硬化(--options runtime), task_for_pid 会被内核挡掉" >&2; fail=1
fi
if [[ "$ENTINFO" != *"get-task-allow"* ]]; then
  echo "❌ entitlements 里没有 get-task-allow" >&2; fail=1
fi
[[ $fail -eq 0 ]] || { rm -rf "$DST"; exit 1; }

echo
echo "✅ 副本就绪: $DST"
echo "   这个副本只是取密钥用的, 1.6GB, 用完可整个删掉。"
echo
echo "接下来(照 README 第四节):"
echo "  1. 退出原版企业微信(副本与原版共用同一个容器, 不能同时开)"
echo "  2. 启动副本: open \"$DST\""
echo "  3. 取 KCV:   head -c 8 <加密库> | xxd -p      # 或 python3 -c '...'"
echo "  4. 扫内存:   $HERE/wckey pid <pid> <kcv,...>  # 分片并行见 WCKEY_SHARD/WCKEY_NSHARD"
echo "  5. 退出副本, 删掉它, 重新打开原版"
