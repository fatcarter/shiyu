#!/bin/bash
# 增量同步媒体备份: 企业微信容器 → data/media
# 缓存目录名就是文件内容 md5 且文件不可变, 所以 rsync 比对大小+时间即可增量补齐。
#
# 用法: sync_media.sh [容器Data目录]
# 路径由 ../wwconfig.py 自动发现; 容器不在默认位置时传参或用 $WEWORK_CONTAINER 指定。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ $# -ge 1 ]] && export WEWORK_CONTAINER="$1"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

SRC="$(python3 -c 'from wwconfig import paths; print(paths().container)')"
DST="$(python3 -c 'from wwconfig import paths; print(paths().media_backup)')"

if [[ ! -d "$SRC" ]]; then
  echo "找不到企业微信数据目录: $SRC" >&2
  echo "(可用 $WEWORK_CONTAINER 指定, 或把路径作为第一个参数传入)" >&2
  exit 1
fi

echo "源   $SRC"
echo "目标 $DST"

sync_one() {  # $1=容器内子路径  $2=备份内相对路径
  if [[ -d "$SRC/$1" ]]; then
    mkdir -p "$DST/$2"
    rsync -a --delete-excluded --exclude '.DS_Store' "$SRC/$1/" "$DST/$2/"
    echo "  同步 $2"
  fi
}

# 目录映射同样来自 wwconfig(media_scan_pairs), 避免容器内的 Profile 哈希在脚本里再写一遍
while IFS=$'\t' read -r cont back; do
  sync_one "$cont" "$back"
done < <(python3 -c '
from wwconfig import paths
for _kind, (back, cont) in paths().media_scan_pairs().items():
    if cont:
        print(f"{cont}\t{back}")
')
echo "DONE"
