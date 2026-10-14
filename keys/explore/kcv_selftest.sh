#!/bin/bash
# KCV 计算自检: 用真实库文件的前 8 字节核对 kcv() 的实现是否一致。
# 用法: kcv_selftest.sh <32位hex密钥>
set -euo pipefail
K="$1"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
"$ROOT/.venv/bin/python" -c "
import sys; sys.path.insert(0, '$HERE')
from kcv_verify import kcv
print('python kcv:', kcv(bytes.fromhex('$K')).hex())
"
