#!/bin/bash
# 编译密钥扫描器 wckey(纯 C, 只依赖系统 CommonCrypto, 无需第三方库)。
#
# 用法: build_wckey.sh
# 产物: keys/wckey
#       8 路分片并行扫描靠环境变量 WCKEY_SHARD / WCKEY_NSHARD, 不需要另一个二进制。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# 用 /usr/bin/clang(不是 Xcode 工具链也行: CommonCrypto 在 libSystem 里,
# -framework CoreFoundation 只是为了让链接器带上 CoreFoundation)
/usr/bin/clang -O2 -o "$HERE/wckey" "$HERE/wckey.c" -framework CoreFoundation

echo "已生成 $HERE/wckey"
"$HERE/wckey" || true   # 无参数时打印用法(退出码 2), 不影响脚本本身
