#!/usr/bin/env python3
"""task_for_pid 探针: 判断"这个进程的内存能不能读", 与 wckey 无关。

用于取密钥前的快速判断(见 README 第四节):
  kr=0 → 可读(副本签名正确);  kr=5(KERN_FAILURE) → 被挡(常见于原版 App,
  或签名带了 --options runtime)。

用法: tfp_test.py [进程名匹配串或 pid]
      默认只认主进程(原版与 keys/WeCom-dev.app 副本都会命中), 不含各种 Helper
"""
from __future__ import annotations

import ctypes
import subprocess
import sys

# 主进程的命令行正好以 "Contents/MacOS/企业微信" 结尾, Helper 进程后面还有别的内容,
# 用 $ 锚定就能只挑出主进程(那个才是持有数据库密钥的进程)。
spec = sys.argv[1] if len(sys.argv) > 1 else "MacOS/企业微信$"
if spec.isdigit():
    pids = [int(spec)]
else:
    r = subprocess.run(["pgrep", "-fl", spec], capture_output=True, text=True)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    pids = [int(ln.split(None, 1)[0]) for ln in lines]
    for ln in lines:
        print("  ", ln)

print("pids:", pids)
if not pids:
    sys.exit("没有匹配的进程")

libc = ctypes.CDLL("/usr/lib/libSystem.dylib", use_errno=True)
mts = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
tfp = libc.task_for_pid
tfp.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
tfp.restype = ctypes.c_int
for pid in pids:
    task = ctypes.c_uint(0)
    kr = tfp(mts, pid, ctypes.byref(task))
    print(f"pid {pid}: kr={kr} task={task.value}" + ("  ← 可读" if kr == 0 else "  ← 被挡"))
