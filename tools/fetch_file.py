# -*- coding: utf-8 -*-
"""从 ECS 拉取文件到本地（base64 分段传输，自动拼接解码）
用法: python fetch_file.py <远端路径> <本地路径>
"""
import sys, subprocess, base64, re, os
os.environ["MSYS_NO_PATHCONV"] = "1"  # 阻止 Git Bash 把 /opt 转成本地路径

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ECS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecs_run.py")
from ecs_run import run as ecs_run_cmd

REMOTE, LOCAL = sys.argv[1], sys.argv[2]
# 询问服务器大小与 md5，然后分段取
r = subprocess.run(
    [sys.executable, ECS,
     f"s=$(stat -c%s {REMOTE}); md5sum {REMOTE}; echo SIZE=$s", "30"],
    capture_output=True, text=True)
print(r.stdout[:200])
m = re.search(r"SIZE=(\d+)", r.stdout)
size = int(m.group(1)) if m else 0
CHUNK = 21000  # b64 输出上限约 32KB，控制单次取 15750 原始字节
parts = []
off = 0
while off < size:
    # 用 dd 按字节取原文再 b64，按原文字节偏移走
    take = CHUNK * 3 // 4
    cmd = f"dd if={REMOTE} bs=1 skip={off} count={take} 2>/dev/null | base64 -w0"
    p = subprocess.run(
        [sys.executable, ECS,
         cmd, "60"], capture_output=True, text=True)
    out = p.stdout
    # 去掉 exit= 行
    lines = [l for l in out.splitlines() if not l.startswith("exit=")]
    b64 = "".join(lines).strip()
    got = 0
    if b64:
        parts.append(base64.b64decode(b64 + "=" * (-len(b64) % 4)))
        got = len(parts[-1])
    if got == 0:
        print(f"[warn] chunk at {off} returned empty, stop"); break
    off += got
data = b"".join(parts)
with open(LOCAL, "wb") as f:
    f.write(data)
print(f"saved {LOCAL} bytes={len(data)} (remote size={size})")
