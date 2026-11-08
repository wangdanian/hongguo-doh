# -*- coding: utf-8 -*-
"""推送本地文件到 ECS（分片 base64 + 远端拼接）
用法: python push_file.py <本地路径> <远端路径>
"""
import sys, subprocess, base64, os, hashlib
os.environ.setdefault("MSYS_NO_PATHCONV", "1")

ECS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecs_run.py")
LOCAL, REMOTE = sys.argv[1], sys.argv[2]

data = open(LOCAL, "rb").read()
b64 = base64.b64encode(data).decode()
tmp = REMOTE + ".push.b64"
# 每片命令总长 < 15KB：b64 片 ≤ 10000 字符
CH = 10000
r = subprocess.run([sys.executable, ECS, f"rm -f {tmp}", "30"], capture_output=True, text=True)
for i in range(0, len(b64), CH):
    chunk = b64[i:i+CH]
    cmd = f"echo {chunk} >> {tmp}"
    assert len(cmd) < 15000, "chunk cmd too long"
    p = subprocess.run([sys.executable, ECS, cmd, "60"], capture_output=True, text=True)
    if "exit=0" not in p.stdout:
        print("[fail] chunk", i // CH, p.stdout[:200]); sys.exit(1)
cmd = (f"base64 -d {tmp} > {REMOTE} && rm -f {tmp} && "
       f"md5sum {REMOTE} && stat -c%s {REMOTE}")
p = subprocess.run([sys.executable, ECS, cmd, "60"], capture_output=True, text=True)
print(p.stdout.strip())
print("local md5:", hashlib.md5(data).hexdigest(), "bytes:", len(data))
