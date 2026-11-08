#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前敏感信息自检。

用法:
    python3 tools/check_before_push.py [仓库根目录] [--deny 额外模式]...

命中任一问题即退出码 1。CI 里跑的是同一份脚本。
可用 --deny 传入你自己的私有域名 / IP 等额外禁止字符串，例如：
    python3 tools/check_before_push.py . --deny my-private.example.com
"""
import os
import re
import sys
import subprocess

SECRET_PATTERNS = [
    ("阿里云 AccessKey ID", re.compile(r"LTAI[A-Za-z0-9]{12,}")),
    ("AWS AccessKey ID", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("GitHub Token", re.compile(r"(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}")),
    ("通用 API token", re.compile(r"\b(?:sk-|xox[baprs]-|AIza)[A-Za-z0-9_\-]{20,}")),
    ("私钥", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("硬编码 key=value 凭据", re.compile(
        r"(?i)\b(?:access[_-]?key[_-]?secret|secret[_-]?key|api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9+/]{20,}['\"]")),
    ("本机绝对路径", re.compile(r"[A-Za-z]:\\Users\\|/home/[a-z0-9_-]+/|\bC:/Users/")),
]

# 允许出现的地址：本机、文档示例网段、常见公共 DNS、私网段
IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
IP_ALLOW_PREFIX = (
    "127.", "0.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "169.254.",
    "203.0.113.", "198.51.100.", "192.0.2.",  # RFC 5737 文档地址
)
IP_ALLOW_EXACT = {
    "223.5.5.5", "119.29.29.29", "114.114.114.114", "1.1.1.1",
    "8.8.8.8", "8.8.4.4", "2400:3200::1", "255.255.255.255",
}

BAD_FILENAMES = (
    "users.json", "doh_log.txt", "ecs_secrets.local.json", "install-qr.png",
)
BAD_SUFFIX = (".log", ".tsv", ".jsonl", ".pem", ".key", ".p12",
              ".bak", ".pyc", ".push.b64", ".mobileconfig")
BAD_NAME_RE = re.compile(r"\.bak[0-9-]*$|_b64\.txt$|^zte_.*\.html$")

MAX_FILE_BYTES = 1024 * 1024  # 1 MB：名单快照不该进仓库
SKIP_DIRS = {".git", "__pycache__", "public-blocklists", "watch", "logs", "reports", ".idea", ".vscode"}
SKIP_EXACT = {"LICENSE", ".gitignore", "check_before_push.py"}


def _tracked_files(root):
    try:
        out = subprocess.check_output(["git", "ls-files"], cwd=root, text=True,
                                      stderr=subprocess.DEVNULL)
        files = [f for f in out.splitlines() if f]
        if files:
            return files
    except Exception:
        pass
    res = []
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for n in names:
            p = os.path.join(base, n)
            res.append(os.path.relpath(p, root).replace(os.sep, "/"))
    return res


def main():
    args = sys.argv[1:]
    root = os.path.abspath(args[0]) if args and not args[0].startswith("--") else os.getcwd()
    extra = []
    for i, a in enumerate(args):
        if a == "--deny" and i + 1 < len(args):
            extra.append(args[i + 1])
    problems = []
    checked = 0

    for rel in _tracked_files(root):
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        name = os.path.basename(rel)
        norm = rel.replace("\\", "/")

        # 文件名 / 后缀类
        if name in BAD_FILENAMES and not norm.startswith("examples/"):
            problems.append((rel, 0, "不应提交的文件: %s" % name))
        if (name.endswith(BAD_SUFFIX) or BAD_NAME_RE.search(name)) and not (
                name.endswith(".mobileconfig") and norm.startswith("examples/")):
            problems.append((rel, 0, "不应提交的文件类型: %s" % name))
        if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
            problems.append((rel, 0, ".env 类文件不应提交"))

        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            problems.append((rel, 0, "文件过大 %d B（名单快照不该入库）" % size))
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="strict") as fh:
                lines = fh.read().splitlines()
        except (UnicodeDecodeError, OSError):
            continue  # 二进制文件（图标等），跳过内容检查
        if name in SKIP_EXACT:
            continue
        checked += 1
        for lineno, line in enumerate(lines, 1):
            for label, pat in SECRET_PATTERNS:
                if pat.search(line):
                    problems.append((rel, lineno, "%s: %s" % (label, line.strip()[:90])))
            for ip in IP_RE.findall(line):
                if ip in IP_ALLOW_EXACT or ip.startswith(IP_ALLOW_PREFIX):
                    continue
                problems.append((rel, lineno, "疑似真实公网 IP: %s" % ip))
            for d in extra:
                if d and d in line:
                    problems.append((rel, lineno, "命中 --deny 模式: %s" % d))

    print("=" * 62)
    print(" check_before_push: 扫描 %d 个文本文件" % checked)
    if problems:
        print(" 发现 %d 处问题：" % len(problems))
        for rel, ln, why in problems[:40]:
            print("  - %s:%s  %s" % (rel, ln or "-", why))
        if len(problems) > 40:
            print("  ... 还有 %d 处" % (len(problems) - 40))
        print("=" * 62)
        return 1
    print(" PASS：未发现凭据、私钥、用户数据、日志、真实公网 IP 或大文件")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
