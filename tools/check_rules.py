#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则文件静态检查：行内注释、非法字符、重复规则、整域收敛缺另一半。

用法: python3 tools/check_rules.py [rules目录]
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "rules")
VALID = re.compile(r"^[a-z0-9.*\-]+$", re.I)

problems = []
warnings = []
seen = {}
parent_rules = set()
sub_rules = set()

for fn in sorted(os.listdir(RULES)):
    if not fn.endswith(".txt"):
        continue
    path = os.path.join(RULES, fn)
    for n, raw in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            problems.append("%s:%d 行内注释会让规则失效: %s" % (fn, n, line[:70]))
            continue
        if not VALID.match(line):
            problems.append("%s:%d 非法字符: %s" % (fn, n, line[:70]))
            continue
        if line in seen:
            problems.append("%s:%d 与 %s 重复: %s" % (fn, n, seen[line], line[:50]))
        seen[line] = "%s:%d" % (fn, n)
        if line.startswith("**."):
            sub_rules.add(line[3:].split("**")[0])
        elif not line.startswith("*") and line.endswith("**"):
            parent_rules.add(line[:-2])

# 整域收敛必须成对：父域** 与 **.父域**
for p in sorted(parent_rules - sub_rules):
    if p.count(".") == 1 and "-" not in p and "*" not in p:
        warnings.append("整域规则 %s** 可能缺配套的 **.%s**（若用于随机子域需补齐）" % (p, p))

print("check_rules: %d 条规则，%d 处问题，%d 条提示" % (len(seen), len(problems), len(warnings)))
for p in problems[:40]:
    print("  - ERROR", p)
for w in warnings[:20]:
    print("  - hint ", w)
sys.exit(1 if problems else 0)
