# -*- coding: utf-8 -*-
"""行为型 DGA 收敛 dry-run：只打印会收敛哪些父域，不写任何文件。"""
import sys
sys.path.insert(0, "/opt/hongguo-doh")
import autodetect as a
from collections import defaultdict

stats = a.collect_recent()
all_by_parent = defaultdict(set)
dga = defaultdict(set)
for dom in stats:
    parts = dom.split(".")
    if len(parts) < 3:
        continue
    p = ".".join(parts[-2:])
    all_by_parent[p].add(dom)
    if a._dga_word(parts[0]):
        dga[p].add(parts[0])

lines = open(a.SHARED_FILE, encoding="utf-8").read().splitlines()
existing = set(l.strip() for l in lines if l.strip() and not l.startswith("#"))
wl = set(l.strip().lower().rstrip("*") for l in
         open(a.WHITELIST_FILE, encoding="utf-8")
         if l.strip() and not l.startswith("#"))

print("近3天唯一域 %d，父域 %d，含DGA词父域 %d" %
      (len(stats), len(all_by_parent), len(dga)))
for p, labels in sorted(dga.items(), key=lambda x: -len(x[1])):
    total = len(all_by_parent[p])
    why = []
    if len(labels) < 3:
        why.append("随机标签<3")
    if total > 40:
        why.append("总域数>40")
    if total and len(labels) / total < 0.8:
        why.append("随机占比<80%")
    if p in a.NO_COLLAPSE:
        why.append("业务大域")
    if p in a.PROTECT_PARENTS:
        why.append("保护父域")
    if p in wl:
        why.append("白名单")
    if ("**.%s**" % p) in existing:
        why.append("已有整域规则")
    verdict = "跳过" if why else "★会收敛"
    print("%-8s %-30s 随机%2d 总%3d  %s  例:%s" %
          (verdict, p, len(labels), total, ",".join(why),
           sorted(labels)[0][:26]))
