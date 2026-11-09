#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""广告反馈自动归因（开源版；部署目录可用 HONGGUO_BASE 覆盖）。

用户点「刚刚有广告」→ 回溯该时刻前 6 分钟的放行日志 → 与近 3 天历史基线
比对 → 找出首次出现/突发的陌生域 → 自动写拦截规则 → 返回可审计的报告。

解决 autodetect.py 的结构性盲区：它靠「广告关键词 + 高频 + 多设备」打分，
像 cf-gl.qiezibenpao.com / sdkgen.data.tianwenca.com 这种纯拼音随机父域
一个关键词都没有，永远进不了候选队列（2026-11-09 23:07 实证：64 次查询、
5 台设备、从凌晨放行到晚上）。用户的一次点击就是最高置信信号。

安全护栏：白名单/保护父域/已拦域/业务 CDN 域一律跳过；只写精确域或
确认整域都是新域的父域；规则行带 #feedback: 标签，可整段 grep 回滚。
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

BASE = os.environ.get("HONGGUO_BASE", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
import doh_server as ds  # noqa: E402

WATCH = os.path.join(BASE, "watch", "apps")
SHARED = os.path.join(BASE, "blacklist-shared.txt")
FORCE = os.path.join(BASE, "force-block.txt")
REPORT = os.path.join(BASE, "ad-feedback.json")
LOG = os.path.join(BASE, "ad-feedback.log")

# 业务 / 视频 / 系统域：这些不可能是「新广告落地页」，先排掉，
# 避免把正片 CDN、苹果推送、DNS 调度误判成广告。
SAFE_RE = re.compile(
    r"(douyin|byte|volc|zijie|snssdk|amemv|ixigua|qznovel|fqnovel|queniu|"
    r"ksyun|ks-cdn|cdnhwc|cdngslb|bsgslb|akadns|alibaba|alikunlun|aliyun|"
    r"amap|autonavi|taobao|alicdn|jd\.com|pinduoduo|yangkeduo|bilibili|"
    r"netease|163\.com|qq\.com|weixin|wechat|tencent|baidu|bdurl|sogou|"
    r"kuaishou|apple|icloud|mzstatic|itunes|microsoft|google|gstatic|"
    r"getui|umeng|sensorsdata|gslb|cdn|tos|vod|hls|flv|live|pull|push|"
    r"download|upload|static|image|img|pic|music|login|pay|api|log|report)",
    re.I)

# 大厂业务父域：即使标签全是字母也不碰。
KNOWN_PARENTS = {
    "bytegecko.com", "bytedance.com", "byteimg.com", "bytecdn.com",
    "zijieapi.com", "volces.com", "volcgtm.com", "snssdk.com", "amemv.com",
    "qznovelvod.com", "fqnovel.com", "fqnovelpic.com", "douyincdn.com",
    "douyinvod.com", "douyinliving.com", "douyinpic.com", "ixigua.com",
    "kuaishou.com", "kwaizt.com", "ksyuncdn.com", "netease.com", "163.com",
    "qq.com", "tencent.com", "baidu.com", "bdurl.net", "taobao.com",
    "alicdn.com", "alibabadns.com", "amap.com", "sogou.com", "bilibili.com",
    "sensorsdata.cn", "getui.net", "gepush.com", "umeng.com", "weibo.com",
    "apple.com", "icloud.com", "mzstatic.com", "akadns.net", "alikunlun.com",
}

PROTECT_PARENTS = {
    "qq.com", "qq.com.cn", "tencent.com", "aliyuncs.com", "baidu.com",
    "sogou.com", "kuaishou.com", "aliyun.com", "apple.com", "microsoft.com",
}

STRANGE_LABEL = re.compile(r"[a-z]{6,24}$")
AD_HINT = re.compile(r"(sdk|cf-|gl-|ad|landing|jump|click|promo|lp-|h5)", re.I)


def log(msg):
    line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    print(line, file=sys.stderr)


def parse_time(s):
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%H:%M"):
        try:
            t = datetime.strptime(s, fmt)
            if fmt == "%H:%M":
                n = datetime.now()
                t = t.replace(year=n.year, month=n.month, day=n.day)
                # 「23:07」这种用户在凌晨补报的，按最近一次出现处理
                if t > n + timedelta(minutes=5):
                    t -= timedelta(days=1)
            return t
        except ValueError:
            continue
    return datetime.now()


def read_logs():
    """返回 [(time, client, domain, app)]，只取最近 4 天的 ok.tsv。"""
    files = []
    now = datetime.now()
    for i in range(5):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        files.extend(sorted(glob.glob(os.path.join(WATCH, "*", day + "-ok.tsv"))))
    out = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    p = line.rstrip("\n").split("\t")
                    if len(p) < 4:
                        continue
                    try:
                        t = datetime.strptime(p[0], "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        continue
                    out.append((t, p[1], p[2].lower().rstrip("."),
                                p[6] if len(p) > 6 else "other"))
        except OSError:
            continue
    return out


def rule_count():
    try:
        return sum(1 for l in open(SHARED, encoding="utf-8")
                   if l.strip() and not l.lstrip().startswith("#"))
    except OSError:
        return 0


def analyze(at, write=True):
    w0 = at - timedelta(minutes=6)
    w1 = at + timedelta(minutes=1)
    rows = read_logs()

    win = defaultdict(lambda: {"q": 0, "clients": set(), "apps": Counter(),
                               "secs": set(), "first": None})
    base = Counter()
    base_first = {}
    for t, cli, dom, app in rows:
        if t < w0:
            base[dom] += 1
            if dom not in base_first or t < base_first[dom]:
                base_first[dom] = t
        elif t <= w1:
            s = win[dom]
            s["q"] += 1
            s["clients"].add(cli)
            s["apps"][app] += 1
            s["secs"].add(t.strftime("%H:%M:%S"))
            if s["first"] is None or t < s["first"]:
                s["first"] = t

    # 同秒出现的其它新域：广告链常在同一秒拉配置 + 落地页
    sec_new = defaultdict(set)
    for dom, s in win.items():
        if base[dom] == 0:
            for sec in s["secs"]:
                sec_new[sec].add(dom)

    bl, wl, force = ds.load_shared(), ds.load_whitelist(), ds.load_force()
    try:
        wl_raw = set(l.strip().lower().rstrip("*") for l in
                     open(ds.WHITELIST_FILE, encoding="utf-8")
                     if l.strip() and not l.startswith("#"))
    except OSError:
        wl_raw = set()

    findings = []
    for dom, s in win.items():
        if SAFE_RE.search(dom):
            continue
        if ds.match_rule(dom, bl, wl, force) is not None:
            continue
        parts = dom.split(".")
        if len(parts) < 2:
            continue
        p2 = ".".join(parts[-2:])
        p3 = ".".join(parts[-3:]) if len(parts) >= 3 else p2
        protected = (p2 in PROTECT_PARENTS or p3 in PROTECT_PARENTS
                     or p2 in KNOWN_PARENTS or p2 in wl_raw)
        label = p2.split(".")[0]
        strange = bool(STRANGE_LABEL.fullmatch(label))

        score = 0
        why = []
        if base[dom] == 0:
            score += 5
            why.append("窗口内首次出现")
        elif s["q"] >= 3 and base[dom] <= 3:
            score += 2
            why.append("历史低频但本窗口突发")
        if s["q"] >= 2:
            score += 1
            why.append("窗口内 %d 次" % s["q"])
        if len(s["clients"]) >= 2:
            score += 1
            why.append("%d 台设备" % len(s["clients"]))
        if any(len(v) >= 2 for sec, v in sec_new.items() if sec in s["secs"]):
            score += 2
            why.append("同秒伴随其它新域")
        if strange:
            score += 4
            why.append("陌生拼音/随机父域")
        # 用户已明确说「这一刻有广告」：窗口内出现的陌生广告 SDK/落地页域，
        # 即使历史上一直放行（如 cf-gl.qiezibenpao.com 放了 33 次），
        # 也应视为漏拦，给足分数让它进自动拦截。
        if strange and AD_HINT.search(dom) and base[dom] > 0:
            score += 4
            why.append("历史长期放行的陌生广告域")
        if AD_HINT.search(dom):
            score += 1
            why.append("广告/SDK 命名特征")
        if score < 4:
            continue
        findings.append({
            "domain": dom, "parent": p2, "score": score,
            "reason": " · ".join(why), "protected": protected,
            "q": s["q"], "clients": len(s["clients"]),
            "apps": dict(s["apps"]), "strange": strange,
            "first": s["first"].strftime("%H:%M:%S") if s["first"] else "-",
            "base": base[dom],
        })
    findings.sort(key=lambda x: (-x["score"], x["domain"]))

    # 只自动拦非保护域、分数 >=6 的；父域下所有窗口域都达标才整域收敛
    before = rule_count()
    by_parent = defaultdict(list)
    for f in findings:
        # 自动拦截必须同时满足：非保护域、陌生父域、域内含广告/SDK 命名
        # 特征、分数 >=8。只靠「首次出现」会误伤 CDN 调度域。
        if (not f["protected"] and f["score"] >= 8 and f["strange"]
                and AD_HINT.search(f["domain"])
                and not SAFE_RE.search(f["domain"])):
            by_parent[f["parent"]].append(f)
    actions = []
    lines = []
    force_lines = []
    try:
        existing = set(l.strip() for l in open(SHARED, encoding="utf-8")
                       if l.strip() and not l.startswith("#"))
    except OSError:
        existing = set()
    for parent, group in by_parent.items():
        # 反馈归因只写精确域：父域整域收敛交给 autodetect 的严格护栏，
        # 一次点击绝不误伤整个业务父域。
        for g in group:
            if ("%s**" % g["domain"]) in existing:
                continue
            lines.append("# feedback:%s %s" %
                         (g["domain"], at.strftime("%Y-%m-%d %H:%M")))
            lines.append("%s**" % g["domain"])
            actions.append({"domain": g["domain"], "score": g["score"],
                            "action": "精确域拦截", "reason": g["reason"]})

    # 保护父域下确凿的高分域写 force（优先级高于白名单）
    for f in findings:
        if (f["protected"] and f["score"] >= 10 and f["strange"]
                and AD_HINT.search(f["domain"])):
            force_lines.append("# feedback:%s %s" %
                               (f["domain"], at.strftime("%Y-%m-%d %H:%M")))
            force_lines.append("%s**" % f["domain"])
            actions.append({"domain": f["domain"], "score": f["score"],
                            "action": "force 强制拦截", "reason": f["reason"]})

    if lines and write:
        with open(SHARED, "a", encoding="utf-8") as fh:
            fh.write("\n# ---- 广告反馈自动归因 %s ----\n" %
                     at.strftime("%Y-%m-%d %H:%M"))
            fh.write("\n".join(lines) + "\n")
    if force_lines and write:
        with open(FORCE, "a", encoding="utf-8") as fh:
            fh.write("\n# ---- 广告反馈 force %s ----\n" %
                     at.strftime("%Y-%m-%d %H:%M"))
            fh.write("\n".join(force_lines) + "\n")

    report = {
        "at": at.strftime("%Y-%m-%d %H:%M"),
        "window": [w0.strftime("%H:%M:%S"), w1.strftime("%H:%M:%S")],
        "allow_in_window": sum(s["q"] for s in win.values()),
        "unique_domains": len(win),
        "findings": findings[:40],
        "actions": actions,
        "rules_before": before,
        "rules_after": rule_count(),
        "skipped_protected": [f["domain"] for f in findings if f["protected"]][:10],
    }
    if write:
        hist = []
        try:
            with open(REPORT, "r", encoding="utf-8") as fh:
                hist = json.load(fh)
        except Exception:
            pass
        hist.append(report)
        tmp = REPORT + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(hist[-50:], fh, ensure_ascii=False, indent=1)
        os.replace(tmp, REPORT)
    log("反馈归因 %s 窗口 %s-%s 放行%d条/%d域 命中%d 自动拦%d 规则%d→%d" %
        (report["at"], report["window"][0], report["window"][1],
         report["allow_in_window"], report["unique_domains"],
         len(findings), len(actions), before, report["rules_after"]))
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--at", default="", help="广告时刻，如 23:07 或 2026-11-09 23:07")
    ap.add_argument("--json", action="store_true", help="stdout 输出 JSON")
    ap.add_argument("--dry-run", action="store_true", help="只归因不写规则")
    a = ap.parse_args()
    at = parse_time(a.at) if a.at else datetime.now()
    r = analyze(at, write=not a.dry_run)
    if a.dry_run:
        r["dry_run"] = True
    if a.json:
        print(json.dumps(r, ensure_ascii=False))
    else:
        print("反馈归因 %s：窗口 %s ~ %s，放行 %d 条 / %d 域" %
              (r["at"], r["window"][0], r["window"][1],
               r["allow_in_window"], r["unique_domains"]))
        for f in r["findings"][:20]:
            print("  [%2d] %-52s %s%s" %
                  (f["score"], f["domain"], f["reason"],
                   "  (保护域，仅报告)" if f["protected"] else ""))
        for x in r["actions"]:
            print("  -> %s  %s" % (x["action"], x["domain"]))
        print("规则 %d -> %d" % (r["rules_before"], r["rules_after"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
