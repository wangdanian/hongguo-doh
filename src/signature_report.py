#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""广告命名特征体检 + 自动归纳。

解决的是「名单更新速度赶不上广告换域名速度」：

  * 体检：把 ad-signatures.txt 里每条特征拿到真实日志回放，报告它拦到
    多少广告域、误伤了多少业务域。业务域 = 从未被拦过、且不含广告语义、
    或落在受保护父域（Apple / 银行 / 支付 / 政务 / 正片 CDN）里的域。
  * 自动归纳：从「已拦域 + 带强广告语义的放行漏网域」里把编号 / 区域码
    泛化成通配，生成能覆盖未来变体的特征。只有对全部业务域 0 命中、
    且至少覆盖 2 个变体的候选才会晋升，每次最多 2 条、每天最多 10 条。
    这样广告方换一个 ads7 / ec9 / v77，不需要人工补任何名单。

用法:
    python3 signature_report.py                 # 只体检，不改文件
    python3 signature_report.py --auto         # 体检 + 自动晋升新特征
    python3 signature_report.py --json         # 机器可读输出
    python3 signature_report.py --days 3       # 回放窗口

部署：本脚本随 src/*.py 一起放到 /opt/hongguo-doh/，规则和日志同目录。
"""
import argparse
import collections
import json
import os
import re
import sys
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
import doh_server as ds  # noqa: E402  复用同一套规则编译 / 匹配语义

LOG_FILE = os.environ.get("DOH_LOG_FILE", os.path.join(BASE_DIR, "doh_log.txt"))
SIG_FILE = os.environ.get("DOH_SIG_FILE", os.path.join(BASE_DIR, "ad-signatures.txt"))
STATE_FILE = os.path.join(BASE_DIR, "signature-state.json")

MAX_PER_RUN = 2
MAX_PER_DAY = 10

# 强广告语义：命中它的放行域视为「历史漏网广告域」，可作为归纳正样本，
# 但不算业务误伤。刻意收窄，避免把 download / upload / head 之类算进来。
AD_SEMANTIC = re.compile(
    r"(reading-ad|ads\d|adx|ad-sign|-ad-|rta\d|mgsdk|deepinstall|"
    r"ecombd|dsp-ad|opinstall|splash|union-click)", re.I)

# 允许自动生成特征时必须出现的强标记。AD_SEMANTIC 只用于判定「是不是
# 广告域」，太宽；晋升规则要更严，避免把 promotion-* 这类通用促销图段
# 归纳成拦截特征。
STRONG_AD = re.compile(
    r"(reading-ad|ads\d+-normal|ad-sign|mgsdk|adx|rta\d|"
    r"ec\d+-core|ecom\d*-normal|isaas\d*-normal|deepinstall|"
    r"opinstall|dsp-ad|-ad-)", re.I)

# 受保护父域：即使名字里带 ad 也算业务，签名命中即判误伤。
# 绝对系统父域：无论名字里有什么字样都不算广告，优先于一切语义判断。
SYSTEM_PARENTS = {
    "apple.com", "aaplimg.com", "icloud.com", "apple-dns.net", "itunes.com",
    "alipay.com", "cmbchina.com", "cmbchina.cn", "bankcomm.com",
    "icbc.com.cn", "ccb.com", "boc.cn", "pbc.gov.cn", "12306.cn",
}

# 确凿的广告命名标记：即使落在共用父域（qznovelvod / byteimg / zijieapi）
# 也判广告域，不能被父域保护机制误当成业务域。
CRITICAL_AD = re.compile(
    r"(reading-ad|ads\d+-normal|ad-sign|rta\d|mgsdk|ec\d+-core|"
    r"ecom\d*-normal|isaas\d*-normal|adx|deepinstall|opinstall|dsp-ad)", re.I)

SAFE_PARENTS = {
    "apple.com", "aaplimg.com", "icloud.com", "apple-dns.net", "itunes.com",
    "amap.com", "autonavi.com", "taobao.com", "tmall.com", "alibaba.com",
    "alibabacorp.com", "alibabadns.com", "aliyun.com", "alipay.com",
    "jd.com", "12306.cn", "ctrip.com", "cmbchina.com", "cmbchina.cn",
    "bankcomm.com", "icbc.com.cn", "ccb.com", "boc.cn", "pbc.gov.cn",
    "qq.com", "wechat.com", "gtimg.cn", "tencent.com", "baidu.com",
    "ks-cdn.com", "ksapisrv.com", "gifshow.com", "douyincdn.com",
    "bytegecko.com", "bytegslb.com", "qznovelvod.com", "douyinvod.com",
    "fqnovel.com", "fqnovelpic.com", "ixigua.com", "wscdns.com",
    "cdngslb.com", "kunluncan.com", "queniucf.com", "tdnsv5.com",
}

# 泛化后的模板至少要含一个广告语义标记，避免生成过宽的业务模式。
NUM = re.compile(r"\d+")


def _parent(dom):
    parts = dom.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else dom


def is_business(dom):
    """True = 业务域，签名命中它即视为误伤。"""
    p2 = _parent(dom)
    for p in SYSTEM_PARENTS:
        if p2 == p or dom.endswith("." + p):
            return True
    if CRITICAL_AD.search(dom):
        return False
    if p2 in SAFE_PARENTS:
        return True
    for p in SAFE_PARENTS:
        if dom.endswith("." + p):
            return True
    return not AD_SEMANTIC.search(dom)


def load_log(days):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    blocked = collections.Counter()
    allowed = collections.Counter()
    try:
        with open(LOG_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                p = line.rstrip("\n").split("\t")
                if len(p) < 5 or p[0] < cutoff:
                    continue
                if p[4] == "BLOCK":
                    blocked[p[2]] += 1
                elif p[4] == "ALLOW":
                    allowed[p[2]] += 1
    except OSError as exc:
        print("日志读取失败: %s" % exc, file=sys.stderr)
    return blocked, allowed


def load_signatures():
    out = []
    try:
        with open(SIG_FILE, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line.lower())
    except OSError:
        pass
    return out


def replay(sigs, blocked, allowed):
    bset = set(blocked)
    only_allow = set(allowed) - bset
    business = {d for d in only_allow if is_business(d)}
    rows = []
    for sig in sigs:
        _, pat = ds._compile_rule(sig)
        if pat is None:
            continue
        hit_b = [d for d in bset if pat.match(d)]
        hit_a = [d for d in only_allow if pat.match(d)]
        collateral = [d for d in hit_a if d in business]
        rows.append({
            "signature": sig,
            "blocked_hits": len(hit_b),
            "allow_hits": len(hit_a),
            "business_collateral": len(collateral),
            "collateral_sample": sorted(collateral)[:5],
            "leak_covered": len(hit_a) - len(collateral),
        })
    return rows, bset, business, only_allow


def _templates(dom):
    """把一个域名里的数字段泛化成 *，产出覆盖编号变体的模板。"""
    out = set()
    parts = dom.lower().split(".")
    for i, seg in enumerate(parts):
        if not NUM.search(seg) or len(seg) > 24:
            continue
        q = list(parts)
        q[i] = NUM.sub("*", seg)
        out.add("**" + ".".join(q) + "**")
    return out


def _load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_state(st):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


def auto_promote(sigs, blocked, business, only_allow):
    """从已拦域 + 漏网广告域归纳新特征，护栏全过才落盘。"""
    today = datetime.now().strftime("%Y-%m-%d")
    st = _load_state()
    if st.get("day") != today:
        st = {"day": today, "promoted": 0}
    if st["promoted"] >= MAX_PER_DAY:
        return [], "已达每日上限 %d 条" % MAX_PER_DAY

    positives = set(blocked)
    # 带强广告语义、且从没被拦过的放行域 = 历史漏网，也参与归纳
    for d in only_allow:
        if d not in business and AD_SEMANTIC.search(d):
            positives.add(d)

    coverage = collections.defaultdict(set)
    for d in positives:
        for t in _templates(d):
            coverage[t].add(d)

    existing = set(sigs)
    existing_pats = [p for _, p in (ds._compile_rule(x) for x in sigs) if p]
    wl = ds.load_whitelist()
    candidates = []
    for tpl, doms in coverage.items():
        if len(doms) < 2 or tpl in existing:
            continue
        if len(tpl) < 14 or not STRONG_AD.search(tpl):
            continue
        # 白名单父域下的签名永远不会生效（白名单优先于特征层），跳过
        parent = ".".join(tpl.strip("*").strip(".").split(".")[-2:])
        if ds._match_any(parent, wl):
            continue
        _, pat = ds._compile_rule(tpl)
        if pat is None:
            continue
        if any(pat.match(d) for d in business):
            continue
        # 只保留「现有特征还没覆盖到」的变体。否则会把已有家族反复
        # 归纳成更窄的冗余规则，白白吃掉每日预算，却带不来新覆盖。
        novel = [d for d in doms if not any(p.match(d) for p in existing_pats)]
        if not novel:
            continue
        candidates.append((len(novel), tpl, sorted(novel)[:4]))
    candidates.sort(reverse=True)

    picked = candidates[:min(MAX_PER_RUN, MAX_PER_DAY - st["promoted"])]
    if not picked:
        return [], "没有通过护栏的候选"
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(SIG_FILE, "a", encoding="utf-8") as fh:
        for n, tpl, sample in picked:
            fh.write("\n# auto:sig:%s novel=%d variants: %s\n"
                     % (stamp, n, ", ".join(sample)))
            fh.write(tpl + "\n")
    st["promoted"] += len(picked)
    _save_state(st)
    return picked, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--auto", action="store_true", help="自动晋升通过护栏的新特征")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--days", type=int, default=7, help="回放窗口天数，默认 7")
    args = ap.parse_args()

    sigs = load_signatures()
    blocked, allowed = load_log(args.days)
    rows, bset, business, only_allow = replay(sigs, blocked, allowed)
    promoted, note = ([], "")
    if args.auto:
        promoted, note = auto_promote(sigs, blocked, business, only_allow)

    result = {
        "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "days": args.days,
        "signatures": len(sigs),
        "blocked_domains": len(bset),
        "business_domains": len(business),
        "rows": rows,
        "total_collateral": sum(r["business_collateral"] for r in rows),
        "promoted": [{"signature": t, "evidence": n, "sample": s}
                     for n, t, s in promoted],
        "note": note,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
        return 0

    print("特征体检 %s | %d 天 | 特征 %d 条 | 已拦域 %d | 业务域 %d"
          % (result["at"], args.days, len(sigs), len(bset), len(business)))
    for r in rows:
        flag = "OK" if not r["business_collateral"] else "!! 误伤 %d" % r["business_collateral"]
        print("  %-50s 已拦=%-4d 补漏=%-4d %s"
              % (r["signature"], r["blocked_hits"], r["leak_covered"], flag))
        for d in r["collateral_sample"]:
            print("       误伤 -> " + d)
    print("业务域误伤合计: %d" % result["total_collateral"])
    if args.auto:
        for n, tpl, _sample in promoted:
            print("晋升: %s (覆盖 %d 个变体)" % (tpl, n))
        if note:
            print("自动归纳: " + note)
    return 1 if result["total_collateral"] else 0


if __name__ == "__main__":
    sys.exit(main())
