#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""广告反馈自动归因（开源版；部署目录可用 HONGGUO_BASE 覆盖）。

用户点「刚刚有广告」→ 回溯该时刻前 6 分钟的放行日志 → 与近 3 天历史基线
比对 → 找出首次出现/突发的陌生域 → 自动写拦截规则 → 返回可审计的报告。

解决 autodetect.py 的结构性盲区：它靠「广告关键词 + 高频 + 多设备」打分，
像 cf-gl.qiezibenpao.com / sdkgen.data.tianwenca.com 这种纯拼音随机父域
一个关键词都没有，永远进不了候选队列（2026-11-09 23:07 实证：64 次查询、
5 台设备、从凌晨放行到晚上）。用户的一次点击就是最高置信信号。

--auto（2026-11-09 23:50 起，cron 每 5 分钟）把这个闭环变成无人值守：
不再依赖用户报时刻，自动扫最近 6 分钟放行的陌生广告域并写精确域规则。
护栏：流式读日志、窗口内 >=2 次、分数 >=8、陌生父域 + 广告命名特征、
大厂/白名单父域分流到 force、金融与品牌业务域直接跳过、
同一品牌下历史子域 >=5 且查询 >=20 视为业务父域（不自动拦）、
每次最多 2 条、每天最多 20 条、只写精确域且规则行带
# feedback: 标签可整段回滚。
2026-11-10 00:20 实证护栏漏洞：招商银行 jump.m.cmbchina.cn/.com
被「纯字母随机父域 + jump 命名」误判为广告并自动拦截，已整段回滚。
2026-11-09 23:43 实证漏点 lf3-ad.searchpstatp.com（11-06 出现过 2 次、
23:41:46 又预取 2 次，低频历史广告域自动发现永远抓不到）。
2026-11-10 00:35 实证盲区：*-reading-ad.qznovelvod.com 已被拦，但归因只读
放行日志，报告里只剩 CDN 调度域、0 动作。现改为反向块读 doh_log.txt 取
窗口内 BLOCK 事件，命中广告规则即记为「广告触发」，并把触发前后 5 秒放行
的域列为伴随的容器/素材通道（只报告、不自动拦，避免误伤共用 CDN）。

安全护栏：白名单/保护父域/已拦域/业务 CDN 域一律跳过；只写精确域或
确认整域都是新域的父域；规则行带 #feedback: 标签，可整段 grep 回滚。
"""
import argparse
import contextlib
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
AUTO_LOG = os.path.join(BASE, "auto-feedback.log")
DOH_LOG = os.path.join(BASE, "doh_log.txt")

# 拦截日志里的「广告触发」信号：命中这些规则的域说明客户端刚刚请求过广告。
# 2026-11-10 00:35 实证：*-reading-ad.qznovelvod.com 已被拦，但归因只读放行
# 日志，完全看不到这次触发，报告里只有 CDN 调度域、0 动作，用户只能继续报时刻。
AD_TRIGGER_RE = re.compile(
    r"(reading-ad|ad-sign|ecom|rta\d|promo|landing|splash|adview|mgsdk|"
    r"dailygn|qiezibenpao|tianwenca|searchpstatp|opinstall|deepinstall|"
    r"-ad\.|ads\d|adx|union|click|jump)", re.I)

# 广告容器/素材下发通道的命名特征，只用于报告里排序，不用于自动拦截。
COMPANION_RE = re.compile(
    r"(sourcecdn|-dl|download|material|creative|splash|config|zip|pkg|res|"
    r"(?:^|[.-])sdk(?:[.-]|$))", re.I)

# 业务 / 视频 / 系统域：这些不可能是「新广告落地页」，先排掉，
# 避免把正片 CDN、苹果推送、DNS 调度误判成广告。
SAFE_RE = re.compile(
    r"(douyin|byte|volc|zijie|snssdk|amemv|ixigua|qznovel|fqnovel|queniu|"
    r"ksyun|ks-cdn|cdnhwc|cdngslb|bsgslb|akadns|alibaba|alikunlun|aliyun|"
    r"amap|autonavi|taobao|alicdn|jd\.com|pinduoduo|yangkeduo|bilibili|"
    r"netease|163\.com|qq\.com|weixin|wechat|tencent|baidu|bdurl|sogou|"
    r"kuaishou|apple|icloud|mzstatic|itunes|microsoft|google|gstatic|"
    r"getui|umeng|sensorsdata|gslb|cdn|tos|vod|hls|flv|live|pull|push|"
    r"download|upload|static|image|img|pic|music|login|pay|api|log|report|"
    r"cmbchina|icbc|ccb\.com|abchina|boc\.cn|bankcomm|psbc|pingan|"
    r"unionpay|alipay|tenpay|bank|meituan|dianping|ctrip|12306|"
    r"gov\.cn|edu\.cn|xiaomi|huawei|oppo|vivo)",
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


def log(msg, path=None):
    line = "[%s] %s" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with open(path or LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    # 无人值守模式只落文件，避免 cron 重定向后同一行日志写两遍
    if path != AUTO_LOG:
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


def iter_logs():
    """流式产出 (时间字符串, client, domain, app)，只取最近 5 天的 ok.tsv。

    必须流式：5 天日志约 83MB，全量读进 list 峰值内存 330MB，
    无人值守每 5 分钟跑一次会把小内存 ECS 拖垮。
    时间保留原始字符串：基线只做字典序比较，窗口内才 strptime，
    避免每行都做一次日期解析（实测 9.5s -> 约 2s）。
    """
    files = []
    now = datetime.now()
    for i in range(5):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        files.extend(sorted(glob.glob(os.path.join(WATCH, "*", day + "-ok.tsv"))))
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    p = line.rstrip("\n").split("\t")
                    if len(p) < 4:
                        continue
                    yield (p[0], p[1], p[2].lower().rstrip("."),
                           p[6] if len(p) > 6 else "other")
        except OSError:
            continue


def read_logs():
    """兼容旧调用；新代码请用 iter_logs()。"""
    return list(iter_logs())


def iter_block_events(w0s, w1s):
    """反向块读 doh_log.txt，产出窗口内被拦的 (时间串, 域, 命中规则)。

    doh_log.txt 约 90MB，每 5 分钟正向全读一遍不划算。按 1MB 从文件尾部
    反向读，一旦某块的时间戳已早于窗口起点就停止，实测只读 2~5MB。
    """
    try:
        size = os.path.getsize(DOH_LOG)
    except OSError:
        return
    chunk = 1024 * 1024
    pos = size
    carry = b""
    seen = set()
    with open(DOH_LOG, "rb") as fh:
        while pos > 0:
            start = max(0, pos - chunk)
            fh.seek(start)
            buf = fh.read(pos - start)
            pos = start
            data = buf + carry
            lines = data.split(b"\n")
            carry = lines[0]          # 跨块残行，与上一块拼接
            for raw in reversed(lines[1:]):
                line = raw.decode("utf-8", "replace").rstrip("\r")
                if not line:
                    continue
                p = line.split("\t")
                if len(p) < 5:
                    continue
                ts = p[0]
                if ts > w1s:
                    continue
                if ts < w0s:
                    return          # 时间倒序，已经越过窗口起点
                if p[4] != "BLOCK":
                    continue
                key = (ts, p[2], p[6] if len(p) > 6 else "")
                if key in seen:
                    continue
                seen.add(key)
                yield (ts, p[2].lower().rstrip("."), key[2])
    for raw in [carry]:
        line = raw.decode("utf-8", "replace").rstrip("\r")
        p = line.split("\t")
        if len(p) >= 5 and w0s <= p[0] <= w1s and p[4] == "BLOCK":
            yield (p[0], p[2].lower().rstrip("."), p[6] if len(p) > 6 else "")


def rule_count():
    try:
        return sum(1 for l in open(SHARED, encoding="utf-8")
                   if l.strip() and not l.lstrip().startswith("#"))
    except OSError:
        return 0


def analyze(at, write=True, auto=False):
    w0 = at - timedelta(minutes=6)
    w1 = at + timedelta(minutes=1)

    win = defaultdict(lambda: {"q": 0, "clients": set(), "apps": Counter(),
                               "secs": set(), "first": None})
    base = Counter()
    w0s = w0.strftime("%Y-%m-%d %H:%M:%S")
    w1s = w1.strftime("%Y-%m-%d %H:%M:%S")
    for ts, cli, dom, app in iter_logs():
        if ts < w0s:
            base[dom] += 1
            continue
        if ts > w1s:
            continue
        t = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        s = win[dom]
        s["q"] += 1
        s["clients"].add(cli)
        s["apps"][app] += 1
        s["secs"].add(ts[11:])
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

    # 业务父域护栏：同一二级域标签下历史上有成体系的子域和查询量，
    # 说明是银行/电商/政企的业务系统，不是独立广告落地父域。
    # 2026-11-10 00:20 实证：招商银行 jump.m.cmbchina.* 被当成随机父域误拦，
    # 同批还有 20+ 个 paas.cmbchina.com 业务子域；自动闭环已回滚并加此护栏。
    brand_q = Counter()
    brand_domains = defaultdict(set)
    for dom, cnt in base.items():
        parts = dom.split(".")
        if len(parts) >= 2:
            b = parts[-2].lower()
            brand_q[b] += cnt
            brand_domains[b].add(dom)

    def busy_brand(dom):
        parts = dom.split(".")
        if len(parts) < 2:
            return False
        b = parts[-2].lower()
        return len(brand_domains[b]) >= 5 and brand_q[b] >= 20

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
        # 白名单是按父域整域放行的；命中白名单的域写普通黑名单会被架空，
        # 必须改走 force-block.txt。用 doh_server 自己的匹配函数判断，
        # 比只比对 p2 精确父域名更可靠（optimus-ads.amap.com 这种）。
        try:
            whitelisted = bool(ds._match_any(dom, wl))
        except Exception:
            whitelisted = False
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
            "whitelisted": whitelisted,
            "q": s["q"], "clients": len(s["clients"]),
            "apps": dict(s["apps"]), "strange": strange,
            "first": s["first"].strftime("%H:%M:%S") if s["first"] else "-",
            "base": base[dom],
        })
    findings.sort(key=lambda x: (-x["score"], x["domain"]))

    # ---- 广告触发信号：拦截日志里「客户端刚刚请求过广告」 ----
    # 只读放行日志时，广告域被拦掉后归因窗口里剩下的全是 CDN 调度域，
    # 分数全低、0 动作，系统看起来像没干活。这里把已拦的广告请求当成
    # 最高置信信号，并把触发前后 5 秒放行的域列成「容器/素材通道」。
    block_rows = list(iter_block_events(w0s, w1s))
    triggers = []
    seen_trig = set()
    for ts, dom, rule in block_rows:
        if not (AD_TRIGGER_RE.search(dom) or AD_TRIGGER_RE.search(rule)):
            continue
        # A / AAAA / HTTPS 三条查询是同一次广告请求，按 (秒, 域) 去重，
        # 否则「广告触发次数」会被放大三倍。
        if (ts, dom) in seen_trig:
            continue
        seen_trig.add((ts, dom))
        triggers.append((ts, dom, rule))
    trig_secs = []
    for ts, _, _ in triggers:
        h, m, s = (int(x) for x in ts[11:].split(":"))
        trig_secs.append(h * 3600 + m * 60 + s)

    def near_ad(sec):
        h, m, s = (int(x) for x in sec.split(":"))
        v = h * 3600 + m * 60 + s
        return any(abs(v - t) <= 5 for t in trig_secs)

    # 伴随域大多与正片共用 CDN（sourcecdn / 字节系 CDN / GSLB），
    # 自动拦会白屏，所以只报告、绝不自动写规则。
    companions = []
    if trig_secs:
        for dom, s in win.items():
            hits = [sec for sec in s["secs"] if near_ad(sec)]
            if not hits:
                continue
            parts = dom.split(".")
            if len(parts) < 2:
                continue
            p2 = ".".join(parts[-2:])
            companions.append({
                "domain": dom, "q": s["q"], "at": sorted(hits)[0],
                "base": base[dom],
                "material_hint": bool(COMPANION_RE.search(dom)),
                "shared_cdn": bool(SAFE_RE.search(dom)) or p2 in KNOWN_PARENTS,
                "blocked": ds.match_rule(dom, bl, wl, force) is not None,
            })
        companions.sort(key=lambda x: (not x["material_hint"], x["shared_cdn"],
                                      x["blocked"], -x["q"], x["domain"]))
        companions = companions[:25]

    # 只自动拦非保护域、分数 >=6 的；父域下所有窗口域都达标才整域收敛
    before = rule_count()
    by_parent = defaultdict(list)
    for f in findings:
        # 自动拦截必须同时满足：陌生父域、域内含广告/SDK 命名特征、分数 >=8，
        # 且不是被保护的大厂父域。白名单命中的域仍要处理，但改走 force。
        # 无人值守模式额外要求窗口内 >=2 次，避免偶发单条误伤。
        if auto and f["q"] < 2:
            continue
        if ((not f["protected"] or f["whitelisted"]) and f["score"] >= 8
                and f["strange"] and AD_HINT.search(f["domain"])
                and not SAFE_RE.search(f["domain"])
                and not busy_brand(f["domain"])):
            by_parent[f["parent"]].append(f)
    actions = []
    lines = []
    force_lines = []
    try:
        existing = set(l.strip() for l in open(SHARED, encoding="utf-8")
                       if l.strip() and not l.startswith("#"))
    except OSError:
        existing = set()
    try:
        force_existing = set(l.strip() for l in open(FORCE, encoding="utf-8")
                             if l.strip() and not l.startswith("#"))
    except OSError:
        force_existing = set()
    done = set()
    for parent, group in by_parent.items():
        # 反馈归因只写精确域：父域整域收敛交给 autodetect 的严格护栏，
        # 一次点击绝不误伤整个业务父域。
        for g in group:
            rule = "%s**" % g["domain"]
            if rule in existing or rule in force_existing:
                continue
            # 无人值守每次最多 2 条，配合每日上限，控制误伤扩散范围
            if auto and len(actions) >= 2:
                break
            tag = "# feedback:%s %s" % (
                g["domain"], at.strftime("%Y-%m-%d %H:%M"))
            if g["whitelisted"]:
                force_lines.append(tag)
                force_lines.append(rule)
                actions.append({"domain": g["domain"], "score": g["score"],
                                "action": "force 强制拦截（白名单父域）",
                                "reason": g["reason"]})
            else:
                lines.append(tag)
                lines.append(rule)
                actions.append({"domain": g["domain"], "score": g["score"],
                                "action": "精确域拦截", "reason": g["reason"]})
            done.add(g["domain"])

    # 保护父域下确凿的高分域写 force（优先级高于白名单）
    for f in findings:
        rule = "%s**" % f["domain"]
        if (f["protected"] and f["score"] >= 10 and f["strange"]
                and AD_HINT.search(f["domain"])
                and not SAFE_RE.search(f["domain"])
                and not busy_brand(f["domain"])
                and f["domain"] not in done
                and rule not in force_existing and rule not in existing):
            if auto and len(actions) >= 2:
                break
            force_lines.append("# feedback:%s %s" %
                               (f["domain"], at.strftime("%Y-%m-%d %H:%M")))
            force_lines.append(rule)
            actions.append({"domain": f["domain"], "score": f["score"],
                            "action": "force 强制拦截", "reason": f["reason"]})
            done.add(f["domain"])

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
        "blocked_in_window": len(block_rows),
        "ad_triggers": len(triggers),
        "ad_trigger_domains": sorted({d for _, d, _ in triggers})[:12],
        "companions": companions,
        "rules_before": before,
        "rules_after": rule_count(),
        "auto": auto,
        "skipped_protected": [f["domain"] for f in findings if f["protected"]][:10],
    }
    # 无人值守每 5 分钟一次，不写历史报告（避免文件无限膨胀），
    # 只留日志与规则行里的 # feedback: 标签，随时可整段回滚。
    if write and not auto:
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
    log("%s反馈归因 %s 窗口 %s-%s 放行%d条/%d域 拦截%d 广告触发%d "
        "伴随域%d 命中%d 自动拦%d 规则%d→%d" %
        ("[auto] " if auto else "", report["at"], report["window"][0],
         report["window"][1], report["allow_in_window"],
         report["unique_domains"], len(block_rows), len(triggers),
         len(companions), len(findings), len(actions),
         before, report["rules_after"]), AUTO_LOG if auto else LOG)
    return report


AUTO_COUNT_FILE = os.path.join(BASE, "auto-feedback-count.json")
AUTO_DAILY_LIMIT = 20


def auto_budget():
    """无人值守每日自动拦截上限；返回 (今天已用, 计数文件当前内容)。"""
    today = datetime.now().strftime("%Y-%m-%d")
    try:
        with open(AUTO_COUNT_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        data = {}
    return int(data.get(today, 0)), {today: int(data.get(today, 0))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--at", default="", help="广告时刻，如 23:07 或 2026-11-09 23:07")
    ap.add_argument("--json", action="store_true", help="stdout 输出 JSON")
    ap.add_argument("--dry-run", action="store_true", help="只归因不写规则")
    ap.add_argument("--auto", action="store_true",
                    help="无人值守模式：扫最近 6 分钟，自动拦确凿广告域；"
                         "每次最多 2 条、每天最多 %d 条" % AUTO_DAILY_LIMIT)
    a = ap.parse_args()
    if a.auto:
        used, counter = auto_budget()
        if used >= AUTO_DAILY_LIMIT:
            print("[auto] 今日自动拦截已达上限 %d，跳过" % AUTO_DAILY_LIMIT)
            return 0
        # doh_server 热加载规则时会 print 到 stdout，重定向掉，
        # 保证 --json 纯净、cron 日志不重复
        with contextlib.redirect_stdout(sys.stderr):
            r = analyze(datetime.now(), write=not a.dry_run, auto=True)
        if a.dry_run:
            r["dry_run"] = True
        if r["actions"] and not a.dry_run:
            counter[datetime.now().strftime("%Y-%m-%d")] = used + len(r["actions"])
            tmp = AUTO_COUNT_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(counter, fh)
            os.replace(tmp, AUTO_COUNT_FILE)
        if a.json:
            print(json.dumps(r, ensure_ascii=False))
        return 0
    at = parse_time(a.at) if a.at else datetime.now()
    with contextlib.redirect_stdout(sys.stderr):
        r = analyze(at, write=not a.dry_run)
    if a.dry_run:
        r["dry_run"] = True
    if a.json:
        print(json.dumps(r, ensure_ascii=False))
    else:
        print("反馈归因 %s：窗口 %s ~ %s，放行 %d 条 / %d 域" %
              (r["at"], r["window"][0], r["window"][1],
               r["allow_in_window"], r["unique_domains"]))
        print("拦截 %d 条，其中广告触发 %d 次（%s）" %
              (r["blocked_in_window"], r["ad_triggers"],
               ", ".join(r["ad_trigger_domains"][:5]) or "无"))
        if r["companions"]:
            print("广告触发前后放行的素材/容器通道（仅报告，不自动拦）：")
            for c in r["companions"][:10]:
                print("  %-52s %s 次  基线%d  %s%s" %
                      (c["domain"], c["q"], c["base"],
                       "素材特征 " if c["material_hint"] else "",
                       "与正片共用CDN" if c["shared_cdn"] else ""))
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
