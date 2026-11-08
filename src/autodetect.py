#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
广告自动发现引擎（autodetect.py）
=================================
让服务器自己从真实 DNS 日志里发现新广告域，不再靠人盯。

数据源（三层信号）：
  1) 公开拦截名单：anti-AD（中文生态最全）/ oisd-small / AdGuard DNS Filter
     每 24h 拉一次，缓存在 public-blocklists/。
  2) 字节系广告指纹：-aw-（AdWorks）、穿山甲 pangolin、pglstatp、mssdk
     —— 这些是字节广告 SDK 的固定命名特征。
  3) 行为统计：广告关键词命中 + 多设备 + 多天 + 突增 + 同父域子域轮换。

动作分级：
  A 级 → 自动拦截：命中公开名单或字节系指纹的、当前没被任何规则覆盖的域，
         直接追加到 blacklist-shared.txt（带 #auto: 标签，服务器 mtime 热加载）。
  B 级 → 进候选队列 autodetect-candidates.json，
         在 /candidates 页面一键「拦截 / 放行」。

安全护栏：
  * 白名单父域命中的域 → 永不处理（淘宝 H5 那次的教训）；
  * 已被现有规则覆盖 → 跳过；
  * 每次运行自动拦截上限 MAX_AUTO 条，防止名单雪崩；
  * 全部动作打日志，#auto: 标签可 grep 回滚。

跑法：cron 每 30 分钟（见 crontab），flock 防并发。
"""
import json
import os
import re
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta

BASE = "/opt/hongguo-doh"
sys.path.insert(0, BASE)
import doh_server as ds  # noqa: E402  复用同一套规则匹配语义（main 有保护，import 安全）

WATCH_DIR = os.path.join(BASE, "watch", "apps")
SHARED_FILE = os.path.join(BASE, "blacklist-shared.txt")
WHITELIST_FILE = os.path.join(BASE, "whitelist.txt")
BLACKLIST_FILE = os.path.join(BASE, "blacklist.txt")
STATE_FILE = os.path.join(BASE, "autodetect-state.json")
CAND_FILE = os.path.join(BASE, "autodetect-candidates.json")
PUB_DIR = os.path.join(BASE, "public-blocklists")

PUBLIC_SOURCES = [
    ("anti-ad", "https://anti-ad.net/domains.txt"),
    ("oisd-small", "https://small.oisd.nl/domainswild"),
    ("adguard-dns", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
]

MAX_AUTO = 40          # 每次运行自动拦截上限
MAX_CAND = 30          # 候选队列上限
DAYS_WINDOW = 3        # 只看最近 3 天的日志
PUBLIC_TTL = 86400     # 公开名单每 24h 刷新
PUB_VER = 2            # 解析器版本：改动解析逻辑时 +1，让旧缓存自动失效
LAUNCH_GAP = 600       # 同一 App 两次查询间隔 >10 分钟视为冷启动
LAUNCH_WINDOW = 8      # 冷启动后 8 秒内的请求算「启动期突发」

# 保护父域：公开名单对这些大厂域的「整域级收录」不可信（曾把
# api.unipay.qq.com 当 qq.com 广告拦掉）。命中这些父域的域一律
# 降级为候选人工裁决，绝不自动拦截。
PROTECT_PARENTS = {
    "qq.com", "qq.com.cn", "tencent.com", "tencent-cloud.net", "aliyuncs.com",
    "amazonaws.com", "baidu.com", "sogou.com", "kuaishou.com",
    "aliyun.com", "cloudflare.com", "microsoft.com", "apple.com",
}

# 保护父域里「确凿的广告子域」：这些是广点通/百度联盟 SDK 本体，
# 拦掉等于让 App 拉不到开屏素材（正是要的效果），不误伤登录/支付等主功能。
PROTECTED_AD_RE = re.compile(
    r"(?:^|\.)(?:gdt\.qq\.com|e\.qq\.com|rqd\.qq\.com|afd(?:conf)?\.baidu\.com)$")

# 字节系广告指纹：命中即 A 级
BYTEDANCE_AD_RE = re.compile(
    r"(?:-aw-|-ad-sign|-mgsdk-sign|-vodad-|(?:^|\.)[^.]*pangolin[^.]*\.|(?:^|\.)[^.]*pg[l]?statp[^.]*\."
    r"|(?:^|\.)mssdk[^.]*\.|\.pangolin-sdk-toutiao)")

# 电商广告指纹：短视频/短剧里的「卖东西 + 8 秒倒计时」插屏广告。
# 广告视频域被拦后，容器仍从字节电商 API 拉商品卡数据、从 ecombdimg 拉
# 商品图渲染出广告界面。2026-11-08 22:55:03（广告起后整 8 秒）实证。
# 这类父域不会被 PROTECT_PARENTS 降级，命中即 A 级自动拦截。
ECOM_AD_RE = re.compile(
    r"(?:^|\.)(?:ecombdapi|ecombdimg|ecomapi|ecombd)\.com(?:\.|$)")

# 巨量引擎广告线索组件（信息流广告的留资/咨询/落地页入口）。
# bytecdn.com 是字节主 CDN，只按 leads 标签精确匹配，不碰其它子域。
LEADS_AD_RE = re.compile(r"(?:^|\.)[^.]*leads[^.]*\.bytecdn\.com(?:\.|$)")

# 广告关键词（按 label 边界匹配，避免 log 误伤 login/catalog）
STRONG_TOKENS = {"ad", "ads", "adv", "adx", "adsci", "adsdk", "adscience",
                 "banner", "promo", "monetize", "applog", "slardar",
                 "pangolin", "telemetry", "tracker", "adview", "admob",
                 "vodad", "splash", "launchad", "openad", "bootad",
                 "screenad", "adopen", "gdt"}
WEAK_TOKENS = {"stat", "track", "collect", "sdk", "mon", "tnc", "metrics",
               "report", "event", "click", "push-ad", "adsys", "log-collect",
               "download"}
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def log(msg):
    print("[%s] %s" % (datetime.now().strftime("%m-%d %H:%M:%S"), msg), flush=True)


# ---------------------------------------------------------------- 状态
def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {"first_seen": {}, "public_date": "", "history": {}}


def save_state(st):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, ensure_ascii=False)
    os.replace(tmp, STATE_FILE)


# ---------------------------------------------------------------- 公开名单
def refresh_public_lists(st):
    """每 24h 刷新公开拦截名单，解析成域名集合。

    缓存带解析器版本号：解析逻辑一改（PUB_VER+1），旧缓存立即失效，
    直接重新解析本地已下载的 .txt，不必重新走网络。
    """
    os.makedirs(PUB_DIR, exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    cache = os.path.join(PUB_DIR, ".cache.json")
    if st.get("public_date") == today and st.get("public_ver") == PUB_VER:
        try:
            with open(cache, "r", encoding="utf-8") as fh:
                c = json.load(fh)
            if c.get("ver") == PUB_VER:
                return set(c["domains"])
        except Exception:
            pass
    domains = set()
    for name, url in PUBLIC_SOURCES:
        path = os.path.join(PUB_DIR, name + ".txt")
        stale = (not os.path.exists(path) or
                 time.time() - os.path.getmtime(path) > PUBLIC_TTL)
        if stale:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "hongguo-autodetect/1.0"})
                t0 = time.time()
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read()
                with open(path, "wb") as fh:
                    fh.write(data)
                log("public list %-12s downloaded %6.1fs" % (name, time.time() - t0))
            except Exception as e:
                log("[warn] %s 下载失败: %s（沿用旧文件）" % (name, e))
        try:
            n = parse_public_file(path, domains)
            log("public list %-12s %6d domains (累计 %d)" % (name, n, len(domains)))
        except OSError:
            log("[warn] %s 本地文件缺失且下载失败" % name)
    with open(cache, "w", encoding="utf-8") as fh:
        json.dump({"ver": PUB_VER, "domains": sorted(domains)}, fh)
    st["public_date"] = today
    st["public_ver"] = PUB_VER
    return domains


def parse_public_file(path, out):
    """解析名单行 → 域名集合。

    严格按 adblock 语法取域：
      ||domain^        -> domain
      *.sub.domain     -> sub.domain（通配必须占完整标签）
      ad-host-*.x.com  -> 丢弃（* 在标签中间，绝不能截取出 x.com 整域！）
      plain.domain     -> domain
    """
    n0 = len(out)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip().lower()
            if not line or line[0] in "!#@<" or line.startswith("@@"):
                continue
            m = re.search(r"\|\|([a-z0-9.*-]+?)\^", line)
            token = m.group(1) if m else line
            # 去掉 adblock 修饰符尾巴（$third-party 等）
            token = token.split("$")[0].strip(".")
            if not token or len(token) > 253:
                continue
            parts = token.split(".")
            if any(p == "*" for p in parts):
                star_at = parts.index("*")
                if star_at == 0 and len(parts) >= 3:
                    token = ".".join(parts[1:])   # *.ads.foo.com -> ads.foo.com
                else:
                    continue                       # * 夹在中间 → 整条丢弃
            if DOMAIN_RE.match(token):
                out.add(token)
    return len(out) - n0


def public_match(domain, pubset):
    """domain 或其任意父域在公开名单里"""
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in pubset:
            return ".".join(parts[i:])
    return None


# ---------------------------------------------------------------- 日志收集
def collect_recent():
    """扫 watch/apps/<App>/ 最近 N 天的 tsv，聚合每个域名的统计"""
    since = (datetime.now() - timedelta(days=DAYS_WINDOW)).strftime("%Y-%m-%d")
    stats = {}  # domain -> {"q":n, "clients":set, "apps":{app:n}, "last":ts}
    if not os.path.isdir(WATCH_DIR):
        return stats
    for app in os.listdir(WATCH_DIR):
        adir = os.path.join(WATCH_DIR, app)
        if not os.path.isdir(adir):
            continue
        for fn in os.listdir(adir):
            if not fn.endswith("-ok.tsv") or fn[:10] < since:
                continue
            try:
                with open(os.path.join(adir, fn), "r", encoding="utf-8",
                          errors="replace") as fh:
                    for line in fh:
                        f = line.rstrip("\n").split("\t")
                        if len(f) < 4:
                            continue
                        dom = f[2].lower().strip(".")
                        if not DOMAIN_RE.match(dom) or len(dom) > 253:
                            continue
                        s = stats.get(dom)
                        if s is None:
                            s = stats[dom] = {"q": 0, "clients": set(),
                                              "apps": defaultdict(int), "last": ""}
                        s["q"] += 1
                        s["clients"].add(f[1])
                        s["apps"][app] += 1
                        if f[0] > s["last"]:
                            s["last"] = f[0]
            except OSError:
                continue
    return stats


def collect_launch_bursts():
    """启动期突发检测：找「其他 App 的开屏广告」。

    开屏广告的典型节奏 = App 冷启动后的头几秒，一批广告域集中解析
    （拉取素材/上报曝光），之后不再出现。DNS 只有域名没有 PID，但可以按
    (设备, App) 的查询时间序列还原冷启动：间隔 >LAUNCH_GAP 秒视为新会话，
    会话前 LAUNCH_WINDOW 秒内的域名即为「启动期突发」。
    """
    since = (datetime.now() - timedelta(days=DAYS_WINDOW)).strftime("%Y-%m-%d")
    seq = defaultdict(list)  # (ip, app) -> [(epoch, domain)]
    if not os.path.isdir(WATCH_DIR):
        return set()
    for app in os.listdir(WATCH_DIR):
        adir = os.path.join(WATCH_DIR, app)
        if not os.path.isdir(adir):
            continue
        for fn in os.listdir(adir):
            if not fn.endswith("-ok.tsv") or fn[:10] < since:
                continue
            try:
                with open(os.path.join(adir, fn), "r", encoding="utf-8",
                          errors="replace") as fh:
                    for line in fh:
                        f = line.rstrip("\n").split("\t")
                        if len(f) < 4:
                            continue
                        dom = f[2].lower().strip(".")
                        if not DOMAIN_RE.match(dom):
                            continue
                        try:
                            ep = time.mktime(time.strptime(f[0][:19], "%Y-%m-%d %H:%M:%S"))
                        except ValueError:
                            continue
                        seq[(f[1], app)].append((ep, dom))
            except OSError:
                continue
    bursts = set()
    for rows in seq.values():
        rows.sort()
        t0 = prev = None
        for ep, dom in rows:
            if prev is None or ep - prev > LAUNCH_GAP:
                t0 = ep
            if t0 is not None and ep - t0 <= LAUNCH_WINDOW:
                bursts.add(dom)
            prev = ep
    return bursts


# ------------------------------------------------ DGA 随机子域自动收敛
# 广告/追踪域常用「每次生成新随机子域」规避名单。jspcdn.cn 是实例：
# 公开名单穷举了 46 个旧串，客户端换一个串就漏（2026-11-08 22:54:56
# 同一秒旧串被拦、新串放行）。当某父域被公开名单多次收录、且已拦下的
# 子域全是高随机串时，自动升级成整域规则，一次性堵死后续所有轮换。
#
# 规则格式坑：父域** 只匹配「以父域开头」的串，而随机子域是 xxx.父域，
# 必须再写 **.父域** 才覆盖得住（已实测验证）。
NO_COLLAPSE = {
    # 业务大域：即便出现随机子域也绝不整域拦，否则废掉正片/登录/支付
    "zijieapi.com", "fqnovel.com", "fqnovelpic.com", "amemv.com",
    "snssdk.com", "qznovelvod.com", "douyinvod.com", "idouyinvod.com",
    "douyinpic.com", "byteimg.com", "douyinstatic.com", "volcgtm.com",
    "bytefcdn.com", "douyincdn.com", "douyinliving.com", "bytedance.com",
    "ecombdapi.com", "amap.com", "bdstatic.com", "bdimg.com",
    "taobao.com", "tmall.com", "jd.com", "163.com", "126.net",
}


def _random_label(label):
    """高随机串：长度>=12、无连字符、元音占比<12%（或纯十六进制）"""
    if len(label) < 12 or not re.fullmatch(r"[a-z0-9]+", label):
        return False
    if re.fullmatch(r"[0-9a-f]{12,}", label):
        return True
    return sum(label.count(c) for c in "aeiou") / len(label) < 0.12


def collapse_dga_parents(stats):
    """把「公开名单反复收录 + 全是随机子域」的父域升级为整域规则"""
    try:
        lines = open(SHARED_FILE, encoding="utf-8").read().splitlines()
    except OSError:
        return []
    existing = set(l.strip() for l in lines
                   if l.strip() and not l.startswith("#"))
    try:
        with open(WHITELIST_FILE, encoding="utf-8") as fh:
            wl_raw = set(l.strip().lower().rstrip("*") for l in fh
                         if l.strip() and not l.startswith("#"))
    except OSError:
        wl_raw = set()

    pub_hits = defaultdict(int)
    for line in lines:
        m = re.match(r"#\s*auto:public:(\S+)", line.strip())
        if m:
            pub_hits[m.group(1)] += 1

    rand_by_parent = defaultdict(set)
    for rule in existing:
        bare = rule.rstrip("*").rstrip(".")
        parts = bare.split(".")
        if len(parts) < 3 or not _random_label(parts[0]):
            continue
        rand_by_parent[".".join(parts[-2:])].add(parts[0])

    active_parents = set(".".join(d.split(".")[-2:]) for d in stats)

    new_rules = []
    for parent, labels in rand_by_parent.items():
        if len(labels) < 3 or pub_hits.get(parent, 0) < 3:
            continue
        if parent in NO_COLLAPSE or parent in PROTECT_PARENTS or parent in wl_raw:
            continue
        if parent not in active_parents or ("**.%s**" % parent) in existing:
            continue
        new_rules.append(parent)

    if new_rules:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        with open(SHARED_FILE, "a", encoding="utf-8") as fh:
            fh.write("\n# ---- DGA 随机子域自动收敛 %s ----\n" % stamp)
            for parent in new_rules:
                fh.write("# auto:dga:%s 随机子域%d个/公开名单%d次 %s\n"
                         % (parent, len(rand_by_parent[parent]),
                            pub_hits.get(parent, 0), stamp))
                fh.write("%s**\n**.%s**\n" % (parent, parent))
        log("DGA 整域收敛 %d 个：%s" % (len(new_rules), ", ".join(new_rules)))
    return new_rules


def _dga_word(label):
    """DGA 词：纯小写字母、12-48 长、元音占比 <25%。
    jspcdn.cn / dy.zzcdnx.com 家族的 vuq...nnbqq / bbbhvhkkhvqb 都落在这里；
    IPv6 编码(240e09...)、内容哈希(7a9e2f79)、CDN 标签(pull-flv-l11-caster)、
    词典词(coelacanth) 全部排除，避免把 CDN 调度域误收敛。"""
    if not (12 <= len(label) <= 48) or not re.fullmatch(r"[a-z]+", label):
        return False
    return sum(label.count(c) for c in "aeiou") / len(label) < 0.25


def collapse_new_dga_parents(stats):
    """发现公开名单尚未收录的「新马甲 DGA 父域」（行为型收敛）。

    collapse_dga_parents 只能把「已有 >=3 条精确规则 + 公开名单多次收录」
    的父域升级为整域，对新注册的马甲域无能为力——2026-11-08 的
    dy.zzcdnx.com 就是这么漏的：14 次全放行，公开名单零收录。
    这里改为直接看近 3 天真实查询日志：同一父域下出现 >=3 个不同
    高随机字母子域、父域总域数 <=40 且随机占比 >=80%，即判定为
    轮换域并一次写死整域两条规则。护栏沿用同一套白名单/业务大域。
    """
    try:
        lines = open(SHARED_FILE, encoding="utf-8").read().splitlines()
    except OSError:
        return []
    existing = set(l.strip() for l in lines
                   if l.strip() and not l.startswith("#"))
    try:
        with open(WHITELIST_FILE, encoding="utf-8") as fh:
            wl_raw = set(l.strip().lower().rstrip("*") for l in fh
                         if l.strip() and not l.startswith("#"))
    except OSError:
        wl_raw = set()

    all_by_parent = defaultdict(set)
    dga_by_parent = defaultdict(set)
    for dom in stats:
        parts = dom.split(".")
        if len(parts) < 3:
            continue
        parent = ".".join(parts[-2:])
        all_by_parent[parent].add(dom)
        if _dga_word(parts[0]):
            dga_by_parent[parent].add(parts[0])

    new = []
    for parent, labels in dga_by_parent.items():
        total = len(all_by_parent[parent])
        if len(labels) < 3 or total > 40 or len(labels) / total < 0.8:
            continue
        if parent in NO_COLLAPSE or parent in PROTECT_PARENTS or parent in wl_raw:
            continue
        if ("**.%s**" % parent) in existing:
            continue
        new.append(parent)

    if new:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        with open(SHARED_FILE, "a", encoding="utf-8") as fh:
            fh.write("\n# ---- 新马甲 DGA 自动收敛（行为型，公开名单未收录） %s ----\n" % stamp)
            for p in new:
                fh.write("# auto:behavioral-dga:%s 随机子域%d个 %s\n"
                         % (p, len(dga_by_parent[p]), stamp))
                fh.write("%s**\n**.%s**\n" % (p, p))
        log("行为型 DGA 收敛 %d 个：%s" % (len(new), ", ".join(new)))
    return new


# ---------------------------------------------------------------- 主流程
def main():
    st = load_state()
    now = time.time()

    # 1. 现有规则 + 白名单
    bl = ds.load_blacklist() + ds.load_shared()
    wl = ds.load_whitelist()
    force = ds.load_force()

    # 2. 公开名单
    pubset = refresh_public_lists(st)

    # 3. 真实查询聚合 + 启动期突发（开屏广告识别）
    stats = collect_recent()
    bursts = collect_launch_bursts()
    splash_n = 0
    log("近 %d 天唯一域名 %d 个，启动期突发域 %d 个，规则 black=%d shared=%d wl=%d"
        % (DAYS_WINDOW, len(stats), len(bursts), len(ds.load_blacklist()),
           len(ds.load_shared()), len(wl)))

    auto_block = []       # (domain, reason)
    candidates = {}       # domain -> cand dict
    fs = st.setdefault("first_seen", {})

    for dom, s in sorted(stats.items()):
        # 白名单父域命中 → 永不碰（防误伤的最终底线）
        if ds._match_any(dom, wl):
            continue
        # 已被现有规则覆盖 → 跳过
        if ds.match_rule(dom, bl, wl, force) is not None:
            continue
        # 本引擎以前已经自动拦过的 → 跳过（双保险，防规则语义边缘漏匹配）
        if dom in st.get("auto_added", ()):
            continue

        # 记录首次出现时间
        if dom not in fs:
            fs[dom] = now
        age_h = (now - fs.get(dom, now)) / 3600.0

        parent2 = ".".join(dom.split(".")[-2:])
        parent3 = ".".join(dom.split(".")[-3:])
        protected = parent2 in PROTECT_PARENTS or parent3 in PROTECT_PARENTS
        splash = dom in bursts   # 冷启动头 8 秒集中出现 = 疑似开屏广告

        # ---- A 级：公开名单 ----
        phit = public_match(dom, pubset)
        if phit and (not protected or PROTECTED_AD_RE.search(dom)):
            tag = "protected-ad-sdk" if protected else "public:%s" % phit
            auto_block.append((dom, ("splash+" + tag) if splash else tag))
            if splash:
                splash_n += 1
            continue
        if phit:
            candidates.setdefault(dom, {
                "domain": dom, "score": 2 + (3 if splash else 0),
                "reason": ("公开名单命中 %s · 疑似开屏 · 保护父域(%s)需人工确认"
                           if splash else "公开名单命中 %s · 保护父域(%s)需人工确认")
                          % (phit, parent2),
                "apps": dict(s["apps"]), "clients": len(s["clients"]),
                "q": s["q"], "first_seen_h": round(age_h, 1),
                "splash": splash, "protected": True,
            })
            continue

        # ---- A 级：独立广告交易域（adx.* 几乎专用于广告交易）----
        if "adx" in re.split(r"[.-]", dom) and not protected:
            auto_block.append((dom, ("splash+adx" if splash else "adx-network")))
            if splash:
                splash_n += 1
            continue

        # ---- A 级：字节系指纹 ----
        if BYTEDANCE_AD_RE.search(dom) and not protected:
            auto_block.append((dom, ("splash+bytedance" if splash else "bytedance-fingerprint")))
            if splash:
                splash_n += 1
            continue

        # ---- A 级：电商广告（卖货倒计时）----
        if ECOM_AD_RE.search(dom) and not protected:
            auto_block.append((dom, ("splash+ecom-ad" if splash else "ecom-ad")))
            if splash:
                splash_n += 1
            continue

        # ---- A 级：广告线索组件（抖音信息流广告留资入口）----
        if LEADS_AD_RE.search(dom) and not protected:
            auto_block.append((dom, ("splash+leads" if splash else "leads-ad")))
            if splash:
                splash_n += 1
            continue

        # ---- B 级：行为打分 ----
        labels = re.split(r"[.-]", dom)
        strong = [t for t in STRONG_TOKENS if t in labels]
        weak = [t for t in WEAK_TOKENS if t in labels]
        if not strong and not weak:
            continue
        score = 2 * len(strong) + len(weak)
        ncli = len(s["clients"])
        if ncli >= 2:
            score += 1
        if age_h < 48:
            score += 1
        if s["q"] >= 100:
            score += 1
        if splash:
            score += 3
        parent = ".".join(dom.split(".")[-2:])
        st.setdefault("history", {}).setdefault(parent, 0)
        reason = ("tokens:%s%s · %d台设备 · %d次 · 首见%.0f小时前"
                  % (",".join(strong), ("/" + ",".join(weak)) if weak else "",
                     ncli, s["q"], age_h))
        if splash:
            reason += " · 疑似开屏(冷启动8秒内)"
        if strong or score >= 4:
            candidates[dom] = {
                "domain": dom, "score": score, "reason": reason,
                "apps": dict(s["apps"]), "clients": ncli, "q": s["q"],
                "first_seen_h": round(age_h, 1), "splash": splash,
            }

    # 同父域子域轮换检测（随机子域洪泛是广告/追踪 CDN 的典型特征）
    by_parent = defaultdict(set)
    for dom in stats:
        by_parent[".".join(dom.split(".")[-2:])].add(dom)
    for dom, c in list(candidates.items()):
        parent = ".".join(dom.split(".")[-2:])
        if len(by_parent.get(parent, ())) >= 10:
            c["score"] += 2
            c["reason"] += " · 父域%d个子域在轮换" % len(by_parent[parent])

    # 4. 写自动拦截（带上限）。注意：规则行必须干净——load_shared 不解析
    #    行内注释，注释必须独立成行，否则整条规则编译成垃圾永不匹配。
    added = 0
    if auto_block:
        seen = set(st.get("auto_added", []))
        block_lines, new_added = [], []
        for dom, why in auto_block:
            if dom in seen or added >= MAX_AUTO:
                continue
            seen.add(dom)
            new_added.append(dom)
            block_lines.append("# auto:%s %s" % (
                why, datetime.now().strftime("%Y-%m-%d %H:%M")))
            block_lines.append("%s**" % dom)
            added += 1
        if block_lines:
            with open(SHARED_FILE, "a", encoding="utf-8") as fh:
                fh.write("\n# ---- autodetect 自动拦截 %s（共 %d 条）----\n"
                         % (datetime.now().strftime("%Y-%m-%d %H:%M"), len(new_added)))
                fh.write("\n".join(block_lines) + "\n")
            st["auto_added"] = sorted(seen)
            log("A 级自动拦截 %d 条：%s" % (len(new_added),
                ", ".join(new_added[:8]) + (" ..." if len(new_added) > 8 else "")))

    # 4b. 随机子域域收敛（须在写精确规则之后，才能看到本轮新增的规则）
    collapse_dga_parents(stats)
    # 4c. 行为型：抓公开名单还没收录的新马甲轮换域
    collapse_new_dga_parents(stats)

    # 5. 候选队列（合并旧的，保留未处理项）
    old = {}
    try:
        with open(CAND_FILE, "r", encoding="utf-8") as fh:
            for c in json.load(fh):
                old[c["domain"]] = c
    except Exception:
        pass
    # 旧候选里的保护父域条目压低优先级，别把真正的开屏广告挤出队列
    for d, c in old.items():
        p2 = ".".join(d.split(".")[-2:])
        p3 = ".".join(d.split(".")[-3:])
        if p2 in PROTECT_PARENTS or p3 in PROTECT_PARENTS:
            c["protected"] = True
            c["score"] = min(c.get("score", 0), 5)
    for d, c in candidates.items():
        old[d] = c  # 新数据覆盖旧条目
    # 疑似开屏且非保护域的排前面，避免被「保护父域待确认」噪声挤掉
    def _rank(c):
        return -(c.get("score", 0)
                 + (8 if c.get("splash") and not c.get("protected") else 0))
    ranked = sorted(old.values(), key=_rank)
    # 已被本轮/历史规则拦掉的域不该还占着候选页
    already = set(st.get("auto_added", ()))
    merged = [c for c in ranked
              if c["domain"] not in already
              and ds.match_rule(c["domain"], bl, wl, force) is None][:MAX_CAND]
    tmp = CAND_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, CAND_FILE)
    splash_cand = sum(1 for c in merged if c.get("splash"))
    log("B 级候选 %d 条（队列现 %d 条，其中疑似开屏 %d 条，见 /candidates 页）"
        % (len(candidates), len(merged), splash_cand))

    # 6. 状态瘦身：first_seen 只留最近还在查询的 + 历史压到 2 万
    fs_keys = set(stats.keys())
    st["first_seen"] = {k: v for k, v in fs.items()
                        if k in fs_keys or now - v < 14 * 86400}
    if len(st["first_seen"]) > 20000:
        keep = sorted(st["first_seen"].items(), key=lambda kv: -kv[1])[:15000]
        st["first_seen"] = dict(keep)
    hist = st.get("history", {})
    for p in list(hist.keys()):
        if p not in by_parent:
            hist.pop(p, None)
    st["last_run"] = datetime.now().isoformat(timespec="seconds")
    save_state(st)
    log("完成。auto_block=%d（其中开屏 %d） candidates=%d" % (added, splash_n, len(merged)))


if __name__ == "__main__":
    main()
