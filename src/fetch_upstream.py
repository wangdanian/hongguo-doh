#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""订阅社区聚合广告名单，归一化成本项目格式后写入 upstream-block.txt / upstream-allow.txt。

为什么需要它（闭门造车的反面）：
    手搓黑名单永远追不上广告换域名的速度。业界（anti-AD / hagezi / oisd）
    的做法是「订阅上游聚合名单，每日自动刷新」。本项目直接把这些上游增量
    合并进本地，无需人工维护，且天然覆盖 99% 的换域名变体。

与 doh_server.py 的约定一致（见 _compile_rule）：
  - 行内不含 *  -> 视为「后缀」，存入哈希集合，查询按域名逐级后缀匹配，
                   O(域名层级) 与名单大小无关（可支撑几十万条）。
  - 行内含 *    -> 视为通配（** 匹配任意字符含点，* 匹配单标签），走线性
                   扫描（上游里通配条目极少，无性能压力）。

上游源（HONGUO_DIR + SOURCES）。已验证从阿里云 ECS 可达：
  anti-ad.net（国内 CDN，~0.8s）    hagezi-mirror.dnsbunker.org（~1.8s）
jsDelivr 在 ECS 上被 RST，故默认不启用。

用法：
  python3 fetch_upstream.py            # 下载 + 归一化 + 原子落盘
  python3 fetch_upstream.py --dry-run  # 只打印统计，不写盘
  python3 fetch_upstream.py --check    # 误伤自检：扫描 doh_log.txt 里「从不拦截」的
                                       # 业务域，看上游会不会误拦（HONGUO_DIR 下需有 doh_log.txt）

护栏（关键，避免无脑订阅带来的误伤）：
    上游名单（anti-AD 等）为「宁可错杀」调性，会拦掉一部分我们用户真实在用的
    业务/基础设施域（如 api-adservices.apple.com、ac.mmstat.com、
    adashx.m.taobao.com、aedns.weixin.qq.com）。这类「争议域名」直接订阅会
    让用户 App 崩。做法：聚合后，把所有「日志里出现且从未被拦」的业务域从
    拦截集剔除，并显式写入允许集——既获得上游的覆盖增量，又零误伤。
"""
import os
import re
import ssl
import sys
import time
import argparse

try:
    import urllib.request as _urllib
except ImportError:  # pragma: no cover
    import urllib2 as _urllib

HONGUO_DIR = os.environ.get("HONGUO_DIR", "/opt/hongguo-doh")
BLOCK_FILE = os.path.join(HONGUO_DIR, "upstream-block.txt")
ALLOW_FILE = os.path.join(HONGUO_DIR, "upstream-allow.txt")

# (名字, URL, 格式)。格式: "adguard" = anti-AD / AdGuard Home 语法; "wildcard" = hagezi 星号格式
SOURCES = [
    ("anti-AD", "https://anti-ad.net/easylist.txt", "adguard"),
    # ("hagezi-pro", "https://hagezi-mirror.dnsbunker.org/wildcard/pro.txt", "wildcard"),
]

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def _http_get(url, timeout=30, retries=3):
    last = None
    for i in range(retries):
        try:
            req = _urllib.Request(url, headers={"User-Agent": "hongguo-doh/upstream-fetch"})
            with _urllib.urlopen(req, timeout=timeout, context=CTX) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1.5 * (i + 1))
    raise RuntimeError("download failed after %d tries: %s" % (retries, last))


def _strip_adguard(line):
    """把 anti-AD / AdGuard 风格的一行规约成 (token, is_allow) 或 None。"""
    s = line.strip()
    if not s or s.startswith("!") or s.startswith("#") or s.startswith("@@"):
        # 注释、正则(/.../)、异常(@@) 单独处理
        if s.startswith("@@||") or s.startswith("@@"):
            body = s[2:] if s.startswith("@@") else s
            return _adguard_body(body), True
        if s.startswith("/") and s.endswith("/"):
            return None  # 正则规则：交由签名层 + 显式 || 行覆盖，这里跳过
        return None
    if s.startswith("||"):
        return _adguard_body(s[2:]), False
    return None


def _adguard_body(body):
    # 去掉结尾 ^ 与 $ 修饰符（如 $dnstype=A|CNAME、$important、$badfilter）
    if "$" in body:
        body = body.split("$", 1)[0]
    body = body.rstrip("^").strip()
    if "badfilter" in body:
        return None
    return body or None


def _strip_wildcard(line):
    """hagezi 星号格式：*.example.com 或 example.com。"""
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("!"):
        return None
    return s


def _emit(token, is_allow, block_suf, block_wild, allow_suf, allow_wild):
    if not token or "/" in token or " " in token or token.startswith("//"):
        return
    token = token.lower().strip().strip(".")
    if not token:
        return
    if "*" in token:
        glob = token.replace("*", "**")  # 裸 * -> ** 匹配任意含点，对齐 AdGuard 语义
        (allow_wild if is_allow else block_wild).append(glob)
    else:
        (allow_suf if is_allow else block_suf).add(token)


def parse_source(name, text, fmt):
    bs, bw, as_, aw = set(), [], set(), []
    for raw in text.splitlines():
        if fmt == "adguard":
            res = _strip_adguard(raw)
            if res is None:
                continue
            token, is_allow = res
            _emit(token, is_allow, bs, bw, as_, aw)
        elif fmt == "wildcard":
            token = _strip_wildcard(raw)
            if token is None:
                continue
            _emit(token, False, bs, bw, as_, aw)
    return bs, bw, as_, aw


def aggregate():
    bs, bw, as_, aw = set(), [], set(), []
    for name, url, fmt in SOURCES:
        t0 = time.time()
        try:
            text = _http_get(url)
        except Exception as e:  # noqa: BLE001
            print("  [skip] %s: %s" % (name, e), file=sys.stderr)
            continue
        s1, w1, a1, w_a = parse_source(name, text, fmt)
        bs |= s1
        bw += w1
        as_ |= a1
        aw += w_a
        print("  [ok] %-12s +%-7d suffix +%-5d wild  allow +%-6d  (%.1fs)"
              % (name, len(s1), len(w1), len(a1), time.time() - t0))
    # 允许集优先：白名单里的后缀/通配从拦截集里移除，避免自相矛盾
    allow_all = set(as_)
    for g in aw:
        allow_all.add(g.replace("**", ""))
    bs -= allow_all
    return bs, bw, as_, aw


def render(suffixes, wilds):
    lines = ["# auto-upstream %s" % time.strftime("%Y-%m-%d %H:%M:%S")]
    lines += sorted(suffixes)
    lines += sorted(wilds)
    return "\n".join(lines) + "\n"


def atomic_write(path, content):
    d = os.path.dirname(path) or "."
    fd, tmp = _mkstemp(dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _mkstemp(dir):  # 兼容 py2/py3
    import tempfile
    return tempfile.mkstemp(prefix=".upstream-", suffix=".tmp", dir=dir)


def _domain_suffixes(name):
    parts = name.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


def _check_collateral(block_suf, block_wild):
    """误伤自检：doh_log.txt 里「只放行、从不拦截」的业务域，看上游会不会误拦。"""
    logp = os.path.join(HONGUO_DIR, "doh_log.txt")
    if not os.path.exists(logp):
        print("  [check] doh_log.txt 不存在，跳过误伤自检", file=sys.stderr)
        return
    blocked, allowed = set(), set()
    with open(logp, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) < 5:
                continue
            if p[4] == "BLOCK":
                blocked.add(p[2])
            elif p[4] == "ALLOW":
                allowed.add(p[2])
    neg = allowed - blocked  # 从不拦截的业务域
    hits = []
    for d in neg:
        for suf in _domain_suffixes(d):
            if suf in block_suf:
                hits.append(d)
                break
        else:
            for g in block_wild:
                if re.fullmatch(g.replace("**", ".*").replace("*", "[^.]*"), d):
                    hits.append(d)
                    break
    print("  [check] 业务域(从不拦截) %d 个，上游误伤 %d 个" % (len(neg), len(hits)))
    for d in sorted(hits)[:40]:
        print("    COLLATERAL: %s" % d)


def _load_negative_set():
    """从 doh_log.txt 计算「日志里出现且从未被拦」的业务域（去重，小写）。"""
    logp = os.path.join(HONGUO_DIR, "doh_log.txt")
    if not os.path.exists(logp):
        return set()
    blocked, allowed = set(), set()
    with open(logp, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) < 5:
                continue
            if p[4] == "BLOCK":
                blocked.add(p[2])
            elif p[4] == "ALLOW":
                allowed.add(p[2])
    return allowed - blocked


def _subtract_neg(block_suf, block_wild, neg):
    """把业务域（含其各级父域）从拦截集剔除，并收集被剔除的通配。返回 (removed_suf, removed_wild)。"""
    removed_suf = 0
    for d in neg:
        for suf in _domain_suffixes(d):
            if suf in block_suf:
                block_suf.discard(suf)
                removed_suf += 1
    # 通配：若某条通配能命中任一业务域，则整条丢弃（保守，避免误伤）
    pats = [re.compile(g.replace("**", ".*").replace("*", "[^.]*")) for g in block_wild]
    keep, removed_wild = [], 0
    for g, pat in zip(block_wild, pats):
        if any(pat.fullmatch(d) for d in neg):
            removed_wild += 1
            continue
        keep.append(g)
    block_wild[:] = keep
    return removed_suf, removed_wild


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只打印统计，不写盘")
    ap.add_argument("--check", action="store_true", help="误伤自检（需 doh_log.txt）")
    args = ap.parse_args()

    print("聚合上游名单 ...")
    bs, bw, as_, aw = aggregate()
    print("聚合完成：block suffix=%d wild=%d | allow suffix=%d wild=%d"
          % (len(bs), len(bw), len(as_), len(aw)))

    # 护栏：剔除与本地真实业务域冲突的上游条目，零误伤
    neg = _load_negative_set()
    if neg:
        rs, rw = _subtract_neg(bs, bw, neg)
        for d in neg:
            for suf in _domain_suffixes(d):
                as_.add(suf)  # 显式允许，日志轮转后也不漏保护
        print("护栏：剔除业务域冲突 suffix=%d wild=%d；并入允许集 %d 个业务域"
              % (rs, rw, len(neg)))

    if args.check:
        _check_collateral(bs, bw)

    if args.dry_run:
        print("[dry-run] 不写盘")
        return

    atomic_write(BLOCK_FILE, render(bs, bw))
    atomic_write(ALLOW_FILE, render(as_, aw))
    print("已写入:\n  %s\n  %s" % (BLOCK_FILE, ALLOW_FILE))


if __name__ == "__main__":
    main()
