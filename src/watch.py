#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
watch.py —— 红果去广告 · 观察期日志 + App 会话窗口
=================================================================
两个职责：

1) 观察日志（给「找人测试两天，再按日志改规则」用）
   watch/YYYY-MM-DD.jsonl  机器读（分析脚本用，字段全）
   watch/YYYY-MM-DD.tsv    人读（grep / Excel 直接开）
   watch/clients.txt       IP → 备注（谁是谁的手机）
   保留 7 天，按天自动切，跨天自动清理。

2) App 会话窗口（等价实现「只针对红果这个 App」）
   DNS 层天生看不到 PID / 进程名 —— iOS 的加密 DNS 是全系统的，
   服务端只能拿到「客户端 IP + 域名」。但红果打开时必然会解析一组
   只有红果/番茄系才会用的内容域（正片、封面、内容网关），
   拿这些域名当**指纹锚点**：锚点一出现，就把这台设备标记为
   「红果活跃中」，窗口 15 分钟，锚点每来一次就续期。
   窗口内才启用「跨 App 共用域名」那份黑名单（穿山甲/百度联盟等）；
   窗口外只拦红果自家广告位 —— 别的 App 完全不受影响。

   效果上等价于「按 App 拦」，而且比 PID 稳：App 切后台、进程重启、
   PID 变化都不影响，只要它还在请求内容就一直在窗口里。

用法：
    import watch
    app = watch.observe(client_ip)      # "hongguo" / "other"
    if watch.is_anchor(qname):
        watch.touch(client_ip); app = "hongguo"
    watch.log(client_ip, qname, "A", "BLOCK", rule, 12.0, app)

本模块任何异常都必须被吞掉 —— 日志挂了也绝不能让 DNS 服务停摆。
"""

import json
import os
import threading
import time
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WATCH_DIR = os.path.join(BASE_DIR, "watch")
CLIENTS_FILE = os.path.join(BASE_DIR, "watch-clients.txt")

SESSION_TTL = 900          # 红果会话窗口：15 分钟
KEEP_DAYS = int(os.environ.get("WATCH_KEEP_DAYS", "30"))  # 观察日志保留天数

# ---- App 域名指纹：按域名后缀把查询归到具体 App（分流日志用） ----
# DNS 层看不到进程，只能靠「这个 App 必然查的域名」归类
APP_MAP = (
    ("红果",   ("fqnovel.com", "qznovelvod.com", "fqnovelpic.com",
               "hongguoshuaji.com", "hongguoduanju.com",
               "reading-lq.snssdk.com", "snssdk.com", "zijieapi.com",
               "pangolin-sdk", "toutiao.com")),
    ("抖音",   ("douyin.com", "douyincdn.com", "douyinliving.com",
               "douyinstatic.com", "iesdouyin.com", "bytecdn.cn",
               "queniucf.com", "gslb.cdnhwcljk10")),
    ("京东",   ("jd.com", "360buyimg.com", "jdcdn.com", "jdl.com",
               "jdcloud.com", "3.cn", "jd.hk", "yiyaojd.com")),
    ("网易云", ("163.com", "126.net", "netease.im", "netease.com",
               "music.126.net", "slb.126.net")),
    ("微信",   ("weixin.qq.com", "wechat.com", "wxs.qq.com",
               "qpic.cn", "wx.qq.com", "wechatpay.com.cn",
               "tenpay.com", "qlogo.cn")),
    ("淘宝",   ("taobao.com", "tbcdn.cn", "tmall.com", "alipay.com",
               "alicdn.com", "aliyun.com", "mmstat.com")),
    ("拼多多", ("pinduoduo.com", "yangkeduo.com", "pddpic.com")),
    ("苹果",   ("apple.com", "icloud.com", "mzstatic.com",
               "cdn-apple.com", "me.com")),
)

# ---- 红果 / 番茄阅读系「内容域」指纹：只有这个 App 会查 ----
# 命中任意一个 → 认为这台设备正在用红果
ANCHOR_SUFFIXES = (
    ".fqnovel.com",             # 内容 API / 网关
    ".qznovelvod.com",          # 正片视频
    ".fqnovelpic.com",          # 封面图
    "reading-lq.snssdk.com",    # 阅读基础服务
    ".hongguoshuaji.com",
    ".hongguoduanju.com",
)

_lk = threading.Lock()
_sessions = {}             # ip -> expire_ts
_stats_cache = {"day": None, "ts": 0.0, "data": None}
_fh = {"day": None, "fp": None}
_clients = {"mtime": None, "map": {}}

ANCHOR_HITS = {"n": 0}     # 供状态页显示「当前有多少设备在红果窗口内」


# ------------------------------------------------------------------ 会话
def is_anchor(name):
    if not name:
        return False
    for suf in ANCHOR_SUFFIXES:
        if name == suf.lstrip(".") or name.endswith(suf):
            return True
    return False


def touch(ip):
    """把该客户端拉进/续期红果窗口"""
    try:
        with _lk:
            _sessions[ip] = time.time() + SESSION_TTL
    except Exception:
        pass


def observe(ip):
    """返回 "hongguo"（窗口内）/ "other"（窗口外）；顺手清理过期项"""
    try:
        now = time.time()
        with _lk:
            exp = _sessions.get(ip, 0)
            if exp > now:
                return "hongguo"
            if exp:
                _sessions.pop(ip, None)
        return "other"
    except Exception:
        return "other"


def active_sessions():
    try:
        now = time.time()
        with _lk:
            return sum(1 for v in _sessions.values() if v > now)
    except Exception:
        return 0


# ------------------------------------------------------------------ 客户端备注
def load_clients():
    try:
        mtime = os.path.getmtime(CLIENTS_FILE)
    except OSError:
        return _clients["map"]
    with _lk:
        if mtime == _clients["mtime"]:
            return _clients["map"]
        m = {}
        try:
            with open(CLIENTS_FILE, "r", encoding="utf-8-sig") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        m[parts[0].strip()] = parts[1].strip()
        except OSError:
            return _clients["map"]
        _clients["mtime"] = mtime
        _clients["map"] = m
        return m


def client_label(ip):
    try:
        return load_clients().get(ip, "")
    except Exception:
        return ""


# ------------------------------------------------------------------ App 分流
def classify(qname):
    """按域名后缀把查询归到具体 App；认不出的归 other"""
    try:
        n = (qname or "").lower().rstrip(".")
        for name, suffixes in APP_MAP:
            for suf in suffixes:
                if suf in n:
                    return name
        return "other"
    except Exception:
        return "other"


# ------------------------------------------------------------------ 写日志
def _rotate_if_needed():
    """跨天切文件；顺手清理 KEEP_DAYS 天前的文件"""
    day = datetime.now().strftime("%Y-%m-%d")
    if _fh["day"] == day and _fh["fp"] is not None:
        return day
    if _fh["fp"] is not None:
        try:
            _fh["fp"].close()
        except Exception:
            pass
        _fh["fp"] = None
    try:
        if not os.path.isdir(WATCH_DIR):
            os.makedirs(WATCH_DIR, exist_ok=True)
    except OSError:
        return None
    # 清理老文件（主目录 + apps/<App>/ 分流目录）
    try:
        cutoff = (datetime.now() - timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%d")
        dirs = [WATCH_DIR]
        try:
            apps_root = os.path.join(WATCH_DIR, "apps")
            if os.path.isdir(apps_root):
                dirs += [os.path.join(apps_root, d) for d in os.listdir(apps_root)]
        except OSError:
            pass
        for d in dirs:
            for fn in os.listdir(d):
                if len(fn) >= 10 and fn[:10] < cutoff:
                    try:
                        os.remove(os.path.join(d, fn))
                    except OSError:
                        pass
    except OSError:
        pass
    try:
        _fh["fp"] = open(os.path.join(WATCH_DIR, day + ".jsonl"), "a", encoding="utf-8")
        _fh["day"] = day
    except OSError:
        _fh["fp"] = None
    return day


def log(ip, qname, qtype, action, rule, ms, app):
    """一条观察记录。rule 为空表示未命中任何规则。
    同时按「域名 App 指纹」分流写 per-app 日志：
      apps/<App>/<day>-ok.tsv      成功放行
      apps/<App>/<day>-block.tsv   拦截/失败（规则命中的 BLOCK、上游失败）
    """
    try:
        now = datetime.now()
        day = now.strftime("%Y-%m-%d")
        label = client_label(ip)
        rec = {
            "t": now.strftime("%Y-%m-%dT%H:%M:%S"),
            "ip": ip,
            "q": qname,
            "ty": qtype,
            "a": action,
            "r": rule or "",
            "ms": round(ms, 1),
            "app": app,
            "c": classify(qname),
        }
        if label:
            rec["lbl"] = label
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        tsv = "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.0fms\n" % (
            now.strftime("%Y-%m-%d %H:%M:%S"), ip, qname, qtype, action,
            rule or "-", app, ms,
        )
        with _lk:
            if _rotate_if_needed() != day:
                return
            fp = _fh["fp"]
            if fp is not None:
                fp.write(line + "\n")
                fp.flush()
            try:
                with open(os.path.join(WATCH_DIR, day + ".tsv"), "a",
                          encoding="utf-8") as tf:
                    tf.write(tsv)
            except OSError:
                pass
            # ---- App 分流日志（成功 / 拦截失败 两个文件） ----
            try:
                adir = os.path.join(WATCH_DIR, "apps", rec["c"])
                if not os.path.isdir(adir):
                    os.makedirs(adir, exist_ok=True)
                kind = "ok" if action == "ALLOW" else "block"
                with open(os.path.join(adir, "%s-%s.tsv" % (day, kind)),
                          "a", encoding="utf-8") as af:
                    af.write(tsv)
            except OSError:
                pass
    except Exception:
        pass


# ------------------------------------------------------------------ 统计（状态页用）
def stats_today(force=False):
    """读今日 jsonl 聚合，20 秒缓存。返回 dict。"""
    try:
        now = time.time()
        day = datetime.now().strftime("%Y-%m-%d")
        with _lk:
            if (not force and _stats_cache["day"] == day
                    and now - _stats_cache["ts"] < 20
                    and _stats_cache["data"] is not None):
                return _stats_cache["data"]
        path = os.path.join(WATCH_DIR, day + ".jsonl")
        total = blocked = allowed = 0
        bl = {}
        al = {}
        ips = {}
        apps = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    total += 1
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    q = r.get("q", "")
                    ip = r.get("ip", "")
                    ips[ip] = ips.get(ip, 0) + 1
                    c = r.get("c") or classify(q)
                    apps[c] = apps.get(c, 0) + 1
                    if r.get("a") == "BLOCK":
                        blocked += 1
                        bl[q] = bl.get(q, 0) + 1
                    else:
                        allowed += 1
                        al[q] = al.get(q, 0) + 1
        data = {
            "day": day,
            "total": total,
            "blocked": blocked,
            "allowed": allowed,
            "apps": sorted(apps.items(), key=lambda x: -x[1]),
            "blocked_top": sorted(bl.items(), key=lambda x: -x[1])[:15],
            "allowed_top": sorted(al.items(), key=lambda x: -x[1])[:20],
            "clients": sorted(ips.items(), key=lambda x: -x[1])[:30],
        }
        with _lk:
            _stats_cache.update({"day": day, "ts": now, "data": data})
        return data
    except Exception:
        return {"day": "", "total": 0, "blocked": 0, "allowed": 0,
                "apps": [], "blocked_top": [], "allowed_top": [], "clients": []}


def note_anchor():
    try:
        ANCHOR_HITS["n"] += 1
    except Exception:
        pass
