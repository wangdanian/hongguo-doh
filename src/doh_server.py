#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
红果短剧去广告 —— DNS-over-HTTPS (DoH) 服务端
=========================================================
跑在飞牛 NAS 上，由 nginx(443) 反代暴露为
    https://doh.example.com/dns-query
iPhone 通过「配置描述文件」把全局 DNS 指向该地址，
出门用蜂窝网络也能生效。

设计要点（与 dns_server.py 保持一致）：
  * 不做 MITM、不装证书 -> 不触发字节系 App 的 SSL Pinning
  * 上游转发保持原始报文，最大兼容性
  * 规则语义完全相同（含 ** 跨点通配，用来封 CNAME 别名绕过）

规则语法（blacklist.txt）:
  abc.com                        匹配 abc.com 及其所有子域
  *-ad.qznovelvod.com            *  匹配任意不含点的字符串
  ads3-normal-lq.zijieapi.com**  ** 匹配任意字符(含点)，覆盖 CNAME 目标

用法:
  DOH_LISTEN_IP=127.0.0.1 DOH_LISTEN_PORT=5053 python3 doh_server.py
  python3 doh_server.py            # 默认 127.0.0.1:5053
"""

import base64
import json
import os
import re
import secrets
import signal
import socket
import struct
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.txt")
SHARED_FILE = os.path.join(BASE_DIR, "blacklist-shared.txt")
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.txt")
FORCE_FILE = os.path.join(BASE_DIR, "force-block.txt")
LOG_FILE = os.path.join(BASE_DIR, "doh_log.txt")

# 观察日志 + 红果会话窗口（watch.py）。导入失败绝不影响 DNS 服务。
try:
    import watch
except Exception as _exc:                                    # pragma: no cover
    watch = None
    print("[warn] watch.py unavailable: %s" % _exc, flush=True)

LISTEN_IP = os.environ.get("DOH_LISTEN_IP", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("DOH_LISTEN_PORT", "5053"))


def _parse_upstreams(raw, default):
    """HONGGUO_UPSTREAM="223.5.5.5,119.29.29.29:53,[2400:3200::1]:53" """
    out = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("["):
            host, _, rest = item.partition("]")
            host = host.lstrip("[")
            port = int(rest.lstrip(":")) if rest.startswith(":") else 53
        elif item.count(":") == 1:
            host, _, p = item.partition(":")
            port = int(p)
        else:
            host, port = item, 53
        out.append((host, port))
    return out or default


_DEFAULT_UPSTREAMS = [("223.5.5.5", 53), ("119.29.29.29", 53), ("114.114.114.114", 53)]
UPSTREAMS = _parse_upstreams(os.environ.get("HONGGUO_UPSTREAM"), _DEFAULT_UPSTREAMS)
UPSTREAM_TIMEOUT = 3.0

# ---- 日志级别（隐私开关）----
#   full  : 记录全部查询（默认，调规则时需要）
#   block : 只记录被拦截的域名，放行的不落盘
#   off   : 完全不写日志，只保留内存里的计数（/stats 仍可用）
# 切换：hongguo-log full|block|off
LOG_MODE = (os.environ.get("DOH_LOG_MODE", "full") or "full").strip().lower()
if LOG_MODE not in ("full", "block", "off"):
    LOG_MODE = "full"

MAX_BODY = 8192          # DoH 请求体上限
DOH_CONTENT_TYPE = "application/dns-message"

QTYPE_NAMES = {
    1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR",
    33: "SRV", 65: "HTTPS", 64: "SVCB", 6: "SOA", 2: "NS", 43: "DS",
    257: "CAA", 255: "ANY",
}

_log_lock = threading.Lock()
_bl_lock = threading.Lock()
_bl_cache = {"mtime": None, "entries": []}
_sh_cache = {"mtime": None, "entries": []}
_wl_cache = {"mtime": None, "entries": []}
_force_cache = {"mtime": None, "entries": []}
_stats = {"total": 0, "allowed": 0, "blocked": 0, "failed": 0}
_stats_lock = threading.Lock()

# ---------------------------------------------------------------- 多用户令牌
# 每台设备装「专属描述文件」时领一个 token：
#   DNS 地址  https://203.0.113.10/u/<token>/dns-query
#   桌面图标  https://203.0.113.10/u/<token>   （点开 = 自己的开关页）
# token 即唯一身份凭证：开关只影响自己，互不干扰。
BASE_URL = os.environ.get("DOH_BASE_URL", "https://203.0.113.10")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
CAND_FILE = os.path.join(BASE_DIR, "autodetect-candidates.json")  # autodetect.py 产出
_users_lock = threading.Lock()
_users = {}                 # 内存主副本，磁盘只做持久化
_users_dirty = False
_users_loaded = False


def _users_load_if_needed():
    global _users, _users_loaded, _users_dirty
    if _users_loaded:
        return
    with _users_lock:
        if _users_loaded:
            return
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as fh:
                _users = json.load(fh)
        except Exception:
            _users = {}
        _users_loaded = True
        _users_dirty = False


def _users_flush():
    """原子写盘（只在开关/新用户/定时器时调用，不在查询热路径上）"""
    global _users_dirty
    tmp = USERS_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_users, fh, ensure_ascii=False)
        os.replace(tmp, USERS_FILE)
        _users_dirty = False
    except OSError:
        pass


def _users_periodic_flush():
    while True:
        time.sleep(60)
        with _users_lock:
            if _users_dirty:
                _users_flush()


def issue_user():
    """发一个新 token（内存+磁盘）。

    1 小时内已签发、但从未产生过任何查询的空令牌直接复用，避免反复点
    「领取描述文件」堆积出无流量的僵尸用户（2026-11-10 实证：64 个令牌
    里 61 个从未使用）。一旦令牌被设备真正使用（last_seen / total_q 非空）
    就永远不会再被复用，不会让两个人共用同一个开关。
    """
    _users_load_if_needed()
    with _users_lock:
        cutoff = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        for tok, u in _users.items():
            if (not u.get("last_seen") and not u.get("total_q")
                    and u.get("created", "") >= cutoff):
                return tok, dict(u)
        tok = secrets.token_urlsafe(9)            # 12 个 URL 安全字符
        while tok in _users:
            tok = secrets.token_urlsafe(9)
        _users[tok] = {
            "enabled": True,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": "",
            "day": datetime.now().strftime("%Y-%m-%d"),
            "day_q": 0, "day_block": 0,
            "total_q": 0, "total_block": 0,
        }
        _users_flush()
        return tok, dict(_users[tok])


def get_user(tok):
    _users_load_if_needed()
    with _users_lock:
        return dict(_users[tok]) if tok in _users else None


def user_bump(tok, blocked):
    """查询计数：纯内存，60 秒定时落盘"""
    _users_load_if_needed()
    with _users_lock:
        u = _users.get(tok)
        if not u:
            return
        today = datetime.now().strftime("%Y-%m-%d")
        if u.get("day") != today:
            u["day"] = today
            u["day_q"] = 0
            u["day_block"] = 0
        u["day_q"] += 1
        u["total_q"] += 1
        if blocked:
            u["day_block"] += 1
            u["total_block"] += 1
        u["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        global _users_dirty
        _users_dirty = True


def set_user_enabled(tok, enabled):
    _users_load_if_needed()
    with _users_lock:
        u = _users.get(tok)
        if not u:
            return False
        u["enabled"] = bool(enabled)
        _users_flush()
        return True


def reset_user_stats(tok):
    """清零该用户的今日/累计统计（不影响开关状态与令牌本身）"""
    _users_load_if_needed()
    with _users_lock:
        u = _users.get(tok)
        if not u:
            return False
        u["day_q"] = 0
        u["day_block"] = 0
        u["total_q"] = 0
        u["total_block"] = 0
        _users_flush()
        return True


def users_snapshot():
    _users_load_if_needed()
    with _users_lock:
        return {t: dict(u) for t, u in _users.items()}


# ---------------------------------------------------------------- DNS 解析
def parse_question(packet):
    """返回 (qname, qtype, qclass, questionEndOffset)，解析失败返回 None"""
    if len(packet) < 12:
        return None
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount < 1:
        return None
    pos, labels, guard = 12, [], 0
    while pos < len(packet):
        guard += 1
        if guard > 128:
            return None
        length = packet[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:          # 压缩指针
            pos += 2
            break
        if length > 63:
            return None
        pos += 1
        if pos + length > len(packet):
            return None
        labels.append(packet[pos:pos + length].decode("ascii", "replace"))
        pos += length
    if pos + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack("!HH", packet[pos:pos + 4])
    return ".".join(labels), qtype, qclass, pos + 4


DNS_TTL_CAP = 60


def clamp_answer_ttl(packet, cap=DNS_TTL_CAP):
    """把应答 Answer 区每条 RR 的 TTL 压到 cap 秒内，
    缩短规则变更后客户端沿用旧 DNS 缓存的窗口。"""
    try:
        qd = struct.unpack("!H", packet[4:6])[0]
        an = struct.unpack("!H", packet[6:8])[0]
    except struct.error:
        return packet
    if an == 0:
        return packet
    buf = bytearray(packet)
    pos = 12
    for _ in range(qd):
        while pos < len(buf) and buf[pos] != 0:
            if (buf[pos] & 0xC0) == 0xC0:
                pos += 2
                break
            pos += buf[pos] + 1
        else:
            pos += 1
        pos += 4
    for _ in range(an):
        if pos >= len(buf):
            break
        if (buf[pos] & 0xC0) == 0xC0:
            pos += 2
        else:
            while pos < len(buf) and buf[pos] != 0:
                pos += buf[pos] + 1
            pos += 1
        if pos + 10 > len(buf):
            break
        old = struct.unpack_from("!I", buf, pos + 4)[0]
        if old > cap:
            struct.pack_into("!I", buf, pos + 4, cap)
        rdlen = struct.unpack_from("!H", buf, pos + 8)[0]
        pos += 10 + rdlen
    return bytes(buf)


def min_ttl(packet):
    """从应答里取最小 TTL，用于给浏览器/CDN 设置缓存时间"""
    try:
        qd = struct.unpack("!H", packet[4:6])[0]
        an = struct.unpack("!H", packet[6:8])[0]
    except struct.error:
        return 60
    if an == 0:
        return 60
    pos = 12
    for _ in range(qd):
        while pos < len(packet) and packet[pos] != 0:
            if (packet[pos] & 0xC0) == 0xC0:
                pos += 2
                break
            pos += packet[pos] + 1
        else:
            pos += 1
        pos += 4
    best = 3600
    for _ in range(an):
        if pos >= len(packet):
            break
        if (packet[pos] & 0xC0) == 0xC0:
            pos += 2
        else:
            while pos < len(packet) and packet[pos] != 0:
                pos += packet[pos] + 1
            pos += 1
        if pos + 10 > len(packet):
            break
        _rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", packet[pos:pos + 10])
        pos += 10 + rdlen
        if ttl < best:
            best = ttl
    return max(30, min(best, 3600))


# ---------------------------------------------------------------- 黑名单
def _compile_rule(rule):
    """无通配返回 (rule, None)；含通配返回 (rule, 预编译正则)

    *  匹配任意不含点的字符串
    ** 匹配任意字符(含点) —— 用于覆盖 CNAME 目标，例如
       ads3-normal-lq.zijieapi.com**
       会连带拦掉 ads3-normal-lq.zijieapi.com.w.cdngslb.com
    """
    if "*" not in rule:
        return rule, None
    escaped = re.escape(rule).replace(r"\*\*", "\x00")
    escaped = escaped.replace(r"\*", "[^.]*").replace("\x00", ".*")
    return rule, re.compile("^" + escaped + "$")


def load_blacklist():
    """热加载：文件 mtime 变化时重新读取，改完立即生效无需重启"""
    try:
        mtime = os.path.getmtime(BLACKLIST_FILE)
    except OSError:
        return _bl_cache["entries"]
    with _bl_lock:
        if mtime == _bl_cache["mtime"]:
            return _bl_cache["entries"]
        entries = []
        try:
            with open(BLACKLIST_FILE, "r", encoding="utf-8-sig") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entries.append(_compile_rule(line.lower().strip(".")))
        except OSError:
            return _bl_cache["entries"]
        _bl_cache["mtime"] = mtime
        _bl_cache["entries"] = entries
        print("[blacklist] reloaded, %d rule(s)" % len(entries), flush=True)
        return entries


def load_whitelist():
    """热加载白名单。**白名单优先于黑名单**：命中白名单的域名永不拦截。

    防误伤兜底。DNS 层拦的是域名、不是 App，同一域名多 App 共用时
    无法只拦一个（见 blacklist.txt 里淘宝 ut 埋点的历史教训）。
    """
    try:
        mtime = os.path.getmtime(WHITELIST_FILE)
    except OSError:
        return _wl_cache["entries"]
    with _bl_lock:
        if mtime == _wl_cache["mtime"]:
            return _wl_cache["entries"]
        entries = []
        try:
            with open(WHITELIST_FILE, "r", encoding="utf-8-sig") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entries.append(_compile_rule(line.lower().strip(".")))
        except OSError:
            return _wl_cache["entries"]
        _wl_cache["mtime"] = mtime
        _wl_cache["entries"] = entries
        print("[whitelist] reloaded, %d rule(s)" % len(entries), flush=True)
        return entries


def load_force():
    """热加载「强制拦截例外」，优先级高于白名单。

    白名单是按父域整域放行的（如 amap.com），其下确凿的广告子域
    （optimus-ads.amap.com）写进普通黑名单会被白名单直接架空。
    这个文件只放经过确认的广告子域，命中即拦，绕过白名单检查。
    文件不存在时返回空表，行为与旧版完全一致。
    """
    try:
        mtime = os.path.getmtime(FORCE_FILE)
    except OSError:
        return []
    if mtime == _force_cache["mtime"]:
        return _force_cache["entries"]
    entries = []
    try:
        with open(FORCE_FILE, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(_compile_rule(line.lower().strip(".")))
    except OSError:
        return []
    _force_cache["mtime"] = mtime
    _force_cache["entries"] = entries
    print("[force] reloaded, %d rule(s)" % len(entries), flush=True)
    return entries


def load_shared():
    """跨 App 共用域名（穿山甲/百度联盟等）。

    这份名单**只在红果会话窗口内生效** —— 见 watch.py 的说明。
    DNS 层看不到 PID，但红果打开时一定会解析 fqnovel/qznovelvod 这类
    专属内容域，用它们当指纹锚点，就能把这台设备标记成「正在用红果」，
    窗口内才应用本名单。别的 App 触发不了锚点，自然不受影响。
    """
    try:
        mtime = os.path.getmtime(SHARED_FILE)
    except OSError:
        return _sh_cache["entries"]
    with _bl_lock:
        if mtime == _sh_cache["mtime"]:
            return _sh_cache["entries"]
        entries = []
        try:
            with open(SHARED_FILE, "r", encoding="utf-8-sig") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entries.append(_compile_rule(line.lower().strip(".")))
        except OSError:
            return _sh_cache["entries"]
        _sh_cache["mtime"] = mtime
        _sh_cache["entries"] = entries
        print("[shared] reloaded, %d rule(s)" % len(entries), flush=True)
        return entries


def _match_any(name, entries):
    """返回命中的规则串，未命中返回 None"""
    for rule, pattern in entries:
        if pattern is not None:
            if pattern.match(name):
                return rule
        elif name == rule or name.endswith("." + rule):
            return rule
    return None


def is_blocked(name, entries, wl_entries=(), force_entries=()):
    if not name:
        return False
    # ★ 强制例外最高优先：白名单父域下确凿的广告子域
    if force_entries and _match_any(name, force_entries):
        return True
    # ★ 白名单优先：命中即放行，不再看黑名单
    if wl_entries and _match_any(name, wl_entries):
        return False
    if not entries:
        return False
    for rule, pattern in entries:
        if pattern is not None:
            if pattern.match(name):
                return True
        elif name == rule or name.endswith("." + rule):
            return True
    return False


def match_rule(name, entries, wl_entries=(), force_entries=()):
    """返回命中的规则串（未命中 None）。强制例外 > 白名单 > 黑名单。"""
    if not name:
        return None
    if force_entries:
        f = _match_any(name, force_entries)
        if f:
            return "force:" + f
    if not entries:
        return None
    if wl_entries and _match_any(name, wl_entries):
        return None
    return _match_any(name, entries)


def build_blocked_response(query, qtype, qend):
    """A -> 0.0.0.0；其余类型 -> NOERROR + 0 条应答(让客户端快速失败而非超时)"""
    txid = query[:2]
    question = query[12:qend]
    flags = b"\x81\x80"                       # QR=1 RD=1 RA=1 RCODE=NOERROR
    if qtype == 1:
        header = txid + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x00\x00\x00\x00"
        return header + question + answer
    header = txid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
    return header + question


# ---------------------------------------------------------------- 上游转发
def forward_udp(query):
    for upstream in UPSTREAMS:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(UPSTREAM_TIMEOUT)
            sock.sendto(query, upstream)
            resp, _ = sock.recvfrom(8192)
            return resp
        except Exception:
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return None


def forward_tcp(query):
    """UDP 被截断(TC=1)时回退到 TCP"""
    for upstream in UPSTREAMS:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(UPSTREAM_TIMEOUT)
            sock.connect(upstream)
            sock.sendall(struct.pack("!H", len(query)) + query)
            head = sock.recv(2)
            if len(head) < 2:
                continue
            (rlen,) = struct.unpack("!H", head)
            buf = b""
            while len(buf) < rlen:
                chunk = sock.recv(rlen - len(buf))
                if not chunk:
                    break
                buf += chunk
            if buf:
                return buf
        except Exception:
            continue
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return None


def resolve(query):
    """转发查询；被截断则走 TCP"""
    resp = forward_udp(query)
    if resp and len(resp) > 3 and (resp[2] & 0x02):      # TC 位
        tcp_resp = forward_tcp(query)
        if tcp_resp:
            return tcp_resp
    return resp


# ---------------------------------------------------------------- 日志
def write_log(client, name, qtype, action, ms, rule="", app=""):
    # 隐私开关：off 完全不落盘；block 只记被拦截的
    if LOG_MODE == "off":
        return
    if LOG_MODE == "block" and action != "BLOCK":
        return
    line = "%s\t%s\t%s\t%s\t%s\t%.0fms" % (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client, name,
        QTYPE_NAMES.get(qtype, str(qtype)), action, ms,
    )
    if rule or app:
        line += "\t%s\t%s" % (rule or "-", app or "-")
    with _log_lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    # 观察日志（按天切分、保留 7 天，供 analyze.py 出报告）
    if watch is not None:
        watch.log(client, name, QTYPE_NAMES.get(qtype, str(qtype)),
                  action, rule, ms, app)


def handle_query(query, client, ua="", user=None):
    """核心入口：返回 (响应字节, 动作)。user 为 None 或 dict（含 enabled）"""
    t0 = datetime.now()
    parsed = parse_question(query)
    if not parsed:
        return None, "MALFORMED"
    qname, qtype, _qclass, qend = parsed
    name = (qname or "").lower().strip(".")

    # ── App 会话窗口 ──────────────────────────────────────────────
    # 锚点域名（红果专属内容域）一出现，就把该客户端标记为「红果活跃」，
    # 15 分钟窗口，锚点每来一次续期。
    app = watch.observe(client) if watch is not None else "hongguo"
    if watch is not None and watch.is_anchor(name):
        watch.touch(client)
        watch.note_anchor()
        app = "hongguo"

    # ── 用户级开关：关闭 = 该用户全放行，只解析不拦截 ──────────────
    filtering_on = True
    if user is not None:
        filtering_on = bool(user.get("enabled", True))

    rule = None
    if filtering_on:
        wl = load_whitelist()
        force = load_force()
        rule = match_rule(name, load_blacklist(), wl, force)
        if rule is None:
            # 共享名单常开（全是广告域）：不再依赖红果会话窗口，
            # 避免服务重启/窗口过期出现拦截真空期（2026-11-06 漏广告根因）
            rule = match_rule(name, load_shared(), wl, force)

    if rule is not None:
        response, action, bucket = build_blocked_response(query, qtype, qend), "BLOCK", "blocked"
    else:
        response = resolve(query)
        action = "ALLOW" if response else "FAIL"
        bucket = "allowed" if response else "failed"

    with _stats_lock:
        _stats["total"] += 1
        _stats[bucket] += 1

    ms = (datetime.now() - t0).total_seconds() * 1000
    write_log(client, name, qtype, action, ms, rule or "", app)
    return response, action


# ---------------------------------------------------------------- 状态页
def _render_watch():
    """状态页里的「观察日志」区块"""
    if watch is None:
        return ('<h2>观察日志</h2><p class="k">watch.py 未加载，'
                '日志功能不可用（DNS 解析不受影响）。</p>')
    import html as _h
    s = watch.stats_today()
    labels = watch.load_clients()
    cli_rows = "".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>%d</td></tr>"
        % (_h.escape(ip), _h.escape(labels.get(ip, "") or "-"), n)
        for ip, n in s["clients"][:15]
    ) or '<tr><td colspan="3" class="k">今日还没有查询</td></tr>'
    bl_rows = "".join(
        "<tr><td><code>%s</code></td><td>%d</td></tr>" % (_h.escape(q), n)
        for q, n in s["blocked_top"][:10]
    ) or '<tr><td colspan="2" class="k">今日没有拦截</td></tr>'
    return """
<h2>观察日志 · 今日（%s）</h2>
<table>
<tr><th>查询</th><td>%d</td></tr>
<tr><th>拦截</th><td>%d</td></tr>
<tr><th>放行</th><td>%d</td></tr>
<tr><th>红果窗口内设备</th><td>%d 台</td></tr>
</table>
<h2>测试设备</h2>
<table><tr><th>客户端 IP</th><th>备注</th><th>查询数</th></tr>%s</table>
<p class="k">给 IP 起名字：在 NAS 上执行
<code>python3 /opt/hongguo-doh/analyze.py</code> 看报告，或直接编辑
<code>/opt/hongguo-doh/watch-clients.txt</code>（一行：IP 空格 备注）。</p>
<h2>今日拦截 Top 10</h2>
<table><tr><th>域名</th><th>次数</th></tr>%s</table>
<p class="k">完整日志：<code>/opt/hongguo-doh/watch/</code>（按天，保留 7 天）。
出报告：<code>python3 analyze.py</code> → <code>reports/</code>。</p>
""" % (s["day"], s["total"], s["blocked"], s["allowed"],
       watch.active_sessions(), cli_rows, bl_rows)


# ---------------------------------------------------------------- 专属描述文件
ICON_FILE = os.path.join(BASE_DIR, "webclip-icon.png")

PROFILE_TPL = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>PayloadContent</key>
\t<array>
\t\t<dict>
\t\t\t<key>DNSSettings</key>
\t\t\t<dict>
\t\t\t\t<key>DNSProtocol</key>
\t\t\t\t<string>HTTPS</string>
\t\t\t\t<key>ServerURL</key>
\t\t\t\t<string>%(base)s/u/%(token)s/dns-query</string>
\t\t\t</dict>
\t\t\t<key>PayloadDescription</key>
\t\t\t<string>把本机 DNS 指向自建 DoH 节点（专属令牌 %(token)s），拦截红果短剧广告域名。可在桌面图标里随时开关过滤，删除本描述文件即完全恢复原状。</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>红果短剧去广告 · DNS(专属)</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>com.example.hongguo.dns.%(token)s</string>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.dnsSettings.managed</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>%(uuid1)s</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t</dict>
\t\t<dict>
\t\t\t<key>Icon</key>
\t\t\t<data>%(icon)s</data>
\t\t\t<key>IsRemovable</key>
\t\t\t<true/>
\t\t\t<key>FullScreen</key>
\t\t\t<true/>
\t\t\t<key>Precomposed</key>
\t\t\t<true/>
\t\t\t<key>Label</key>
\t\t\t<string>红果去广告</string>
\t\t\t<key>URL</key>
\t\t\t<string>%(base)s/u/%(token)s</string>
\t\t\t<key>PayloadDescription</key>
\t\t\t<string>桌面图标：点开查看数据、开关广告过滤</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>红果去广告</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>com.example.hongguo.webclip.%(token)s</string>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.webClip.managed</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>%(uuid2)s</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t</dict>
\t</array>
\t<key>PayloadDescription</key>
\t<string>自建 DoH 去广告（专属令牌 %(token)s，独立开关）；桌面图标可随时开/关过滤、查看拦截数据。删除本描述文件即完全恢复原状。</string>
\t<key>PayloadDisplayName</key>
\t<string>红果短剧去广告(专属 %(token)s)</string>
\t<key>PayloadIdentifier</key>
\t<string>com.example.hongguo.%(token)s</string>
\t<key>PayloadOrganization</key>
\t<string>hongguo-adblock</string>
\t<key>PayloadRemovalDisallowed</key>
\t<false/>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadUUID</key>
\t<string>%(uuid3)s</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
</dict>
</plist>
"""


def build_profile(token):
    icon = ""
    try:
        icon = base64.b64encode(open(ICON_FILE, "rb").read()).decode()
    except OSError:
        pass
    return PROFILE_TPL % {
        "base": BASE_URL,
        "token": token,
        "icon": icon,
        "uuid1": str(uuid.uuid4()).upper(),
        "uuid2": str(uuid.uuid4()).upper(),
        "uuid3": str(uuid.uuid4()).upper(),
    }


_USER_PAGE_CSS = """body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;
background:#f2f3f7;color:#1c1c1e;margin:0;padding:20px;line-height:1.7}
.card{background:#fff;border-radius:16px;padding:22px;max-width:520px;margin:0 auto 14px;
box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:19px;margin:0 0 6px}
.k{color:#6b6b70;font-size:13px}
table{width:100%%;border-collapse:collapse;font-size:14px}
td,th{text-align:left;padding:6px 0;border-bottom:1px solid #f0f0f2}
.btn{display:block;width:100%%;text-align:center;border:none;border-radius:14px;
padding:16px;font-size:17px;font-weight:700;color:#fff;cursor:pointer;-webkit-appearance:none}
.on{background:#34c759}.off{background:#ff3b30}
.btn.ghost{background:#f2f2f7;color:#3a3a3c;margin-top:10px;text-decoration:none}
.pill{display:inline-block;border-radius:999px;padding:2px 12px;font-size:13px;font-weight:600}
.pill.on{background:#e8f8ee;color:#137a3f}.pill.off{background:#fdecec;color:#b3261e}
.btn.share{background:#0a84ff;color:#fff;margin-top:10px}
.share-box{margin-top:12px;padding:14px;background:#f7f8fc;border-radius:12px;
border:1px solid #e3e5ee}
.share-link{display:block;font-family:ui-monospace,Menlo,monospace;font-size:12px;
word-break:break-all;background:#fff;padding:10px;border-radius:8px;
border:1px solid #e3e5ee;margin:8px 0;color:#0a84ff}
.share-box .btn{font-size:15px;padding:12px}
.qr{text-align:center;margin:12px 0}
.qr svg{width:180px;height:180px;max-width:180px}
"""

_USER_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>红果去广告 · 我的开关</title><style>%(css)s</style></head><body>
<div class="card">
<h1>红果去广告 <span class="pill %(pill)s">%(state)s</span></h1>
<p class="k">专属令牌 <code>%(token)s</code> · 本开关只影响你自己这台设备，别人不受影响。</p>
<table>
<tr><th>今日查询</th><td>%(day_q)d 次</td></tr>
<tr><th>今日拦截广告</th><td>%(day_block)d 次</td></tr>
<tr><th>累计查询</th><td>%(total_q)d 次</td></tr>
<tr><th>累计拦截</th><td>%(total_block)d 次</td></tr>
<tr><th>最近活动</th><td>%(last_seen)s</td></tr>
</table>
<form method="post" action="/u/%(token)s/toggle"
onsubmit="return confirm('%(confirm)s');">
<button class="btn %(btn)s" type="submit">%(btn_text)s</button>
</form>
<form method="post" action="/u/%(token)s/reset"
onsubmit="return confirm('确定要清除我的查询/拦截记录吗？\\n只清零统计数字，不影响开关状态。');">
<button class="btn ghost" type="submit">清除我的记录</button>
</form>
<a class="btn ghost" href="/u/%(token)s">刷新数据</a>
<button class="btn share" type="button" onclick="toggleShare()">分享给朋友 · 让他也能去广告</button>
<div id="shareBox" class="share-box" style="display:none">
<p class="k">把下面的链接发给朋友，他用 Safari 打开就能领自己的描述文件。
链接里不含你的专属令牌，对方碰不到你的开关和统计。</p>
<code class="share-link" id="shareLink">%(share_url)s</code>
<button class="btn ghost" type="button" onclick="copyLink()">复制链接</button>
<button class="btn ghost" type="button" id="sysShareBtn" onclick="sysShare()">用系统分享</button>
<div class="qr">%(qr)s</div>
<p class="k">%(qr_note)s</p>
</div>
<p class="k">%(tip)s</p>
</div>
<div class="card">
<p class="k"><a href="%(base)s/stats">全局状态页</a> · 开关立即生效，无需删除或重装描述文件。</p>
</div>
<script>
var SHARE_URL = %(share_url_json)s;
function toggleShare(){
  var b=document.getElementById('shareBox');
  b.style.display = b.style.display==='none' ? 'block' : 'none';
}
function legacyCopy(t){
  var i=document.createElement('textarea');i.value=t;document.body.appendChild(i);
  i.select();document.execCommand('copy');document.body.removeChild(i);
  alert('链接已复制，发给朋友吧');
}
function copyLink(){
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(SHARE_URL).then(
      function(){alert('链接已复制，发给朋友吧');},
      function(){legacyCopy(SHARE_URL);});
  }else{legacyCopy(SHARE_URL);}
}
function sysShare(){
  if(navigator.share){
    navigator.share({title:'红果短剧去广告',
      text:'装个描述文件，红果短剧广告就没了',url:SHARE_URL}).catch(function(){});
  }else{alert('当前浏览器不支持系统分享，请点「复制链接」');}
}
if(!navigator.share){document.getElementById('sysShareBtn').style.display='none';}
</script>
</body></html>"""


# ---- 邀请安装：分享出去的链接不含任何 token ----
INVITE_PATH = "/invite"
INVITE_URL = BASE_URL + INVITE_PATH
_QR_CACHE = {}


def invite_qr_svg():
    """邀请链接二维码内联 SVG。segno 是可选依赖，没装就返回空串。"""
    if "svg" in _QR_CACHE:
        return _QR_CACHE["svg"]
    try:
        import segno
        svg = segno.make(INVITE_URL, error="m").svg_inline(scale=4)
        _QR_CACHE["svg"] = svg
    except Exception:
        _QR_CACHE["svg"] = ""
    return _QR_CACHE["svg"]


_INVITE_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>红果短剧去广告 · 邀请安装</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;
background:#f2f3f7;color:#1c1c1e;margin:0;padding:20px;line-height:1.7}
.card{background:#fff;border-radius:16px;padding:22px;max-width:520px;margin:0 auto;
box-shadow:0 1px 4px rgba(0,0,0,.08)}h1{font-size:20px;margin:0 0 6px}
.k{color:#6b6b70;font-size:13px}ol{padding-left:20px;font-size:14px}
.install{display:block;text-align:center;background:#0a84ff;color:#fff;
text-decoration:none;padding:15px;border-radius:14px;font-size:17px;font-weight:700;margin:16px 0}
.qr{text-align:center;margin:12px 0}.qr svg{width:180px;height:180px;max-width:180px}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}</style>
</head><body>
<div class="card">
<h1>红果短剧去广告</h1>
<p class="k">朋友分享给你的自建去广告节点。iPhone 装一个描述文件，红果短剧的开屏和卖货广告就没了；
不想用了随时关，不用删描述文件。</p>
<h2>怎么装</h2>
<ol>
<li><b>用 Safari 打开这个页面</b>（微信里点右上角「···」→ 在 Safari 中打开）</li>
<li>点下面的按钮，会领到<b>你自己的专属令牌</b>并下载描述文件 → 允许</li>
<li>设置 → 通用 → VPN 与设备管理 → 已下载的描述文件 → 安装</li>
<li>提示「未签名」时再点一次「安装」即可（自建节点没有 Apple 签名，正常）</li>
<li>桌面出现「红果去广告」图标，点开就是你自己的开关页，可以随时开/关，不影响别人</li>
</ol>
<a class="install" href="/issue">领取我的专属描述文件</a>
<div class="qr">%(qr)s</div>
<p class="k">%(qr_note)s</p>
<p class="k">邀请链接：<code>%(url)s</code></p>
</div>
</body></html>"""


# ---- 广告自动发现：候选审核页（autodetect.py 产出 autodetect-candidates.json）----
_FEEDBACK_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>广告反馈自动归因 · 红果去广告</title>
<style>body{font-family:-apple-system,"PingFang SC",sans-serif;background:#f5f6f8;
margin:0;padding:24px;line-height:1.6}.card{background:#fff;border-radius:14px;
padding:20px 22px;max-width:820px;margin:0 auto 16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 4px}.k{color:#6b6b70;font-size:13px}
code{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:14px}
td,th{text-align:left;padding:10px 6px;border-bottom:1px solid #f0f0f2;vertical-align:top}
.b{display:inline-block;padding:6px 14px;border-radius:8px;text-decoration:none;
font-size:13px;font-weight:600;margin:2px;background:#e02e2e;color:#fff}
.ok{display:inline-block;background:#e8f8ee;color:#137a3f;border-radius:999px;
padding:2px 10px;font-size:12px;font-weight:600}</style></head><body>
<div class="card">
<h1>广告反馈自动归因 <span class="ok">__COUNT__</span></h1>
<p class="k">回溯 <b>__AT__</b> 前 6 分钟（__WINDOW__）的放行日志，
与近 3 天历史基线比对，自动找出首次出现的陌生域并写入拦截规则。
规则带 <code># feedback:</code> 标签，可整段删除回滚。</p>
__SUMMARY__
<h2>本次动作</h2>
__ACTIONS__
<h2>可疑域（按分数）</h2>
<table><tr><th>域名 / 依据</th><th>分数</th></tr>__ROWS__</table>
<p class="k"><a href="/feedback">再跑一次（当前时刻）</a> ·
<a href="/candidates">候选审核</a> · <a href="/">状态页</a></p>
</div></body></html>"""

_CAND_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>可疑广告域审核 · 红果去广告</title>
<style>body{font-family:-apple-system,"PingFang SC",sans-serif;background:#f5f6f8;
margin:0;padding:24px;line-height:1.6}.card{background:#fff;border-radius:14px;
padding:20px 22px;max-width:760px;margin:0 auto 16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;color:#3a3a3c;margin:18px 0 8px}
.k{color:#6b6b70;font-size:13px}code{font-family:ui-monospace,Menlo,monospace;font-size:13px;
word-break:break-all}table{width:100%%;border-collapse:collapse;font-size:14px}
td,th{text-align:left;padding:10px 6px;border-bottom:1px solid #f0f0f2;vertical-align:top}
.b{display:inline-block;padding:6px 14px;border-radius:8px;text-decoration:none;
font-size:13px;font-weight:600;margin:2px}
.blk{background:#e02e2e;color:#fff}.wl{background:#e8f8ee;color:#137a3f;border:1px solid #b7e2c6}
.ok{display:inline-block;background:#e8f8ee;color:#137a3f;border-radius:999px;
padding:2px 10px;font-size:12px;font-weight:600}</style></head><body>
<div class="card">
<h1>可疑广告域审核 <span class="ok">%d 条待定</span></h1>
<p style="background:#fff0e6;border-radius:10px;padding:10px 14px;margin:12px 0"><b>刚刚又看到广告？</b> <a class="b blk" href="/feedback">一键自动归因并拦截</a> <span class="k">（回溯前 6 分钟放行日志，自动找首次出现的陌生域写规则；也可带时刻：/feedback?at=23:07）</span></p>
<p class="k">autodetect.py 每半小时扫一遍真实 DNS 日志：命中公开拦截名单或字节系广告指纹的
会<b>自动拦截</b>；拿不准的（广告关键词 + 突增 + 多设备）会放进这张表等你一键裁决。
<a href="/candidates">刷新</a> · <a href="/">状态页</a></p>
<table><tr><th>域名 / 依据</th><th>操作</th></tr>
%s
</table>
<p class="k">「拦截」= 写入共享黑名单（所有用户立即生效）；「放行」= 写入白名单永不拦截。
两个动作都会把该域从候选队列移除。</p>
</div></body></html>"""


class DoHHandler(BaseHTTPRequestHandler):
    server_version = "hongguo-doh/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 20

    # ---- 工具 ----
    def _client_ip(self):
        for h in ("X-Real-IP", "CF-Connecting-IP", "X-Forwarded-For"):
            val = self.headers.get(h)
            if val:
                return val.split(",")[0].strip()
        return self.client_address[0]

    def _send(self, code, body, ctype, extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *_args):
        pass                                  # 关掉 http.server 默认的 stderr 噪音

    _USER_RE = re.compile(r"^/u/([A-Za-z0-9_-]{4,64})(/.*)?$")

    # ---- 路由 ----
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/dns-query", "/dns-query/"):
            self._do_doh(get_params=parse_qs(urlparse(self.path).query))
            return
        if path == "/issue":
            tok, _u = issue_user()
            body = build_profile(tok)
            self._send(200, body, "application/x-apple-aspen-config", extra={
                "Content-Disposition": "attachment; filename=hongguo-%s.mobileconfig" % tok,
            })
            return
        if path in (INVITE_PATH, INVITE_PATH + "/"):
            self._do_invite()
            return
        m = self._USER_RE.match(path)
        if m:
            tok, sub = m.group(1), m.group(2) or ""
            u = get_user(tok)
            if u is None:
                self._send(404, "未知令牌\n", "text/plain; charset=utf-8")
                return
            if sub == "/dns-query":
                self._do_doh(get_params=parse_qs(urlparse(self.path).query), user=(tok, u))
            else:
                self._do_user_page(tok, u)
            return
            self._send(404, "not found\n", "text/plain; charset=utf-8")
            return
        if path in ("/", "/index.html"):
            self._do_status()
        elif path == "/stats":
            self._do_stats()
        elif path == "/watch":
            self._do_watch()
        elif path == "/users":
            import json as _j
            self._send(200, _j.dumps(users_snapshot(), ensure_ascii=False),
                       "application/json; charset=utf-8")
        elif path == "/feedback":
            self._do_feedback()
        elif path == "/candidates":
            self._do_candidates()
        elif path.startswith("/cand/"):
            self._do_cand_action(path)
        else:
            self._send(404, "not found\n", "text/plain; charset=utf-8")

    # ---- 广告自动发现：候选审核 ----
    def _load_cands(self):
        try:
            with open(CAND_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return []

    def _save_cands(self, items):
        tmp = CAND_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, CAND_FILE)

    def _do_feedback(self):
        import html as _h
        import json as _j
        import subprocess as _sp
        import sys as _sys
        q = parse_qs(urlparse(self.path).query)
        at = (q.get("at") or [""])[0]
        cmd = [_sys.executable, os.path.join(BASE_DIR, "ad_feedback.py"), "--json"]
        if at:
            cmd += ["--at", at]
        try:
            r = _sp.run(cmd, capture_output=True, text=True, timeout=120)
            out = (r.stdout or "").strip().splitlines()
            data = _j.loads(out[-1]) if out else {"error": "no output"}
            if r.returncode != 0:
                data["error"] = (r.stderr or "")[-400:]
        except Exception as e:
            data = {"error": repr(e)}

        if data.get("error"):
            rows = "<tr><td colspan='2'>归因失败：" + _h.escape(str(data["error"])) + "</td></tr>"
            acts = "<p class='k'>未写入任何规则。</p>"
            summary = "<p style='color:#c00'>脚本执行失败，服务器日志见 ad-feedback.log</p>"
            cnt, at_s, win_s = "失败", at or "当前", "-"
        else:
            acts_list = data.get("actions", [])
            findings = data.get("findings", [])
            rows = []
            for f in findings[:40]:
                tag = " <span class='k'>(保护域，仅报告)</span>" if f.get("protected") else ""
                rows.append("<tr><td><code>%s</code>%s<br><span class='k'>%s · 首见 %s · "
                            "窗口 %s 次 / %s 台设备 · 历史 %s 次</span></td><td>%d</td></tr>"
                            % (_h.escape(f["domain"]), tag, _h.escape(f["reason"]),
                               f.get("first", "-"), f.get("q", 0), f.get("clients", 0),
                               f.get("base", 0), f.get("score", 0)))
            rows = "".join(rows) or "<tr><td colspan='2' class='k'>这个窗口没有可疑放行域</td></tr>"
            if acts_list:
                acts = "<table><tr><th>动作</th><th>域名</th></tr>" + "".join(
                    "<tr><td>%s</td><td><code>%s</code></td></tr>"
                    % (_h.escape(x["action"]), _h.escape(x["domain"]))
                    for x in acts_list) + "</table>"
            else:
                acts = "<p class='k'>没有达到自动拦截阈值（分数 &gt;= 6 且非保护域），未写规则。"
                acts += "可疑域已列在下面，可在 <a href='/candidates'>候选页</a> 人工裁决。</p>"
            summary = ("<p>窗口放行 <b>%d</b> 条 / <b>%d</b> 个域，命中 <b>%d</b> 个可疑域，"
                       "自动拦截 <b>%d</b> 个。规则 <b>%d → %d</b>。</p>"
                       % (data.get("allow_in_window", 0), data.get("unique_domains", 0),
                          len(findings), len(acts_list),
                          data.get("rules_before", 0), data.get("rules_after", 0)))
            cnt = "%d 条自动拦截" % len(acts_list)
            at_s = _h.escape(data.get("at", ""))
            win_s = " ~ ".join(data.get("window", ["-", "-"]))

        html = (_FEEDBACK_PAGE.replace("__COUNT__", cnt)
                .replace("__AT__", at_s).replace("__WINDOW__", win_s)
                .replace("__SUMMARY__", summary)
                .replace("__ACTIONS__", acts)
                .replace("__ROWS__", rows))
        self._send(200, html, "text/html; charset=utf-8")

    def _do_candidates(self):
        import html as _h
        items = self._load_cands()
        rows = []
        for c in items:
            d = c.get("domain", "?")
            reason = _h.escape(c.get("reason", ""))
            apps = ", ".join("%s×%s" % (k, v) for k, v in c.get("apps", {}).items()) or "-"
            row = ("<tr><td><code>%s</code>%s<br><span class='k'>%s</span><br>"
                   "<span class='k'>App 分布：%s · 设备 %s 台 · 查询 %s 次</span></td>"
                   "<td><a class='b blk' href='/cand/block?d=%s' "
                   "onclick=\"return confirm('拦截 %s ?')\">拦截</a> "
                   "<a class='b wl' href='/cand/allow?d=%s' "
                   "onclick=\"return confirm('放行 %s ?')\">放行</a></td></tr>")
            badge = (" <span style='background:#fff0e6;color:#c25a00;border-radius:6px;"
                     "padding:1px 7px;font-size:12px;font-weight:600'>疑似开屏</span>"
                     if c.get("splash") else "")
            rows.append(row % (_h.escape(d), badge, reason, _h.escape(apps),
                               c.get("clients", 0), c.get("q", 0),
                               quote(d), _h.escape(d),
                               quote(d), _h.escape(d)))
        if not rows:
            rows.append("<tr><td colspan='2' class='k'>暂无候选 —— autodetect.py "
                        "发现拿不准的域时会自动填到这里</td></tr>")
        self._send(200, _CAND_PAGE % (len(items), "\n".join(rows)),
                   "text/html; charset=utf-8")

    def _do_cand_action(self, path):
        import html as _h
        q = parse_qs(urlparse(self.path).query)
        dom = (q.get("d", [""])[0] or "").strip().lower().strip(".")
        act = path.rsplit("/", 1)[-1]
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", dom) or act not in ("block", "allow"):
            self._send(400, "bad request\n", "text/plain; charset=utf-8")
            return
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        if act == "block":
            with open(SHARED_FILE, "a", encoding="utf-8") as fh:
                fh.write("#auto:candidate %s\n%s**\n" % (stamp, dom))
            load_shared()  # 立即热加载，不等下一次查询
        else:
            with open(WHITELIST_FILE, "a", encoding="utf-8") as fh:
                fh.write("#auto:candidate 放行 %s\n%s\n" % (stamp, dom))
            load_whitelist()
        self._save_cands([c for c in self._load_cands() if c.get("domain") != dom])
        self.send_response(303)
        self.send_header("Location", "/candidates")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        m = self._USER_RE.match(path)
        if m and (m.group(2) or "") == "/toggle":
            tok = m.group(1)
            u = get_user(tok)
            if u is None:
                self._send(404, "未知令牌\n", "text/plain; charset=utf-8")
                return
            set_user_enabled(tok, not u["enabled"])
            # 303 回到开关页（Web Clip 全屏模式下也能正常跳转）
            self.send_response(303)
            self.send_header("Location", "/u/%s" % tok)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if m and (m.group(2) or "") == "/reset":
            tok = m.group(1)
            if get_user(tok) is None:
                self._send(404, "未知令牌\n", "text/plain; charset=utf-8")
                return
            reset_user_stats(tok)
            self.send_response(303)
            self.send_header("Location", "/u/%s" % tok)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in ("/dns-query", "/dns-query/"):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                self._send(400, "bad length\n", "text/plain; charset=utf-8")
                return
            self._do_doh(body=self.rfile.read(length))
            return
        mm = self._USER_RE.match(path)
        if mm and (mm.group(2) or "") == "/dns-query":
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                self._send(400, "bad length\n", "text/plain; charset=utf-8")
                return
            tok = mm.group(1)
            u = get_user(tok)
            self._do_doh(body=self.rfile.read(length),
                         user=(tok, u) if u else None)
            return
        self._send(404, "not found\n", "text/plain; charset=utf-8")

    # ---- 处理 ----
    def _do_doh(self, body=None, get_params=None, user=None):
        client = self._client_ip()
        if body is None:
            raw = (get_params or {}).get("dns", [""])[0]
            if not raw:
                self._send(400, "missing dns param\n", "text/plain; charset=utf-8")
                return
            pad = "=" * (-len(raw) % 4)
            try:
                body = base64.urlsafe_b64decode(raw + pad)
            except Exception:
                self._send(400, "bad base64\n", "text/plain; charset=utf-8")
                return

        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if self.command == "POST" and ctype and ctype != DOH_CONTENT_TYPE:
            self._send(415, "unsupported media type\n", "text/plain; charset=utf-8")
            return

        response, action = handle_query(body, client, user=user[1] if user else None)
        if response is None:
            self._send(400, "malformed dns query\n", "text/plain; charset=utf-8")
            return

        if user is not None:
            user_bump(user[0], action == "BLOCK")

        if action == "BLOCK":
            ttl = 30
        else:
            response = clamp_answer_ttl(response, DNS_TTL_CAP)
            ttl = min(min_ttl(response), DNS_TTL_CAP)
        self._send(
            200, response, DOH_CONTENT_TYPE,
            extra={"Cache-Control": "max-age=%d" % ttl, "X-DNS-Action": action},
        )

    def _do_user_page(self, tok, u):
        on = bool(u.get("enabled", True))
        day_ok = u.get("day") == datetime.now().strftime("%Y-%m-%d")
        html = _USER_PAGE % {
            "css": _USER_PAGE_CSS,
            "base": BASE_URL,
            "token": tok,
            "state": "过滤已开启" if on else "过滤已关闭",
            "pill": "on" if on else "off",
            "day_q": u.get("day_q", 0) if day_ok else 0,
            "day_block": u.get("day_block", 0) if day_ok else 0,
            "total_q": u.get("total_q", 0),
            "total_block": u.get("total_block", 0),
            "last_seen": u.get("last_seen") or "暂无",
            "btn": "off" if on else "on",
            "btn_text": "关闭广告过滤（红果恢复原样）" if on else "开启广告过滤",
            "confirm": ("确定要关闭广告过滤吗？\\n关闭后红果里广告会回来，"
                        "随时可以再开。") if on else "确定要开启广告过滤吗？",
            "tip": ("当前正在拦截广告域名。点上面按钮暂停后，所有域名照常解析，"
                    "等于暂时回到无过滤状态，但描述文件保留。") if on else
                   ("当前处于「只解析不拦截」状态，红果广告会回来。"
                    "点上面按钮随时恢复拦截。"),
            "share_url": INVITE_URL,
            "share_url_json": json.dumps(INVITE_URL),
            "qr": invite_qr_svg(),
            "qr_note": ("扫描二维码可以直接把这个安装页发给朋友。"
                        if invite_qr_svg() else
                        "（当前节点未装二维码组件，点「复制链接」即可分享）"),
        }
        # 桌面图标（Web Clip）可能复用旧页面缓存；禁缓存保证新按钮立刻可见
        self._send(200, html, "text/html; charset=utf-8",
                   extra={"Cache-Control": "no-store"})

    def _do_invite(self):
        qr = invite_qr_svg()
        html = _INVITE_PAGE % {
            "qr": qr,
            "url": INVITE_URL,
            "qr_note": ("扫描二维码可以把这个安装页发给别人。" if qr else
                        "（当前节点未装二维码组件，直接转发链接即可）"),
        }
        self._send(200, html, "text/html; charset=utf-8",
                   extra={"Cache-Control": "no-store"})

    def _do_status(self):
        entries = load_blacklist()
        wl_entries = load_whitelist()
        with _stats_lock:
            s = dict(_stats)
        rules = "\n".join(r for r, _ in entries) or "(空)"
        wl_text = "\n".join(r for r, _ in wl_entries) or "(空)"
        log_label = {
            "full": "full（记录全部查询）",
            "block": "block（只记被拦截的）",
            "off": "off（不落盘，仅内存计数）",
        }.get(LOG_MODE, LOG_MODE)
        html = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>红果去广告 · DoH 节点</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;
background:#f5f6f8;color:#1c1c1e;margin:0;padding:24px;line-height:1.7}
.card{background:#fff;border-radius:14px;padding:20px 22px;max-width:640px;margin:0 auto 16px;
box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:18px 0 8px;color:#3a3a3c}
.ok{display:inline-block;background:#e8f8ee;color:#137a3f;border-radius:999px;
padding:2px 10px;font-size:12px;font-weight:600}
code,pre{font-family:ui-monospace,Menlo,monospace;font-size:13px}
pre{background:#f2f3f5;border-radius:10px;padding:12px;overflow:auto}
.k{color:#6b6b70;font-size:13px}table{width:100%%;border-collapse:collapse;font-size:14px}
td,th{text-align:left;padding:6px 0;border-bottom:1px solid #f0f0f2}
</style></head><body>
<div class="card">
<h1>红果去广告 · DoH 节点 <span class="ok">运行中</span></h1>
<div class="k">监听 %s:%d &nbsp;|&nbsp; 上游 %s</div>
<h2>统计</h2>
<table>
<tr><th>总查询</th><td>%d</td></tr>
<tr><th>放行</th><td>%d</td></tr>
<tr><th>拦截</th><td>%d</td></tr>
<tr><th>失败</th><td>%d</td></tr>
<tr><th>规则数</th><td>%d（另有 %d 条白名单保护）</td></tr>
<tr><th>日志级别</th><td>%s</td></tr>
</table>
<h2>DoH 地址</h2>
<pre>https://doh.example.com/dns-query</pre>
<h2>安装（每人专属）</h2>
<p><a href="/issue" style="display:inline-block;background:#0a84ff;color:#fff;
text-decoration:none;padding:11px 22px;border-radius:10px;font-weight:600">领取我的专属描述文件</a></p>
<p><a href="/invite" style="color:#0a84ff;font-size:14px">把这个去广告节点分享给朋友 →</a></p>
<ol style="padding-left:20px;font-size:14px;color:#3a3a3c">
<li>点上面的按钮 → 会领到一个<b>专属令牌</b>并下载你的描述文件 → 允许</li>
<li>打开 设置 → 通用 → VPN 与设备管理 → 已下载的描述文件 → 安装</li>
<li>提示「未签名」时再点一次「安装」即可（自建节点没有 Apple 签名，正常）</li>
<li>装完桌面上有「红果去广告」图标，点开就是<b>你自己的开关页</b>：
可以随时开/关过滤、看自己的拦截数据，不影响其他人的设备</li>
</ol>
<p class="k">不想过滤了不用删描述文件，点图标里的「关闭广告过滤」即可；
删除该描述文件则完全恢复原状。令牌即身份凭证，请勿把带令牌的链接发给不想给权限的人。</p>
<h2>当前拦截规则</h2><pre>%s</pre>
<h2>白名单 · 永不拦截（防误伤）</h2>
<p class="k">DNS 拦的是域名、不是 App。以下域名无论黑名单怎么改都放行，
避免出现「拦了广告但把别的 App 弄坏」——例如淘宝 H5 依赖的 ut 埋点通道。</p><pre>%s</pre>
</div></body></html>""" % (
            LISTEN_IP, LISTEN_PORT, ", ".join("%s:%d" % u for u in UPSTREAMS),
            s["total"], s["allowed"], s["blocked"], s["failed"],
            len(entries), len(wl_entries),
            log_label, rules, wl_text,
        )
        # 观察日志区块（拼接而非 % 格式化，避免域名里的 % 触发格式化错误）
        html = html.replace("</div></body></html>",
                            _render_watch() + "</div></body></html>")
        self._send(200, html, "text/html; charset=utf-8")

    def _do_stats(self):
        import json
        with _stats_lock:
            s = dict(_stats)
        s["rules"] = len(load_blacklist())
        s["shared_rules"] = len(load_shared())
        s["sessions"] = watch.active_sessions() if watch is not None else 0
        self._send(200, json.dumps(s), "application/json; charset=utf-8")

    def _do_watch(self):
        """今日观察摘要，JSON。给远程排查用：https://example.com/watch"""
        import json
        if watch is None:
            self._send(503, '{"error":"watch unavailable"}', "application/json")
            return
        s = watch.stats_today()
        s["sessions"] = watch.active_sessions()
        s["labels"] = watch.load_clients()
        self._send(200, json.dumps(s, ensure_ascii=False),
                   "application/json; charset=utf-8")


def main():
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as fh:
            fh.write("# 一行一条规则，# 开头为注释\n")
    load_blacklist()
    load_shared()
    if watch is not None:
        watch.load_clients()
    _users_load_if_needed()
    threading.Thread(target=_users_periodic_flush, daemon=True).start()

    srv = ThreadingHTTPServer((LISTEN_IP, LISTEN_PORT), DoHHandler)
    srv.daemon_threads = True

    def shutdown(_s, _f):
        print("[exit] %s" % _stats, flush=True)
        # 注意：绝不能在这里调 srv.shutdown()。
        # srv.shutdown() 会阻塞等待 serve_forever() 退出并 set __is_shut_down，
        # 而 serve_forever() 跑在主线程、主线程此刻正卡在这个信号处理器里
        #   -> 死锁，systemd 只能等满 TimeoutStopSec(90s) 再 SIGKILL。
        # 实测 2026-11-03 01:28:15 停服一直卡到 01:29:46，
        # 那 91 秒里手机 DoH 完全不可用（iOS 加密 DNS 不会回退到 DHCP DNS，
        # 表现就是整机断网）。等于每次改规则/重启都会断网一分半。
        # 本服务无持久化状态要落盘，立即退出才是正确做法。
        try:
            srv.socket.close()
        except Exception:
            pass
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("=" * 62, flush=True)
    print(" DoH server online -> http://%s:%d/dns-query" % (LISTEN_IP, LISTEN_PORT), flush=True)
    print(" blacklist         -> %s (%d rules)" % (BLACKLIST_FILE, len(load_blacklist())), flush=True)
    print(" shared(常开)      -> %s (%d rules)" % (SHARED_FILE, len(load_shared())), flush=True)
    print(" whitelist         -> %s (%d rules)" % (WHITELIST_FILE, len(load_whitelist())), flush=True)
    print(" force(越过白名单) -> %s (%d rules)" % (FORCE_FILE, len(load_force())), flush=True)
    print(" watch log         -> %s" % (watch.WATCH_DIR if watch else "(disabled)"), flush=True)
    print(" upstreams         -> %s" % ", ".join("%s:%d" % u for u in UPSTREAMS), flush=True)
    print("=" * 62, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
