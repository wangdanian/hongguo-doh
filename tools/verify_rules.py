#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真实 DoH 查询验证：拦截是否生效、业务域是否误伤。

用法:
    python3 tools/verify_rules.py
    DOH_URL=http://127.0.0.1:5053/dns-query python3 tools/verify_rules.py

需先启动服务（或 nginx 已反代）。FAILED>0 时退出码 1。
新增规则后请把代表性域名加进下面两个列表。
"""
import base64
import os
import struct
import sys
import urllib.request

DOH_URL = os.environ.get("DOH_URL", "http://127.0.0.1:5053/dns-query")


def query(name):
    tid = b"\x12\x34"
    qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    pkt = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qn + struct.pack(">HH", 1, 1)
    url = DOH_URL + "?dns=" + base64.urlsafe_b64encode(pkt).decode().rstrip("=")
    try:
        r = urllib.request.urlopen(url, timeout=5).read()
        return "拦截" if r.endswith(b"\x00\x00\x00\x00") else "放行"
    except Exception as e:
        return "ERR:%s" % e


SHOULD_BLOCK = [
    # 随机子域轮换（DGA）广告父域：含从未出现过的全新随机串，验证整域收敛
    "vuqsntdnsqqqnttqjnnbqq.jspcdn.cn",
    "zzqknewrotatingstring8821.jspcdn.cn",
    "bbqhvvnewrandom999.jspcdn.cn",
    "jspcdn.cn",
    "vuqenkdvkneqtsnbmqbnnbub.dy.zzcdnx.com",
    "zznewrandom999.dy.zzcdnx.com",
    "zzcdnx.com",
    # 广告视频 / 广告 API / 追踪
    "v95-aw-reading-video.qznovelvod.com",
    "v26-reading-ad.qznovelvod.com",
    "ads3-normal-lq.zijieapi.com",
    "ad.xhey.top", "track-gateway.y5kfpt.com", "track-config.y5kfpt.com",
    "mobads-logs.baidu.com", "dy-download-a.yangyi02.com",
    # 电商广告（卖货 + 倒计时）：商品数据 API 与商品图 CDN
    "ec3-core-lq.ecombdapi.com", "ecom3-normal-lq.ecombdapi.com",
    "ec5-core-hl.ecombdapi.com", "isaas5-normal-lq.ecombdapi.com",
    "ecombdapi.com",
    "ec3-core-lq.ecombdapi.com.queniuum.com",
    "ec5-core-lq.ecombdapi.com.c.dsa.cdnbuild.net",
    "p3-aio.ecombdimg.com", "p3-item.ecombdimg.com",
    "p26-item.ecombdimg.com.51296c5e.c.cdnhwc1.com",
    "p3-item.ecombdimg.com.queniuuf.com",
    "p3-item.ecombdimg.com.w.kunluncan.com",
    "p3-ecom-qualification-sign.ecombdimg.com",
    # 广告线索 / 落地页组件
    "lf-leads-fe-scm.bytecdn.com",
    "lf-leads-fe-scm.bytecdn.com.230b2a2545cfa773.queniubg.com",
    "lf-leads-test.bytecdn.com",
    "orzonera.yingt.fun", "coelacanth.yingt.fun",
    "1e10adc3949ba59abr3gidltl7x7xowwkuwser3u36u.wmzfylgdsz.com",
    "7a9e2f79.ydycdn.com",
    "47901788647306081891635066702227852167.ydycdn.com",
    # 广告 SDK 去 sign 马甲与父域自动收敛（2026-11-09）
    "lf3-mgsdk.dailygn.com", "zzz-newrandom.dailygn.com",
    "p3-ad-aweme.byteimg.com", "multi-az-ad.kuaishou.com",
    "tao.ad.cn.nt.ad.tengine.ingress.alibacorp.com.gds.alibabadns.com",
    "zz-newrandom.1rtb.com", "zz-newrandom.adview.cn",
    "zz-newrandom.ugdtimg.com", "zz-newrandom.mmstat.com",
]

SHOULD_ALLOW = [
    # 正片视频域（误伤会导致短剧播不了）
    "v5-se2-gddgtc-reading-video.qznovelvod.com",
    "v5-se2-alismart-reading-video.qznovelvod.com",
    "v11-reading-video.qznovelvod.com",
    "v9-reading-video.qznovelvod.com",
    # 业务域：搜索、支付、图片、内容 API、地图、时间服务
    "www.baidu.com", "api.unipay.qq.com", "p26.douyinpic.com",
    "p11.douyinpic.com", "api5-normal-lq.fqnovel.com",
    "api5-normal-sinfonlinea.fqnovel.com", "www.amap.com",
    "v26-qingtao.douyinvod.com", "time.apple.com",
    # IPv6 调度探测、字节 CDN 非广告子域、直播 CDN
    "240e09350a042d000000000000010009.qrstuvwxyzab.com",
    "lf-webcast-sourcecdn-tos.bytegecko.com",
    "pull-flv-l11.douyincdn.com", "p3.douyinpic.com",
    # 同 CDN 下的业务域，防止 *-ad-aweme / dailygn 整域收敛误伤
    "p3-novel-sign.byteimg.com", "www.bytedance.com",
    "frontier-aweme.snssdk.com", "opencdn.jomodns.com",
    "lf3-reading.fqnovelpic.com",
]


def main():
    print("DoH endpoint: %s" % DOH_URL)
    bad = 0
    print("\n=== 应拦截 (%d) ===" % len(SHOULD_BLOCK))
    for d in SHOULD_BLOCK:
        r = query(d)
        if r != "拦截":
            bad += 1
        print("%-62s %s%s" % (d, r, "  <-- 漏了" if r != "拦截" else ""))
    print("\n=== 应放行 (%d) ===" % len(SHOULD_ALLOW))
    for d in SHOULD_ALLOW:
        r = query(d)
        if r != "放行":
            bad += 1
        print("%-62s %s%s" % (d, r, "  <-- 误伤" if r != "放行" else ""))
    print("\nFAILED=%d / %d" % (bad, len(SHOULD_BLOCK) + len(SHOULD_ALLOW)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
