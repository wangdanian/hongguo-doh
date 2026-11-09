#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""真实 DoH 查询验证：拦截是否生效、业务域是否误伤。

用法:
    python3 tools/verify_rules.py
    DOH_URL=https://118.178.183.90/dns-query python3 tools/verify_rules.py

默认打「IP 直连版」对应的公网端点（与红果去广告-IP直连版.mobileconfig 的
ServerURL 一致），不依赖域名解析，避免 DDNS 抽风导致的假失败。
需先启动服务（或 nginx 已反代）。FAILED>0 时退出码 1。
新增规则后请把代表性域名加进下面两个列表。
"""
import base64
import os
import struct
import sys
import urllib.request

# 默认打「IP 直连版」对应的公网端点（与红果去广告-IP直连版.mobileconfig 的 ServerURL 一致）
DOH_URL = os.environ.get("DOH_URL", "https://118.178.183.90/dns-query")


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
    "zz-newrandom.ugdtimg.com",
    # 上游订阅层增量（anti-AD 等社区聚合名单）：这些域本项目 own 规则/签名层
    # 并未单独枚举，纯靠上游层拦。验证「手搓名单追不上换域名」已由订阅层解决。
    # （mmstat.com 因双用途已加白名单，不再放 SHOULD_BLOCK，见 SHOULD_ALLOW）
    "doubleclick.net", "ad.doubleclick.net",
    "pagead2.googlesyndication.com", "googleadservices.com", "www.googleadservices.com",
    # 低频历史广告域：自动发现的「首次出现/突发」抓不到，--auto 通道补漏
    # （2026-11-09 23:43 实测 lf3-ad.searchpstatp.com 预取广告素材）
    "lf3-ad.searchpstatp.com", "lf1-ad.searchpstatp.com",
    "p6-ad.searchpstatp.com",
    # RTA 实时竞价广告决策接口：精确域规则会漏编号变体（2026-11-10 00:35）
    "rta1.wesure100.com", "rta2.wesure100.com", "rta3.wesure100.com",
    # 2026-11-10 01:03 起同族主域整域收敛（www 于 01:00:55 首次出现）
    "www.wesure100.com", "zz-newrandom.wesure100.com",
    # 广告命名特征层（2026-11-10）：以下域名从未在日志里出现过，换编号 /
    # 换区域码 / 换 CDN 别名也必须第一次查询就拦。锁死「不追具体域名」
    # 这一行为，防止以后有人把特征层删掉或改窄而悄悄退化回枚举名单。
    "ads9-normal-zz.zijieapi.com",
    "ads7-normal-lq.zijieapi.com.brandnewcdn999.com",
    "v77-reading-ad.qznovelvod.com", "v88-reading-ad.douyinvod.com",
    "ec9-core-zz.ecombdapi.com", "ecom8-normal-zz.ecombdapi.com",
    "isaas9-normal-zz.ecombdapi.com", "p8-ad-foobar.byteimg.com",
    "p7-ad-sign.byteimg.com.futurecdn888.com", "p9-mgsdk-sign.byteimg.com",
    "rta9.wesure100.com", "lf9-mgsdk-x.dailygn.com",
    "stat9.deepinstall.com", "foo-adx-web.bar.cn",
    "sdk9.adx.newexchange.cn", "lf9-ad.zz.searchpstatp.com",
    "ads12-normal-qa.zijieapi.com.queniuzzz.com",
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
    # searchpstatp.com 是独立广告域，别把白名单里的 pstatp.com 视频 CDN 一起拦了
    "pull-l3-hs.pstatp.com", "aweme.snssdk.com",
    # 金融业务域：自动归因不得把「纯字母父域 + jump 命名」判成广告落地页
    # （2026-11-10 00:20 误拦 jump.m.cmbchina.*，已回滚并加护栏）
    "jump.m.cmbchina.cn", "jump.m.cmbchina.com",
    "netpay.cmbchina.com", "ccgateway.paas.cmbchina.com",
    # 广告触发时伴随出现的通用资源/素材通道：与正片共用 CDN，拦了会白屏。
    # 2026-11-10 00:35 实测 zt-dl* 与广告触发吻合率仅 10%，属 App 常规下载。
    "zt-dl-lf1.bytegslb.com",
    "lf-normal-gr-sourcecdn.bytegecko.com", "v26-reading-video.qznovelvod.com",
    # 特征层误伤护栏：名字里带 ad / adx，但属于系统服务或受保护业务父域。
    # 2026-11-10 回放 7216 个业务域 0 命中，这些是最容易写宽时踩到的。
    "api-adservices.apple.com", "ad-pic.amap.com",
    "modeldownload.taobao.com", "itunes.apple.com.download.ks-cdn.com",
    "promotion-2.pddpic.com", "www.cmbchina.com",
    "gateway.icloud.com", "www.apple.com",
    # 上游订阅层的「负集护栏」保护域：这些域被 anti-AD 等上游列为广告，但本
    # 项目日志证明它们是真实业务域（阿里/腾讯/苹果统计与推送），已并入允许集。
    # 验证订阅上游的同时零误伤。
    "ac.mmstat.com", "adashx.m.taobao.com", "aedns.weixin.qq.com",
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
