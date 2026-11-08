# -*- coding: utf-8 -*-
"""生成「DNS 拦截 + Web Clip 桌面图标」合并版描述文件"""
import base64, os

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
icon_b64 = base64.b64encode(
    open(os.path.join(PROJ, "profiles", "webclip-icon.png"), "rb").read()
).decode()

TPL = """<?xml version="1.0" encoding="UTF-8"?>
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
\t\t\t\t<string>https://203.0.113.10/dns-query</string>
\t\t\t</dict>
\t\t\t<key>PayloadDescription</key>
\t\t\t<string>把本机 DNS 指向自建 DoH 节点（纯 IP 直连，不依赖任何域名解析），拦截红果短剧广告域名。删除本描述文件即可完全恢复原状。</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>红果短剧去广告 · DNS(IP直连)</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>com.example.hongguo.dns.ip443</string>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.dnsSettings.managed</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>C5D1E7F2-8A30-4B96-9E14-6F2C0D85B3A9</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t</dict>
\t\t<dict>
\t\t\t<key>Icon</key>
\t\t\t<data>{ICON}</data>
\t\t\t<key>IsRemovable</key>
\t\t\t<true/>
\t\t\t<key>FullScreen</key>
\t\t\t<true/>
\t\t\t<key>Precomposed</key>
\t\t\t<true/>
\t\t\t<key>Label</key>
\t\t\t<string>红果去广告</string>
\t\t\t<key>URL</key>
\t\t\t<string>https://203.0.113.10/stats</string>
\t\t\t<key>PayloadDescription</key>
\t\t\t<string>桌面图标：点开查看实时拦截数据</string>
\t\t\t<key>PayloadDisplayName</key>
\t\t\t<string>红果去广告</string>
\t\t\t<key>PayloadIdentifier</key>
\t\t\t<string>com.example.hongguo.webclip.stats</string>
\t\t\t<key>PayloadType</key>
\t\t\t<string>com.apple.webClip.managed</string>
\t\t\t<key>PayloadUUID</key>
\t\t\t<string>E4A7B29C-1D56-4F83-B2E0-9C37D5A16F84</string>
\t\t\t<key>PayloadVersion</key>
\t\t\t<integer>1</integer>
\t\t</dict>
\t</array>
\t<key>PayloadDescription</key>
\t<string>把本机 DNS 指向自建 DoH 节点（纯 IP 直连），拦截红果短剧广告域名；并在桌面放置「红果去广告」图标，点开查看实时拦截数据。删除本描述文件即完全恢复原状。</string>
\t<key>PayloadDisplayName</key>
\t<string>红果短剧去广告(IP直连)</string>
\t<key>PayloadIdentifier</key>
\t<string>com.example.hongguo.ip443</string>
\t<key>PayloadOrganization</key>
\t<string>hongguo-adblock</string>
\t<key>PayloadRemovalDisallowed</key>
\t<false/>
\t<key>PayloadType</key>
\t<string>Configuration</string>
\t<key>PayloadUUID</key>
\t<string>D8B3F6A1-5E72-4C09-A83F-1B94E6C2D705</string>
\t<key>PayloadVersion</key>
\t<integer>1</integer>
</dict>
</plist>
"""

out = TPL.replace("{ICON}", icon_b64)
dest = os.path.join(PROJ, "profiles", "红果去广告-IP直连版.mobileconfig")
with open(dest, "w", encoding="utf-8") as fh:
    fh.write(out)
print("written", dest, len(out), "bytes")
