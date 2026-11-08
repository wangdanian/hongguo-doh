# iOS 描述文件

## Payload 结构

一份描述文件里放两个 payload，一次安装同时得到「全局 DNS」和「桌面图标」：

```xml
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key><string>HTTPS</string>
        <key>ServerURL</key><string>https://203.0.113.10/u/&lt;token&gt;/dns-query</string>
      </dict>
      ...
    </dict>
    <dict>
      <key>PayloadType</key><string>com.apple.webClip.managed</string>
      <key>URL</key><string>https://203.0.113.10/u/&lt;token&gt;</string>
      <key>Icon</key><data>&lt;PNG base64&gt;</data>
      <key>IsRemovable</key><true/>
      ...
    </dict>
  </array>
</dict>
```

`src/doh_server.py` 的 `build_profile(token)` 动态生成；`src/gen_profile.py` 是离线版生成器
（适合不想跑服务、只想手工造一份文件的场景）。`examples/profile.template.mobileconfig`
是不含任何真实地址的模板。

## 实测踩过的坑

### 1. iOS 会忽略 ServerURL 里的非标端口（最关键）

把 `ServerURL` 写成 `https://203.0.113.10:8443/dns-query` 后，服务端 8443 开着、
nginx 也配了，但手机**实际连的是 443**。表现是整机 DNS 全故障：网页图片不加载、
App 报"网络异常"、服务端日志完全没有该设备的查询记录。

抓包确认后，在 443 上加一个 `default_server` 并挂同一份证书，**同一份描述文件立刻恢复正常**。
结论：服务端必须在 443 提供 DoH，8443 只能作为额外的兼容端口。

### 2. Web Clip 的 PayloadType 大小写

`com.apple.webclip.managed`（全小写）安装时会报「未知有效载荷」，桌面不出现图标。
正确值是 **`com.apple.webClip.managed`**，C 必须大写。

### 3. 描述文件签名

- 未签名的描述文件可以正常安装使用，iOS 只是显示"未签名"，功能不受影响。
- 想签名需要 Apple Developer 账号的签名证书。免费 Apple ID 签出来的证书 7 天过期，
  对长期分发的描述文件没有实际意义。
- 本项目**不提供**签名、不代生成账号、不扫描他人凭据。需要签名时用自己的开发者账号自行签。

### 4. PayloadUUID / PayloadIdentifier

每份描述文件的 `PayloadIdentifier` 建议带令牌后缀（`...dns.<token>`），
这样多人装同一个链接时不会互相覆盖。UUID 用 `uuid.uuid4()` 每次重生成，
或像 `gen_profile.py` 那样固定（固定 UUID 会导致重复安装时被识别为同一份文件，
适合单人场景）。

### 5. 域名版 vs IP 直连版

域名版 `ServerURL` 依赖系统先解析这个域名。在 NS 切换、运营商 DNS 缓存旧记录、
IPv6 前缀变化的过渡期，可能出现"装完描述文件整机断网"。
**IP 直连版**（`https://<公网IP>/...`）不依赖任何域名解析，是本项目默认方案，
代价是证书必须是覆盖该 IP 的 IP 地址证书，见 [DEPLOY.md](DEPLOY.md)。

### 6. 删除即恢复

描述文件是系统级 DNS 设置，删除后立刻回到运营商 DNS，不留残留。
项目里的开关页只是服务端门控（`users.json` 里 `enabled`），
关掉开关后 DNS 查询照常转发、只是不再套用拦截规则，别人不受影响。

## 多用户流程

```
手机浏览器打开 https://<地址>/
   └─ 点「领取我的专属描述文件」→ GET /issue
        └─ secrets.token_urlsafe(9) 生成令牌，默认 enabled=True
             ├─ 返回一份带该令牌的 .mobileconfig
             └─ 桌面 Web Clip 指向 /u/<token>（自己的开关页）

开关页 /u/<token>
   ├─ 大按钮：开 / 关过滤（带 onsubmit 二次确认，防误触）
   ├─ 清除我的记录：/u/<token>/reset
   └─ 刷新数据：/u/<token>
```

令牌即身份凭证，请当作密码保管。`/users` 后台列出所有令牌与统计，
生产环境建议给 `/users`、`/candidates` 加 HTTP Basic Auth 或 IP 白名单
（在 `config/nginx-locations.conf.example` 里取消注释即可）。

## 安装页与二维码

把 `examples/install-page.html` 放到 `/var/www/hongguo/index.html`，
用任意二维码生成器把 `https://<地址>/` 做成二维码即可分发。
二维码图片含真实地址，**不要提交进仓库**（`.gitignore` 已排除 `install-qr.png`）。
