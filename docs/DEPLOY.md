# 从零部署

以 Ubuntu 22.04 / Debian 12 + 一台有公网 IPv4 的 VPS 为例。全部命令可顺序执行，
**唯一必须改的是最上面 `SERVER_IP` 那一行的值**（示例用的是 RFC 5737 文档地址 `203.0.113.10`）。

> 前提：安全组 / 防火墙放行 TCP 80、443。80 只在申请/续期证书时需要。

```bash
export SERVER_IP="203.0.113.10"          # ← 改成你的公网 IP
export DEPLOY_DIR="/opt/hongguo-doh"
sudo mkdir -p "$DEPLOY_DIR"/{watch/apps,logs,public-blocklists} /var/www/hongguo
```

## 1. 装依赖、放文件

```bash
sudo apt update && sudo apt install -y nginx python3 curl ca-certificates
sudo cp src/*.py "$DEPLOY_DIR"/
sudo cp rules/*.txt "$DEPLOY_DIR"/
sudo cp examples/profile.template.mobileconfig "$DEPLOY_DIR"/ 2>/dev/null || true
sudo chown -R www-data:www-data "$DEPLOY_DIR"
```

服务本体只用 Python 标准库。`autodetect.py` 也只用标准库（`urllib`）。
`tools/ecs_run.py` 是可选的阿里云运维助手，需要时才 `pip install alibabacloud_ecs20140526`。

## 2. TLS 证书（IP 地址证书）

iOS 的 `ServerURL` 要求 HTTPS 且证书必须覆盖地址。两种选择：

### 2a. 用 IP 直连（推荐，不依赖域名解析）

Let's Encrypt 支持给**公网 IP**签短期证书，必须使用 `shortlived` profile + HTTP-01：

```bash
curl https://get.acme.sh | sh -s email=admin@example.com
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

# 80 端口先给 ACME 校验用（临时配置，装完证书会被 nginx 正式配置覆盖）
sudo mkdir -p /var/www/html/.well-known/acme-challenge
sudo tee /etc/nginx/sites-available/00-acme.conf >/dev/null <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    location /.well-known/acme-challenge/ { allow all; }
    location / { return 404; }
}
NGINX
sudo ln -sf /etc/nginx/sites-available/00-acme.conf /etc/nginx/sites-enabled/00-acme.conf
sudo nginx -t && sudo systemctl reload nginx

~/.acme.sh/acme.sh --issue --server letsencrypt --profile shortlived \
  -d "$SERVER_IP" --webroot /var/www/html --force

sudo mkdir -p /etc/nginx/tls
~/.acme.sh/acme.sh --install-cert -d "$SERVER_IP" \
  --cert-file /etc/nginx/tls/cert.pem \
  --key-file  /etc/nginx/tls/key.pem \
  --fullchain-file /etc/nginx/tls/fullchain.pem \
  --reloadcmd "systemctl reload nginx"
```

短期证书约 6.5 天有效，acme.sh 会按 ARI 窗口自动续期（安装时已写入 crontab）。
确认续期任务存在：

```bash
crontab -l | grep acme.sh
```

### 2b. 用自有域名

域名先 A 记录指向 `$SERVER_IP`，然后按普通 `--issue -d doh.example.com --webroot` 申请，
再把下面 nginx 配置里的 `server_name _` 换成域名。注意域名版描述文件在 NS 切换 /
运营商 DNS 缓存过渡期会短暂失效，IP 直连版没有这个问题。

## 3. nginx

`config/nginx-locations.conf.example` 是共享的 location 片段，
`config/nginx-hongguo-doh.conf.example` 是 server 块。把示例里的证书路径确认后安装：

```bash
sudo cp config/nginx-locations.conf.example /etc/nginx/snippets/hongguo-doh-locations.conf
sudo cp config/nginx-hongguo-doh.conf.example /etc/nginx/conf.d/99-hongguo-doh.conf
sudo nginx -t && sudo systemctl reload nginx
```

关键约定（都在示例配置里）：

- **443 必须是 `default_server` 且带证书**：iOS 实测会忽略 `ServerURL` 里的非标端口，
  写 `:8443` 时手机实际连 443。只监听 8443 会导致整机"DNS 全挂"（图片不加载、App 报网络错误）。
- `80` 保留 `/.well-known/acme-challenge/` 给证书续期。
- 所有动态路径 `proxy_pass http://127.0.0.1:5053`，附带 `X-Real-IP` 供日志分流。
- `/candidates` 与 `/cand/` 是自动发现引擎的审核页，别漏配，否则点按钮 404。

安装页（用户领描述文件的入口）：把 `examples/install-page.html` 放到 `/var/www/hongguo/index.html`，
把里面的 `DOH_BASE_URL` 换成 `https://$SERVER_IP`。

## 4. systemd

```bash
sudo cp config/hongguo-doh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hongguo-doh
systemctl is-active hongguo-doh
journalctl -u hongguo-doh -n 20 --no-pager
```

启动时日志会打印四层规则各自的条数，以及 `watch` 开关状态。
环境变量在 service 文件里设置，至少需要：

```ini
Environment=DOH_BASE_URL=https://203.0.113.10
```

其它可选项见 `.env.example`。

## 5. 自动发现引擎

```bash
sudo cp config/crontab.example /etc/cron.d/hongguo-autodetect
sudo chmod 644 /etc/cron.d/hongguo-autodetect
```

内容等价于：

```cron
*/30 * * * * root flock -n /tmp/autodetect.lock /usr/bin/python3 /opt/hongguo-doh/autodetect.py >> /opt/hongguo-doh/autodetect.log 2>&1
```

首次运行会下载三份公开名单（约 22.5 万域），给足 3 分钟：

```bash
cd "$DEPLOY_DIR" && timeout 280 python3 autodetect.py
python3 tools/dga_dryrun.py     # 第一次部署建议先看收敛结果会不会误伤
```

## 6. 日志轮转

```bash
sudo cp config/logrotate.example /etc/logrotate.d/hongguo-doh
sudo logrotate -d /etc/logrotate.d/hongguo-doh
```

## 7. 验收

```bash
# 页面
curl -sk -o /dev/null -w 'index=%{http_code}\n'      https://127.0.0.1/
curl -sk -o /dev/null -w 'candidates=%{http_code}\n' https://127.0.0.1/candidates
curl -sk -o /dev/null -w 'users=%{http_code}\n'      https://127.0.0.1/users

# 真实 DoH 查询（A 记录，被拦时应答 0.0.0.0）
python3 tools/verify_rules.py

# 服务直连
curl -s 'http://127.0.0.1:5053/dns-query' -o /dev/null -w 'direct=%{http_code}\n'
```

然后手机浏览器打开 `https://$SERVER_IP/`，点「领取我的专属描述文件」，
按 iOS 提示到「设置 → 通用 → VPN 与设备管理」安装。装完即可，
**不需要重启服务、不需要重装描述文件**——改规则是 mtime 热加载。

## 排障速查

| 现象 | 检查 |
|---|---|
| 装完描述文件整机断网 | 443 没监听 / 证书不覆盖地址 / 上游 DNS 不通；先看 `journalctl -u hongguo-doh` |
| 手机能上网但统计一直是 0 | 描述文件没生效，或 `ServerURL` 写了非标端口（iOS 走 443） |
| `/candidates` 404 | nginx 片段缺 `location = /candidates` 与 `location ~ ^/cand/` |
| 规则改了没生效 | 行内注释污染规则串；注释必须独立成行 |
| 随机子域广告漏拦 | 整域收敛要写 `父域**` + `**.父域**` 两条 |
| 桌面没出现图标 | Web Clip 的 `PayloadType` 必须是 `com.apple.webClip.managed`（大写 C） |

更多见 [IOS_PROFILE.md](IOS_PROFILE.md)、[RULES.md](RULES.md)、[FAQ.md](FAQ.md)。
