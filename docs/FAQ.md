# FAQ

## 装上描述文件后整机断网 / 图片不加载

先确认 443：`ServerURL` 里写 `:8443` 时，iOS 实测仍然连 **443**。
服务端必须在 443 上 `default_server` 且证书覆盖地址。检查：

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1/
journalctl -u hongguo-doh -n 30 --no-pager
```

另一类原因是域名版描述文件在 DNS 缓存过渡期解析不到，改用 IP 直连版即可。

## 为什么还有广告

按顺序排查：

1. **规则是不是真生效**：`tools/verify_rules.py` 真发 DoH 查询看返回 `0.0.0.0`。
2. **是不是随机子域轮换**：广告域像 `vuqsntdnsqqqnttqjnnbqq.jspcdn.cn` 这种
   每次生成新串。整域规则要写 `父域**` + `**.父域**` 两条。
3. **是不是白名单整域放行了广告子域**：用 `force-block.txt` 打例外。
4. **是不是 DNS 层根本看不见**：信息流原生广告由 feed API 在响应里下发，
   广告视频和正常视频共用 CDN；后台预缓存的素材冷启动时零 DNS 请求。
   这类只能掐追踪/线索/落地页链路，抹不掉卡片本身。
5. **是不是本地缓存**：改完规则刷几次仍出现， kill 掉 App 重开再试。

报漏拦时最好给**精确到分钟的时间窗**，服务端的时序日志能把那一刻
所有 `ALLOW` / `BLOCK` 拉出来对比，定位快得多。

## 能去掉别的 App 的开屏广告吗

能去一部分。描述文件是全局 DoH，所有 App 的 DNS 都走这个节点，
自动发现引擎里有「启动期突发」识别（冷启动头 8 秒集中解析的域标成疑似开屏），
实测抓到并拦掉了广点通、百度联盟、字节系视频广告域。

去不掉的是：广告由业务 API 在同一域名返回、素材和正常封面共用 CDN、
后台预缓存素材、以及"跳过"倒计时按钮。这些需要 MITM 按 URL 过滤，本项目不做。

## 会不会把正常功能拦坏

有护栏，但不能保证零误伤。项目自带的白名单覆盖内容 CDN、支付、时间服务、
API 网关；大厂父域命中公开名单只进人工审核；改解析器会先跑 `dga_dryrun.py`。
发现某个功能坏了，把域名加进 `whitelist.txt`（若被 `force-block.txt` 拦住，同时删掉），
改完立即生效。

## 证书会不会过期，要不要手动续

用 Let's Encrypt `shortlived` profile 签的 IP 证书约 6.5 天有效，
acme.sh 会按 ARI 窗口自动续期并 reload nginx，不需要手动操作。
确认 `crontab -l | grep acme.sh` 有输出即可。

## 20 个人用要多少资源

单设备约 1.5 小时 7495 条查询、0.35 MB DoH 流量；服务常驻约 29 MB 内存、
CPU 长期 < 3%。20 人平均带宽约 0.16 Mbps，1 核 1G 的小机器绰绰有余。

## 日志留多久、能看到具体哪个 App 吗

`watch/apps/<App>/<日期>-ok.tsv` 与 `-block.tsv` 按 App、按天、按结果分开，
默认 30 天；`doh_log.txt` 由 logrotate 管 14 天。
App 归类是基于域名指纹的推测（DNS 层看不到 PID），不是进程级事实。

## 多个人用会互相影响吗

不会。每人一个令牌，开关只作用于自己的 `/u/<token>/dns-query`。
共享广告规则是全局的（避免重启真空期漏拦），但个人开关关掉后
这台设备的所有查询都直接放行。

## 描述文件需要签名吗

不需要，未签名可以正常安装使用，iOS 只显示"未签名"。
签名要 Apple Developer 账号；免费 Apple ID 签的证书 7 天过期，
对长期分发没实际意义。本项目不提供签名服务。

## 能开源吗 / 为什么仓库里没有完整名单

能，本项目是 MIT。仓库里**不分发**上游名单文件或合并快照：
`autodetect.py` 在运行时按需下载（anti-AD MIT、oisd、AdGuard DNS Filter GPL-3.0），
只在本地做比对。这样既不把几十 MB 名单塞进 Git 历史，也避免上游许可的再分发问题。
使用者若要再分发合并名单，需自行遵守各上游许可与署名要求。

## 我 Fork 之后要改哪些地方

1. `.env.example` / systemd 里的 `DOH_BASE_URL` → 你的地址。
2. `config/nginx-hongguo-doh.conf.example` 里的证书路径。
3. 申请覆盖你 IP（或域名）的证书。
4. `examples/install-page.html` 与二维码里的地址。
5. `rules/` 按你的 App 组合调整，先跑 `verify_rules.py`。

不要提交：`users.json`、任何 `*.log` / `*.tsv`、带值的凭据文件、
含真实地址的 `.mobileconfig`、证书私钥、备份文件。
凭据只走环境变量或**项目之外**的私有文件（见 `.env.example`），
不要放进仓库目录。`tools/check_before_push.py` 会替你检查。
