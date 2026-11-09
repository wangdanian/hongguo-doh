# Changelog

本项目的开发历程按功能阶段记录。版本号以 GitHub Release / tag 为准。

## 0.1.3 · 无人值守自动归因闭环

- `src/ad_feedback.py` 新增 `--auto`：cron 每 5 分钟扫最近 6 分钟放行日志，
  自动拦确凿广告域，不再需要用户报时刻或点「一键归因」按钮
- 修复 23:43 漏点 `lf3-ad.searchpstatp.com`：11-06 出现过 2 次、
  23:41:46 又预取 2 次，低频历史广告域永远进不了「首次出现 / 突发」通道。
  补精确域规则 + `*-ad.searchpstatp.com**` 覆盖 lf1/lf3/p6 编号变体
- 白名单命中的广告子域自动改写 `force-block.txt`（优先级高于白名单），
  避免规则写了却被父域白名单架空；`--json` 输出保持纯净
- 流式读日志 + 时间戳字符串比较：单次 9.5s / 330MB → 1.4s / 28MB，
  小内存机器也能每 5 分钟跑
- 护栏：窗口内 ≥2 次、分数 ≥8、陌生父域 + 广告命名特征、保护父域分流、
  每次最多 2 条 / 每天最多 20 条、只写精确域、`# feedback:` 可整段回滚
- 规则同步至 431 条。真实 DoH 查询验证：广告域返回 `0.0.0.0`，
  `pull-l3-hs.pstatp.com` 视频 CDN 与 `aweme.snssdk.com` 正常解析

## 0.1.2 · 广告反馈自动归因闭环

- 新增 `src/ad_feedback.py` 与 `/feedback` 页面：看到广告时点一下（或带
  `?at=23:07`），回溯前 6 分钟放行日志、与近 3 天基线比对，自动找出
  首次出现 / 突发 / 陌生父域的域并写拦截规则，报告落 `ad-feedback.json`
- `/candidates` 页新增「一键自动归因并拦截」入口，不用再口头报时刻
- 修复自动发现的结构性盲区：打分器靠广告关键词，像
  `cf-gl.qiezibenpao.com` / `sdkgen.data.tianwenca.com` 这类纯拼音随机
  父域一个关键词都没有，永远进不了候选队列（实测 64 次查询、5 台设备
  从凌晨放行到晚上）。新增 `auto_stranger_parents()` 严格护栏通道：
  所有子域标签都带广告/SDK 特征、父域标签无业务语义、查询 8~120 次、
  2 台以上设备、显式排除大厂业务父域
- 候选队列上限 30 → 60，避免低分新域被「保护父域待确认」噪声挤出
- 自动拦截阈值收紧：必须同时满足陌生父域 + 广告命名特征 + 分数 ≥8；
  反馈归因只写精确域，父域整域收敛只走自动发现的严格护栏
- 共享规则同步至 428 条；业务父域误伤检查 0 命中，
  `verify_rules.py` 67 个域 FAILED=0

## 0.1.1 · 广告 SDK 马甲自动收敛与 DNS 缓存窗口

- 修复广告 SDK 去掉 `-sign` 后缀的子域漏拦（`lf3-mgsdk.dailygn.com` 一类）
- `autodetect.py` 新增 B 级高置信候选自动晋升（`AUTO_APPROVE_RE`）：
  明确是广告专用子域的域不再需要人工点 `/candidates`
- 新增保守父域收敛：某父域下所有现有子域均已被拦时自动写整域规则，
  防换前缀 / 换后缀的新马甲；`NO_COLLAPSE` 排除 `alibaba.com`、
  `volces.com` 等业务父域，dry-run 确认零新增误伤
- `doh_server.py` 新增 `DNS_TTL_CAP = 60` 与 `clamp_answer_ttl()`：
  放行应答 RR TTL 压到 ≤60 秒，规则变更后客户端旧缓存窗口从最长 1 小时缩到 1 分钟
- 共享规则同步至 371 条；`verify_rules.py` 扩到 67 个域，线上实测 FAILED=0

## 0.1.0 · 开源首个版本

- 抽出可公开的源码、规则、部署配置与文档，凭据与运行期数据全部外置
- 新增 `tools/check_before_push.py` 发布前敏感信息自检
- 新增 CI：编译检查、规则语法检查、敏感信息扫描
- 补齐 MIT 许可、贡献指南、Issue / PR 模板
- 明确上游公开名单只在运行时下载，仓库不分发名单快照

## 0.4 · 自动发现引擎与随机子域收敛

- `autodetect.py`：cron 每 30 分钟自动发现广告域
  - 公开名单（anti-AD / oisd-small / AdGuard DNS Filter）与真实查询日志取交集
  - 字节系广告指纹、电商广告指纹、广告线索组件、广点通 / 百度联盟确凿子域
  - 启动期突发识别（冷启动头 8 秒），候选页打「疑似开屏」标记
  - DGA 随机子域收敛：从真实日志识别新注册马甲域，一次写两条整域规则
  - `/candidates` 审核页一键拦截 / 放行
- 护栏：`PROTECT_PARENTS`、`NO_COLLAPSE`、`_dga_word()` 反例过滤、
  `PUB_VER` 解析器版本号缓存失效、dry-run 工具
- 修正规则写入格式：注释独立成行、整域收敛两条规则

## 0.3 · 多用户与桌面图标

- `/issue` 动态签发令牌，每人专属描述文件、独立开关页
- `users.json` 持久化（内存 + 定时落盘），`/users` 后台
- Web Clip 合并进描述文件（`com.apple.webClip.managed`）
- 开关页加二次确认、清除记录、刷新按钮
- `/stats` 状态页、安装二维码

## 0.2 · 全局 DoH 与日志分流

- 从「只拦红果」扩展到全局 DoH（描述文件接管整机 DNS）
- `watch.py` 按 App、按天、按放行/拦截分流日志，`APP_MAP` 域名指纹归类
- 共享名单改为常开，消除服务重启后的拦截真空期
- 强制拦截例外层 `force-block.txt`（优先级高于白名单）

## 0.1 · IP 直连版

- Let's Encrypt `shortlived` profile 给公网 IP 签证书，acme.sh 自动续期
- 确认 iOS 忽略 `ServerURL` 非标端口，服务端补 443 `default_server`
- 纯标准库 DoH 服务、四层规则、mtime 热加载、nginx 反代、systemd 单元
