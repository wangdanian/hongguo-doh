# Changelog

本项目的开发历程按功能阶段记录。版本号以 GitHub Release / tag 为准。

## 0.1.11 · 补齐字节/穿山甲广告拦截 + 白名单误放行修复 + SSH 直部署

- **红果广告真根因是字节/穿山甲体系，不是百度**。实测线上 DoH 端点：百度系早已全 BLOCK，
  漏网的是字节广告 SDK 与穿山甲(Pangle)——`is.snssdk.com` / `ad.snssdk.com`（广告配置/SDK
  初始化主通道）、`pangolin.pangle.io` / `ad.pangle.io` / `aduser.pangle.io` /
  `pangle.hoyoverse.com` / `c.pangle.cn`、`ad.kuaishou.com` 系、`ad.qq.com` / `union.qq.com`。
  已在 `rules/blacklist-shared.txt` 显式补齐。
- **致命 bug：`whitelist.txt` 第 98 行 `snssdk.com` 整段白名单**（白名单优先级高于黑名单），
  把 `is.snssdk.com` 广告 SDK 也一并放行。已删除该条——视频域 `v*` / `ib*` / `aweme*` 等
  不在黑名单，删后仍为默认放行，**不影响看剧**；仅 `is/ad/adx/ace.snssdk.com` 被拦。
- **部署去云助手化**：新增 `deploy/hongguo-doh.{service,path,restart.service}`——
  `hongguo-doh.path` 监控 `doh_server.py` 变化后自动重启，改代码落地即生效，不再依赖阿里云
  云助手 RunCommand API（之前因限流导致改完没立刻生效）。`doh_server.py` 加 SIGHUP 信号做
  零中断规则重载；`fetch_upstream.py` 聚合写盘后自动 `systemctl reload`。
- 实测：字节/百度/快手/腾讯/穿山甲广告域全 BLOCK；`aweme.snssdk.com`/`www.douyin.com`/
  `www.baidu.com` 等业务域正常 ALLOW，无连带误伤。

## 0.1.10 · 修复上游允许集父域误放行广告子域（baidu / shifen 等）

- **根因**：上游层（anti-AD）把 `baidu.com` 这类裸父域放进了允许集，而
  `doh_server.py` 对允许集做**父域匹配**——于是 `baidu.com` 在允许集里，旗下所有
  `*.baidu.com`（含 `ada` / `adavideo` / `as` / `cpro` / `eclick` / `union` /
  `wm` 等确属广告/联盟的子域，上游 block 里共 241 条）被整段放行。另：负集护栏
  把"日志里只放行、从不拦截"的域（含被父域误放行的广告子域）学成白名单，形成正反馈环路。
- `src/fetch_upstream.py`：
  - `_strip_adguard` 对 `@@||x.com^` 例外去掉 `@@` 的同时也去掉 `||` 前缀，存成
    干净后缀，避免 `||baidu.com` 这种脏值让护栏与父域匹配都识别不到。
  - 负集护栏新增**广告父域过滤**：统计每个 2 段父域下被上游收录的"被拦子域"数量，
    ≥5 视为广告网络（本次识别 527 个），其下的负集域一律**保持被拦、不加白**，
    既不再误放行广告子域，也不再因加白父域而连带放行整族。允许集从 7572 降到 6245。
  - 既有宽父域护栏（剔除 `@@` 例外中与 block 冲突的父域）保留并互补。
- `src/doh_server.py`：上游允许集覆盖逻辑改为"更具体者胜"——允许命中若是拦截命中的
  **父域（更宽，如 `baidu.com` 之于 `ada.baidu.com`）则拦截优先**，不再放任父域例外
  把旗下广告子域整段放行；允许命中同级或更具体（确凿的 `@@` 例外）才放行；手工白名单
  始终最高优先，不受影响。
- `rules/blacklist-shared.txt`：补 `mobads.baidu.com**` / `mobads.e.shifen.com**`（百度移动广告主域，上游未收录、手工规则优先级即时止血）。
- 实测（IP 直连端点 `118.178.183.90`）：`ada/adavideo/as/cpro/eclick/union/wm/mobads`
  等百度广告子域全部 BLOCK；`www/pan/m/map/tieba.baidu.com` 与 apple/taobao/qq/google
  等大站正常 ALLOW，`verify_rules.py` 全量回归 `FAILED=0 / 116`。

## 0.1.9 · 订阅社区聚合名单（上游层）+ 零误伤护栏

- 调研 GitHub 同类开源方案，结论：**本项目没有闭门造车**。签名层
  (`rules/ad-signatures.txt`) 与 anti-AD / hagezi 的「通配 / 正则一类一拦」思路
  完全同构；但「手搓名单追不上广告换域名」的正确解法是**订阅上游聚合名单自动日更**，
  这正是业界标准做法（anti-AD 每日 GitHub Actions 刷新、hagezi 4~8h、CMU WWW'22
  论文把「轮转/换域名」列为 filter list 最大盲区，对策 = 通配 + 订阅 + 自动监测）
- 新增 `src/fetch_upstream.py`：订阅 anti-AD（`anti-ad.net/easylist.txt`，国内 CDN，
  约 9.6 万条，每日刷新），归一化成本项目 `后缀哈希 + 通配` 格式，原子落盘到
  `upstream-block.txt` / `upstream-allow.txt`。`doh_server.py` 判定链末级加入上游层
  `force > whitelist > signatures > blacklist > shared > upstream`，
  上游集按 mtime 热加载，无需重启；后缀哈希 O(域名层级) 查询，与名单大小（数十万）无关
- **零误伤护栏（关键）**：anti-AD 是「宁可错杀」调性，裸订阅会拦掉用户真实在用的
  业务/基础设施域（`api-adservices.apple.com`、`ac.mmstat.com`、
  `adashx.m.taobao.com`、`aedns.weixin.qq.com` 等）。`fetch_upstream.py` 从本地
  `doh_log.txt` 计算「出现且从未被拦」的业务域（负集），聚合后从上游拦截集剔除并
  显式并入允许集；实测 9.6 万条上游净增，同时 **269 个业务域误伤 → 0**
- 顺带暴露并修复手工规则的双用途误伤：本项目 own `rules/blacklist-shared.txt` 把
  阿里统计域 `mmstat.com` 整族拦了（`ac.mmstat.com` 是淘宝/支付宝统计，App 崩）。
  已移除共享名单全部 `mmstat.com` 拦截规则，并把 5 个确属双用途的基础设施父域
  (`mmstat.com` / `cnzz.com` / `getui.net` / `51y5.net` / `alibabadns.com`) 加白名单
- 新增 `config/crontab.example` 中 `fetch_upstream.py` 每日 03:15 刷新条目（已装入
  ECS root crontab），配合 `doh_server` 热加载实现「换域名」类广告的无人值守兜底覆盖
- `tools/verify_rules.py` 新增上游层回归断言：上游广告域（`doubleclick.net`、
  `pagead2.googlesyndication.com`、`googleadservices.com` 等）必须 BLOCK；负集保护域
  (`ac.mmstat.com`、`adashx.m.taobao.com`、`aedns.weixin.qq.com`) 必须 ALLOW。
  公网真机验证（正确端点 `doh.niange.top:8443`）**FAILED=0/116**

## 0.1.8 · 从「枚举域名」改为「命名特征判定」

- 结构性诊断：近 7 天 1005122 条查询、988734 条放行 / 7514 个唯一域 /
  885 个父域，每天新增 476~1192 个域；但新增的绝大多数是 CDN 随机子域和
  别名外壳，广告标识本身不变。现有 445 条规则里 `jspcdn.cn` 51 条、
  `zijieapi.com` 45 条全是同族编号变体 —— 按域名一条条补，永远追不上
- 新增 `rules/ad-signatures.txt`（14 条）与 `load_signatures()`：一行是一条
  **命名结构**（编号、区域码、CDN 别名后缀可任意变），不是见过的域名。
  判定链改为 `force > whitelist > signatures > blacklist > shared`，白名单
  仍最高优先，特征层 mtime 热加载，文件不存在时行为与旧版完全一致。
  新广告域名第一次出现即拦，不需要先见过、不需要更新名单
- 回放护栏：2026-11-04~11-10 全部日志、7216 个从未被拦的业务域，
  14 条特征 **0 误伤**，同时额外覆盖 19 个历史漏网广告域。真发 DoH 验证
  17 个从未出现过的「未来域名」（`ads9-normal-zz.zijieapi.com`、
  `v77-reading-ad.qznovelvod.com`、`p8-ad-foobar.byteimg.com`、
  `ads12-normal-qa.zijieapi.com.queniuzzz.com` 等）全部返回 `0.0.0.0`；
  `api-adservices.apple.com`、`ad-pic.amap.com`、`modeldownload.taobao.com`、
  银行域 / 正片域照常解析
- 新增 `src/signature_report.py`：回放体检 + 自动归纳。从「已拦域 + 带强
  广告语义的漏网域」把数字段泛化成通配特征，护栏为业务域 0 误伤 /
  必须含强广告标记 / 白名单父域跳过 / 只保留现有特征尚未覆盖的变体 /
  每次最多 2 条、每天最多 10 条；带 `# auto:sig:` 注释可整段回滚。
  cron 每天 04:10 运行
- 修复 01:30 `autodetect` 误拦银行域：`auto_stranger_parents` 把
  `jump.m.cmbchina.cn` 的 `jump` 当成广告 SDK 标签，整域收敛了
  `cmbchina.cn`。已回滚两条规则；`PROTECT_PARENTS` 补金融 / 支付 / 政务 /
  身份父域，新增 `SENSITIVE_PARENT_RE` 语义兜底，`AD_LABEL` 去掉
  `jump|click|h5|lp-`，`KNOWN` 补 `cmbchina.*`。回归测试确认银行域不再被
  收敛，同时真实广告父域通道仍可正常收敛（通道没有被护栏废掉）
- `verify_rules.py` 加入「未来域名必须拦」与「名字带 ad 的业务域必须放行」
  两组回归断言；线上 `FAILED=0/109`，规则 446 条 + 特征 14 条

## 0.1.7 · DNS 边界定性结论与竞价平台主域收敛

- 01:03 归因实证：窗口内拦截 109 条、其中 59 次广告请求（按秒去重），
  放行 4361 条 / 833 个域，没有出现新的陌生广告域。三个在用令牌全部
  `enabled=true`，每台设备在该窗口都有 BLOCK 记录，排除「某台设备没生效」
- 用「用户报障的 6 个时刻 ±90 秒」做标注复核全部 833 个放行域：集中度最高
  仅 0.33，且都是 Apple/业务域；`*-gr-sourcecdn.bytegecko.com` 只有 0.11，
  与正片域同一水平。广告素材不是靠某个漏网域当场拉取的，而是提前预取或
  随信息流 API 混排下发，和正片共用同一批 CDN 域名
- 顺手排除「别名域绕过」：所有 `ecombdimg` 广告图别名（`.queniu*` /
  `.cdnhwc1` / `.kunluncan`）最后一次放行停在 2026-11-08 23:16:48，
  11-09 起 0 条；`p3-aio.ecombdimg.com.queniusy.com` 实测返回 `0.0.0.0`
- 归因报告新增 `verdict` 定性结论（`dns_exhausted` / `rule_added` /
  `candidates` / `no_signal`），`/feedback` 页面顶部直接显示结论卡片；
  0 动作不再看起来像「系统没干活」。伴随通道新增 `whitelisted` 标记，
  列出被 `bytegecko.com` 等整域白名单保护的素材域，说明看到了但不动的原因
- 规则收敛 `wesure100.com**` / `**.wesure100.com**`：`rta1/2/3` 已确认是 RTA
  实时竞价接口，`www.wesure100.com` 于 01:00:55 首次出现，同族主域一并覆盖。
  线上规则 445 条；实测 `www.wesure100.com`、`rta2`、广告图别名全部
  `0.0.0.0`，正片域 / `jump.m.cmbchina.cn` / `gateway.icloud.com` 正常解析
- `tools/verify_rules.py` 把 `www.wesure100.com` 从放行断言移到拦截断言，
  并增加随机子域断言，防止整域规则退化

## 0.1.6 · 广告触发信号与伴随通道归因

- 修掉自动归因的结构性盲区：此前只读放行日志 `ok.tsv`，广告域一旦被拦，
  归因窗口里剩下的全是 CDN 调度域、分数全低、0 动作，系统看起来像没干活
  （2026-11-10 00:35 实证）。现改为反向按 1MB 块读 `doh_log.txt`，
  把窗口内命中广告规则的 BLOCK 记录识别为「广告触发」，并把触发前后
  5 秒放行的域列成「容器 / 素材通道」。实测单次 1.2 秒 / 32MB，
  每 5 分钟跑一次无压力
- 00:35 窗口复演：拦截 97 条、广告相关 54 条、伴随通道 25 个、
  自动动作 0（不乱拦）。伴随域多为 `sourcecdn.bytegecko.com`、
  抖音/西瓜直播 CDN、`snssdk.com` 网关等与正片共用的通道，
  拦掉会白屏，因此只报告不自动写规则
- `/feedback` 页面新增「广告触发信号」区块，直接显示拦截条数、触发域、
  伴随通道清单，并对共用 CDN 的域做标注；命令行输出同步增加三个计数
- 触发按 `(秒, 域)` 去重，A / AAAA / HTTPS 三条查询不再算成三次广告；
  `COMPANION_RE` 收紧 `sdk` 匹配，避免把 `aweme.snssdk.com` 误标成素材域
- 规则补 `rta*.wesure100.com**`（RTA 实时竞价广告决策接口的编号变体，
  此前只拦 `rta2` 精确域）；线上 441 条。实测 `rta1/rta2/rta3` 返回
  `0.0.0.0`，`www.wesure100.com`、`aweme.snssdk.com`、正片域正常解析
  （`www.wesure100.com` 自 0.1.7 起随竞价平台主域收敛一并拦截）
- `tools/verify_rules.py` 增加 3 个 RTA 变体拦截断言 + 4 个伴随通道放行断言，
  把「不能拦的通用 CDN」写进回归测试，防止以后自动闭环误伤

## 0.1.5 · 分享安装按钮与僵尸令牌治理

- 开关页（WebClip 桌面图标点开的页面）新增「分享给朋友」按钮：展开面板里
  有邀请链接、复制链接、系统分享（`navigator.share`）和邀请二维码。
  分享链接固定为 `/invite`，**不含任何令牌**，对方领到的是自己独立的
  描述文件与开关，碰不到分享者的开关和统计
- 新增 `/invite` 邀请安装页（Safari 打开提示、四步安装说明、领取按钮、二维码），
  nginx 片段补 `/invite` 反代（顺手补齐遗漏的 `/feedback`）
- 二维码用可选依赖 `segno` 生成内联 SVG，未安装时自动降级为纯链接，
  部署文档补安装命令与 nginx 注意事项
- `/issue` 加空令牌复用：1 小时内已签发、从未使用过的令牌直接复用，
  避免反复点「领取描述文件」堆积僵尸用户（2026-11-10 实证：64 个令牌里
  61 个从未使用）。令牌一旦被真正使用就永不复用，不会两人共用一个开关
- 线上用户治理：`users.json` 从 66 个令牌收敛到 3 个真实在用设备，
  63 个空壳 / 历史测试令牌归档到 `users-archived-20261110.json`，
  原文件备份 `users.json.bak-1110-0041`，三个用户的开关与统计数据完整保留
- 验证：3 个用户开关全开；开关页含分享按钮与二维码；
  `/invite` 直连与 nginx 443 均 200；已归档令牌 404；
  `issue_user()` 连调三次只生成 1 个用户；DoH 广告域仍返回 `0.0.0.0`、
  业务域正常解析
- 同版本修订：开关页补 `Cache-Control: no-store`，Web Clip 点开不复用旧页面缓存，
  新按钮当场可见（实测响应头 200 + `no-store` + 二维码 SVG）

## 0.1.4 · 自动归因误伤护栏与多用户规则一致性

- 修复无人值守闭环上线后的首次误伤（2026-11-10 00:20）：招商银行
  `jump.m.cmbchina.cn` / `.com` 因「纯字母父域 + jump 命名」被判成广告落地页
  并自动写入黑名单。同批日志里还有 20+ 个 `paas.cmbchina.com` 业务子域，
  确认为误判；已整段回滚（服务器备份 `blacklist-shared.txt.bak-1110-0028`），
  真实 DoH 验证银行域恢复解析
- `src/ad_feedback.py` 加两层护栏：金融/支付/政务/品牌业务域直接跳过；
  同一品牌标签下历史子域 ≥5 且查询 ≥20 的判为业务父域，自动通道不写规则。
  人工「一键归因」同样受保护，避免把业务域写进 `force-block.txt`
- 复演 00:20 窗口：`cmbchina` 不再进 findings、自动动作 0；实时
  `--auto --dry-run` 命中 7 个可疑域但自动拦 0；单次 1.34s / 28MB 不变
- 多用户一致性实证：3 个不同 token 走同一套规则（广告域 → `0.0.0.0`、
  业务域正常解析），64 个用户开关全开；规则文件全局一份按 mtime 热加载，
  只有开关与统计按 token 独立，更新不需要重装描述文件
- 确认 00:23 另一设备的广告来自抖音信息流原生混排（该设备当天无红果内容域，
  00:22-00:24 只查抖音主域与视频 CDN），属 DNS 层硬边界
- 规则同步至 440 条（含 00:05 `deepinstall.com` 自动收敛、00:30 公开名单增量）；
  给 3 个整域规则补 `**.` 通配，修掉随机子域漏拦的格式坑，
  `check_rules` 500 条 0 问题 0 提示；
  `tools/verify_rules.py` 增加 4 个银行业务域放行断言

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
