# 架构与实现细节

## 一次查询的完整路径

```
iOS 加密 DNS 客户端
  └─ POST/GET https://<地址>/u/<token>/dns-query?dns=<base64url(DNS wire)>
       └─ nginx :443 (TLS, default_server, X-Real-IP)
            └─ doh_server.py :5053 (ThreadingHTTPServer / BaseHTTPRequestHandler)
                 ├─ 解析 URL 里的 token → users.json 查 enabled
                 ├─ 解析 DNS wire 报文，取 QNAME / QTYPE
                 ├─ 规则匹配（四层，见下）
                 ├─ 命中 → 构造 0.0.0.0 (A) / :: (AAAA) 应答
                 └─ 未命中 → 转发上游 DNS，原样回传应答
                      └─ watch.log(...) 异步落盘，按 App 分流
```

DoH 报文解析与应答构造都在 `src/doh_server.py` 内用标准库手工完成，
不依赖 dnspython。GET 用 `?dns=` 的 base64url（去掉 `=` 填充），
POST 直接读 body（`application/dns-message`）。

## 规则优先级

```
force-block.txt          最高：强制拦截例外，白名单也压不住
        ↓
whitelist.txt            命中即放行，不再看黑名单
        ↓
blacklist.txt            基础广告规则
blacklist-shared.txt     共享广告规则（常开，自动发现引擎写入）
```

`force-block.txt` 解决的是结构性漏洞：白名单里常有 `amap.com` 这类**整域放行**，
会把它下面确凿的广告子域（`optimus-ads.amap.com`）一起放掉。
强制层让"白名单父域 + 确凿广告子域"能同时成立。

所有规则文件都按 **mtime 热加载**：每次查询前检查文件修改时间，
变了就重载。所以改规则不用重启服务、不用重装描述文件。

## 规则语法

规则是简化的通配串，`_compile_rule()` 编译成正则：

| 写法 | 匹配 |
|---|---|
| `example.com**` | `example.com` 本身及以它开头的串（含 `example.com.cdn.xxx` 这类 CNAME 后缀） |
| `**.example.com**` | 任意子域 `xxx.example.com` |
| `*-aw-*.qznovelvod.com**` | 标签里带 `-aw-` 的广告视频域 |
| `#` 开头 | 注释（**必须独立成行**） |

解析规则时**不做行内注释裁剪**。`example.com**  # 广告` 会把注释当成规则的一部分，
导致这条规则永远不匹配。自动发现引擎写入的规则把说明写在**独立的注释行**里，
并带 `#auto:` / `#dga:` 标签，方便整批 grep 回滚。

## 共享名单为什么常开

早期实现把 `blacklist-shared.txt` 挂在"红果会话窗口"上：靠 `watch.py` 识别
内容域指纹，标记这台设备"红果活跃中"，窗口内才启用跨 App 共用域名的规则。
服务重启会清空窗口，出现几秒到几分钟的**拦截真空期**，实测漏过广告。
现在共享名单常开，会话窗口只用于日志里的 App 归类。

## 日志

`watch.py` 维护两套输出：

```
watch/
├── apps/<App>/<YYYY-MM-DD>-ok.tsv       放行
├── apps/<App>/<YYYY-MM-DD>-block.tsv    拦截
└── clients.txt                          IP → 备注（可选）
```

`APP_MAP` 按域名特征把查询归到 红果 / 抖音 / 京东 / 网易云 / 微信 / 淘宝 /
拼多多 / 苹果 / other。DNS 层看不到 PID，这个归类是基于域名指纹的**推测**，
不是进程级事实。`KEEP_DAYS` 默认 30，跨天自动清理。

主日志 `doh_log.txt` 是制表符分隔：

```
时间 \t 客户端IP \t 域名 \t 类型 \t ALLOW|BLOCK \t 命中规则 \t 耗时ms \t App
```

任何日志写入异常都必须被吞掉——日志挂了不能让 DNS 服务停摆。

## 多用户状态

`users.json`（运行期文件，不入仓库）：

```json
{
  "<token>": {
    "enabled": true,
    "created": "2026-11-05 01:12:52",
    "last_seen": "...",
    "day": "2026-11-08", "day_q": 7495, "day_block": 128,
    "total_q": 16238, "total_block": 779
  }
}
```

内存字典 + 定时落盘（约 60s），避免每条查询都写磁盘。
开关只影响该令牌对应的 `/u/<token>/dns-query`，互不干扰。

## 自动发现引擎

`src/autodetect.py`，cron 每 30 分钟 + `flock` 防并发。数据源是近 3 天的
`watch/apps/**/*.tsv`，聚合出唯一域名、设备数、查询次数、首次出现时间、
启动期突发标记。判定分两级：

- **A 级（自动写规则）**：公开名单命中、字节系广告指纹（`-aw-` / `pangolin` /
  `pglstatp` / `mssdk` / `-vodad-`）、电商广告指纹（`ecombdapi` / `ecombdimg`）、
  广告线索组件（`lf-leads-*`）、确凿广告子域（保护父域内的 `gdt.qq.com` 等）。
  每轮上限 40 条，写入带标签、幂等。
- **B 级（进候选队列）**：广告关键词 + 多设备 + 多天 + 突增打分，
  推送到 `/candidates` 页面，一键拦截 / 放行，303 回跳。

护栏：

- `PROTECT_PARENTS`：`qq.com` / `aliyuncs.com` / `baidu.com` / `amazonaws.com` 等
  大厂父域命中公开名单时**降级人工**，避免整域误杀（实测 anti-AD 曾收录 `qq.com` 整域，
  差点干掉 `api.unipay.qq.com`）。
- 白名单父域永不自动拦截。
- `_dga_word()` 排除纯 hex / 数字 / 连字符 / 词典词，避免把 IPv6 地址编码的
  CDN 调度域（`240e09....qrstuvwxyzab.com`）误判成随机广告域。
- 新注册马甲域由 `collapse_new_dga_parents()` 从真实日志直接识别：
  同父域 ≥3 个不同高随机字母子域、总域数 ≤40、随机占比 ≥80% 才收敛。
  `tools/dga_dryrun.py` 可先跑一遍看会收敛哪些父域。

## 资源消耗

单设备约 1.5 小时产生 7495 条查询，每条日志约 650 B，DoH 流量约 0.35 MB；
服务端常驻内存约 29 MB，CPU 长期 < 3%。20 人同时用，平均带宽约 0.16 Mbps。
公开名单解析后的域名集合约 22.5 万条，占内存约 20–30 MB，只在引擎运行时存在。

## 页面与路由

| 路径 | 作用 |
|---|---|
| `/` | 安装页（领描述文件） |
| `/issue` | 签发令牌并返回 `.mobileconfig` |
| `/u/<token>/dns-query` | 该用户的 DoH 端点 |
| `/u/<token>` | 开关页（开关 / 清除 / 刷新） |
| `/u/<token>/toggle`、`/reset` | POST 动作 |
| `/users` | 用户与统计后台（JSON） |
| `/stats` | 全局状态页 |
| `/candidates` | 候选广告审核页 |
| `/cand/block?d=`、`/cand/allow?d=` | 一键拦截 / 放行（303 回跳） |
| `/hongguo.mobileconfig` | 旧版固定描述文件入口 |

生产环境请给 `/users` 与 `/cand/` 加鉴权。
