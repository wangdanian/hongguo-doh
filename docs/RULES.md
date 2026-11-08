# 规则与自动发现

## 四层文件

| 文件 | 优先级 | 内容 | 谁维护 |
|---|---|---|---|
| `force-block.txt` | 1（最高） | 白名单父域下确凿的广告子域 | 人工 |
| `whitelist.txt` | 2 | 业务域、内容 CDN、支付、时间服务 | 人工 |
| `blacklist.txt` | 3 | 基础广告规则（含 `-reading-ad` 等精确特征） | 人工 |
| `blacklist-shared.txt` | 3 | 共享广告规则，**常开**，自动发现引擎写入 | 人 + 引擎 |

匹配顺序：`force` → `whitelist` → `blacklist` + `shared`。
命中 `force` 直接拦；命中 `whitelist` 直接放行；否则看两份黑名单。

## 语法

```
example.com**                        # 精确及前缀（含 CNAME 后缀域）
**.example.com**                     # 任意子域
*-aw-reading-video.qznovelvod.com**  # 标签里带 -aw- 的广告视频域
*-aw-*.douyinvod.com**               # aw = AdWorks 字节广告标签
# 这是注释（必须独立成行）
```

`**` 表示通配。引擎内部把规则编译成正则，`_compile_rule()` 有自匹配检查。

**三个必须记住的坑**（都是实测踩过的）：

1. **注释不能写在规则后面**。`load_shared()` 不裁剪行内注释，
   `example.com**  #auto:xxx` 会把整行当规则串，永不命中。
   引擎写入时说明放在独立注释行。
2. **整域收敛要两条**。`jspcdn.cn**` 覆盖 `jspcdn.cn.queniuuf.com` 这类 CNAME 后缀，
   但覆盖不到 `vuqsntdnsqqqnttqjnnbqq.jspcdn.cn`；必须再写 `**.jspcdn.cn**`。
   只写一条时，客户端换个随机串就能漏过去。
3. **白名单整域会架空其下的广告规则**。`amap.com` 一放行，
   `optimus-ads.amap.com` 也跟着放行。用 `force-block.txt` 打例外。

## 自动发现引擎分级

`src/autodetect.py` 每 30 分钟跑一次，只读近 3 天日志，不上传任何数据。

### A 级：自动拦截（每轮上限 40 条）

| 触发 | 例子 |
|---|---|
| 公开名单命中且不在保护父域 | `ads3-normal-hl.zijieapi.com` |
| 字节系广告指纹 | `-aw-`、`pangolin`、`pglstatp`、`mssdk`、`-vodad-` |
| 电商广告指纹 | `ecombdapi.com`、`ecombdimg.com`（卖货倒计时广告的商品数据 / 图片） |
| 广告线索组件 | `lf-leads-fe-scm.bytecdn.com` 等 `leads` 标签 |
| 保护父域内的确凿广告子域 | `*.gdt.qq.com`（广点通）、`afd*.baidu.com`（百度联盟） |
| 启动期突发 + 公开名单 | 冷启动头 8 秒集中出现的广告域 |
| DGA 父域收敛 | `jspcdn.cn`、`zzcdnx.com`、`ctydoh.cn`、`pkoplink.com` |

写入格式：先一行独立注释（`# ---- autodetect <时间> ----`、带 `#auto:` / `#dga:` 标签），
再写规则行。幂等：已有规则或已在 `auto_added` 状态里的域不会重复添加。

### B 级：人工裁决

广告关键词 + 多设备 + 多天 + 突增打分后进 `autodetect-candidates.json`，
在 `/candidates` 页面显示依据（命中词、几台设备、查询次数、是否疑似开屏），
红「拦截」/ 绿「放行」一键生效，303 回跳。写 `whitelist.txt` 的放行项立即热加载。

优先级排序：疑似开屏 > 分数 > 查询次数。已被自动拦掉的域会从队列里清掉。

### 护栏

- `PROTECT_PARENTS`：大厂父域命中公开名单只进候选，不自动拦。
  实测 anti-AD 曾收录 `qq.com` 整域，这层保住了 `api.unipay.qq.com`。
- `NO_COLLAPSE`：CDN / 调度 / 业务父域永不整域收敛。
- `_dga_word()` 排除纯 hex、纯数字、含连字符、词典词、元音比例过高的串，
  避免把 IPv6 地址编码的 CDN 就近调度域误判成广告 DGA。
- 解析器对 `||ad-host-backup-*.aliyuncs.com^` 这类**通配符在标签中间**的
  AdGuard 规则整条丢弃。早期版本用贪婪正则从 `*` 后面截出了 `aliyuncs.com` 整域，
  差点误杀一大片；`*.ad.qq.com` 这种通配符在开头的才解析出 `ad.qq.com`。
- 公开名单缓存带 `PUB_VER` 解析器版本号，改解析器后缓存自动失效重建。

## 提交新规则的流程

1. 拿到**证据**：出现时间窗（精确到分钟）、App、具体域名、日志里的 `ALLOW` 行。
   `doh_log.txt` 是 TSV，可按时间过滤：
   ```bash
   awk -F'\t' '$1>="2026-11-08 22:54:50" && $1<="2026-11-08 22:55:20"' doh_log.txt | cut -f1,3,5
   ```
2. 确认不是业务域：查 `whitelist.txt`、看全天查询次数、看是不是多台设备都在用。
   内容 CDN、支付、时间服务、API 网关一律不拦整域。
3. 选最小粒度：能写标签特征就不写整域，能写单个子域就不写父域。
4. 加进对应规则文件，注释独立成行说明来源和日期。
5. 跑验证：
   ```bash
   python3 tools/verify_rules.py        # 真发 DoH 查询，SHOULD_BLOCK / SHOULD_ALLOW 两组
   python3 tools/dga_dryrun.py          # 若改了收敛逻辑
   python3 tools/check_before_push.py
   ```
6. PR 里附上验证输出。CI 会再跑一遍编译检查 + 敏感信息扫描。

## 误伤与回滚

```bash
# 看引擎自动加了什么
grep -n '#auto:\|#dga:' /opt/hongguo-doh/blacklist-shared.txt

# 整批删掉自动规则（保留人工规则）
# 引擎永远只在文件尾部追加，所以截到第一个自动块之前即可
cd /opt/hongguo-doh
cp blacklist-shared.txt blacklist-shared.txt.bak
ln=$(grep -n '^# ---- autodetect\|^# ---- DGA' blacklist-shared.txt | head -1 | cut -d: -f1)
if [ -n "$ln" ]; then
  head -n $((ln-1)) blacklist-shared.txt > /tmp/bs.clean && mv /tmp/bs.clean blacklist-shared.txt
fi
```

若曾经手工在自动块之后补过规则，直接用部署时的备份恢复更省事：
`cp blacklist-shared.txt.bak-<日期> blacklist-shared.txt`。

单个域误伤就把它加进 `whitelist.txt`（若被 `force-block.txt` 拦住，同时从那里删掉）。
规则文件都是 mtime 热加载，改完立即生效。

## 已知拦不掉的情况

- 信息流原生广告卡片：由 feed API 在响应里下发，广告与正常内容共用 CDN。
- 后台预缓存素材：冷启动时零 DNS 请求。
- 倒计时 / 跳过按钮：App 内部 UI 逻辑。

DNS 只能掐掉独立广告域、追踪上报、留资线索、落地页和素材预载链路。
要按 URL 路径或响应体过滤需要 MITM 代理 + 根证书，本项目不做。
