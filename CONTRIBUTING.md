# 参与贡献

## 最欢迎的三类贡献

1. **漏拦的域名**：附出现时间（精确到分钟）、App、具体域名、日志证据。
2. **误伤报告**：哪个功能坏了、坏在哪个域名、期望行为。
3. **规则 / 引擎改进**：尤其是新的广告域识别特征、降低误判的护栏。

## 提一条新规则

```markdown
域名：example-ad.com
出现时间：2026-11-08 22:54:55 - 22:55:10
App：红果 / 抖音 / ...
证据：doh_log.txt 里该域名 ALLOW 的行（贴 3-5 行即可）
判断依据：广告视频域 / 轮换上报 / 商品数据 API / 公开名单已收录 / ...
验证：verify_rules.py 输出（SHOULD_BLOCK 加了该域，FAILED=0）
```

规则写进哪一层见 [docs/RULES.md](docs/RULES.md)。原则：

- **最小粒度**：能写标签特征就不写整域，能写单个子域就不写父域。
- **注释独立成行**：`load_shared()` 不解析行内注释。
- **整域收敛写两条**：`父域**` + `**.父域**`。
- **不碰业务域**：内容 CDN、支付、时间服务、API 网关、IPv6 调度域一律不拦整域。
- 大厂父域（`qq.com` / `aliyuncs.com` / `baidu.com` / `amazonaws.com`）命中公开名单时
  只进候选审核，不自动拦。

## 改引擎

`src/autodetect.py` 的自动拦截有真实误伤风险，任何新判定逻辑都要：

1. 先跑 `python3 tools/dga_dryrun.py`，把「会收敛哪些父域」的输出贴进 PR。
2. 保持幂等：同一轮重复运行不应重复写规则（`auto_added` 状态 + 现有规则检查）。
3. 新护栏要带反例测试，例如 `_dga_word()` 必须不把 `240e09...` 这类
   IPv6 地址编码的 CDN 调度域判成随机广告域。
4. 每轮自动拦截上限 `MAX_AUTO`、候选队列上限 `MAX_CAND` 不要随意调大。

## PR 前检查

```bash
python3 -m py_compile src/*.py tools/*.py
python3 tools/verify_rules.py          # 需要已启动的服务
python3 tools/dga_dryrun.py
python3 tools/check_before_push.py     # 必须通过
git diff --stat
```

CI 会在 PR 上跑编译检查、规则语法检查、敏感信息扫描。

## PR 里不要出现

- 你自己的服务器公网 IP、域名、令牌、`users.json`、客户端 IP。
- `*.log` / `*.tsv` / `*.jsonl` / `doh_log.txt`。
- 任何带值的凭据文件、证书私钥、`.env`、备份文件（`*.bak*`）。
  凭据只走环境变量或项目之外的私有文件，不进仓库。
- 第三方名单的合并快照（几十 MB，且受上游许可约束）。

`check_before_push.py` 会逐项检查这些。

## 提交信息

简短说明改了什么、为什么：

```
rules: block *.zzcdnx.com (rotating ad subdomains seen 14x)
autodetect: exclude IPv6-encoded CDN labels from DGA collapse
docs: clarify iOS ignores non-standard ServerURL port
```

## 讨论

规则取舍、误伤争议、架构方向都欢迎开 Issue 或 Discussion 讨论。
有分歧时以「不误伤正常功能」优先，宁可漏一条广告，也不整域封杀业务域。
