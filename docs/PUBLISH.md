# 发布到 GitHub：准备清单

本项目代码是 MIT，DNS 层过滤类项目在 GitHub 上是常见品类（AdGuard Home、
anti-AD、AdGuardSDNSFilter 等都在公开托管），可以正常开源。
要准备的其实只有三件事：**干净的仓库副本**、**账号与推送权限**、**仓库设置**。

## 一、最重要的前提：从干净副本初始化

**不要**把私有工作区整个 `git init` 之后 push，再删掉敏感文件。
公开仓库的全部历史都能被克隆，删掉文件不等于删掉历史。
本项目已经准备好 `open-source/` 作为独立干净副本：

- 不含 `users.json`（令牌）、`doh_log.txt`、`*.tsv` / `*.log`、客户端 IP。
- 不含 AccessKey / 私钥 / `.env` / 备份文件 / 含真实地址的描述文件与二维码。
- 不含上游名单快照（体积大，且 AdGuard DNS Filter 是 GPL-3.0，本项目只运行时下载不再分发）。
- 源码里的真实服务器 IP、私有域名、本机绝对路径全部换成文档示例值。

发布前跑一遍：

```bash
cd open-source
python3 tools/check_before_push.py .     # 凭据 / 私钥 / 用户数据 / 真实 IP / 大文件
python3 -m py_compile src/*.py tools/*.py
python3 tools/check_rules.py
```

`publish.sh` 会自动跑这三步，CI 也会跑同一份检查。

## 二、账号与推送权限（二选一）

```bash
# A. SSH key
ssh-keygen -t ed25519 -C "your_email@example.com"
# 把 ~/.ssh/id_ed25519.pub 加到 GitHub → Settings → SSH and GPG keys
ssh -T git@github.com

# B. GitHub CLI
gh auth login
gh repo create hongguo-doh --public --source=. --remote=origin --push
```

用 `publish.sh` 的话走 SSH：

```bash
GITHUB_OWNER=你的账号 ./publish.sh
```

脚本里 `OWNER` 默认值是 `wangdanian`，`REPO` 默认值是 `hongguo-doh`，
分支默认 `main`。这三个都能用环境变量覆盖，或直接改脚本顶部三行。

## 三、创建仓库后要填的设置

| 位置 | 建议值 |
|---|---|
| Visibility | Public |
| Description | `自建 DoH 广告过滤节点 + 广告域名自动发现引擎（iOS 全局加密 DNS）` |
| Website | 你的项目主页或部署说明页（没有就留空） |
| Topics | `dns` `doh` `dns-over-https` `adblock` `privacy` `ios` `python` `self-hosted` |
| Default branch | `main`（`publish.sh` 已按此初始化） |
| Issues | 开启（模板已在 `.github/ISSUE_TEMPLATE/`） |
| Discussions | 开启，建议分 `规则讨论` / `部署答疑` / `想法` 三类 |
| Actions | 开启，CI 会自动跑 `check_before_push.py` + `check_rules.py` + 编译检查 |
| Branch protection | 对 `main` 要求 PR + CI 通过，避免规则被直接推坏 |
| License | 仓库里已有 `LICENSE`（MIT），GitHub 会自动识别 |
| Releases | 首次发布打个 `v0.1.0` tag，内容抄 `CHANGELOG.md` |

## 四、Fork / 部署者必须替换的默认值

| 文件 | 默认值 | 改成 |
|---|---|---|
| `.env.example` → `.env` | `DOH_BASE_URL=https://203.0.113.10` | 你的公网 IP 或域名 |
| `config/hongguo-doh.service` | `Environment=DOH_BASE_URL=...` | 同上 |
| `config/nginx-*.example` | `/etc/nginx/tls/*.pem` | 你的证书路径 |
| `examples/install-page.html` | 相对链接 `/issue` | 一般无需改；二维码要用你的地址生成 |
| `.github/ISSUE_TEMPLATE/config.yml` | `github.com/wangdanian/hongguo-doh/...` | 你的仓库地址 |
| `README.md` clone 命令 | `wangdanian/hongguo-doh` | 你的账号 / 组织 |
| `publish.sh` | `GITHUB_OWNER=wangdanian` | 你的账号 |

**证书不能复用**：IP 地址证书绑定具体 IP，每个部署者要用自己的 IP 重新签
（Let's Encrypt `shortlived` profile，见 [DEPLOY.md](DEPLOY.md)）。

## 五、凭据处置

云助手运维工具（`tools/ecs_run.py` / `push_file.py` / `fetch_file.py`）按以下顺序取凭据：

1. 环境变量 `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET` /
   `ALIYUN_REGION` / `ALIYUN_INSTANCE_ID` —— 完全不落盘，推荐。
2. **项目之外**的用户级私有文件 `~/.workbuddy/private/ecs_secrets.json`
   （可用 `ECS_SECRETS_FILE` 改路径），文件权限设为仅当前用户可读。

任何仓库目录内都不存放带值的凭据：脚本不会读取同目录的
`ecs_secrets.local.json`，`.gitignore` 与 `check_before_push.py` 也会把
误放进来的文件一律拦下。`tools/ecs_secrets.example.json` 只是空值格式示例。

如果某对 AccessKey 曾经出现在提交、日志或截图里，在阿里云
「访问控制 → 用户 → AccessKey」里禁用并重建。云助手建议用最小权限子账号的 AK。

## 六、发布后的协作流程

- 漏拦 / 误伤走 `.github/ISSUE_TEMPLATE/ad_domain_report.yml`，
  模板会要求给时间窗、App、域名、日志证据和判断依据。
- 规则 PR 必须贴 `tools/verify_rules.py` 的输出；改自动收敛逻辑必须贴
  `tools/dga_dryrun.py` 结果（见 [CONTRIBUTING.md](../CONTRIBUTING.md)）。
- CI 会拦下凭据、私钥、用户数据、日志与超过 1 MB 的名单快照。
- 规则取舍有分歧时以「不误伤正常功能」优先，见 [RULES.md](RULES.md)。

## 七、许可边界

- 本仓库代码与文档：MIT。
- `rules/` 下随仓库提供的规则：本项目整理，MIT。
- `autodetect.py` 运行时下载的 anti-AD（MIT）、oisd、AdGuard DNS Filter（GPL-3.0）：
  **只在本地参与比对，不随本仓库分发**。若有人要再分发合并名单，
  需自行核对各上游许可与署名要求。
- 仓库不提供签名描述文件、不代生成 Apple 开发者账号、不含任何根证书或 MITM 组件。
