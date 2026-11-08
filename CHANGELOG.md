# Changelog

本项目的开发历程按功能阶段记录。版本号以 GitHub Release / tag 为准。

## 未发布 · 开源首个版本

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
