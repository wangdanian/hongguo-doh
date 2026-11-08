#!/usr/bin/env bash
# 一键初始化并推送公开仓库。默认值可直接改，或用环境变量覆盖：
#   GITHUB_OWNER=你的账号 GITHUB_REPO=hongguo-doh ./publish.sh
set -euo pipefail

OWNER="${GITHUB_OWNER:-wangdanian}"         # ← 改成你的 GitHub 账号 / 组织名
REPO="${GITHUB_REPO:-hongguo-doh}"
BRANCH="${GITHUB_BRANCH:-main}"
PY="$(command -v python3 || command -v python)"
REMOTE="git@github.com:${OWNER}/${REPO}.git"

cd "$(dirname "$0")"

echo "[1/5] 发布前自检"
"$PY" tools/check_before_push.py .

echo "[2/5] 编译检查"
"$PY" -m py_compile src/*.py tools/*.py
"$PY" tools/check_rules.py

echo "[3/5] 初始化仓库"
if [ ! -d .git ]; then
  git init -b "$BRANCH"
fi
git config core.autocrlf false
if ! git config user.email >/dev/null 2>&1; then
  git config user.name "${GIT_AUTHOR_NAME:-hongguo-doh}"
  git config user.email "${GIT_AUTHOR_EMAIL:-maintainers@users.noreply.github.com}"
fi
git add -A

echo "[4/5] 提交"
git diff --cached --quiet || git commit -m "Initial open-source release: DoH ad filter with auto-discovery"

echo "[5/5] 推送到 ${REMOTE}"
if ! git remote get-url origin >/dev/null 2>&1; then
  git remote add origin "$REMOTE"
fi
git push -u origin "$BRANCH"

echo "完成：https://github.com/${OWNER}/${REPO}"
echo "记得在仓库设置里填 Description / Topics、开启 Discussions 与分支保护（见 README）。"
