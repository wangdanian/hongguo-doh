## 改了什么

<!-- 一句话说明 -->

## 为什么

<!-- 漏拦证据 / 误伤现象 / 改进点 -->

## 验证

```
python3 -m py_compile src/*.py tools/*.py
python3 tools/verify_rules.py
python3 tools/dga_dryrun.py
python3 tools/check_before_push.py .
```

<!-- 贴关键输出；改了自动收敛逻辑必须贴 dry-run 结果 -->

## 检查清单

- [ ] 规则注释独立成行，没写行内注释
- [ ] 整域收敛写了 `父域**` + `**.父域**` 两条
- [ ] 没有提交公网 IP、令牌、users.json、日志、私钥、备份文件
- [ ] `tools/check_before_push.py` 通过
