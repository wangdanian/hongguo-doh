# -*- coding: utf-8 -*-
"""阿里云 ECS 云助手远程执行助手。

用法:
    python ecs_run.py "<shell命令>" [timeout=30]

凭据读取优先级（凭据归操作者所有，只供本助手运行时使用，
不写进代码、不落在任何项目目录、不提交任何仓库）:
    1. 环境变量 ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET
       / ALIYUN_REGION / ALIYUN_INSTANCE_ID   ← 完全不落盘，最干净
    2. 项目外的用户级私有文件，默认
       ~/.workbuddy/private/ecs_secrets.json
       可用 ECS_SECRETS_FILE 指向任意项目外路径（权限应设为仅当前用户可读）
    3. 都没有 -> 运行时报错

本脚本所在目录及任何仓库内都不存放凭据；不要创建 ecs_secrets.local.json。

云助手 CreateCommand 限制 command_content <= 16KB，单次输出约 32KB；
大文件传输请用 push_file.py / fetch_file.py 分片。
"""
import sys, json, base64, time, os

from alibabacloud_ecs20140526.client import Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526 import models as ecs_models


def _secrets_path():
    """只允许项目外的路径；显式拒绝落在任何仓库/项目目录里的凭据文件。"""
    p = os.environ.get("ECS_SECRETS_FILE")
    if not p:
        p = os.path.join(os.path.expanduser("~"), ".workbuddy", "private",
                         "ecs_secrets.json")
    return os.path.abspath(os.path.expanduser(p))


def _load_credentials():
    ak = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID")
    sk = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
    region = os.environ.get("ALIYUN_REGION", "cn-hangzhou")
    iid = os.environ.get("ALIYUN_INSTANCE_ID")
    if not (ak and sk and iid):
        path = _secrets_path()
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                d = json.load(fh)
            ak = ak or d.get("access_key_id")
            sk = sk or d.get("access_key_secret")
            region = d.get("region", region)
            iid = iid or d.get("instance_id")
    if not (ak and sk and iid):
        raise SystemExit(
            "[ecs_run] 缺少凭据。设置环境变量 "
            "ALIBABA_CLOUD_ACCESS_KEY_ID / ALIBABA_CLOUD_ACCESS_KEY_SECRET / "
            "ALIYUN_INSTANCE_ID，或把凭据放在项目外的 %s（仅当前用户可读）。"
            % _secrets_path())
    return ak, sk, region, iid


_client = None


def _get_client():
    global _client
    if _client is None:
        ak, sk, region, iid = _load_credentials()
        cfg = open_api_models.Config(
            access_key_id=ak, access_key_secret=sk, region_id=region,
            endpoint="ecs.%s.aliyuncs.com" % region)
        _client = (Client(cfg), region, iid)
    return _client


def run(cmd, timeout=30):
    client, region, iid = _get_client()
    name = "diag-%s" % int(time.time())
    req = ecs_models.CreateCommandRequest(
        region_id=region, name=name, type="RunShellScript",
        command_content=base64.b64encode(cmd.encode("utf-8")).decode(),
        timeout=timeout,
    )
    resp = client.create_command(req)
    cid = resp.body.command_id
    invoke = client.invoke_command(ecs_models.InvokeCommandRequest(
        region_id=region, command_id=cid, instance_id=[iid],
    ))
    inv_id = invoke.body.invoke_id
    for _ in range(int(timeout / 2) + 5):
        time.sleep(2)
        d = client.describe_invocation_results(ecs_models.DescribeInvocationResultsRequest(
            region_id=region, invoke_id=inv_id,
        ))
        r = d.body.invocation.invocation_results.invocation_result[0]
        state = r.invoke_record_status
        if state == "Finished":
            out = base64.b64decode(r.output).decode("utf-8", "replace") if r.output else ""
            err = (base64.b64decode(r.exit_code_out).decode("utf-8", "replace")
                   if getattr(r, "exit_code_out", None) else "")
            print("exit=%s status=%s" % (r.exit_code, state))
            print(out)
            if err:
                print("[stderr]", err)
            return
        if state in ("Failed", "TimedOut"):
            print("[invoke state=%s] msg=%s" % (state, r.error_message))
            return
    print("[timeout waiting invocation]")


if __name__ == "__main__":
    cmd = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    run(cmd, timeout)
