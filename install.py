#!/usr/bin/env python3
"""跨平台外挂监管种子 . 跨平台安装器（零第三方依赖）。

把工具包核心部署到目标环境，登记规则签名，按平台生成接入指引与 seam 自检清单，
并校验内核可加载、防篡改闭环、授权降级逻辑正常。不远程安装（做不到），只做
本地部署 + 校验 + 指引；--pack 顺便打包 zip 分发。

用法：
  python install.py --target /path/to/deploy --platform workbuddy [--pack]
"""
import os
import sys
import json
import shutil
import hashlib
import argparse

PKG = os.path.dirname(os.path.abspath(__file__))
CORE = ["manifest.json", "kernel", "cli.py", "adapters", "deploy", "README.md", "LICENSE", "docs", "examples"]

# 各平台 seam 自检清单：安装器能自动验证的 + 需人工确认的项
SEAM_CHECKS = {
    "workbuddy": [
        "本工具包已挂接为工具前置（tool-use hook / 中间件），所有 tool 调用先过 evaluate",
        "确认 hook 在 stop=true 时能真正阻断调用（而非仅记录）",
        "确认 rules.json 以只读方式随包分发，宿主机无法被 Agent 改写",
    ],
    "deepseek-harness": [
        "已把 AGENT_INSTALL_GUIDE.md 投喂给目标 Agent，且其每次 tool 调用前调用 evaluate",
        "确认 harness 把 verdict.stop 当作硬阻断（拒绝执行该工具）",
        "确认 rules.json 与 .rules.sig 一并随 Agent 上下文加载",
    ],
    "generic-api": [
        "API 网关/中间件在 tool 分发前同步调用 evaluate，并尊重 verdict",
        "确认 verdict.stop 返回 403/阻断，verdict.suggest 触发人工复核队列",
        "确认规则文件存放在中间件侧且中间件进程有权限读 .rules.sig",
    ],
    "hunyuan-sandbox": [
        "沙箱在 tool 执行前挂载本内核为前置拦截器",
        "确认沙箱层面 stop 能中止本次工具执行",
        "确认 rules.json 以只读挂载进沙箱（容器 ro 卷或 immutable 属性）",
    ],
}


def check_runtime():
    if sys.version_info < (3, 8):
        sys.exit("[安装失败] 需要 Python 3.8+，当前 %d.%d" % (sys.version_info[:2]))


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def register_sig(target):
    """首次部署登记 .rules.sig（P0 防篡改闭环的签名源）。"""
    rp = os.path.join(target, "kernel", "rules.json")
    if not os.path.exists(rp):
        return
    sig_path = os.path.join(target, "kernel", ".rules.sig")
    digest = _sha256_file(rp)
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(digest)
    print("[签名] 已登记 .rules.sig（sha256=%s...）" % digest[:16])


def deploy(target):
    os.makedirs(target, exist_ok=True)
    for item in CORE:
        src = os.path.join(PKG, item)
        if not os.path.exists(src):
            continue
        dst = os.path.join(target, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
    print("[部署] 核心已复制到 %s" % target)
    register_sig(target)


def verify(target):
    rp = os.path.join(target, "kernel", "rules.json")
    sys.path.insert(0, target)
    from kernel.engine import load_rules, evaluate
    rules = load_rules(rp)
    integrity = rules.get("_integrity")
    assert integrity in ("ok", "unsigned"), "[校验失败] 规则完整性=%s" % integrity
    if integrity == "ok":
        print("[校验] 防篡改闭环正常：.rules.sig 匹配")
    else:
        print("[校验] 警告：未登记签名（unsigned），制止档位运行时将不可用")
    assert rules["enforcement"]["observe"] is True
    assert rules["enforcement"]["suggest"] is True
    assert rules["enforcement"]["stop"] is False
    # 默认 stop=false -> 高危降级为建议
    sample = {"tool": "shell", "intent": "sandbox_escape"}
    v = evaluate(rules, sample)
    assert v["verdict"] == "suggest", v
    print("[校验] 内核可加载，默认档位降级逻辑正常：%s" % v["verdict"])
    # 授权降级：即便伪造 stop=true，授权缺失也应降级
    rules["enforcement"]["stop"] = True
    v2 = evaluate(rules, sample)
    assert v2["verdict"] == "suggest", v2
    print("[校验] 授权真伪加固正常：stop=true 但授权缺失仍降级为建议")


def guide(platform):
    g = os.path.join(PKG, "adapters", platform + ".md")
    if os.path.exists(g):
        print("[接入] 请按 %s 完成挂接：\n" % g)
        with open(g, encoding="utf-8") as f:
            print(f.read())
    else:
        print("[接入] 未知平台 %s；可选：workbuddy / deepseek-harness / generic-api / hunyuan-sandbox" % platform)


def seam_selfcheck(platform):
    print("\n[seam 自检] 平台=%s —— 请逐项确认（任一项不满足则 stop 档位不可用）：" % platform)
    for i, item in enumerate(SEAM_CHECKS.get(platform, SEAM_CHECKS["generic-api"]), 1):
        print("  %d. %s" % (i, item))
    print("  [!] 若无法确认上述 seam，请勿打开 enforcement.stop；观察/建议档位不受影响。")


def enterprise_check(target):
    from kernel.env_lock import check_enterprise_lock
    from kernel.engine import load_rules
    rp = os.path.join(target, "kernel", "rules.json")
    rules = load_rules(rp)
    stop_on = rules["enforcement"].get("stop", False)
    res = check_enterprise_lock(rp, stop_on)
    print("\n[企业隔离] %s" % res["message"])
    if not res["locked"] and stop_on:
        print("  [!] 宿主不可篡改隔离未落实，制止档位在企业环境下面临被改写风险；建议只读挂载后再开 stop。")


def pack():
    import zipfile
    out = os.path.join(PKG, "跨平台外挂监管种子.zip")
    out_abs = os.path.abspath(out)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(PKG):
            for fn in files:
                fp = os.path.join(root, fn)
                if os.path.abspath(fp) == out_abs:
                    continue  # 不把 zip 自身打进 zip
                z.write(fp, os.path.relpath(fp, PKG))
    print("[打包] 已生成 %s" % out)


def main():
    ap = argparse.ArgumentParser(description="跨平台外挂监管种子 installer")
    ap.add_argument("--target", required=True, help="部署目标目录")
    ap.add_argument("--platform", default="generic-api",
                    choices=["workbuddy", "deepseek-harness", "generic-api", "hunyuan-sandbox"])
    ap.add_argument("--pack", action="store_true", help="顺便打包为 zip 分发")
    args = ap.parse_args()
    check_runtime()
    deploy(args.target)
    verify(args.target)
    guide(args.platform)
    seam_selfcheck(args.platform)
    enterprise_check(args.target)
    if args.pack:
        pack()
    print("\n[完成] 工具包已就位。下一步：按上面接入指引挂接，确认 seam 自检，再按需打开 enforcement.stop。")


if __name__ == "__main__":
    main()
