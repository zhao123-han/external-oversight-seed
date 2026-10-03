#!/usr/bin/env python3
"""跨平台外挂监管种子 . 参考中间件 CLI（零第三方依赖）。

stdin 读一条工具调用 JSON -> 调统一内核 evaluate -> stdout 输出 verdict JSON。
各平台接入层可直接复用 cli.py，或 import kernel.engine 自行封装。

示例：
  echo '{"tool":"shell","intent":"sandbox_escape"}' | python cli.py
  => {"verdict": "suggest", ...}   # 默认 stop=false 时高危规则降级为建议

P0/P1 增强：CLI 会把完整性 tamper/unsigned 与授权缺失告警打到 stderr，
verdict 仍走 stdout（机器可解析），人类从 stderr 看安全提示。
"""
import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kernel.engine import evaluate, load_rules


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="跨平台外挂监管种子 reference middleware")
    ap.add_argument("--rules", default=os.path.join(here, "kernel", "rules.json"))
    ap.add_argument("--no-sig", action="store_true", help="跳过签名校验（仅调试用）")
    args = ap.parse_args()
    rules = load_rules(args.rules, check_sig=not args.no_sig)

    # 完整性告警
    integrity = rules.get("_integrity", "unsigned")
    if integrity == "tampered":
        sys.stderr.write("[安全告警] 规则文件疑似被篡改（sha256 与 .rules.sig 不符），"
                         "制止已强制降级为建议。请核查 rules.json 来源并重新运行 install 登记签名。\n")
    elif integrity == "unsigned":
        sys.stderr.write("[安全提示] 未找到 .rules.sig，无法验证规则完整性，"
                         "制止档位不可用（若已获授权也将降级）。请运行 install.py 登记签名。\n")

    raw = sys.stdin.read()
    try:
        call = json.loads(raw)
    except json.JSONDecodeError:
        call = {"tool": "unknown", "raw": raw}
    v = evaluate(rules, call)
    print(json.dumps(v, ensure_ascii=False))


if __name__ == "__main__":
    main()
