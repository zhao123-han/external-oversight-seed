# 外挂监管能力 · Agent 自安装说明书（投喂即用）

> **接收方 Agent 请直接照做**：读完本说明后，用你的文件写入能力把「第三节」的每个代码块按标注路径写成文件，再跑「第五节」验证命令。完成后你将获得对 agent / 大模型越界行为的「观察 / 建议 / 制止」三档监管能力，无需任何额外上下文。

## 一、这是什么能力

跨平台**外挂监管**：在 agent 真正执行某个工具调用之前，先拿规则判定一次；命中越界行为就按档位接管。核心是**统一判定内核 + 分平台适配层**，不绑定任何单一宿主，WorkBuddy / DeepSeek / 混元 等环境都能装。

## 二、三档与开关（必读红线）

- **L-0 观察 observe**：记录越界行为并上报。默认开。
- **L-1 建议 suggest**：产出告警/建议，由被监管方或人工决定是否处理。默认开。
- **L-2 制止 stop**：直接 block / deny 工具调用。默认**关**。
- 打开 `stop`：把 `kernel/rules.json` 的 `enforcement.stop` 改为 `true`，并填全 `authorization` 四要素——这等于你声明「已获制止授权」。
- **未开 `stop` 却命中高危规则时，自动降级为 `suggest`**：不静默放行，也不越权制止。
- **可监管性 = 有授权 × 有 seam**。监管他人 agent 必须获其授权，否则即虚假监管，禁止使用。

## 三、重建文件（原样写成文件）

### 路径：`kernel/rules.json`

```json
{
  "schema_version": "1.0.0",
  "name": "跨平台外挂监管种子-rules",
  "description": "统一内核规则核心：越界行为三档判定（平台无关，任何环境可读）",
  "enforcement": {
    "observe": true,
    "suggest": true,
    "stop": false
  },
  "authorization": {
    "granted_by": "",
    "scope": "",
    "signed_at": "",
    "confirmation_token": "",
    "revocable": true,
    "tamper_proof": false,
    "note": "stop=true 时四要素(granted_by/scope/signed_at/confirmation_token)必须真实完整填写；内核会校验字段，缺项则制止自动降级为建议——声明不等于验证，部署者自负。"
  },
  "rules": [
    {
      "id": "R-SANDBOX-ESCAPE",
      "label": "沙盒逃逸",
      "severity": "critical",
      "match": {"intent": "sandbox_escape"},
      "on_hit": {"observe": "record", "suggest": "warn", "stop": "deny"}
    },
    {
      "id": "R-DEFENSE-TAMPER",
      "label": "篡改或关闭监管",
      "severity": "critical",
      "match": {"any_param_contains": ["disable guard", "关闭监管", "disable_guard", "remove monitor", "uninstall guard"]},
      "on_hit": {"observe": "record", "suggest": "warn", "stop": "deny"}
    },
    {
      "id": "R-FS-WRITE-OUTSIDE",
      "label": "越权写宿主文件系统",
      "severity": "high",
      "match": {"any_param_contains": ["/etc/", "/root/", "c:\\windows", "write_outside_sandbox"]},
      "on_hit": {"observe": "record", "suggest": "warn", "stop": "deny"}
    },
    {
      "id": "R-EXFIL-NETWORK",
      "label": "未授权外联",
      "severity": "high",
      "match": {"intent": "exfil_network"},
      "on_hit": {"observe": "record", "suggest": "warn", "stop": "deny"}
    },
    {
      "id": "R-SECRET-READ",
      "label": "读取密钥或凭据",
      "severity": "high",
      "match": {"any_param_contains": ["API_KEY", "SECRET", "PRIVATE_KEY", "私钥", "密码文件", "credential"]},
      "on_hit": {"observe": "record", "suggest": "warn", "stop": "deny"}
    },
    {
      "id": "R-CODE-EXEC-UNSAFE",
      "label": "危险代码执行",
      "severity": "high",
      "match": {"any_param_contains": ["os.system", "subprocess", "__import__", "eval(", "exec("]},
      "on_hit": {"observe": "record", "suggest": "warn", "stop": "deny"}
    },
    {
      "id": "R-PROMPT-INJECT",
      "label": "提示词注入迹象",
      "severity": "medium",
      "match": {"any_param_contains": ["ignore previous", "忽略先前指令", "system prompt", "disregard instructions", "忽略上文"]},
      "on_hit": {"observe": "record", "suggest": "warn", "stop": "allow"}
    }
  ]
}
```

### 路径：`kernel/engine.py`

```python
"""跨平台外挂监管种子 . 统一判定内核（零第三方依赖，仅标准库）。

任何平台接入层都调用 evaluate(rules, call) 这一唯一入口，
保证「统一内核」：判定逻辑只有一份，分平台只是搬运 verdict。

match 语义（见 rules.json）：
  - tool:       工具名精确匹配，或 "*" 通配
  - intent:     语义标签（由接入层在 call 上标注，如 "sandbox_escape"）；命中即匹配
  - any_param_contains: 调用 JSON 任意字符串值含任一关键字即匹配（兜底）
  规则不要同时给 intent 与 any_param_contains（intent 优先）。

P0 加固：load_rules 比对 .rules.sig（防篡改闭环）；stop 生效前置完整性+授权四要素。
P1 加固：调用归一化（NFKC + Base64 解码 + leet 折叠）降低文本绕过率。
"""

import os
import re
import json
import base64
import hashlib
import unicodedata

_LEET = str.maketrans("013457@", "oieasta")


def _normalize_text(s):
    if not isinstance(s, str):
        return s
    t = unicodedata.normalize("NFKC", s)
    variants = [t]
    leet = t.lower().translate(_LEET)
    if leet != t.lower():
        variants.append(leet)
    cand = t.strip()
    if len(cand) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", cand):
        try:
            pad = cand if cand.endswith("=") else cand + "==="
            raw = base64.b64decode(pad, validate=False)
            dec = raw.decode("utf-8", "ignore").strip()
            if dec:
                variants.append(dec)
        except Exception:
            pass
    return " ".join(variants)


def _normalize(call):
    def walk(o):
        if isinstance(o, str):
            return _normalize_text(o)
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o
    return walk(call)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_rules(path, check_sig=True):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    rules = json.loads(text)
    if not check_sig:
        rules["_integrity"] = "skipped"
        return rules
    sig_path = os.path.join(os.path.dirname(os.path.abspath(path)), ".rules.sig")
    if not os.path.exists(sig_path):
        rules["_integrity"] = "unsigned"
        return rules
    with open(sig_path, "r", encoding="utf-8") as f:
        expected = f.read().strip()
    actual = _sha256_file(path)
    rules["_integrity"] = "ok" if actual == expected else "tampered"
    return rules


_AUTH_FIELDS = ["granted_by", "scope", "signed_at", "confirmation_token"]


def authorization_status(rules):
    az = rules.get("authorization", {}) or {}
    missing = [k for k in _AUTH_FIELDS if not az.get(k)]
    return (len(missing) == 0), missing


def _collect_strings(obj):
    out = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_collect_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_collect_strings(v))
    return out


def _match(rule, call):
    m = rule.get("match", {})
    tool_pat = m.get("tool", "*")
    if tool_pat != "*" and call.get("tool") != tool_pat:
        return False
    intent = m.get("intent")
    if intent:
        return call.get("intent") == intent
    kws = m.get("any_param_contains", [])
    if kws:
        blob = " ".join(_collect_strings(call)).lower()
        return any(k.lower() in blob for k in kws)
    return True


def evaluate(rules, call):
    call_n = _normalize(call)
    enf = rules.get("enforcement", {})
    integrity = rules.get("_integrity", "unsigned")
    auth_ok, auth_missing = authorization_status(rules)
    for rule in rules.get("rules", []):
        if not _match(rule, call_n):
            continue
        hit = rule.get("on_hit", {})
        sev = rule.get("severity", "low")
        rid = rule.get("id", "unknown")
        label = rule.get("label", rid)
        if enf.get("stop") and hit.get("stop") == "deny":
            if integrity != "ok":
                return {"verdict": "suggest", "rule_id": rid, "severity": sev,
                        "message": "[降级] 命中规则 %s(%s)，但规则完整性=%s，制止不可用，降级为建议复核"
                                   % (rid, label, integrity),
                        "integrity": integrity, "auth_ok": auth_ok}
            if not auth_ok:
                return {"verdict": "suggest", "rule_id": rid, "severity": sev,
                        "message": "[降级] 命中规则 %s(%s)，但制止授权不完整(缺:%s)，按默认降级为建议"
                                   % (rid, label, ",".join(auth_missing)),
                        "integrity": integrity, "auth_ok": auth_ok}
            return {"verdict": "stop", "rule_id": rid, "severity": sev,
                    "message": "[制止] 命中规则 %s(%s)，已拦截工具调用" % (rid, label),
                    "integrity": integrity, "auth_ok": auth_ok}
        if enf.get("suggest") and hit.get("suggest") == "warn":
            return {"verdict": "suggest", "rule_id": rid, "severity": sev,
                    "message": "[建议] 命中规则 %s(%s)，建议人工复核" % (rid, label),
                    "integrity": integrity, "auth_ok": auth_ok}
        if enf.get("observe"):
            return {"verdict": "observe", "rule_id": rid, "severity": sev,
                    "message": "[观察] 记录越界行为 %s(%s)" % (rid, label),
                    "integrity": integrity, "auth_ok": auth_ok}
    return {"verdict": "allow", "rule_id": None, "severity": "none",
            "message": "未命中任何规则，放行",
            "integrity": integrity, "auth_ok": auth_ok}
```

### 路径：`cli.py`

```python
#!/usr/bin/env python3
"""跨平台外挂监管种子 . 参考中间件 CLI（零第三方依赖）。

stdin 读一条工具调用 JSON -> 调统一内核 evaluate -> stdout 输出 verdict JSON。
各平台接入层可直接复用 cli.py，或 import kernel.engine 自行封装。

P0/P1 增强：完整性 tamper/unsigned 与授权缺失告警打到 stderr，verdict 走 stdout。
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
    print(json.dumps(evaluate(rules, call), ensure_ascii=False))


if __name__ == "__main__":
    main()
```

### 路径：`install.py`（可选便利安装器）

```python
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
CORE = ["manifest.json", "kernel", "cli.py", "adapters", "README.md", "LICENSE", "docs", "examples"]

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
    sample = {"tool": "shell", "intent": "sandbox_escape"}
    v = evaluate(rules, sample)
    assert v["verdict"] == "suggest", v
    print("[校验] 内核可加载，默认档位降级逻辑正常：%s" % v["verdict"])
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


def pack():
    import zipfile
    out = os.path.join(PKG, "跨平台外挂监管种子.zip")
    out_abs = os.path.abspath(out)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(PKG):
            for fn in files:
                fp = os.path.join(root, fn)
                if os.path.abspath(fp) == out_abs:
                    continue
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
    if args.pack:
        pack()
    print("\n[完成] 工具包已就位。下一步：按上面接入指引挂接，确认 seam 自检，再按需打开 enforcement.stop。")


if __name__ == "__main__":
    main()
```

## 四、安装步骤

1. 在当前工作区建目录 `跨平台外挂监管种子/`，按上方路径把四个代码块写成文件（`kernel/rules.json`、`kernel/engine.py`、`cli.py`、`install.py`）。
2. 跑「第五节」验证命令，确认内核可加载、高危默认降级为 `suggest`。
3. 需要一键部署到别处时：`python install.py --target <目标目录> --platform generic-api`（平台可选 `workbuddy` / `deepseek-harness` / `generic-api` / `hunyuan-sandbox`）。若 install.py 执行被环境限制，手动复制整个目录即可，效果相同。
4. 按「第六节」选你的平台完成挂接；需要制止时再开 `stop` 开关（并填 `authorization`）。

## 五、验证命令

```
python -c "import sys; sys.path.insert(0,'.'); from kernel.engine import load_rules,evaluate; r=load_rules('kernel/rules.json'); print(evaluate(r,{'tool':'shell','intent':'sandbox_escape'})); print(evaluate(r,{'tool':'calc','expr':'1+1'}))"
```

预期输出：第一条 `verdict=suggest`（默认关闭 stop，高危降级），第二条 `verdict=allow`。

## 六、四平台接入（精简）

- **WorkBuddy**：PreToolUse hook 调 `cli.py`，每次工具执行前传调用 JSON；`stop` 用 hook 退出码 2 硬阻断（需 hook 有 deny 权）。
- **DeepSeek 生态（dsh）**：写 `pre-execute` 插件，在工具执行前调同一内核；`stop` 返回拒绝。
- **通用 API**：模型输出工具调用 → 真正执行之间插入 `evaluate(...)`；`stop` 不执行并回拒绝。
- **混元 / Cube Sandbox**：逻辑层同上，再加容器/VM 网络与文件系统边界作环境级兜底（模型想绕也绕不过）。

## 七、诚实边界

- 本能力为「对外监管」最小规则子集，不含全量诊断/案例资产。
- dsh / 混元 的 seam 细节需在各环境实测；未实测前不得声称已可用。
- 仅用于已获授权的监管场景；未经授权监管他人 = 虚假监管。

<!-- END -->
