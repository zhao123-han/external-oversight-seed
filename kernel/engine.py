"""跨平台外挂监管种子 . 统一判定内核（零第三方依赖，仅标准库）。

任何平台接入层都调用 evaluate(rules, call) 这一唯一入口，
保证「统一内核」：判定逻辑只有一份，分平台只是搬运 verdict。

match 语义（见 rules.json）：
  - tool:       工具名精确匹配，或 "*" 通配
  - intent:     语义标签（由接入层在 call 上标注，如 "sandbox_escape"）；命中即匹配
  - any_param_contains: 调用 JSON 任意字符串值含任一关键字即匹配（兜底）
  规则不要同时给 intent 与 any_param_contains（intent 优先）。

P0 加固（按 DeepSeek 反馈落地）：
  - 防篡改闭环：load_rules 比对同目录 .rules.sig 的 sha256，篡改则标记 integrity=tampered
  - 授权真伪：stop 生效前置「完整性 ok + 授权四要素结构化完整」，否则降级 suggest
P1 加固：
  - 调用归一化：NFKC 正规化 + Base64 解码尝试 + 简单 leet 折叠，降低文本绕过率
"""

import os
import re
import json
import base64
import hashlib
import unicodedata

_LEET = str.maketrans("013457@", "oieasta")


# --------------------------------------------------------------------------
# 调用归一化（P1）：降低文本变形绕过率
# --------------------------------------------------------------------------
def _normalize_text(s):
    """对单个字符串做归一化，返回拼接后的扩展文本（不破坏原值）。"""
    if not isinstance(s, str):
        return s
    t = unicodedata.normalize("NFKC", s)          # 全角/同形字折叠
    variants = [t]
    # leet 折叠（d15abl3 -> disable）
    leet = t.lower().translate(_LEET)
    if leet != t.lower():
        variants.append(leet)
    # Base64 解码尝试（调用体可能是 base64 编码的恶意指令）
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
    """对 call 中所有字符串值做归一化，返回新结构（不破坏原 call）。"""
    def walk(o):
        if isinstance(o, str):
            return _normalize_text(o)
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o
    return walk(call)


# --------------------------------------------------------------------------
# 防篡改（P0）：sha256 比对 .rules.sig
# --------------------------------------------------------------------------
def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_rules(path, check_sig=True):
    """加载规则。返回 dict 并附 _integrity：
       ok=已签名且匹配 | tampered=签名不符（疑似篡改） | unsigned=无签名文件 | skipped=跳过校验。
    """
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


# --------------------------------------------------------------------------
# 授权真伪（P0）：stop 生效前必须结构化凭证齐全
# --------------------------------------------------------------------------
_AUTH_FIELDS = ["granted_by", "scope", "signed_at", "confirmation_token"]


def authorization_status(rules):
    """返回 (valid, missing_list)。stop 生效前置条件。"""
    az = rules.get("authorization", {}) or {}
    missing = [k for k in _AUTH_FIELDS if not az.get(k)]
    return (len(missing) == 0), missing


# --------------------------------------------------------------------------
# 匹配
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# 唯一判定入口
# --------------------------------------------------------------------------
def evaluate(rules, call):
    """唯一判定入口。返回 verdict dict: {verdict, rule_id, severity, message, integrity, auth_ok}。

    安全降级原则（默认降级）：
      - 规则文件被篡改(tampered) 或 无签名(unsigned) 时，stop 不可用，强制降级为 suggest 并告警；
      - stop 授权四要素不完整时，同样降级为 suggest 并注明缺失项；
      - 不静默放行、不越权制止。
    """
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

        # 制止前置：完整性 + 授权真伪
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
