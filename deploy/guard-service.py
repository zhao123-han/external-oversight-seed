#!/usr/bin/env python3
"""跨平台外挂监管种子 . 企业级监管微服务（零第三方依赖，仅标准库）。

把统一内核暴露为 HTTP 微服务：POST /evaluate 收 {"call": {...}}，返回 verdict JSON。
规则文件以只读方式随容器分发（见 deploy/ 加固件），内核比对 .rules.sig 做防篡改检测。

企业不可篡改层：stop 命中即返回 HTTP 403 硬阻断，调用方（被监管 agent / 网关）据此拒绝执行。
配合只读挂载 + seccomp + 网络出口策略（见 deploy/），构成「规则不可改 + 越界行为拦不到也跑不掉」。

用法（容器内）：
  python /app/deploy/guard-service.py --host 0.0.0.0 --port 8080
"""

import os
import sys
import json
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PKG)
from kernel.engine import load_rules, evaluate

RULES = os.path.join(PKG, "kernel", "rules.json")
_rules = load_rules(RULES)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok", "integrity": _rules.get("_integrity")})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/evaluate":
            self._send(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n > 0 else b"{}"
            call = json.loads(raw or b"{}")
        except Exception as e:
            self._send(400, {"error": "bad json", "detail": str(e)})
            return
        # 调用归一化与判定在 engine 内完成
        payload = call.get("call", call)
        v = evaluate(_rules, payload)
        # 企业硬阻断：stop 命中即 403
        code = 403 if v["verdict"] == "stop" else 200
        self._send(code, v)

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser(description="跨平台外挂监管种子 企业级监管微服务")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    print("[监管微服务] 监听 %s:%d，rules 完整性=%s"
          % (args.host, args.port, _rules.get("_integrity")))
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
