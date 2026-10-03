# 通用 API 场景接入

适用于任何「模型输出工具调用 → 真正执行工具」之间可插代码的场景（自研 agent、第三方 LLM API、无现成 hook 框架）。

## 步骤
1. 部署工具包：`python install.py --target /path/to/guard --platform generic-api`
2. 在你的调用链里，模型返回 `tool_call` 后、执行前插入：
   ```python
   import sys, json
   sys.path.insert(0, "/path/to/guard")
   from kernel.engine import evaluate, load_rules
   call = {"tool": tool_call.name, "intent": None, **tool_call.args}
   v = evaluate(load_rules("/path/to/guard/kernel/rules.json"), call)
   ```
   或子进程调 `cli.py`。
3. 按 verdict 动作：
   - `stop` → 不执行，回拒绝给模型；
   - `suggest` → 告警后由你的逻辑 / 人工决定；
   - `allow` / `observe` → 执行。
4. `enforcement.stop=true` 启用制止（填 `authorization`）。

## 适用
- 调用链必须经过你，拦截点才有效；若模型能直连工具绕开你，需叠加环境级（见 hunyuan_sandbox.md）。

<!-- END -->
