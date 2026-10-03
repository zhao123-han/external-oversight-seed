# WorkBuddy 接入

在 **PreToolUse** hook 里调用 `cli.py`，使每次工具执行前先过统一内核。

## 步骤
1. 用安装器部署工具包：`python install.py --target /path/to/guard --platform workbuddy`
2. 在 WorkBuddy 的 hook 配置里加 PreToolUse：执行
   `python /path/to/guard/cli.py --rules /path/to/guard/kernel/rules.json`
   并把本次工具调用的 JSON 通过 stdin 传入（接入层负责把工具调用组装成 JSON，可附 `intent` 语义标签）。
3. 读取 stdout 的 verdict：
   - `observe` / `suggest`：放行，把 `message` 写入告警或日志，由人工或被监管方决定；
   - `stop`：hook 以**退出码 2 硬阻断**（需 hook 已被授予 deny 权）。
4. 需要制止时，编辑 `kernel/rules.json` 把 `enforcement.stop` 改为 `true` 并填全 `authorization`。

## 边界
- **PostToolUse 无法真正阻断**，制止必须用 PreToolUse。
- `observe` / `suggest` 默认开，但仍需被监管方授权（可监管性 = 有授权 × 有 seam）。

<!-- END -->
