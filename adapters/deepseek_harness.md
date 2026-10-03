# DeepSeek 生态（dsh）接入

dsh 提供 `pre-execute` 钩子，可挂监管插件，逻辑与统一内核对接。

## 步骤
1. 部署工具包到 dsh 运行环境：`python install.py --target /path/to/guard --platform deepseek-harness`
2. 写一个 `pre-execute` 插件，在工具执行前：
   - 把待执行工具调用组装成 JSON（含 `intent` / 参数）；
   - 调 `python /path/to/guard/cli.py`（或直接 `import kernel.engine; evaluate(...)`）；
   - `verdict=stop` 时返回拒绝，阻断执行；
   - `verdict=suggest` 时记录告警，由 dsh 侧人工决定。
3. `enforcement.stop=true` 才启用制止（并填全 `authorization`）。

## 说明
- dsh 的 seam 细节来自技术文档，**未本机验证**；`pre-execute` 具体 API 以 dsh 实际版本为准。
- 本适配器只给接入路径，不含 dsh 私有代码。

<!-- END -->
