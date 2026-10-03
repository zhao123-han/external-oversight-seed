# 跨平台外挂监管种子 · 统一内核工具包

平台中立的外挂监管套件：在 agent 真正执行工具之前，先拿 `rules.json` 判定一次，按
**L-0 观察 / L-1 建议 / L-2 制止** 三档接管越界行为。核心不绑定任何单一宿主，
WorkBuddy / DeepSeek / 混元 等环境都能装。

> 三份使用说明（都在本文件夹里）：给人读 → USER_GUIDE.md；给 Agent 投喂自安装 → AGENT_INSTALL_GUIDE.md；给程序/智能体直接读（机读版）→ 安装说明_机读版.json。

> ⚠ 状态：实验性 / 参考实现（Experimental / Reference Implementation）
> 本工具包是可运行的参考实现，**非生产级安全产品**。企业级不可篡改部署件（Docker / K8s / seccomp）仅产出配置文件，须在真实 Linux 主机部署并验证后才生效；四平台接入尚未全量实测。监管他人 agent / 大模型须获授权（见 LICENSE）。

## 为什么能跨平台（统一内核）
判定逻辑只有一份，分平台只是搬运 verdict：

```
kernel/rules.json   ← 平台无关规则核心（任何环境可读）
kernel/engine.py    ← 唯一判定入口 evaluate()（零依赖，可移植到任意语言）
cli.py              ← 参考中间件（Python 标准库，stdin 工具调用 → verdict）
adapters/           ← 四平台接入指南（挂接方式不同，判定同一份）
```

## 目录
```
跨平台外挂监管种子/
├── manifest.json          包元数据（版本/入口/零依赖/支持平台）
├── kernel/
│   ├── engine.py          统一判定内核（唯一入口）
│   └── rules.json         平台无关规则核心（7 条越界规则）
├── cli.py                 参考中间件 CLI
├── install.py             跨平台安装器（校验→部署→登记签名→seam自检→可选打包）
├── adapters/              workbuddy / deepseek-harness / generic-api / hunyuan-sandbox / PLATFORM_CHECKLIST
├── deploy/                企业级不可篡改部署件（guard-service / Dockerfile / compose / seccomp / k8s）
├── ENV_HARDENING.md       创造级落地说明（不可篡改稳定性层 + 逐平台映射 + 诚实边界）
├── USER_GUIDE.md          面向人类的使用说明（不堆代码）
├── AGENT_INSTALL_GUIDE.md Agent 投喂即用自安装说明书
├── 安装说明_机读版.json   机读版安装说明（结构化 JSON，程序/智能体可直接解析）
├── docs/设计规格.md        设计规格（四元组 + 三档 + 架构 + 诚实边界）
├── examples/demo_call.json 演示样本
└── LICENSE                Apache-2.0 开源协议（版权：赵涵铖 / 南京召无言教育科技）
```

## 三档与开关
`kernel/rules.json` 顶层 `enforcement`：
- `observe`(L-0) / `suggest`(L-1)：**默认开，安装即生效**；
- `stop`(L-2)：**默认关**，需要制止时改为 `true` 并填全 `authorization` 四要素。

> L-2 开关 = 授权声明，不是授权来源。未开 `stop` 却命中高危规则时，自动降级为 `suggest`（不静默放行、不越权制止）。

## 安全加固（按外部反馈落地）

- **P0 防篡改闭环**：部署时 `install.py` 登记 `kernel/.rules.sig`（rules.json 的 sha256）。内核加载时比对签名，发现被改（哪怕被监管者自己改）即标记 `integrity=tampered`，并强制把 `stop` 降级为 `suggest` + 告警。无签名（`unsigned`）时同样不可用 `stop`。
- **P0 授权真伪**：`stop` 生效前必须 `authorization` 四要素（`granted_by` / `scope` / `signed_at` / `confirmation_token`）真实齐全。只写「我授权了」没用——内核校验字段，缺项即降级。声明 ≠ 验证，部署者自负。
- **P1 调用归一化**：内核对调用体做 NFKC 正规化 + Base64 解码尝试 + 简单 leet 折叠（`d15abl3`→`disable`），降低文本变形绕过率。
- **P1 seam 自检**：`install.py` 按平台打印 seam 确认清单；任一项不满足则 `stop` 不可用。

## 安装
```bash
python install.py --target /path/to/deploy --platform workbuddy [--pack]
```
安装器会校验运行时、部署核心、登记规则签名、校验内核可加载与防篡改闭环、打印 seam 自检清单、做企业隔离探测（env_lock），并按平台输出接入指引；`--pack` 顺便打包 zip 分发。

## 企业级不可篡改部署（创造级落地）

目标：让**监管自身不可被改写、越界行为在环境层被拦死**——即企业级安全基建最看重的「稳」。
授权已由部署者给出，落地形态为可部署 IaC 产物（`deploy/`）：

- **宿主不可篡改隔离**：只读根 fs + 规则只读挂载 / ConfigMap ro + 非 root + drop ALL capabilities
  （`deploy/Dockerfile` / `docker-compose.yml` / `k8s/guard-deployment.yaml`）
- **环境级行为检测**：seccomp 拦截沙盒逃逸/提权相关 syscall（`deploy/seccomp/profile.json`）；
  网络出口默认拒绝 + 白名单（`deploy/k8s/networkpolicy.yaml`）掐断未授权外联
- **企业级微服务**：`deploy/guard-service.py`（stdlib HTTP，POST /evaluate；stop→403 硬阻断）

⇒ 环境层（预防：改不了/跑不掉）+ 内核层（检测：`.rules.sig` / 授权校验兜底）纵深防御。
详见 `ENV_HARDENING.md`。诚实边界：容器/seccomp/eBPF/K8s 需真实 Linux 主机部署，本包只产出配置。

## 诚实边界
- 本包是**设计 + 最小可运行内核 + 企业级部署件**，未在四平台全实测；dsh / 混元 seam 来自文档，未本机验证；容器/seccomp/K8s 需真实环境部署后验证。
- 能力默认可用 **≠ 已获授权**（可监管性 = 有授权 × 有 seam）。
- 只取「对外监管」最小规则子集，不含全量诊断 / 案例资产。
- 不替你决定在哪些平台落地，只给包与路径。

## 最小运行
```bash
echo '{"tool":"shell","intent":"sandbox_escape"}' | python cli.py
# => {"verdict":"suggest",...}   默认 stop=false 时高危降级为建议
```

## 诚实边界
- 本包是**设计 + 最小可运行内核**，未在四平台全实测；dsh / 混元 seam 来自文档，未本机验证。
- 能力默认可用 **≠ 已获授权**（可监管性 = 有授权 × 有 seam）。
- 只取「对外监管」最小规则子集，不含全量诊断 / 案例资产。
- 不替你决定在哪些平台落地，只给包与路径。

<!-- END -->
