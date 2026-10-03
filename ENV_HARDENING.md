# 创造级落地 · 企业级不可篡改稳定性层（ENV_HARDENING）

本文件是「创造级」任务的落地说明。授权已由部署者给出，目标是让**监管自身不可被改写、
越界行为在环境层就被拦死**——即企业级安全基建最看重的「稳 / 不可篡改的稳定性」。

## 一、为什么这一层是「创造级」

- 宿主不可篡改隔离（容器只读挂载 rules.json / 平台级权限隔离）与环境级行为检测
  （seccomp / 网络出口策略）改的是**运行环境 / 平台本身**，不是改一份 Python 文件。
- 它触创造级需授权纪律（创造归人）：本专家只给问询权；**是否落实、如何落实由拿到环境与平台授权的
  部署者决定**。本文件产出的是可部署的 IaC 产物（基础设施即代码），部署动作在部署者侧完成。

## 二、纵深防御：预防（环境层） + 检测（内核层）

| 层 | 机制 | 作用 | 落点 |
|---|---|---|---|
| 环境·预防 | 只读根 fs + rules 只读挂载 / ConfigMap ro | agent 物理上**改不了**规则 | Dockerfile / compose / k8s securityContext |
| 环境·预防 | drop ALL capabilities + no-new-privileges | 阻断提权类沙盒逃逸 | compose security_opt / k8s securityContext |
| 环境·检测 | seccomp 拦截危险 syscall（mount/ptrace/bpf…） | agent 加载内核模块 / ptrace 逃避被拦 | deploy/seccomp/profile.json |
| 环境·检测 | 网络出口默认拒绝 + 白名单 | 未授权外联在网层被掐 | k8s/networkpolicy.yaml |
| 内核·检测 | `.rules.sig` sha256 比对 | 即便规则被改，内核拒绝用 stop 并告警 | kernel/engine.py（P0 已落地） |
| 内核·检测 | 授权四要素校验 | stop 缺授权即降级 | kernel/engine.py（P0 已落地） |

⇒ 环境层把「能不能改 / 能不能跑」堵死；内核层把「改了能否生效」兜底。两层任一层失效，
另一层仍在。

## 三、交付物（deploy/）

```
deploy/
├── guard-service.py     企业级监管微服务（stdlib HTTP，POST /evaluate；stop→403 硬阻断）
├── Dockerfile           只读 rootfs + 规则构建期 0444 + 非 root 10001
├── docker-compose.yml   只读根 fs + rules ro 卷 + cap_drop ALL + seccomp + no-new-privileges
├── seccomp/profile.json 拦截沙盒逃逸/提权相关 syscall
└── k8s/
    ├── guard-deployment.yaml   Deployment+Service（readOnlyRootFilesystem / drop ALL / seccomp Localhost）
    ├── networkpolicy.yaml       默认拒绝出口 + DNS/白名单放行
    └── rules-configmap.yaml     规则只读来源（由 install.py 登记签名后生成）
```

## 四、逐平台映射

- **Linux 容器 / K8s（本层主战场）**：直接用上面的 deploy/ 全部件 → 不可篡改 + 行为检测齐活。
- **WorkBuddy**：沿用 WB 原生 Bash 沙箱（allowedDomains）+ PreToolUse hook；本层规则只读 +
  `.rules.sig` 检测作兜底，防 agent 自行改规则文件。
- **DeepSeek 生态（dsh）**：沿用 dsh 单调守卫（pre-execute allow/deny）+ ctx.tools.restrict；
  本层签名检测兜底。
- **混元 / Cube 沙箱**：沿用 CubeVS eBPF 内核态网络策略（`--deny-out-cidr`）作环境级行为检测；
  本层规则只读 + 签名检测兜底。

⇒ 四平台**统一内核判定不变**，环境级隔离由各平台原生机制 + 本层兜底共同承担。

## 五、部署步骤（以 K8s 为例）

```bash
# 1. 登记规则签名（生成 kernel/.rules.sig）
python install.py --target . --platform generic-api

# 2. 构建镜像（规则构建期即 0444 只读）
docker build -t external-guard-seed:1.0 -f deploy/Dockerfile .

# 3. 把 seccomp 画像放到各节点
#    /var/lib/kubelet/seccomp/guard-seccomp.json  <-  cp deploy/seccomp/profile.json

# 4. 生成规则 ConfigMap（只读挂载源）
kubectl create configmap external-guard-seed-rules \
  --from-file=rules.json=kernel/rules.json \
  --from-file=.rules.sig=kernel/.rules.sig

# 5. 应用工作负载与网络策略
kubectl apply -f deploy/k8s/guard-deployment.yaml
kubectl apply -f deploy/k8s/networkpolicy.yaml

# 6. 被监管面把工具调用转发到 http://external-guard-seed:8080/evaluate
#    verdict.stop -> 403 -> 拒绝执行；verdict.suggest -> 人工复核队列
```

## 六、诚实边界（必读）

- **本沙箱无法实跑**：容器构建、seccomp、eBPF、K8s NetworkPolicy 都需真实 Linux 主机 /
  容器运行时 / K8s 集群，本会话环境（Windows 沙箱）**跑不了**——以上为可部署 IaC 产物，
  生效须在你的真实环境。
- **seccomp 拦截集**：profile.json 拦的是与「沙盒逃逸 / 提权 / 加载 eBPF 逃避」强相关的
  syscall；若你的业务进程需要其中某项（如合法 bpf 观测），需按实际裁剪，避免误伤。
- **网络白名单**：networkpolicy 的 `cidr: 10.0.0.0/8` 是占位，必须按真实管控/被监管网段改。
- **不可篡改是多层共识**：只读挂载 + `.rules.sig` 检测 + 部署者权限控制三者共同成立才真稳；
  任一层被绕过，另一层仍兜，但不能只靠一层。
- **未做**：未实跑任何容器/K8s；未替部署者决定具体网段/节点；env_lock 的检测逻辑已本机验证
  （见各平台部署前 `python install.py` 的 enterprise_check 输出），环境层本身需部署者验证。
