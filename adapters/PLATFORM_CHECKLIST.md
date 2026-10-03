# 宿主平台对接 Checklist（P2）

本清单用于确认目标平台「能否真正把越界调用交给我们拦截」。任一不满足，则
`enforcement.stop` 档位不可用——此时请保持 stop=false，只用观察/建议档位。

## 通用前置（四平台都要）

- [ ] 工具调用在**执行前**先过 `kernel/engine.evaluate(rules, call)`（前置拦截，非事后审计）
- [ ] `verdict.stop` 被当作**硬阻断**（拒绝执行该工具），`verdict.suggest` 进人工复核队列
- [ ] `rules.json` 与 `.rules.sig` 一并提供，且运行时能对 `.rules.sig` 做 sha256 校验
- [ ] 安装后运行 `python install.py --target <dir> --platform <p>` 通过全部 `[校验]` 行

## WorkBuddy

- [ ] 挂接为工具前置 hook / 中间件，覆盖所有 tool 调用入口
- [ ] 确认 hook 在 stop=true 时能真正中止调用（而非仅记录日志）
- [ ] rules.json 以只读方式随包分发，Agent 运行期无法改写

## DeepSeek Harness（投喂式）

- [ ] 已把 `AGENT_INSTALL_GUIDE.md` 全文投喂，目标 Agent 每次 tool 调用前调用 evaluate
- [ ] harness 把 `verdict.stop` 当作硬阻断
- [ ] rules.json 与 .rules.sig 一并随 Agent 上下文加载（同源、同版本）

## 通用 API / 网关

- [ ] API 中间件在 tool 分发前同步调用 evaluate，并尊重 verdict
- [ ] verdict.stop 返回 403/阻断；verdict.suggest 触发人工复核
- [ ] 规则文件存放在中间件侧，中间件进程有读 .rules.sig 的权限

## 混元沙箱

- [ ] 沙箱在 tool 执行前挂载本内核为前置拦截器
- [ ] 沙箱层面 stop 能中止本次工具执行
- [ ] rules.json 以只读挂载进沙箱（容器 ro 卷 / immutable 属性）

## 授权登记（打开 stop 前必做）

`rules.json` 的 `authorization` 四要素必须**真实完整填写**，否则即便 stop=true 也会
被内核降级为建议（声明 ≠ 验证）：

- `granted_by`：谁授权的（人名/组织）
- `scope`：授权范围（哪些环境/哪些 Agent 可制止）
- `signed_at`：授权时间戳
- `confirmation_token`：部署者一次性交互确认凭证

> 说明：本工具包只做「问询与降级」，是否真制止由**已获授权的部署者**决定。
> 未经授权的制止动作 = 虚假监管（见设计规格中的授权纪律）。
