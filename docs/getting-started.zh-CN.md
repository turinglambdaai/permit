# 从零开始使用 Permit

这份指南会带你把一份未签名的 entitlement 模板变成产品可以安全判断的签名凭证。整个流程不需要账号系统、支付平台或服务器。

[English](getting-started.md)

## 先理解两端

Permit 有意把签发端和产品验证端分开：

```text
签发工作区                          随产品发布
----------                          ----------
private-key.der       永不发布
trust-store.json  ----------------> 公共信任库
entitlement.json      只在签发时使用
entitlement.permit.json ----------> 客户凭证
```

私钥只属于签发环境。应用只拿公共信任数据和已经签名的凭证。

## 1. 安装 Permit

```bash
raco pkg install --auto --name permit https://github.com/turlamai/permit.git
raco permit help
```

## 2. 创建只能签 entitlement 的密钥

请在私有的签发工作区运行：

```bash
raco permit keygen --private private-key.der --public public-key.der --trust-store trust-store.json --key-id entitlement-2026 --issuer com.example --purpose entitlement
```

命令会生成：

| 文件 | 用途 | 是否随产品发布 |
| --- | --- | --- |
| `private-key.der` | 签发 entitlement | **绝不发布** |
| `public-key.der` | 单独保存的公钥 | 可选 |
| `trust-store.json` | 公钥及其允许的签名用途 | **需要** |

真实私钥和真实客户凭证都不应提交到源码仓库。

## 3. 准备 payload

把 [`examples/perpetual.json`](../examples/perpetual.json) 复制为 `entitlement.json`，并至少检查以下字段：

- `credential_id`：本次签名声明的唯一 id；
- `entitlement_id`：续期和重签之间保持稳定的商业权益 id；
- `issuer`：必须与信任库一致，这里是 `com.example`；
- `issued_at`：真实的 UTC 签发时间；
- `subject`：客户、组织、安装实例或匿名持有者；
- `grants`：产品、版本、功能、附加项和能力；
- `constraints`：到期时间、更新/新功能窗口、版本范围、数量限制和激活策略。

payload 是普通 UTF-8 JSON，但 Permit 签的是它的精确字节。请先完成编辑再签发；签发后即使只是重新格式化 JSON，也会得到不同消息并导致签名失效。

## 4. 签发凭证

使用带完整策略检查的 `issue`：

```bash
raco permit issue --key private-key.der --key-id entitlement-2026 --trust-store trust-store.json --payload entitlement.json --output entitlement.permit.json
```

issuer 不一致、私钥不匹配、密钥状态不允许、凭证类型超出 key purpose、签发时间越界或 payload schema 错误时，`issue` 都会拒绝操作。低层 `sign` 命令只适合恢复工具和互操作测试等明确由外部承担这些检查的场景。

## 5. 先验证，再相信声明

```bash
raco permit verify --trust-store trust-store.json --credential entitlement.permit.json
```

验证成功表示签名、密钥、issuer、签发窗口、key purpose 和 payload schema 都合法，但还不等于某个具体功能一定可用。

`raco permit inspect` 只是诊断用解码器，输出会明确标记为未经验证；绝不能用 inspect 的结果直接放行产品功能。

## 6. 询问一个产品权限问题

模板授予了 `example-app` 的 `pro` 版本：

```bash
raco permit check --trust-store trust-store.json --credential entitlement.permit.json --product example-app --edition pro
```

JSON 结果会包含整体是否可用、拒绝原因和本次策略查询结果。如果签名策略需要版本、`installation_id`、activation 或功能发布时间，就必须提供对应上下文；上下文缺失时会安全拒绝。

## 7. 在 Racket 应用中验证

```racket
#lang racket/base

(require permit)

(define trust-store (read-trust-store "trust-store.json"))
(define credential
  (verify-credential "entitlement.permit.json" trust-store))

(unless (edition-entitled? credential "example-app" "pro")
  (error 'startup "当前安装没有 pro 版本的使用权限"))
```

`verify-credential` 要么返回封闭构造的 `verified-credential`，要么抛出错误。产品策略函数只接受这个已验证值，因此未经信任的 JSON 不会意外进入授权路径。

## 只在需要时选择更复杂的模型

- 简单永久买断从 [`examples/perpetual.json`](../examples/perpetual.json) 开始。
- 更新维护截止日期参考 [`examples/maintenance.json`](../examples/maintenance.json)。
- 新功能窗口参考 [`examples/feature-window.json`](../examples/feature-window.json)。
- 有限使用期参考 [`examples/subscription.json`](../examples/subscription.json)。
- 设置 `activation_required` 之前先阅读[激活租约](activation-v1.md)。
- 选择签名试用或纯客户端首次启动状态之前先阅读[本地试用](local-trials.md)。
- 轮换或吊销密钥之前先阅读[信任模型](trust-model.md)。

## 上线检查表

- 私钥不得进入应用包或源码仓库。
- 在线 activation signer 只授予 `activation` purpose，不能让它签永久 entitlement。
- Permit 凭证密钥、更新签名密钥和操作系统发布者密钥必须相互独立。
- 一定先验签，再判断策略；绝不能从“已解码但未验证”的声明授权。
- 保留仍被有效永久凭证依赖的 retired 公钥。
- `installation_id` 使用应用生成的随机标识，不做硬件指纹。
- 发布前用 [`test-vectors/v1/`](../test-vectors/v1/) 验证集成实现。

[升级、成熟度与支持](USING.zh-CN.md)。
