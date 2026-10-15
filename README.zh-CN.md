# Permit

**给独立软件的签名产品权益：离线可验证，需要时也能在线管理。**

[![CI](https://github.com/turinglambdaai/permit/actions/workflows/ci.yml/badge.svg)](https://github.com/turinglambdaai/permit/actions/workflows/ci.yml) ![Racket](https://img.shields.io/badge/Racket-9F1D20?logo=racket&logoColor=white) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) ![Protocol](https://img.shields.io/badge/protocol-v1-3559E0)

[English](README.md) · **中文** · [产品主页](https://permit.jrtx.site)

Permit 是一套与应用框架无关的协议及 Racket 参考实现，只回答一个产品问题：

> 这个人、组织或安装实例，现在可以使用什么？

支付平台能说明钱是否到账，账号系统能说明谁已登录；Permit 则把长期产品权益变成带签名、可携带的凭证。应用只需内置公开信任库，就能在本地完成验证——不强制账号、不依赖每次联网，也不把商业授权塞进应用框架。

## 为什么需要 Permit？

商业软件通常同时需要两种看似相反的能力：

- **离线可验证**：已安装的应用不联网也能判断功能是否应该放行。
- **在线可管理**：未来的签发端可以续订订阅、分配席位、轮换密钥或刷新短期激活租约，而不改变客户端验证协议。

Permit 把两者拆开。长期的 **entitlement（权益凭证）** 描述商业权利；可选的 **activation lease（激活租约）** 在有限时间内把权利绑定到某个安装实例；**trial（试用凭证）** 则保持为独立类型。产品只采用自己需要的层级。

Permit 与应用框架并列组合：

```text
                         产品
                       /      \
              Rivet 或 Glaze   Permit
              运行时 / 更新     产品权益
```

Rivet 和 Glaze 都不依赖 Permit。更新制品签名与 Permit 凭证签名也始终使用不同的密钥和信任策略。

## 可表达的产品模型

Protocol v1 用一套词汇覆盖常见商业模型，但不把价格或支付策略写进应用：

| 产品模型 | 使用权 | 更新 | 新发布功能 |
| --- | --- | --- | --- |
| 永久买断 | 永不过期 | 不限制或限定期限 | 不限制或限定期限 |
| 永久使用 + 更新维护期 | 永久 | 截止维护期结束 | 通常不限制 |
| 永久使用 + 新功能窗口 | 永久 | 通常不限制 | 截止功能窗口结束 |
| 订阅 | 截止订阅结束 | 按策略定义 | 按策略定义 |
| 试用 | 截止试用结束 | 按策略定义 | 按策略定义 |

授权项可以表示版本、功能、附加项、套餐和标量能力。团队所有权、实名席位、设备激活数与并发席位是彼此独立的声明，不挤进一个含义模糊的计数器。`installation_id` 由应用生成并保护隐私，不做硬件指纹。

## 快速开始

安装 Racket 包：

```bash
raco pkg install --auto --name permit https://github.com/turinglambdaai/permit.git
```

生成 Ed25519 密钥对和初始信任库：

```bash
raco permit keygen \
  --private private-key.der \
  --public public-key.der \
  --trust-store trust-store.json \
  --key-id license-2026 \
  --issuer com.example
```

私钥不能进入源码仓库或应用包。对 payload 文件的原始字节签名：

```bash
raco permit sign \
  --key private-key.der \
  --key-id license-2026 \
  --payload entitlement.json \
  --output entitlement.permit.json
```

验证签名、信任密钥、签发方和 schema：

```bash
raco permit verify \
  --trust-store trust-store.json \
  --credential entitlement.permit.json
```

再执行产品策略判断：

```bash
raco permit check \
  --trust-store trust-store.json \
  --credential entitlement.permit.json \
  --product gptp-studio \
  --feature pcap-export \
  --feature-published-at 2026-10-01T00:00:00Z \
  --version 2.0.0
```

`inspect` 会明确标记输出未经验证；绝不能只看 inspect 出来的声明就放行功能。

## Protocol v1

凭证是一个很小的 JSON 信封：

```json
{
  "permit_version": 1,
  "algorithm": "Ed25519",
  "key_id": "license-2026",
  "payload": "<原始 JSON 字节的 base64>",
  "signature": "<Ed25519 签名的 base64>"
}
```

Ed25519 对解码后的 `payload` 字节做**精确签名**。验证端先验签，再解析授权声明；绝不为了验签而“解析 JSON 后重新序列化”。这条规则消除了跨语言 JSON 规范化差异。

Protocol v1 包含：

- `entitlement`、`trial`、`activation` 三种凭证
- 相互独立的 `use_expires_at`、`updates_through`、`features_through` 窗口
- 可选的产品版本范围与安装实例绑定
- 版本、功能、附加项、套餐和标量能力授权
- 团队、实名席位、设备数和并发席位限制
- 带明确离线宽限期的短期激活租约
- 支持 `next`、`active`、`retired`、`revoked` 状态的多密钥信任库
- 确定性的跨语言测试向量

详见[规范性的 Protocol v1 文档](docs/protocol-v1.md)和[管理边界](docs/management-boundaries.md)。

## Racket API

```racket
#lang racket/base

(require permit)

(define store (read-trust-store "trust-store.json"))
(define entitlement
  (verify-credential "entitlement.permit.json" store))

(when (feature-entitled? entitlement
                         "gptp-studio"
                         "pcap-export"
                         #:published-at "2026-10-01T00:00:00Z")
  (enable-pcap-export!))
```

在线管理型产品会同时验证长期权益和短期安装租约：

```racket
(credential-usable? entitlement
                    #:installation-id installation-id
                    #:activation activation-lease)
```

纯离线产品完全可以省略 activation 层。

## 信任与密钥轮换

应用只携带公钥。信任库可以先放入 `next` 密钥，再让签发端切换；用 `active` 密钥进行正常签发；通过截止时间让 `retired` 密钥继续验证历史凭证；并让 `revoked` 密钥立即失效。签发方约束、有效期和密码学签名会一起检查。

因此，一个应用版本可以提前携带明天要启用的公钥，而本地验证路径始终保持确定。

## 有意保留的边界

Permit v0.1 **不实现**支付、客户账号、邮件、定价、税务、管理后台、托管计量或完整许可证服务器。未来这些系统可以签发和刷新 Permit 凭证，但不属于验证核心。

席位分配、设备回收、订阅续期和账号恢复属于未来管理操作；v0.1 只定义这些系统与产品之间交换的签名制品。

## 开发

```bash
raco pkg install --auto --no-docs --link
raco make permit/main.rkt permit/cli.rkt
raco test tests/
```

[`test-vectors/v1`](test-vectors/v1) 下的确定性语料是其他语言实现的互操作契约。

## 仓库结构

```text
permit/
├── permit/                 # 信封、schema、策略、信任库和 CLI
├── docs/                   # 规范协议与管理边界
├── test-vectors/v1/        # 确定性跨语言语料
├── tests/                  # 单元、策略与向量测试
└── site/                   # 双语产品主页
```

## 状态

Protocol v1 已实现 v0.1 的全部凭证类型，但仓库尚未作出稳定 1.0 的兼容承诺。安全敏感字段一律严格校验并默认拒绝；只有 `extensions` 保持开放扩展。

## 许可证

[Apache-2.0](LICENSE)
