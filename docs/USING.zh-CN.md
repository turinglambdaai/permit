# Permit 使用与支持

[English](USING.md) · **简体中文**

## 何时使用

需要签名且可离线验证的权益时，在应用旁组合 Permit。从 entitlement 开始；只有产品明确需要在线租约时才增加 activation。免费产品不需要授权子系统。

## 要求与成熟度

Racket 实现需要包声明的运行时与加密依赖。Protocol v1 已实现，但尚未宣布稳定 1.0 兼容承诺。独立验证器必须执行权威测试向量。

## 一次有效验证

签发私钥留在签发端，客户端仅持公钥信任库。先验签，再判断产品、时间和功能政策。revision 替换客户端已收到的快照，不会立即撤销离线凭据。为永久权益保留备份和轮换路径，权益密钥与更新、发行者密钥分离。

## 推荐阅读路径

1. [第一份签名权益](getting-started.zh-CN.md)
2. [Protocol v1](protocol-v1.md)
3. [信任模型](trust-model.md)
4. [框架边界](framework-integration.md)
5. [兼容性](compatibility.md)

技术规范保持一个权威版本；链接目标为英文时，它仍是对应行为的定义，不是第二份中文协议。

## 升级、数据与支持

固定并记录应用实际测试的包版本和平台。升级前阅读 CHANGELOG 与兼容契约，在副本上测试用户数据迁移，并保留可恢复版本。框架或库不替产品提供数据库备份、发布证书、退款、账号恢复或隐私政策。不要把示例夹具中的客户、商品和金额当成真实 offer。

在 [Issues](https://github.com/turinglambdaai/permit/issues) 反馈，中文或英文均可。包含包版本/提交、Racket 版本、系统架构、最小复现和已脱敏的首条错误。不要附带真实密钥、客户凭据、支付原始数据或私密文档。社区支持不承诺响应时限。

[敏感漏洞报告流程](../SECURITY.md)。

[现行许可证](../LICENSE) · [CHANGELOG](../CHANGELOG.md)
