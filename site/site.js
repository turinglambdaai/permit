(function () {
  var I18N = {
    en: {
      'nav.why': 'Why', 'nav.models': 'Models', 'nav.protocol': 'Protocol', 'nav.start': 'Quick start',
      'hero.eyebrow': 'Protocol v1 · Ed25519 · Apache-2.0',
      'hero.title': 'Sign once.\nAuthorize anywhere.',
      'hero.lede': 'Permit gives independent software a small, open format for product rights that work offline and stay manageable online.',
      'hero.start': 'Get started', 'hero.spec': 'Read Protocol v1',
      'proof.offline': 'Offline-verifiable', 'proof.online': 'Online-manageable', 'proof.framework': 'Framework-neutral',
      'credential.label': 'SIGNED CREDENTIAL', 'credential.verified': 'verified', 'credential.public': 'public trust', 'credential.payload': 'exact payload',
      'why.eyebrow': 'THE MISSING PRODUCT LAYER', 'why.title': 'Payments are not permissions.',
      'why.p1': 'A payment event proves that money moved. An account proves identity. Neither gives an installed app a durable, portable answer to “what may this user run right now?”',
      'why.p2': 'Permit turns that answer into a signed artifact. The application verifies it locally with public keys it already trusts. Commerce or another explicit issuer service may issue or refresh credentials, but authorization never depends on that service being reachable.',
      'principle.one.title': 'Exact bytes, no ambiguity',
      'principle.one.body': 'Ed25519 signs the decoded payload bytes exactly. Verifiers never parse and re-serialize JSON before checking the signature.',
      'principle.two.title': 'Rights outlive connectivity',
      'principle.two.body': 'Long-lived entitlements stand on their own. Products add short-lived activation leases only when their policy needs online control.',
      'principle.three.title': 'Policy without platform lock-in',
      'principle.three.body': 'Permit sits beside Rivet, Glaze, native apps, or any other runtime. The application framework never owns commercial policy.',
      'models.eyebrow': 'ONE VOCABULARY, DISTINCT WINDOWS', 'models.title': 'Model the product you actually sell.',
      'models.lede': 'Use rights, update eligibility, and access to newly published features are independent facts.',
      'models.model': 'Model', 'models.use': 'Use', 'models.updates': 'Updates', 'models.features': 'New features',
      'models.perpetual': 'Perpetual purchase', 'models.forever': 'Forever', 'models.open': 'Open or bounded',
      'models.maintenanceModel': 'Perpetual + maintenance', 'models.featureModel': 'Perpetual + feature window',
      'models.maintenance': 'Maintenance window', 'models.featureWindow': 'Feature window',
      'models.subscription': 'Subscription', 'models.untilEnd': 'Until term end', 'models.policy': 'By policy',
      'models.trial': 'Trial', 'models.untilTrial': 'Until trial end',
      'models.note': 'Teams, named seats, devices, concurrent seats, bundles, editions, add-ons, and scalar capabilities remain separate claims — no overloaded “license count.”',
      'protocol.eyebrow': 'SMALL CORE, EXPLICIT LAYERS', 'protocol.title': 'Verify first. Interpret second.',
      'protocol.one.title': 'Envelope', 'protocol.one.body': 'Decode the payload and signature. Reject unknown protocol versions and algorithms.',
      'protocol.two.title': 'Trust', 'protocol.two.body': 'Resolve key_id through next, active, retired, or revoked trust-store state.',
      'protocol.three.title': 'Signature', 'protocol.three.body': 'Verify Ed25519 over the exact payload bytes before claims are used.',
      'protocol.four.title': 'Policy', 'protocol.four.body': 'Evaluate product, version, time windows, grants, installation, and optional lease.',
      'layers.entitlement': 'Durable commercial right', 'layers.activation': 'Optional installation lease', 'layers.trial': 'Independent evaluation right',
      'rotation.eyebrow': 'KEY ROTATION WITHOUT A FLAG DAY', 'rotation.title': 'Ship tomorrow\'s trust before you need it.',
      'rotation.next': 'staged in clients', 'rotation.active': 'signing now', 'rotation.retired': 'historical cutoff', 'rotation.revoked': 'rejected immediately',
      'start.eyebrow': 'RACKET REFERENCE IMPLEMENTATION', 'start.title': 'From zero to verified.',
      'start.lede': 'Install the package, generate a key pair, sign a payload, then verify it with only the public trust store.',
      'start.source': 'Browse source and test vectors →',
      'boundary.eyebrow': 'A DELIBERATE BOUNDARY', 'boundary.title': 'A protocol, not a billing company.',
      'boundary.body': 'Permit v0.1 does not implement payments, accounts, pricing, tax, email, dashboards, hosted metering, or a license server. Commerce owns the family payment-to-rights workflow and may issue credentials through the explicit issuer boundary; it does not belong in the verification core.',
      'footer.tagline': 'Signed product rights for independent software.'
    },
    zh: {
      'nav.why': '为什么', 'nav.models': '产品模型', 'nav.protocol': '协议', 'nav.start': '快速开始',
      'hero.eyebrow': 'Protocol v1 · Ed25519 · Apache-2.0',
      'hero.title': '签一次，\n到处都能验。',
      'hero.lede': 'Permit 给独立软件一套小而开放的产品权益格式：离线可验证，需要时也能在线管理。',
      'hero.start': '快速开始', 'hero.spec': '阅读 Protocol v1',
      'proof.offline': '离线可验证', 'proof.online': '在线可管理', 'proof.framework': '与框架无关',
      'credential.label': '签名凭证', 'credential.verified': '已验证', 'credential.public': '公开信任', 'credential.payload': '精确 payload',
      'why.eyebrow': '缺失的产品层', 'why.title': '付款，不等于权限。',
      'why.p1': '支付事件只能证明钱已到账，账号只能证明用户身份。它们都不能给已安装的应用一个长期、可携带的答案：“这个用户现在可以运行什么？”',
      'why.p2': 'Permit 把答案变成签名制品。应用用已经信任的公钥在本地验证；Commerce 或其他明确的签发服务可以签发或刷新凭证，但授权判断不依赖服务此刻是否在线。',
      'principle.one.title': '精确字节，没有歧义',
      'principle.one.body': 'Ed25519 对解码后的 payload 字节做精确签名。验证端绝不先解析 JSON、重新序列化，再验签。',
      'principle.two.title': '权益不随网络消失',
      'principle.two.body': '长期 entitlement 可以独立成立；只有当产品策略需要在线控制时，才叠加短期 activation lease。',
      'principle.three.title': '商业策略不锁进平台',
      'principle.three.body': 'Permit 可以与 Rivet、Glaze、原生应用或其他运行时并列使用；应用框架不拥有商业授权策略。',
      'models.eyebrow': '一套词汇，三种独立时间窗', 'models.title': '表达你真正售卖的产品。',
      'models.lede': '使用权、更新资格和新发布功能的访问权，是三件互相独立的事实。',
      'models.model': '模型', 'models.use': '使用', 'models.updates': '更新', 'models.features': '新功能',
      'models.perpetual': '永久买断', 'models.forever': '永久', 'models.open': '不限或限定',
      'models.maintenanceModel': '永久使用 + 更新维护期', 'models.featureModel': '永久使用 + 新功能窗口',
      'models.maintenance': '维护期', 'models.featureWindow': '新功能窗口',
      'models.subscription': '订阅', 'models.untilEnd': '到订阅结束', 'models.policy': '按策略',
      'models.trial': '试用', 'models.untilTrial': '到试用结束',
      'models.note': '团队、实名席位、设备、并发席位、套餐、版本、附加项和标量能力分别表达——没有含义过载的“许可证数量”。',
      'protocol.eyebrow': '核心很小，层级明确', 'protocol.title': '先验证，再解释。',
      'protocol.one.title': '信封', 'protocol.one.body': '解码 payload 和签名；拒绝未知协议版本和算法。',
      'protocol.two.title': '信任', 'protocol.two.body': '通过 key_id 解析 next、active、retired 或 revoked 状态。',
      'protocol.three.title': '签名', 'protocol.three.body': '在使用任何声明之前，对精确 payload 字节完成 Ed25519 验证。',
      'protocol.four.title': '策略', 'protocol.four.body': '判断产品、版本、时间窗、授权项、安装实例和可选租约。',
      'layers.entitlement': '长期商业权益', 'layers.activation': '可选的安装租约', 'layers.trial': '独立的试用权益',
      'rotation.eyebrow': '无需停机切换的密钥轮换', 'rotation.title': '在需要之前，先把明天的信任发出去。',
      'rotation.next': '已预置到客户端', 'rotation.active': '当前签发', 'rotation.retired': '保留历史截止线', 'rotation.revoked': '立即拒绝',
      'start.eyebrow': 'RACKET 参考实现', 'start.title': '从零到验证通过。',
      'start.lede': '安装包、生成密钥对、签一个 payload，再只用公开信任库完成验证。',
      'start.source': '查看源码与测试向量 →',
      'boundary.eyebrow': '有意保留的边界', 'boundary.title': '它是协议，不是账单公司。',
      'boundary.body': 'Permit v0.1 不实现支付、账号、定价、税务、邮件、管理后台、托管计量或许可证服务器。家族内从支付到权益的流程由 Commerce 负责，并通过显式 issuer 边界签发凭证；它不进入验证核心。',
      'footer.tagline': '给独立软件的签名产品权益。'
    }
  };

  function language() {
    return document.documentElement.lang === 'zh-CN' ? 'zh' : 'en';
  }

  function applyLanguage(lang) {
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    document.querySelectorAll('[data-i18n]').forEach(function (element) {
      var value = I18N[lang][element.dataset.i18n];
      if (value) {
        if (element.dataset.i18n === 'hero.title') {
          element.innerHTML = value.replace('\n', '<br>');
        } else {
          element.textContent = value;
        }
      }
    });
    document.getElementById('lang-button').textContent = lang === 'zh' ? 'EN' : '中文';
    localStorage.setItem('permit-lang', lang);
  }

  document.getElementById('lang-button').addEventListener('click', function () {
    applyLanguage(language() === 'zh' ? 'en' : 'zh');
  });

  document.getElementById('theme-button').addEventListener('click', function () {
    var next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('permit-theme', next);
  });

  applyLanguage(language());
})();
