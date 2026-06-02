# comply-agent 法规参考数据库

## 设计理念

每条 OWASP 检测规则关联具体法律法规条款，让检测报告从"技术风险"升级为"合规义务"。

## 数据源分层

| 层级 | 数据源 | 覆盖 | 融合方式 |
|------|--------|------|---------|
| L1 核心 | EU AI Act（2026.8生效）| 欧盟 | Article 条款映射 |
| L1 核心 | 中国《生成式AI服务管理暂行办法》+《数据安全法》 | 中国 | 条款映射 |
| L2 参考 | OWASP Agentic Top 10 (ASI01-ASI09) | 全球 | 规则ID映射 |
| L2 参考 | ISO/IEC 42001:2023 | 全球 | 控制点映射 |
| L3 事故 | AIAAIC Repository | 全球 | 相关案例引用 |
| L3 事故 | AI Incident Database | 全球 | 相关案例引用 |

## 融合架构

```
rules/asi01-prompt-injection.yaml  ← 已有
  ↓ 新增 references 字段
references/
├── eu_ai_act.yaml       # EU AI Act 条款 → OWASP 映射
├── china_ai_law.yaml    # 中国 AI 法规 → OWASP 映射
├── iso_42001.yaml        # ISO 42001 控制点 → OWASP 映射
└── incidents.yaml        # AIAAIC/AIID 事故案例 → OWASP 映射
```

## 不做的事

- ❌ 不内置全文（版权+体积）
- ❌ 不做法律建议（只做技术检测+法规引用）
- ❌ 不自动更新法规（手动维护，确保准确性）
