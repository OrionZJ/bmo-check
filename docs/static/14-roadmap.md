# 14 — Static Route Roadmap

本路线图仅跟踪静态二进制分析能力。早期 MVP 阶段列表保留在 Git 历史中，
不再视为当前项目的整体路线或 P19 的验收标准。总研究计划见
[`docs/research/README.md`](../research/README.md)。

## 当前边界

- 静态 `SAFE` 仍要求仓库级 soundness contract 所定义的完整静态证明闭包。
- 静态分析目前仍有多类 recovery/provenance precision gap；不能因动态工作流或
  P18 模型结果而声称这些 gap 已关闭。
- 原 E3.1 thread/lifecycle 改进保持暂停。恢复前需依据 hybrid diagnostics、
  canneal 证据和 2,595-ELF baseline 重新选择高价值通用能力。
- 长期的静态诊断规则路线见
  [`Pattern → Principle → Static Diagnostic Rule`](../research/pattern-to-diagnostic-roadmap.md)，
  当前不实施。

## 后续静态工作准入条件

未来每个静态 precision 改进应先指定一个根因及明确的证明事实，然后：

1. 用合成正例、反例和 Unknown 传播测试刻画原行为；
2. 定义新增 `ProofFact` 的来源、身份、适用范围和独立 replay 条件；
3. 用通用分析能力实现，不按 benchmark、litmus 名称或一次 trace 特判；
4. 对相同的 2,595-ELF corpus 重跑并按 root blocker 比较；
5. 保持 E2.5 correctness baseline、certificate soundness 和动态证据隔离。

选择下一项静态能力之前，先 review 现有 measurement 和研究文档；不得把减少
`UNKNOWN` 数量本身当作正确性证据。
