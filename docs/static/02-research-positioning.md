# 02 — Static Route Positioning

本文件只说明 BMoCheck 静态分析路线的范围，不再承担整个项目的总研究定位。
总研究问题、动态主线、相关工作和长期研究计划以
[`docs/research/positioning.md`](../research/positioning.md) 为准。

静态路线的目标是在没有源码的情况下，从 ELF、实际依赖库、线程/同步事实和
DBT6 `mo-off` contract 中构造静态证明。只有完整的静态 `ProofFact` 闭包才能
支持 `SAFE`；输入不完整、依赖未恢复或义务未闭合时保留 `UNKNOWN`。

本路线与当前近期工作有明确边界：

- P19 属于动态验证路线的二进制依赖与执行证据闭合，不是静态 `SAFE` 能力扩展。
- Litmus Pattern → Principle → Static Diagnostic Rule 是长期研究提案，尚未
  形成已验证的静态诊断规则。
- 动态 ObservedFact 和 DiagnosticHint 可以定位静态缺口，但不能进入静态证明或
  关闭 `UnknownFact`。
- “一个具体程序可能可以使用 `mo-off`”仍是待由静态证明支持的目标，不由一次
  运行、有限次 TRACE_SAFE 或 litmus 结果直接推出。

历史上列出的 CrossMapping、Fency/PORTHOS-style checking、程序级通信切片和
`mo-fsm` 组合仅作为研究背景与候选比较方向，不表示这些组合已经完成或构成
BMoCheck 的已证实新颖性。来源和待核实项集中记录在
[`docs/research/related-work.md`](../research/related-work.md)。
