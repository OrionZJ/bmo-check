# BMoCheck — Agent Rules

## 项目方向

BMoCheck 默认走动态轨迹验证：DynamoRIO 采集原生 x86-64 ELF，离线比较 x86-TSO 与 DBT6 `mo-off + RVWMO`。原静态验证器完整保留在 `bmo_check_static`，但不再是默认入口。

开始修改前阅读：

1. `docs/dynamic/00-project-and-soundness.md`
2. `docs/dynamic/01-trace-ir.md`
3. `docs/dynamic/02-dynamorio-capture.md`
4. `docs/dynamic/03-objects-and-communication.md`
5. `docs/dynamic/04-portability-check.md`
6. `docs/dynamic/05-verdict-and-certificate.md`
7. 当前 `docs/exec-plans/active/` milestone

## 最高规则

动态 verdict 只允许 `TRACE_SAFE`、`COUNTEREXAMPLE`、`UNKNOWN`。

`TRACE_SAFE` 只覆盖证书绑定的轨迹事件骨架。禁止把程序跑通、多跑几次没有报错、本次没看到间接目标、本次地址没有重叠或 DynamoRIO 的实际调度顺序解释成无条件 SAFE。

轨迹丢失、截断、未知记录、资源超限和不支持事件必须传播为 `UNKNOWN`。

## 包边界

- `bmo_check_dynamic` 和 `bmo_check_static` 不得互相 import。
- `bmo-check` 属于动态包；`bmo-check-static` 属于静态包。
- 只有各自的 `proof/` 能构造最终 verdict。
- 不恢复旧 `bmo_check` namespace。
- 本阶段不修改 DBT6，也不实现运行时守卫。

## 动态证据规则

- 程序序只能来自同一 thread 的 sequence。
- ticket 只用于生命周期、同步配对和 object generation，不能给普通访存增加顺序。
- 地址复用必须产生新的 object generation。
- 通信边要求跨线程、字节范围相交且至少一端写。
- 实际间接目标对当前轨迹是已知事实；它不能证明未执行目标不存在。
- target 模型允许过近似。删除 target 行为必须有明确的 Fence、atomic、同步或架构依据。
- 未验证的 target-only candidate 返回 `UNKNOWN`，不能输出反例结论。

## 资源规则

大型轨迹必须流式解码并落盘。禁止用无界 Python list、全量 NetworkX 图或一次性笛卡尔积承载整个程序。超过窗口、页跨度、执行枚举或时间限制时返回带原因的 `UNKNOWN`。

## 测试规则

每项 proof 能力至少需要正例、反例和 Unknown 传播测试。必须保留截断 trace、dropped events、间接目标、地址复用、混合宽度、LOCK/XCHG、显式 Fence 和通信窗口超限用例。

注释重点解释为什么某个事实足以删除行为，或为什么必须传播 Unknown，不逐行翻译代码。
