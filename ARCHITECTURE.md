# BMoCheck Architecture

## 双实现边界

```text
src/bmo_check_dynamic/       默认主线：观测轨迹范围内的内存序验证
src/bmo_check_static/        保留路线：全二进制静态 SAFE 证明
```

两个包不得互相 import。静态 `SAFE` 与动态 `TRACE_SAFE` 使用不同模型和证书，防止调用方误把一次运行的结论当作全程序结论。

## 动态数据流

```text
capture/native
    ↓ fixed-size per-thread records
trace validation
    ↓ complete trace only
storage/DuckDB
    ↓ bounded-memory batches
normalize/object generations
    ↓ concrete address ranges
analysis/communication + windows
    ↓ small proof obligations
proof/TSO-RVWMO comparison
    ↓
report/certificate
```

- `capture/` 只负责启动 DynamoRIO、固定二进制闭包和执行配置。
- `native/` 记录 guest 事件；写失败必须留下 dropped 标志。
- `trace/` 拒绝截断、乱序、未知版本和零宽访存。
- `storage/` 禁止把完整大型轨迹加载到 Python 内存。
- `analysis/` 只在跨线程、地址重叠且至少一端写入时建立通信边。
- `proof/` 是唯一可以生成动态 verdict 的层。
- `report/` 必须展示证书范围和限制。

## 严格性方向

动态 SAFE 主线对目标模型过近似：不使用记录时钟推导 guest 顺序，也不因为一次读取碰巧得到某个值就删除其他 read-from。过近似可能使结果退化为 `UNKNOWN`，但不能制造错误的 `TRACE_SAFE`。

候选 target-only 执行只有在值和控制骨架均闭合时才能升级为 `COUNTEREXAMPLE`；否则保留 witness 并返回 `UNKNOWN`。

## 存储与扩展

原始记录按线程分文件，没有逐访存全局锁。生命周期、同步和 module 事件使用 ticket。Python 按批写入 DuckDB，并利用页分桶后再做精确字节相交。通信连通分量超过配置上限时返回 `UNKNOWN`，不允许内存失控。

当前不修改 DBT6，也不提供运行时守卫或自动 `mo-off` 选择。
