# Dynamic Trace IR

原始 trace 使用 16-byte header 和 56-byte 定长 event。每个线程单独写文件，字段包括 kind、flags、thread id、sequence、ticket、PC、address、value、size 和 aux。

- `sequence` 是唯一可直接用于普通访存程序序的字段。
- 生命周期与同步事件递增 `ticket`；普通访存只读取当前 ticket，用它归属 object generation。分析器禁止用这个值给普通访存排序。
- `VALUE_KNOWN` 表示 value 可用于反例复核；没有该标志时 value 不参与证明。
- LOCK 和内存 XCHG 统一成为 `ATOMIC_RMW`，并保留 flags；分析器不拆改其原子区域。
- LFENCE、SFENCE、MFENCE 保持独立事件。
- pthread API 事件只帮助切片和解释。target 排序必须来自库内部实际执行的 atomic/Fence，不能仅凭 API 名称添加。

`manifest.json` 固定 executable、library closure、argv、显式环境、工具版本、退出状态和 dropped count。manifest 未完成时仍允许生成报告，但 verdict 必须是 `UNKNOWN`。
