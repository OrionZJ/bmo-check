# Dynamic Trace IR

原始 trace 使用 16-byte header 和 56-byte 定长 event。每个线程单独写文件，字段包括 kind、flags、thread id、sequence、ticket、PC、address、value、size 和 aux。

- `sequence` 是唯一可直接用于普通访存程序序的字段。
- 生命周期与同步事件递增 `ticket`；普通访存只读取当前 ticket，用它归属 object generation。分析器禁止用这个值给普通访存排序。
- `VALUE_KNOWN` 表示 value 可用于反例复核；没有该标志时 value 不参与证明。
- 每线程序号必须从 1 连续递增；缺口、重复、未知 flags 和越界地址均拒绝验证。
- LOCK 和内存 XCHG 统一成为 `ATOMIC_RMW`，并保留 flags；分析器不拆改其原子区域。
- LFENCE、SFENCE、MFENCE 保持独立事件。
- pthread API 事件只帮助切片和解释。target 排序必须来自库内部实际执行的 atomic/Fence，不能仅凭 API 名称添加。

`SYNC_CALL=17` 保存条件变量、barrier、semaphore 调用。`aux=(API<<1)|phase`，
phase 为 0 表示进入、1 表示返回。API 1–9 依次为 cond_wait、cond_timedwait、
cond_signal、cond_broadcast、barrier_wait、sem_wait、sem_trywait、sem_timedwait、
sem_post。address 保存同步对象地址；cond wait 的进入记录用 value 保存 mutex
地址，返回记录用 value 保存按有符号 32 位解释后扩展的返回码。
记录失败调用不代表获得了同步；barrier 的特殊成功返回值须按 API 单独解释。

`manifest.json` 固定 executable、library closure、argv、显式环境、DynamoRIO/client
版本、退出状态和 dropped count。`dropped_by_reason` 区分写文件失败、线程状态
缺失、未知宽度、寄存器不足、地址计算失败、生命周期及 module 元数据失败；总数
非零时 verdict 必须是 `UNKNOWN`。manifest 未完成时仍允许生成报告，但 verdict
也必须是 `UNKNOWN`。
