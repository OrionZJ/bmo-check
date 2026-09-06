# Syscall effect 闭合

Trace format 1.1 为每个 syscall 记录 enter、六个 64 位参数和返回值。
exit/exit_group 不返回，允许没有 exit 记录；其他未配对调用一律
`UNKNOWN`。

分析器不把 syscall 名称当作 Fence。它只关闭下列已证明 effect：

- 没有其他 app thread 存活时，内核读写被折叠为后续轨迹的初始或最终状态。
- close、exit 和 exit_group 不读写用户字节。
- mmap 只允许成功的私有、非 MAP_FIXED 新对象。
- mprotect 不改写字节；增加 PROT_EXEC 仍作为 JIT 风险拒绝。
- munmap 必须与同线程、同地址和同长度的 `MUNMAP` 对象生命周期事件匹配。
- rt_sigprocmask 的用户指针必须为 NULL 或完整落在当前线程 stack。
- ARCH_SET_FS/GS 和 rseq 只更新当前线程的 TLS 状态；ARCH_GET
  只允许写回当前线程 stack。
- clone3 参数必须完整落在创建者 stack，线程生命周期仍由
  `THREAD_START/THREAD_END` 记录。

并发 futex、read/write/writev、mremap、brk 和其他未列出 effect 仍返回
`UNKNOWN`。不能因为某次调用成功或程序跑通就移除它们。

## PARSEC 代表验证

2026-09-06 用 client 0.4 的新元数据重跑：

| 程序 | 原阻塞 | 新结果 |
|---|---|---|
| blackscholes | 60 个 opaque syscall | 只剩 1 次并发 futex effect |
| swaptions | 78 个 opaque syscall | syscall 全闭合；进入通信分析，输出分区 safe，但 6,939 事件窗口超限 |
| canneal | 89 个 opaque syscall | syscall 全闭合；得到 3,295 条通信边，1,456 事件窗口超限 |
| dedup | 169 个 opaque syscall | 缩小为并发 write、munmap、sigmask、futex、mremap 和 openat |
| freqmine | 83 个 opaque syscall | 缩小为并发 write、munmap 和 brk |

本轮仍没有把任何 PARSEC 轨迹升级为 `TRACE_SAFE`。结果的改进在于
UNKNOWN 已从“任意 syscall”缩小到未支持的具体 effect，且 swaptions/canneal
已进入真实通信窗口分析。
