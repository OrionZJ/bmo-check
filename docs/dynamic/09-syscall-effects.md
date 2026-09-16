# Syscall effect 闭合

Trace format 1.1 为每个 syscall 记录 enter、六个 64 位参数和返回值。
exit/exit_group 不返回，允许没有 exit 记录；其他未配对调用一律
`UNKNOWN`。

分析器不把 syscall 名称当作 Fence。它只关闭下列已证明 effect：

- 没有其他 app thread 存活时，内核读写被折叠为后续轨迹的初始或最终状态。
- close、exit 和 exit_group 不读写用户字节。
- mmap 只允许成功的私有、非 MAP_FIXED 新对象。
- mprotect 不改写字节；增加 PROT_EXEC 仍作为 JIT 风险拒绝。
- 并发 read、write 和 openat 只有在完整 trace 的用户缓冲区范围扫描确认
  没有其他活跃线程的冲突访存后才关闭；超出页预算或出现交叠仍为 `UNKNOWN`。
- munmap 必须是成功调用，且其页范围完整落在已完成的 mmap 所建立、尚未被
  munmap 移除的范围内。分析按 syscall 返回 ticket 回放映射变化；并发重叠的
  mmap/munmap 会让交叠范围保持未知。HugeTLB、无对应 mmap 证据或边界不合法时，
  不关闭该 syscall effect。部分 munmap 可以关闭 syscall effect，但不会因此把
  整个原 mapping object 标为已结束；对象切片仍保守保留交叠关系。
- rt_sigprocmask 的输出指针必须为 NULL 或完整落在当前线程 stack；输入指针
  还可以指向已按 trace 中模块哈希核对、由 ELF load segment 证明只读的范围。
  任何成功的 writable mprotect 或 munmap 都会撤销重叠范围，未知 ELF/哈希继续
  保留 `UNKNOWN`。
- ARCH_SET_FS/GS 和 rseq 只更新当前线程的 TLS 状态；ARCH_GET
  只允许写回当前线程 stack。
- clone3 参数必须完整落在创建者 stack，线程生命周期仍由
  `THREAD_START/THREAD_END` 记录。

并发 futex、writev、mremap、brk 和其他未列出 effect 仍返回 `UNKNOWN`。
不能因为某次调用成功或程序跑通就移除它们。

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
