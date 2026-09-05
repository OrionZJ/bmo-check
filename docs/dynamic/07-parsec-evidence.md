# PARSEC 动态证据

2026-09-05 复审：实验文件 `certificate-lifecycle.json` 中 blackscholes 和
swaptions 的 TRACE_SAFE 结论已撤回，不可作为安全证据。旧实验用启动/结束 ticket
及 join 数量直接删除通信边，没有证明 DBT6 目标机上的发布/acquire 路径。
当前已停用该剪枝；下面的分区和指令点记录仍只是辅助证据。
随后复审还发现并修复了 RMW from-read 自环及初始读漏边。修复前包含原子窗口的
safe 结果也不构成可信证明；真实程序须在修复和模型复核完成后重新验收。

本文记录 D2 开发期间的可复现实验。应用分区和指令点证据用于解释大型窗口，
不会绕过完整性检查，也不会把整个程序的 `UNKNOWN` 改成 `TRACE_SAFE`。

## blackscholes 与 swaptions：只读输入、分离输出

blackscholes 的 pthread worker 在
`blackscholes.c:281-290` 按 `tid` 切分 `[start,end)`，随后只写自己的
`prices[i]`。两线程测试轨迹包含 233,460 个事件；主模块分区检查得到：

- 2 个 worker，23 个跨 worker 只读共享范围；
- worker 写冲突 0，worker 存活期间的主线程冲突 0；
- 主模块应用分区状态为 `safe`。

二进制 SHA-256：
`9075e16abe11bf6a4fa56e41d4a7da8e2be59a23566d1bb2e98aa6445542f720`。

swaptions 的 pthread worker 在 `HJM_Securities.cpp:83-103` 按余数修正后的
`[beg,end)` 切分 `swaptions`。`-ns 4 -sm 5 -nt 2` 轨迹包含 1,547,625
个事件；主模块分区检查得到：

- 2 个 worker，38 个跨 worker 只读共享范围；
- worker 写冲突 0，worker 存活期间的主线程冲突 0；
- 主模块应用分区状态为 `safe`。

二进制 SHA-256：
`618310690ec0cade7c75f73fe842c0c185ab66ff4ab08f2889ee89d0812f3546`。

这两项只关闭主模块的“只读输入 + 分离输出”子问题。blackscholes 仍有一个
7,835 事件的运行库通信窗口超过当前求解上限，因此整条轨迹仍为 `UNKNOWN`。

## canneal：Checkin 的普通 Store 发布

`AtomicPtr.h:291-297` 想在 `ENABLE_THREADS` 下使用 release store，但条件写成了
`ENABLE_TRHEADS`。当前二进制的 `AtomicPtr<location_t>::Checkin` 在模块偏移
`0x6b7c` 使用普通 `mov %rdx,(%rax)`。

用下列命令按 ASLR 模块基址复核该点：

```bash
bmo-check locate .bmo-check/traces/canneal-test \
  --module /path/to/canneal --offset 0x6b7c
```

测试轨迹中该点执行 3 次，分布在两个 worker；全部为 8 字节 `STORE`，flags
均为 0。追踪器没有把它识别为 LOCK/XCHG 原子访问。二进制 SHA-256：
`b3a76bc8bbdaffd161bd3548061db999c3cdb14e951de04622e91458373f5896`。

这证明轨迹确实经过一个普通 Store 发布点，但还没有证明较弱内存序必然产生错误。
后续求解器必须把该点与对应 checkout/read 及控制依赖放进同一窗口。

## dedup：spin unlock 的普通 Store 发布

`mbuffer.c:21-49` 选择 pthread spin lock，并把 `PTHREAD_UNLOCK` 映射到
`pthread_spin_unlock`。当前 libc 中 `pthread_spin_init` 与
`pthread_spin_unlock` 共用偏移 `0xabaf0`；偏移 `0xabaf4` 都执行
`movl $1,(%rdi)`。因此只看 PC 会把初始化误算成解锁。

`locate` 对 `0xabaf4` 的分线程结果为：

| 线程 | 次数 | 解释 |
|---|---:|---|
| 474 | 1021 | 主线程初始化 `NUMBER_OF_LOCKS` 个锁 |
| 475 | 3 | worker 运行期解锁 |
| 480 | 2 | worker 运行期解锁 |
| 482 | 1 | worker 运行期解锁 |

全部 1027 个事件都是 4 字节 `STORE` 且 flags=0；扣除源码中明确的 1021 次
初始化后，剩余 6 次来自 worker。dedup 二进制 SHA-256 为
`1f67b2713fd684a57aee5cd6a366819333988080301c2839e46113547aabcc47`，
libc SHA-256 为
`a3947513a02831ec692ebf13053c07614882ab54a2101fb91a1b15724062ed0c`。

这说明 DBT6 `mo-off` 必须正确建模运行库里的普通 Store release，不能把同步 API
名字直接当成硬件 Fence。下一步要把 acquire/read 一侧和临界区数据访问一起建模，
才可能产生可验证的 target-only 反例或关闭该窗口。

## 证据边界

- `application_partition.status=safe` 只覆盖主模块中已执行的普通访存范围。
- `locate` 只证明某个模块偏移在该轨迹里如何被分类和执行。
- 运行库窗口、未执行路径、其他输入和未来调度仍需各自证明。
- 上述辅助证据不能单独改变证书 verdict。
