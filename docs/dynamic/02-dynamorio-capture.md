# DynamoRIO 采集

追踪 client 对每个 app memory operand 插入记录点，并识别 LOCK/XCHG、显式 Fence、间接分支、module、thread、signal 和 syscall。常见 allocator 与 pthread 锁 API 使用 `drwrap` 记录对象生命周期和同步边界。

REP 字符串指令和 gather/scatter 可以在一条指令中访问多个地址。client
在 app2app 阶段展开它们，再对每次真实访存插桩；展开失败记为
`instrumentation` drop，防止不完整轨迹获得 `TRACE_SAFE`。原生验收还用精确
PC 和宽度覆盖 push/pop、CALL/RET、x87 及 SIMD 访存。

条件变量、barrier、semaphore 分别记录进入和返回，保留对象地址与返回码。
libc 同名版本符号可能对应不同实现地址，client 枚举导出符号覆盖各版本。
原生测试覆盖 timedwait 超时、sem_trywait 失败以及 barrier serial-thread 成功返回。

普通访存写入线程私有文件，不取得全局锁。只有需要跨线程配对的事件领取 ticket。写文件或寄存器插桩失败会增加 dropped count，进程退出时写 `.dropped` 与 `.complete`。

Python launcher 在执行前保存不完整 manifest，执行后读取两个 marker。追踪器崩溃、被 kill 或 marker 缺失时不能伪装成空通信。

首版支持 WSL2 和原生 Linux 的 x86-64 ELF。PE、JIT、自修改代码及跨进程共享映射不在支持范围。
`MAP_SHARED`、匿名可执行 mmap、fork/vfork、非 `CLONE_VM` clone 和 exec 会记录
`unsupported` drop，使完整性检查严格返回 `UNKNOWN`。

当前 syscall 事件只记录编号。内核可能通过参数访问共享用户内存，因此多线程轨迹
不能把它当无副作用边界；完整性检查会保守返回 `UNKNOWN`。后续只有在采集参数、
返回值并由 syscall effect 表覆盖后，才能逐项解除该限制。
