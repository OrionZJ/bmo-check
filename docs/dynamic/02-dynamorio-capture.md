# DynamoRIO 采集

追踪 client 对每个 app memory operand 插入记录点，并识别 LOCK/XCHG、显式 Fence、间接分支、module、thread、signal 和 syscall。常见 allocator 与 pthread 锁 API 使用 `drwrap` 记录对象生命周期和同步边界。

普通访存写入线程私有文件，不取得全局锁。只有需要跨线程配对的事件领取 ticket。写文件或寄存器插桩失败会增加 dropped count，进程退出时写 `.dropped` 与 `.complete`。

Python launcher 在执行前保存不完整 manifest，执行后读取两个 marker。追踪器崩溃、被 kill 或 marker 缺失时不能伪装成空通信。

首版支持 WSL2 和原生 Linux 的 x86-64 ELF。PE、JIT、自修改代码及跨进程共享映射不在支持范围。
