# Verdict 与证书

动态证书包含 verdict、trace digest、可执行文件和动态库哈希、命令、DBT contract hash、事件/线程/通信边数量、每个窗口结果、Unknown 原因和假设。

schema 1.1 的 read-from witness 为每个来源记录 read event、write event 以及精确
address/size。宽 Load 分片后即使出现多个来源，证书仍能逐字节区间复核；
write event 为 null 表示该片段读取初始值。

- `TRACE_SAFE` 要求 trace 完整、Unknown 列表为空、每个窗口均 safe。
- `COUNTEREXAMPLE` 要求至少一个经过值和控制骨架复核的 witness。
- 其他情况一律 `UNKNOWN`。

`trace_complete` 只表示文件、退出 marker、dropped count 和序号完整。完整轨迹也可能
因 opaque syscall 或模型资源上限返回 `UNKNOWN`；这类情况不能写成采集截断。

证书固定写明：结论只覆盖已记录的线程内事件、实际地址和控制流骨架。`explain` 必须展示这条限制，不能只打印一个容易误用的 SAFE 单词。

Campaign 的总体 verdict 是成员证书的合取；它不会把多次测试升级为全程序证明。
