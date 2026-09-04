# Verdict 与证书

动态证书包含 verdict、trace digest、可执行文件和动态库哈希、命令、DBT contract hash、事件/线程/通信边数量、每个窗口结果、Unknown 原因和假设。

- `TRACE_SAFE` 要求 trace 完整、Unknown 列表为空、每个窗口均 safe。
- `COUNTEREXAMPLE` 要求至少一个经过值和控制骨架复核的 witness。
- 其他情况一律 `UNKNOWN`。

证书固定写明：结论只覆盖已记录的线程内事件、实际地址和控制流骨架。`explain` 必须展示这条限制，不能只打印一个容易误用的 SAFE 单词。

Campaign 的总体 verdict 是成员证书的合取；它不会把多次测试升级为全程序证明。
