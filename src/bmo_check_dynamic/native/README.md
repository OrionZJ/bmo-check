# BMoCheck DynamoRIO client

该 client 在原生 x86-64 进程中记录实际访存、原子、Fence、线程、常见
pthread 同步、分配、映射、module、间接跳转、signal 和 syscall 事件。

```bash
cmake -S src/bmo_check_dynamic/native \
      -B src/bmo_check_dynamic/native/build \
      -DDynamoRIO_DIR="$DYNAMORIO_HOME/cmake"
cmake --build src/bmo_check_dynamic/native/build -j
```

追踪器按线程写 `events-<tid>.bin`。写失败会增加 dropped 计数；Python 端看到
非零计数后只能返回 `UNKNOWN`。
