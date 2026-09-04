#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drwrap.h"

#include <atomic>
#include <cstdint>
#include <cstring>

namespace {

constexpr char kMagic[8] = {'B', 'M', 'O', 'T', 'R', 'A', 'C', 'E'};
constexpr uint16_t kVersionMajor = 1;
constexpr uint16_t kVersionMinor = 0;

enum class EventKind : uint16_t {
    Load = 1,
    Store = 2,
    AtomicRmw = 3,
    Lfence = 4,
    Sfence = 5,
    Mfence = 6,
    ThreadStart = 10,
    ThreadEnd = 11,
    SyncAcquire = 12,
    SyncRelease = 13,
    SyncFull = 14,
    ThreadCreate = 15,
    ThreadJoin = 16,
    Alloc = 20,
    Free = 21,
    Mmap = 22,
    Munmap = 23,
    ThreadStack = 24,
    ThreadStackEnd = 25,
    ModuleLoad = 30,
    ModuleUnload = 31,
    IndirectTarget = 32,
    Syscall = 33,
    Signal = 34,
};

enum EventFlags : uint16_t {
    None = 0,
    ValueKnown = 1 << 0,
    LockPrefix = 1 << 1,
    Xchg = 1 << 2,
    Tls = 1 << 4,
};

enum class DropReason : size_t {
    Write,
    MissingThreadState,
    UnknownWidth,
    RegisterReservation,
    AddressCalculation,
    Lifecycle,
    ModuleMetadata,
    Count,
};

constexpr const char *kDropReasonNames[] = {
    "write", "missing_thread_state", "unknown_width", "register_reservation",
    "address_calculation", "lifecycle", "module_metadata",
};

#pragma pack(push, 1)
struct TraceHeader {
    char magic[8];
    uint16_t major;
    uint16_t minor;
    uint32_t record_size;
};

struct TraceRecord {
    uint16_t kind;
    uint16_t flags;
    uint32_t thread_id;
    uint64_t sequence;
    uint64_t ticket;
    uint64_t pc;
    uint64_t address;
    uint64_t value;
    uint32_t size;
    uint32_t aux;
};
#pragma pack(pop)

static_assert(sizeof(TraceRecord) == 56, "Python and native trace layouts differ");

struct ThreadState {
    // file 只由所属 app thread 写，普通访存不需要全局锁。
    file_t file = INVALID_FILE;
    // sequence 是该线程唯一可信的 guest 程序序。
    uint64_t sequence = 0;
    static constexpr size_t kBufferRecords = 4096;
    // buffer 把磁盘写入摊到固定大小的批次，不随轨迹增长。
    TraceRecord buffer[kBufferRecords]{};
    // used 标出下一条可写记录；flush 后由所属线程清零。
    size_t used = 0;
    // stack_base/size 由 thread init 保存，thread exit 用它关闭 generation。
    uintptr_t stack_base = 0;
    uint32_t stack_size = 0;
};

int tls_index = -1;
client_id_t client_id;
char trace_dir[MAXIMUM_PATH] = {0};
std::atomic<uint64_t> global_ticket{1};
std::atomic<uint64_t> dropped_events{0};
std::atomic<uint64_t> dropped_by_reason[static_cast<size_t>(DropReason::Count)]{};
std::atomic<uintptr_t> first_unknown_width_pc{0};
std::atomic<int> first_unknown_width_opcode{0};
file_t module_file = INVALID_FILE;
void *module_lock = nullptr;

void note_drop(DropReason reason, uint64_t count = 1) {
    dropped_events.fetch_add(count, std::memory_order_relaxed);
    dropped_by_reason[static_cast<size_t>(reason)].fetch_add(
        count, std::memory_order_relaxed);
}

ThreadState *state_for(void *drcontext) {
    return static_cast<ThreadState *>(drmgr_get_tls_field(drcontext, tls_index));
}

void flush_state(ThreadState *state) {
    if (state == nullptr || state->file == INVALID_FILE || state->used == 0)
        return;
    const size_t bytes = state->used * sizeof(TraceRecord);
    if (dr_write_file(state->file, state->buffer, bytes) != bytes)
        note_drop(DropReason::Write, state->used);
    state->used = 0;
}

void write_record(EventKind kind, app_pc pc, uintptr_t address, uint32_t size,
                  uint16_t flags = EventFlags::None, uint64_t value = 0,
                  uint32_t aux = 0, bool needs_ticket = false) {
    void *drcontext = dr_get_current_drcontext();
    ThreadState *state = state_for(drcontext);
    if (state == nullptr || state->file == INVALID_FILE) {
        note_drop(DropReason::MissingThreadState);
        return;
    }
    TraceRecord record{};
    record.kind = static_cast<uint16_t>(kind);
    record.flags = flags;
    record.thread_id = static_cast<uint32_t>(dr_get_thread_id(drcontext));
    record.sequence = ++state->sequence;
    record.ticket = needs_ticket
        ? global_ticket.fetch_add(1, std::memory_order_relaxed)
        : global_ticket.load(std::memory_order_relaxed);
    record.pc = reinterpret_cast<uintptr_t>(pc);
    record.address = address;
    record.value = value;
    record.size = size;
    record.aux = aux;
    state->buffer[state->used++] = record;
    if (state->used == ThreadState::kBufferRecords)
        flush_state(state);
}

void record_memory(uint32_t kind, app_pc pc, void *address, uint32_t size,
                   uint32_t flags) {
    write_record(static_cast<EventKind>(kind), pc,
                 reinterpret_cast<uintptr_t>(address), size,
                 static_cast<uint16_t>(flags));
}

void record_boundary(uint32_t kind, app_pc pc) {
    write_record(static_cast<EventKind>(kind), pc, 0, 0);
}

void record_indirect(app_pc pc, app_pc target) {
    write_record(EventKind::IndirectTarget, pc,
                 reinterpret_cast<uintptr_t>(target), 0);
}

bool is_implicit_atomic_xchg(instr_t *instr) {
    // 只有内存 XCHG 不写 LOCK 前缀也具备原子性。XADD/CMPXCHG 缺少 LOCK 时
    // 仍是普通访存，把它们标成 atomic 会凭空给 mo-off 增加排序边。
    return instr_get_opcode(instr) == OP_xchg;
}

bool is_extended_state_access(int opcode) {
    switch (opcode) {
    case OP_xsave32:
    case OP_xsave64:
    case OP_xsaveopt32:
    case OP_xsaveopt64:
    case OP_xsavec32:
    case OP_xsavec64:
    case OP_xsaves32:
    case OP_xsaves64:
    case OP_xrstor32:
    case OP_xrstor64:
    case OP_xrstors32:
    case OP_xrstors64:
        return true;
    default:
        return false;
    }
}

dr_emit_flags_t instrument_instruction(void *drcontext, void *, instrlist_t *bb,
                                       instr_t *instr, bool, bool, void *) {
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;
    // PREFETCH 只有地址提示，没有可参与 read-from/coherence 的架构访存。
    // DynamoRIO 因此返回宽度 0；把它当 dropped 会让常见运行库永远 UNKNOWN。
    if (instr_is_prefetch(instr))
        return DR_EMIT_DEFAULT;
    app_pc pc = instr_get_app_pc(instr);
    const int opcode = instr_get_opcode(instr);
    EventKind fence_kind;
    if (opcode == OP_lfence)
        fence_kind = EventKind::Lfence;
    else if (opcode == OP_sfence)
        fence_kind = EventKind::Sfence;
    else if (opcode == OP_mfence)
        fence_kind = EventKind::Mfence;
    else
        fence_kind = static_cast<EventKind>(0);
    if (static_cast<uint16_t>(fence_kind) != 0) {
        dr_insert_clean_call(drcontext, bb, instr,
                             reinterpret_cast<void *>(record_boundary), false, 2,
                             OPND_CREATE_INT32(static_cast<uint32_t>(fence_kind)),
                             OPND_CREATE_INTPTR(pc));
        return DR_EMIT_DEFAULT;
    }

    const bool implicit_atomic = is_implicit_atomic_xchg(instr);
    const bool atomic = instr_get_prefix_flag(instr, PREFIX_LOCK) || implicit_atomic;
    const uint32_t instruction_flags =
        (instr_get_prefix_flag(instr, PREFIX_LOCK) ? EventFlags::LockPrefix : 0) |
        (implicit_atomic ? EventFlags::Xchg : 0);
    bool atomic_recorded = false;
    const bool reads_memory = instr_reads_memory(instr);
    const bool writes_memory = instr_writes_memory(instr);
    const int operand_count = instr_num_srcs(instr) + instr_num_dsts(instr);
    for (int index = 0; index < operand_count; ++index) {
        const bool source = index < instr_num_srcs(instr);
        opnd_t operand = source ? instr_get_src(instr, index)
                                : instr_get_dst(instr, index - instr_num_srcs(instr));
        if (!opnd_is_memory_reference(operand))
            continue;
        // LEA 和多字节 NOP 使用内存形式表达地址，但不会读取内存。若把它们写入
        // trace，会产生 size=0 的伪访存并让完整轨迹错误退化为 UNKNOWN。
        if ((source && !reads_memory) || (!source && !writes_memory))
            continue;
        if (atomic && atomic_recorded)
            continue;
        uint32_t access_size = opnd_size_in_bytes(opnd_get_size(operand));
        if (access_size == 0)
            access_size = instr_memory_reference_size(instr);
        if (access_size == 0 && is_extended_state_access(opcode)) {
            // XSAVEC 的真实紧凑长度还受 EDX:EAX 和 XCR0 影响。使用完整状态区
            // 上界只会增加可能重叠，不能漏掉它实际触及的字节。
            const size_t state_size = proc_fpstate_save_size();
            if (state_size <= UINT32_MAX)
                access_size = static_cast<uint32_t>(state_size);
        }
        if (access_size == 0) {
            // 未知宽度不能被静默丢弃，否则通信边可能消失。
            note_drop(DropReason::UnknownWidth);
            uintptr_t expected = 0;
            if (first_unknown_width_pc.compare_exchange_strong(
                    expected, reinterpret_cast<uintptr_t>(pc),
                    std::memory_order_relaxed))
                first_unknown_width_opcode.store(opcode, std::memory_order_relaxed);
            continue;
        }
        const reg_id_t segment = opnd_get_segment(operand);
        const uint32_t flags = instruction_flags |
            ((segment == DR_SEG_FS || segment == DR_SEG_GS) ? EventFlags::Tls : 0);
        reg_id_t address_reg = DR_REG_NULL;
        reg_id_t scratch_reg = DR_REG_NULL;
        if (drreg_reserve_register(drcontext, bb, instr, nullptr, &address_reg) !=
                DRREG_SUCCESS ||
            drreg_reserve_register(drcontext, bb, instr, nullptr, &scratch_reg) !=
                DRREG_SUCCESS) {
            note_drop(DropReason::RegisterReservation);
            if (address_reg != DR_REG_NULL)
                drreg_unreserve_register(drcontext, bb, instr, address_reg);
            continue;
        }
        if (!drutil_insert_get_mem_addr(drcontext, bb, instr, operand, address_reg,
                                        scratch_reg)) {
            note_drop(DropReason::AddressCalculation);
        } else {
            const EventKind kind = atomic ? EventKind::AtomicRmw
                                          : (source ? EventKind::Load : EventKind::Store);
            dr_insert_clean_call(
                drcontext, bb, instr, reinterpret_cast<void *>(record_memory), false, 5,
                OPND_CREATE_INT32(static_cast<uint32_t>(kind)), OPND_CREATE_INTPTR(pc),
                opnd_create_reg(address_reg), OPND_CREATE_INT32(access_size),
                OPND_CREATE_INT32(flags));
            atomic_recorded = atomic;
        }
        drreg_unreserve_register(drcontext, bb, instr, scratch_reg);
        drreg_unreserve_register(drcontext, bb, instr, address_reg);
    }
    if (instr_is_mbr(instr))
        dr_insert_mbr_instrumentation(drcontext, bb, instr,
                                      reinterpret_cast<void *>(record_indirect),
                                      SPILL_SLOT_1);
    return DR_EMIT_DEFAULT;
}

void thread_init(void *drcontext) {
    auto *state = new ThreadState();
    char path[MAXIMUM_PATH];
    dr_snprintf(path, sizeof(path), "%s/events-%u.bin", trace_dir,
                static_cast<unsigned>(dr_get_thread_id(drcontext)));
    state->file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    drmgr_set_tls_field(drcontext, tls_index, state);
    if (state->file != INVALID_FILE) {
        TraceHeader header{};
        std::memcpy(header.magic, kMagic, sizeof(kMagic));
        header.major = kVersionMajor;
        header.minor = kVersionMinor;
        header.record_size = sizeof(TraceRecord);
        if (dr_write_file(state->file, &header, sizeof(header)) != sizeof(header))
            note_drop(DropReason::Write);
    }
    write_record(EventKind::ThreadStart, nullptr, 0, 0, 0, 0, 0, true);
    dr_mcontext_t context{sizeof(context), DR_MC_CONTROL};
    dr_mem_info_t stack{};
    if (dr_get_mcontext(drcontext, &context) &&
        dr_query_memory_ex(reinterpret_cast<const byte *>(context.xsp), &stack) &&
        stack.size <= UINT32_MAX) {
        state->stack_base = reinterpret_cast<uintptr_t>(stack.base_pc);
        state->stack_size = static_cast<uint32_t>(stack.size);
        write_record(EventKind::ThreadStack, nullptr, state->stack_base,
                     state->stack_size, 0, 0, 0, true);
    }
    // thread_init 早于可读 app context 时保留匿名地址。它可能增加伪通信边，
    // 但不会删除真实通信，因此不能冒充“丢失了访存事件”。
}

void thread_exit(void *drcontext) {
    ThreadState *state = state_for(drcontext);
    if (state != nullptr && state->stack_base != 0)
        write_record(EventKind::ThreadStackEnd, nullptr, state->stack_base,
                     state->stack_size, 0, 0, 0, true);
    write_record(EventKind::ThreadEnd, nullptr, 0, 0, 0, 0, 0, true);
    if (state != nullptr) {
        flush_state(state);
        if (state->file != INVALID_FILE)
            dr_close_file(state->file);
        delete state;
        drmgr_set_tls_field(drcontext, tls_index, nullptr);
    }
}

void allocation_post(void *wrapcxt, void *user_data) {
    const uintptr_t size = reinterpret_cast<uintptr_t>(user_data);
    const uintptr_t result = reinterpret_cast<uintptr_t>(drwrap_get_retval(wrapcxt));
    if (result == 0)
        return;
    if (size > UINT32_MAX) {
        // Trace IR 的 size 是 32 位。截断会把对象尾部误判为无归属地址。
        note_drop(DropReason::Lifecycle);
        return;
    }
    write_record(EventKind::Alloc, nullptr, result, static_cast<uint32_t>(size),
                 0, 0, 0, true);
}

void malloc_pre(void *wrapcxt, void **user_data) {
    *user_data = drwrap_get_arg(wrapcxt, 0);
}

void calloc_pre(void *wrapcxt, void **user_data) {
    const uintptr_t count = reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 0));
    const uintptr_t size = reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 1));
    *user_data = reinterpret_cast<void *>(count * size);
}

void free_pre(void *wrapcxt, void **) {
    const uintptr_t address = reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 0));
    if (address != 0)
        write_record(EventKind::Free, nullptr, address, 0, 0, 0, 0, true);
}

struct ReallocCall {
    // old_address 在成功后关闭旧 generation；失败时旧对象仍然有效。
    uintptr_t old_address;
    // requested_size 决定新 generation 的范围，不能从返回地址反推。
    uintptr_t requested_size;
};

void realloc_pre(void *wrapcxt, void **user_data) {
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    auto *call = static_cast<ReallocCall *>(
        dr_thread_alloc(drcontext, sizeof(ReallocCall)));
    if (call == nullptr) {
        note_drop(DropReason::Lifecycle);
        return;
    }
    call->old_address = reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 0));
    call->requested_size = reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 1));
    *user_data = call;
}

void realloc_post(void *wrapcxt, void *user_data) {
    auto *call = static_cast<ReallocCall *>(user_data);
    if (call == nullptr)
        return;
    const uintptr_t result = reinterpret_cast<uintptr_t>(drwrap_get_retval(wrapcxt));
    if (result != 0) {
        if (call->requested_size > UINT32_MAX) {
            note_drop(DropReason::Lifecycle);
        } else {
            // 即使地址没变，也开启新 generation。否则 realloc 前后的范围会混用。
            if (call->old_address != 0)
                write_record(EventKind::Free, nullptr, call->old_address, 0,
                             0, 0, 0, true);
            write_record(EventKind::Alloc, nullptr, result,
                         static_cast<uint32_t>(call->requested_size),
                         0, 0, 0, true);
        }
    }
    dr_thread_free(drwrap_get_drcontext(wrapcxt), call, sizeof(ReallocCall));
}

void mmap_pre(void *wrapcxt, void **user_data) {
    *user_data = drwrap_get_arg(wrapcxt, 1);
}

void mmap_post(void *wrapcxt, void *user_data) {
    const uintptr_t address = reinterpret_cast<uintptr_t>(drwrap_get_retval(wrapcxt));
    const uintptr_t size = reinterpret_cast<uintptr_t>(user_data);
    if (address == UINTPTR_MAX)
        return;
    if (size > UINT32_MAX) {
        note_drop(DropReason::Lifecycle);
        return;
    }
    write_record(EventKind::Mmap, nullptr, address, static_cast<uint32_t>(size),
                 0, 0, 0, true);
}

struct MunmapCall {
    // address 标识只有在 munmap 成功后才结束的 mapping generation。
    uintptr_t address;
    // size 记录部分 unmap 的真实范围，后续对象切分会依赖它。
    uintptr_t size;
};

void munmap_pre(void *wrapcxt, void **user_data) {
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    auto *call = static_cast<MunmapCall *>(
        dr_thread_alloc(drcontext, sizeof(MunmapCall)));
    if (call == nullptr) {
        note_drop(DropReason::Lifecycle);
        return;
    }
    call->address = reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 0));
    call->size = reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 1));
    *user_data = call;
}

void munmap_post(void *wrapcxt, void *user_data) {
    auto *call = static_cast<MunmapCall *>(user_data);
    if (call == nullptr)
        return;
    const intptr_t result = reinterpret_cast<intptr_t>(drwrap_get_retval(wrapcxt));
    if (result == 0) {
        if (call->size > UINT32_MAX) {
            note_drop(DropReason::Lifecycle);
        } else {
            write_record(EventKind::Munmap, nullptr, call->address,
                         static_cast<uint32_t>(call->size), 0, 0, 0, true);
        }
    }
    dr_thread_free(drwrap_get_drcontext(wrapcxt), call, sizeof(MunmapCall));
}

void sync_acquire_pre(void *wrapcxt, void **user_data) {
    *user_data = drwrap_get_arg(wrapcxt, 0);
}

void sync_acquire_post(void *wrapcxt, void *user_data) {
    // 锁操作失败时没有 acquire，记录它会把无序访问切到错误的 epoch。
    if (reinterpret_cast<intptr_t>(drwrap_get_retval(wrapcxt)) != 0)
        return;
    write_record(EventKind::SyncAcquire, nullptr,
                 reinterpret_cast<uintptr_t>(user_data), 0, 0, 0, 0, true);
}

void sync_release_pre(void *wrapcxt, void **user_data) {
    *user_data = drwrap_get_arg(wrapcxt, 0);
}

void sync_release_post(void *wrapcxt, void *user_data) {
    if (reinterpret_cast<intptr_t>(drwrap_get_retval(wrapcxt)) != 0)
        return;
    write_record(EventKind::SyncRelease, nullptr,
                 reinterpret_cast<uintptr_t>(user_data), 0,
                 0, 0, 0, true);
}

void thread_create_pre(void *wrapcxt, void **user_data) {
    *user_data = drwrap_get_arg(wrapcxt, 0);
}

void thread_create_post(void *wrapcxt, void *user_data) {
    if (reinterpret_cast<intptr_t>(drwrap_get_retval(wrapcxt)) != 0)
        return;
    uintptr_t handle = 0;
    size_t bytes_read = 0;
    if (!dr_safe_read(user_data, sizeof(handle), &handle, &bytes_read) ||
        bytes_read != sizeof(handle)) {
        note_drop(DropReason::Lifecycle);
        return;
    }
    write_record(EventKind::ThreadCreate, nullptr, handle, 0, 0, 0, 0, true);
}

void thread_join_pre(void *wrapcxt, void **user_data) {
    *user_data = drwrap_get_arg(wrapcxt, 0);
}

void thread_join_post(void *wrapcxt, void *user_data) {
    if (reinterpret_cast<intptr_t>(drwrap_get_retval(wrapcxt)) != 0)
        return;
    write_record(EventKind::ThreadJoin, nullptr,
                 reinterpret_cast<uintptr_t>(user_data), 0, 0, 0, 0, true);
}

void wrap_if_present(const module_data_t *module, const char *name,
                     void (*pre)(void *, void **), void (*post)(void *, void *)) {
    app_pc function = reinterpret_cast<app_pc>(dr_get_proc_address(module->handle, name));
    if (function != nullptr)
        drwrap_wrap(function, pre, post);
}

void module_load(void *, const module_data_t *module, bool) {
    write_record(EventKind::ModuleLoad, nullptr,
                 reinterpret_cast<uintptr_t>(module->start),
                 static_cast<uint32_t>(module->end - module->start), 0, 0, 0, true);
    if (module_file != INVALID_FILE && module->full_path != nullptr) {
        char line[MAXIMUM_PATH + 96];
        const int length = dr_snprintf(
            line, sizeof(line), "%p\t%p\t%s\n", module->start, module->end,
            module->full_path);
        if (length <= 0 || length >= static_cast<int>(sizeof(line))) {
            note_drop(DropReason::ModuleMetadata);
        } else {
            dr_mutex_lock(module_lock);
            const ssize_t written = dr_write_file(module_file, line, length);
            dr_mutex_unlock(module_lock);
            if (written != length)
                note_drop(DropReason::ModuleMetadata);
        }
    }
    wrap_if_present(module, "malloc", malloc_pre, allocation_post);
    wrap_if_present(module, "calloc", calloc_pre, allocation_post);
    wrap_if_present(module, "free", free_pre, nullptr);
    wrap_if_present(module, "realloc", realloc_pre, realloc_post);
    wrap_if_present(module, "mmap", mmap_pre, mmap_post);
    wrap_if_present(module, "mmap64", mmap_pre, mmap_post);
    wrap_if_present(module, "munmap", munmap_pre, munmap_post);
    wrap_if_present(module, "pthread_create", thread_create_pre, thread_create_post);
    wrap_if_present(module, "pthread_join", thread_join_pre, thread_join_post);
    wrap_if_present(module, "pthread_mutex_lock", sync_acquire_pre, sync_acquire_post);
    wrap_if_present(module, "pthread_rwlock_rdlock", sync_acquire_pre, sync_acquire_post);
    wrap_if_present(module, "pthread_rwlock_wrlock", sync_acquire_pre, sync_acquire_post);
    wrap_if_present(module, "pthread_mutex_unlock", sync_release_pre, sync_release_post);
    wrap_if_present(module, "pthread_rwlock_unlock", sync_release_pre, sync_release_post);
}

void module_unload(void *, const module_data_t *module) {
    write_record(EventKind::ModuleUnload, nullptr,
                 reinterpret_cast<uintptr_t>(module->start),
                 static_cast<uint32_t>(module->end - module->start), 0, 0, 0, true);
}

bool pre_syscall(void *, int number) {
    write_record(EventKind::Syscall, nullptr, 0, 0, 0, 0,
                 static_cast<uint32_t>(number), true);
    return true;
}

dr_signal_action_t signal_event(void *, dr_siginfo_t *info) {
    write_record(EventKind::Signal, info->mcontext == nullptr ? nullptr : info->mcontext->pc,
                 0, 0, 0, 0, static_cast<uint32_t>(info->sig), true);
    return DR_SIGNAL_DELIVER;
}

void process_exit() {
    char path[MAXIMUM_PATH];
    dr_snprintf(path, sizeof(path), "%s/.drop-reasons", trace_dir);
    file_t file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE);
    if (file != INVALID_FILE) {
        for (size_t index = 0; index < static_cast<size_t>(DropReason::Count); ++index) {
            const uint64_t count = dropped_by_reason[index].load(std::memory_order_relaxed);
            if (count == 0)
                continue;
            char line[128];
            const int length = dr_snprintf(
                line, sizeof(line), "%s\t%llu\n", kDropReasonNames[index],
                static_cast<unsigned long long>(count));
            if (length <= 0 || dr_write_file(file, line, length) != length)
                note_drop(DropReason::Write);
        }
        const uintptr_t unknown_pc = first_unknown_width_pc.load(std::memory_order_relaxed);
        if (unknown_pc != 0) {
            char line[160];
            const int length = dr_snprintf(
                line, sizeof(line), "unknown_width_opcode_%d_pc_%p\t1\n",
                first_unknown_width_opcode.load(std::memory_order_relaxed),
                reinterpret_cast<void *>(unknown_pc));
            if (length <= 0 || dr_write_file(file, line, length) != length)
                note_drop(DropReason::Write);
        }
        dr_close_file(file);
    } else {
        note_drop(DropReason::Write);
    }
    dr_snprintf(path, sizeof(path), "%s/.dropped", trace_dir);
    file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE);
    if (file != INVALID_FILE) {
        char count[64];
        const int length = dr_snprintf(count, sizeof(count), "%llu\n",
            static_cast<unsigned long long>(dropped_events.load(std::memory_order_relaxed)));
        dr_write_file(file, count, length);
        dr_close_file(file);
    }
    dr_snprintf(path, sizeof(path), "%s/.complete", trace_dir);
    file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE);
    if (file != INVALID_FILE)
        dr_close_file(file);
    if (module_file != INVALID_FILE)
        dr_close_file(module_file);
    if (module_lock != nullptr)
        dr_mutex_destroy(module_lock);
    drmgr_unregister_bb_insertion_event(instrument_instruction);
    drmgr_unregister_tls_field(tls_index);
    drwrap_exit();
    drutil_exit();
    drreg_exit();
    drmgr_exit();
}

}  // namespace

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    client_id = id;
    dr_set_client_name("BMoCheck dynamic trace collector", "https://gitee.com/OrionZJ/bmo-check");
    for (int index = 1; index + 1 < argc; ++index) {
        if (std::strcmp(argv[index], "--trace-dir") == 0) {
            dr_snprintf(trace_dir, sizeof(trace_dir), "%s", argv[index + 1]);
            break;
        }
    }
    if (trace_dir[0] == '\0')
        dr_abort();
    char module_path[MAXIMUM_PATH];
    dr_snprintf(module_path, sizeof(module_path), "%s/modules.tsv", trace_dir);
    module_file = dr_open_file(
        module_path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    module_lock = dr_mutex_create();
    drmgr_init();
    drutil_init();
    drwrap_init();
    drreg_options_t options{sizeof(options), 3, false};
    drreg_init(&options);
    tls_index = drmgr_register_tls_field();
    dr_register_exit_event(process_exit);
    drmgr_register_thread_init_event(thread_init);
    drmgr_register_thread_exit_event(thread_exit);
    drmgr_register_module_load_event(module_load);
    drmgr_register_module_unload_event(module_unload);
    drmgr_register_pre_syscall_event(pre_syscall);
    drmgr_register_signal_event(signal_event);
    drmgr_register_bb_instrumentation_event(nullptr, instrument_instruction, nullptr);
}
