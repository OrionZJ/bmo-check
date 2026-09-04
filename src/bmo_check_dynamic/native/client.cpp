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
    Alloc = 20,
    Free = 21,
    Mmap = 22,
    Munmap = 23,
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
    file_t file = INVALID_FILE;
    uint64_t sequence = 0;
    static constexpr size_t kBufferRecords = 4096;
    TraceRecord buffer[kBufferRecords]{};
    size_t used = 0;
};

int tls_index = -1;
client_id_t client_id;
char trace_dir[MAXIMUM_PATH] = {0};
std::atomic<uint64_t> global_ticket{1};
std::atomic<uint64_t> dropped_events{0};
file_t module_file = INVALID_FILE;
void *module_lock = nullptr;

ThreadState *state_for(void *drcontext) {
    return static_cast<ThreadState *>(drmgr_get_tls_field(drcontext, tls_index));
}

void flush_state(ThreadState *state) {
    if (state == nullptr || state->file == INVALID_FILE || state->used == 0)
        return;
    const size_t bytes = state->used * sizeof(TraceRecord);
    if (dr_write_file(state->file, state->buffer, bytes) != bytes)
        dropped_events.fetch_add(state->used, std::memory_order_relaxed);
    state->used = 0;
}

void write_record(EventKind kind, app_pc pc, uintptr_t address, uint32_t size,
                  uint16_t flags = EventFlags::None, uint64_t value = 0,
                  uint32_t aux = 0, bool needs_ticket = false) {
    void *drcontext = dr_get_current_drcontext();
    ThreadState *state = state_for(drcontext);
    if (state == nullptr || state->file == INVALID_FILE) {
        dropped_events.fetch_add(1, std::memory_order_relaxed);
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

bool is_xchg(instr_t *instr) {
    const int opcode = instr_get_opcode(instr);
    return opcode == OP_xchg || opcode == OP_xadd || opcode == OP_cmpxchg ||
           opcode == OP_cmpxchg8b;
}

dr_emit_flags_t instrument_instruction(void *drcontext, void *, instrlist_t *bb,
                                       instr_t *instr, bool, bool, void *) {
    if (!instr_is_app(instr))
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

    const bool atomic = instr_get_prefix_flag(instr, PREFIX_LOCK) || is_xchg(instr);
    const uint32_t flags =
        (instr_get_prefix_flag(instr, PREFIX_LOCK) ? EventFlags::LockPrefix : 0) |
        (is_xchg(instr) ? EventFlags::Xchg : 0);
    bool atomic_recorded = false;
    const int operand_count = instr_num_srcs(instr) + instr_num_dsts(instr);
    for (int index = 0; index < operand_count; ++index) {
        const bool source = index < instr_num_srcs(instr);
        opnd_t operand = source ? instr_get_src(instr, index)
                                : instr_get_dst(instr, index - instr_num_srcs(instr));
        if (!opnd_is_memory_reference(operand))
            continue;
        if (atomic && atomic_recorded)
            continue;
        reg_id_t address_reg = DR_REG_NULL;
        reg_id_t scratch_reg = DR_REG_NULL;
        if (drreg_reserve_register(drcontext, bb, instr, nullptr, &address_reg) !=
                DRREG_SUCCESS ||
            drreg_reserve_register(drcontext, bb, instr, nullptr, &scratch_reg) !=
                DRREG_SUCCESS) {
            dropped_events.fetch_add(1, std::memory_order_relaxed);
            if (address_reg != DR_REG_NULL)
                drreg_unreserve_register(drcontext, bb, instr, address_reg);
            continue;
        }
        if (!drutil_insert_get_mem_addr(drcontext, bb, instr, operand, address_reg,
                                        scratch_reg)) {
            dropped_events.fetch_add(1, std::memory_order_relaxed);
        } else {
            const EventKind kind = atomic ? EventKind::AtomicRmw
                                          : (source ? EventKind::Load : EventKind::Store);
            dr_insert_clean_call(
                drcontext, bb, instr, reinterpret_cast<void *>(record_memory), false, 5,
                OPND_CREATE_INT32(static_cast<uint32_t>(kind)), OPND_CREATE_INTPTR(pc),
                opnd_create_reg(address_reg), OPND_CREATE_INT32(opnd_size_in_bytes(opnd_get_size(operand))),
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
            dropped_events.fetch_add(1, std::memory_order_relaxed);
    }
    write_record(EventKind::ThreadStart, nullptr, 0, 0, 0, 0, 0, true);
}

void thread_exit(void *drcontext) {
    ThreadState *state = state_for(drcontext);
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
    if (result != 0)
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
    write_record(EventKind::Free, nullptr,
                 reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 0)), 0,
                 0, 0, 0, true);
}

void sync_acquire_pre(void *wrapcxt, void **user_data) {
    *user_data = drwrap_get_arg(wrapcxt, 0);
}

void sync_acquire_post(void *, void *user_data) {
    write_record(EventKind::SyncAcquire, nullptr,
                 reinterpret_cast<uintptr_t>(user_data), 0, 0, 0, 0, true);
}

void sync_release_pre(void *wrapcxt, void **) {
    write_record(EventKind::SyncRelease, nullptr,
                 reinterpret_cast<uintptr_t>(drwrap_get_arg(wrapcxt, 0)), 0,
                 0, 0, 0, true);
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
            dropped_events.fetch_add(1, std::memory_order_relaxed);
        } else {
            dr_mutex_lock(module_lock);
            const ssize_t written = dr_write_file(module_file, line, length);
            dr_mutex_unlock(module_lock);
            if (written != length)
                dropped_events.fetch_add(1, std::memory_order_relaxed);
        }
    }
    wrap_if_present(module, "malloc", malloc_pre, allocation_post);
    wrap_if_present(module, "calloc", calloc_pre, allocation_post);
    wrap_if_present(module, "free", free_pre, nullptr);
    wrap_if_present(module, "pthread_mutex_lock", sync_acquire_pre, sync_acquire_post);
    wrap_if_present(module, "pthread_rwlock_rdlock", sync_acquire_pre, sync_acquire_post);
    wrap_if_present(module, "pthread_rwlock_wrlock", sync_acquire_pre, sync_acquire_post);
    wrap_if_present(module, "pthread_mutex_unlock", sync_release_pre, nullptr);
    wrap_if_present(module, "pthread_rwlock_unlock", sync_release_pre, nullptr);
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
    dr_snprintf(path, sizeof(path), "%s/.dropped", trace_dir);
    file_t file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE);
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
    drmgr_unregister_bb_instrumentation_event(nullptr, instrument_instruction);
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
