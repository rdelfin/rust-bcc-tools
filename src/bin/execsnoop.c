#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct sys_enter_execve_args {
    // as per /sys/kernel/debug/tracing/events/syscall/sys_enter_execve/format
    uint64_t common__unused;
    int syscall_nr;
    char* executable;
    char* const* argv;
    char* const* envp;
};


struct sys_exit_execve_args {
    // as per /sys/kernel/debug/tracing/events/syscall/sys_exit_execve/format
    uint64_t common__unused;
    int syscall_nr;
    long ret;
};

struct val_t {
    uint64_t id;
    uint32_t ppid;
    char executable[255];
};

struct event_t {
    uint64_t ts;
    uint32_t pid;
    uint32_t tid;
    uint32_t ppid;
    int32_t ret;
    char executable[255];
};

BPF_HASH(tmp_events, u64, struct val_t);  // Temporary storage
BPF_PERF_OUTPUT(events);  // Data structure that program should read

int trace_entry(struct sys_enter_execve_args* attr) {
    struct val_t val = {};

    struct task_struct* t = (struct task_struct*)bpf_get_current_task();

    int32_t ppid = PPID_FILTER_VALUE;

    if(PPID_FILTER_VALUE >= 0 && PPID_FILTER_VALUE != t->real_parent->pid) {
        return 0;
    }

    val.id = (uint64_t)t->tgid << 32 | (uint64_t)t->pid;
    val.ppid = t->real_parent->pid;
    bpf_probe_read_str(&val.executable, sizeof(val.executable), attr->executable);

    tmp_events.update(&val.id, &val);
    return 0;
}

int trace_return(struct sys_exit_execve_args* attr) {
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct event_t event = {};

    valp = tmp_events.lookup(&id);
    if(valp == 0) {
        // Missing entry (probably filtered out). Skip
        return 0;
    }

    bpf_probe_read_str(&event.executable, sizeof(event.executable), valp->executable);
    event.ts = bpf_ktime_get_ns();
    event.tid = id >> 32;  // TGID is in the higher order bits
    event.pid = id;        // PID is in the lower order bits (cast out)
    event.ppid = valp->ppid;
    event.ret = attr->ret;

    events.perf_submit(attr, &event, sizeof(event));
    tmp_events.delete(&id);

    return 0;
}
