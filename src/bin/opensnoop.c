#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    uint64_t id;
    uint64_t ts;
    char comm[TASK_COMM_LEN];
    const char *fname;
};
struct data_t {
    uint64_t id;
    uint64_t ts;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};
BPF_HASH(infotmp, uint64_t, struct val_t);
BPF_PERF_OUTPUT(events);
int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    struct val_t val = {};
    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t pid = id >> 32; // PID is higher part
    uint32_t tid = id;       // Cast and get the lower part

    // Skip entries of PIDs not specified if one's provided
    if (PID > 0 && pid != PID) {
        return 0;
    }

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.ts = bpf_ktime_get_ns();
        val.fname = filename;
        infotmp.update(&id, &val);
    }
    return 0;
};
int trace_return(struct pt_regs *ctx)
{
    uint64_t id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    uint64_t tsp = bpf_ktime_get_ns();
    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }

    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.ret = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}
