// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Target Process ID
const volatile int target_pid = 0;

SEC("fmod_ret/__x64_sys_write")
int BPF_PROG(fake_write, struct pt_regs *regs)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != target_pid) {
        return 0;
    }

    // Target PID, check FD so we don't block
    // stdin, stdout, or stderr
    u32 fd = PT_REGS_PARM1(regs);
    u32 count = PT_REGS_PARM3(regs);
    if (fd <= 2) {
        return 0;
    }

    // Log event and overwrite return
    struct event *e;
    bpf_printk("Faking write for pid=%d; fd=%d; count=%d\n", target_pid, fd, count);
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = true;
        // Send fd as PID
        e->pid = fd;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    // Return the number of bytes sent to be written
    // which makes it look like a sucessful write
    return count;
}