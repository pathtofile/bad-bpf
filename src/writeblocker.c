// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "writeblocker.skel.h"
#include "common_um.h"
#include "common.h"

// Setup Argument stuff
static struct env {
    int target_pid;
} env;

const char *argp_program_version = "writeblocker 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Write Blocker\n"
"\n"
"Fakes all write syscalls for a given Process\n"
"\n"
"USAGE: ./writeblocker [-p 1111]\n";

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "PID of Process to fake writes" },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        errno = 0;
        env.target_pid = strtol(arg, NULL, 10);
        if (errno || env.target_pid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    // We sent the fd as the pid in the event
    printf("Blocked Write for PID %d (%s) FD %d\n", env.target_pid, e->comm, e->pid);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct writeblocker_bpf *skel;
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }
    if (env.target_pid == 0) {
        fprintf(stderr, "Must supply target PID (--pid)\n");
        exit(1);
    }

    // Open BPF application 
    skel = writeblocker_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Set target pid
    skel->rodata->target_pid = env.target_pid;

    // Verify and load program
    err = writeblocker_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Attach tracepoint handler 
    err = writeblocker_bpf__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    printf("Blocking all writes for Process PID %d\n", env.target_pid);
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    writeblocker_bpf__destroy( skel);
    return -err;
}
