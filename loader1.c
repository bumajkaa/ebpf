#include <bpf/libbpf.h>
#include "controller.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>

void fatal_error(const char *message) {
    puts(message);
    exit(1);
}

bool initialized = false;

static int syscall_logger(void *ctx, void *data, size_t len) {
    struct inner_syscall_info *info = (struct inner_syscall_info *)data;
    if (!info) return -1;

    if (info->mode == SYS_ENTER) {
        initialized = true;
        printf("%s(", info->name);
        for (int i = 0; i < info->num_args; i++) {
            printf("%p,", info->args[i]);
        }
        printf("\b) = ");
    } else if (info->mode == SYS_EXIT) {
        if (initialized) {
            printf("0x%lx (took %llu ns)\n", info->retval, bpf_ktime_get_ns() - info->timestamp);
        }
    }
    return 0;
}

void print_stats(int map_fd) {
    uint32_t key = 0;
    uint32_t next_key;
    struct syscall_stats stats;
    int err;

    printf("\n=== System Call Statistics ===\n");
    
    while ((err = bpf_map_get_next_key(map_fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
            printf("Syscall %d:\n", next_key);
            printf("  Calls: %llu\n", stats.count);
            printf("  Avg time: %.2f ns\n", (double)stats.total_time / stats.count);
            printf("  Max time: %llu ns\n", stats.max_time);
            printf("  Min time: %llu ns\n", stats.min_time);
            printf("  Total time: %llu ns\n\n", stats.total_time);
        }
        key = next_key;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fatal_error("Usage: ./beetrace <path_to_program>");
    }

    pid_t pid = fork();
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd == -1) fatal_error("failed to open /dev/null");
        dup2(fd, 1);
        sleep(2);
        char *args[] = {argv[1], NULL};
        execve(argv[1], args, NULL);
    } else {
        printf("Spawned child process with PID %d\n", pid);

        struct bpf_object *obj = bpf_object__open("controller.o");
        if (!obj) fatal_error("failed to open BPF object");
        if (bpf_object__load(obj)) fatal_error("failed to load BPF object");

        struct bpf_program *enter_prog = bpf_object__find_program_by_name(obj, "detect_syscall_enter");
        struct bpf_program *exit_prog = bpf_object__find_program_by_name(obj, "detect_syscall_exit");
        if (!enter_prog || !exit_prog) fatal_error("failed to find BPF programs");
        if (bpf_program__attach(enter_prog) || bpf_program__attach(exit_prog)) {
            fatal_error("failed to attach BPF programs");
        }

        struct bpf_map *syscall_map = bpf_object__find_map_by_name(obj, "pid_hashmap");
        if (!syscall_map) fatal_error("failed to find BPF map");
        const char *map_key = "child_pid";
        if (bpf_map__update_elem(syscall_map, map_key, strlen(map_key)+1, &pid, sizeof(pid_t), BPF_ANY)) {
            fatal_error("failed to insert child PID");
        }

        int rb_fd = bpf_object__find_map_fd_by_name(obj, "syscall_info_buffer");
        struct ring_buffer *rb = ring_buffer__new(rb_fd, syscall_logger, NULL, NULL);
        if (!rb) fatal_error("failed to create ring buffer");

        int stats_fd = bpf_object__find_map_fd_by_name(obj, "syscall_stats");

        int status;
        if (wait(&status) == -1) fatal_error("wait failed");

        while (ring_buffer__poll(rb, 100) >= 0);

        if (stats_fd > 0) print_stats(stats_fd);

        ring_buffer__free(rb);
    }
    return 0;
}
