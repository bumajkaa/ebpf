#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <sys/syscall.h>
#include "controller.h"

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, 10);
  __uint(value_size, 4);
  __uint(max_entries, 256 * 1024);
} pid_hashmap SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} syscall_info_buffer SEC(".maps");

// Добавляем карту для статистики
struct {
      __uint(type, BPF_MAP_TYPE_HASH);
      __uint(key_size, sizeof(u32));
      __uint(value_size, sizeof(struct syscall_stats));
      __uint(max_entries, MAX_SYSCALL_NR);
  } syscall_stats SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int detect_syscall_enter(struct trace_event_raw_sys_enter *ctx)
{
  // Retrieve the system call number
  long syscall_nr = ctx->id;
  const char *key = "child_pid";
  int target_pid;

  // Reading the process id of the child process in userland
  void *value = bpf_map_lookup_elem(&pid_hashmap, key);
  void *args[MAX_ARGS];

  if (value)
  {
    target_pid = *(int *)value;

    // PID of the process that executed the current system call
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (pid == target_pid && syscall_nr >= 0 && syscall_nr < MAX_SYSCALL_NR)
    {

      int idx = syscall_nr;
      // Reserve space in the ring buffer
      struct inner_syscall_info *info = bpf_ringbuf_reserve(&syscall_info_buffer, sizeof(struct inner_syscall_info), 0);
      if (!info)
      {
        bpf_printk("bpf_ringbuf_reserve failed");
        return 1;
      }
      info->timestamp = bpf_ktime_get_ns();
      // Copy the syscall name into info->name
      bpf_probe_read_kernel_str(info->name, sizeof(syscalls[syscall_nr].name), syscalls[syscall_nr].name);
      for (int i = 0; i < MAX_ARGS; i++)
      {
        info->args[i] = (void *)BPF_CORE_READ(ctx, args[i]);
      }
      info->num_args = syscalls[syscall_nr].num_args;
      info->syscall_nr = syscall_nr;
      info->mode = SYS_ENTER;
      // Insert into ring buffer
      bpf_ringbuf_submit(info, 0);
    }
  }
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int detect_syscall_exit(struct trace_event_raw_sys_exit *ctx)
{
  const char *key = "child_pid";
  void *value = bpf_map_lookup_elem(&pid_hashmap, key);
  pid_t pid, target_pid;

  if (value)
  {
    pid = bpf_get_current_pid_tgid() & 0xffffffff;
    target_pid = *(pid_t *)value;
    if (pid == target_pid)
    {
      struct inner_syscall_info *info = bpf_ringbuf_reserve(&syscall_info_buffer, sizeof(struct inner_syscall_info), 0);
      if (!info)
      {
        bpf_printk("bpf_ringbuf_reserve failed");
        return 1;
      }
                 u64 duration = bpf_ktime_get_ns() - info->timestamp;
           u32 syscall_nr = info->syscall_nr;

           // Обновляем статистику
           struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats, &syscall_nr);
           if (!stats) {
               struct syscall_stats new_stats = {
                   .count = 1,
                   .total_time = duration,
                   .max_time = duration,
                   .min_time = duration
               };
               bpf_map_update_elem(&syscall_stats, &syscall_nr, &new_stats, BPF_ANY);
           } else {
               stats->count++;
               stats->total_time += duration;
               if (duration > stats->max_time) stats->max_time = duration;
               if (duration < stats->min_time) stats->min_time = duration;
               bpf_map_update_elem(&syscall_stats, &syscall_nr, stats, BPF_ANY);
           }
      info->mode = SYS_EXIT;
      info->retval = ctx->ret;
      bpf_ringbuf_submit(info, 0);
    }
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
