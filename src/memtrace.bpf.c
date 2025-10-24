
#define __TARGET_ARCH_x86

#include "../include/vmlinux.h"       // must come first for __u32, __u64
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/memtrace.h"

struct{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); 
    __uint(key_size, sizeof(32)); 
    __uint(value_size, sizeof(32)); 
}events SEC(".maps"); 


struct{
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, u32); 
    __type(value, size_t); 
    __uint(max_entries, 4096); 
}pending_sizes SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_HASH); 
    __type(key, void *); 
    __type(value, size_t); 
    __uint(max_entries, 65536); 
}active_allocs SEC(".maps"); 

SEC("uprobe/libc.so.6:malloc")
int BPF_KPROBE(on_malloc_enter, size_t size) 
{
    u32 pid = bpf_get_current_pid_tgid() >> 32; 
    bpf_map_update_elem(&pending_sizes, &pid, &size, BPF_ANY); 
    
    return 0; 
}

SEC("uretprobe/libc.so.6:malloc")
int BPF_KRETPROBE(on_malloc_exit, void *ptr)
{
    if(!ptr)
        return 1; 

    u32 pid = bpf_get_current_pid_tgid() >> 32; 

    size_t *sizep = bpf_map_lookup_elem(&pending_sizes, &pid); 
    if(!sizep)
        return 1; 

    struct data_t data = {}; 
    data.pid = pid; 
    data.tgid = pid; 
    data.uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF); 
    data.ts = bpf_ktime_get_ns(); 
    data.cpu = bpf_get_smp_processor_id(); 
    data.bytes_alloc = (u64)(*sizep); 
    data.bytes_freed = 0; 
    
    bpf_get_current_comm(&data.command, sizeof(data.command)); 

    bpf_map_update_elem(&active_allocs, &ptr, sizep, BPF_ANY); 

    bpf_perf_event_output((void*)ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    bpf_map_delete_elem(&pending_sizes, &pid); 

    return 0; 
}
SEC("uprobe/libc.so.6:free")
int BPF_KPROBE(on_free_enter, void *ptr)
{
    if (!ptr)
        return 1;

    size_t *sizep = bpf_map_lookup_elem(&active_allocs, &ptr);

    if (!sizep)
        return 1;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct data_t data = {};
    data.pid = pid;
    data.tgid = pid;
    data.uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);
    data.ts = bpf_ktime_get_ns();
    data.cpu = bpf_get_smp_processor_id();
    data.bytes_alloc = 0;
    data.bytes_freed = (u64)(*sizep);

    bpf_get_current_comm(&data.command, sizeof(data.command));

    bpf_perf_event_output((void *)ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    bpf_map_delete_elem(&active_allocs, &ptr);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
