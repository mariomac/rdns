#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define HOSTNAME_MAX_LEN 64

// code copied from libc
//struct addrinfo {
//    int ai_flags;             /* AI_PASSIVE, AI_CANONNAME */
//    int ai_family;            /* PF_xxx */
//    int ai_socktype;          /* SOCK_xxx */
//    int ai_protocol;          /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
//    __u64 ai_addrlen;           /* length of ai_addr */
//    char *ai_canonname;       /* canonical name for hostname */
//    void *ai_addr;            /* binary address */
//    struct addrinfo *ai_next; /* next structure in linked list */
//};

//struct addr_request {
//    struct addrinfo *res;
//    __u8 name[HOSTNAME_MAX_LEN];
//};

typedef struct dns_entry {
    __u8 name[HOSTNAME_MAX_LEN];
    __u8 ip[16];
} __attribute__((packed)) dns_entry_t;

// Force emitting struct dns_entry_t into the ELF for automatic creation of Golang struct
const dns_entry_t *unused_dns_entry_t __attribute__((unused));

// The ringbuffer is used to forward messages directly to the user space (Go program)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} resolved SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u8[64]);
    __uint(max_entries, 128);
} ongoing_calls SEC(".maps");


SEC("uprobe/libc.so.6:getaddrinfo")
int BPF_KPROBE(uprobe_getaddrinfo,
               const char *name,
               const char *service,
               const void *hints, //const struct addrinfo *hints,
               void **pai) {      //struct addrinfo **pai

    __u64 id = bpf_get_current_pid_tgid();

    dns_entry_t entry;
    bpf_probe_read_str(entry.name, HOSTNAME_MAX_LEN, name);

    bpf_map_update_elem(&ongoing_calls, &id, entry.name, BPF_ANY);

    return 0;
}

SEC("uretprobe/libc.so.6:getaddrinfo")
int BPF_KRETPROBE(uretprobe_getaddrinfo, int ret) { //struct addrinfo **pai
    __u64 id = bpf_get_current_pid_tgid();
    dns_entry_t *entry = bpf_map_lookup_elem(&ongoing_calls, &id);
    if (entry == NULL) {
        return 0;
    }

    dns_entry_t *info = bpf_ringbuf_reserve(&resolved, sizeof(dns_entry_t), 0);
    if (!info) {
        return 0;
    }
    bpf_probe_read_str(info->name, HOSTNAME_MAX_LEN, entry->name);
    bpf_ringbuf_submit(info, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
