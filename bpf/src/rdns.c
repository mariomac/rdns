#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// For reference, see:
// https://datatracker.ietf.org/doc/html/rfc1035

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buffer SEC(".maps");

enum {
    // the DNS header is made of 6 16-bit words
    k_dns_header_size = 6 * sizeof(__u16),
};

enum offsets {
    kQROffset = 7,
    kOpcodeOffset = 3,
    kOpcodeMask = 0xf,
    kAAOffset = 2,
    kTCOffset = 1,
    kRDOffset = 0,
    kRAOffset = 7,
    kZOffset = 4,
    kZMask = 0x7,
    kRCodeOffset = 0,
    kRCodeMask = 0xf
};

enum dns_qr { k_qr_query = 0, k_qr_response = 1 };

enum dns_opcode { k_op_query = 0, k_op_iquery = 1, k_op_status = 2 };

enum { rb_record_len = 256 };

static __always_inline __u8 get_bit(__u8 word, __u8 offset) {
    return (word >> offset) & 0x1;
}

static __always_inline void *ctx_data(struct xdp_md *ctx) {
    void *data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct xdp_md, data)), "m"(*ctx));

    return data;
}

static __always_inline void *ctx_data_end(struct xdp_md *ctx) {
    void *data_end;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data_end)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct xdp_md, data_end)), "m"(*ctx));

    return data_end;
}

__attribute__((unused)) static __always_inline struct ethhdr *eth_header(struct xdp_md *ctx) {
    void *data = ctx_data(ctx);

    return (data + sizeof(struct ethhdr) > ctx_data_end(ctx)) ? NULL : data;
}

static __always_inline struct iphdr *ip_header(struct xdp_md *ctx) {
    void *data = ctx_data(ctx);

    data += sizeof(struct ethhdr);

    return (data + sizeof(struct iphdr) > ctx_data_end(ctx)) ? NULL : data;
}

static __always_inline struct udphdr *udp_header(struct xdp_md *ctx) {
    struct iphdr *iph = ip_header(ctx);

    if (!iph)
        return NULL;

    if (iph->protocol != IPPROTO_UDP)
        return NULL;

    const __u32 advance = iph->ihl * 4;

    void *data = (void *)iph + advance;

    return (data + sizeof(struct udphdr) > ctx_data_end(ctx)) ? NULL : data;
};

static __always_inline __u32 validate_qsection(struct xdp_md *ctx, const unsigned char *data) {
    __u32 size = 0;

    // try at most 16 sections
    for (__u8 i = 0; i < 16; ++i) {
        if ((void*)data >= ctx_data_end(ctx)) {
            return 0;
        }

        const __u8 len = data[0];

        ++size;
        ++data;

        if (len == 0) {
            size += 4; // account for QTYPE and QCLASS
            if ((void*)(data + size) < ctx_data_end(ctx)) {
                return size;
            } else {
                return 0;
            }
        }

        data += len;
        size += len;
    }

    return 0;
}

static __always_inline __u32 validate_asection(struct xdp_md *ctx, const unsigned char *data) {
    __u32 size = 0;
    __u8 name_records_ok = 0;

    unsigned char *end = ctx_data_end(ctx);

    // try at most 16 sections
    for (__u8 i = 0; i < 16; ++i) {
        if (data >= end) {
            return 0;
        }

        const __u8 len = data[0];

        // check for compressed section
        if ((len & 0xf000) == 0xc000) {
            // advance two octets
            data += 2;
            size += 2;
            continue;
        }

        // regular section
        ++size;
        ++data;

        if (len == 0) {
            name_records_ok = 1;
            break;
        }

        data += len;
        size += len;
    }

    // something wrong parsing the NAME records
    if (!name_records_ok) {
        return 0;
    }

    // skip over TYPE, CLASS and TTL
    const __u32 skip_size = sizeof(__u16) * 3;
    size += skip_size;
    data += skip_size;

    // check if we can have RDLENGTH and RDATA
    if ((void*)(data + sizeof(__u16)) > ctx_data_end(ctx)) {
        return 0;
    }

    const __u16 rdlen = bpf_ntohs(*(const __be16 *)(data));

    bpf_printk("RDLEN: %u\n", rdlen);

#if 0
	data += rdlen;

	if (data >= ctx_data_end(ctx)) {
		return 0;
	}
#endif

    return size + rdlen;
}

static __always_inline void
parse_dns_response(struct xdp_md *ctx, const unsigned char *data, __u32 size) {
    const __u8 flags0 = *(data + 2);
    const __u8 flags1 = *(data + 3);

    const __u16 id = bpf_ntohs(*(const __be16 *)(data));
    const __u8 qr = get_bit(flags0, kQROffset);
    const __u8 opcode = (flags0 >> kOpcodeOffset) & kOpcodeMask;
    const __u8 aa = get_bit(flags0, kAAOffset);
    const __u8 tc = get_bit(flags0, kTCOffset);
    const __u8 rd = get_bit(flags0, kRDOffset);
    const __u8 ra = get_bit(flags1, kRAOffset);
    const __u8 z = (flags1 >> kZOffset) & kZMask;
    const __u8 rcode = (flags1 >> kRCodeOffset) & kRCodeMask;
    const __u16 qdcount = bpf_ntohs(*(const __be16 *)(data + 4));
    const __u16 ancount = bpf_ntohs(*(const __be16 *)(data + 6));

    // heuristic check to see if this is a DNS response
    if (qr != k_qr_response || opcode != k_op_query || z != 0 || rcode != 0 || qdcount == 0 ||
        ancount == 0) {
        return;
    }

#if 0
	bpf_printk("Found possible DNS response: %x!\n", id);

	bpf_printk("flags[0] = %x\n", flags0);
	bpf_printk("id: %x, qr: %u, opcode: %u, aa: %u, tc: %u, rd: %u, ra: %u\n",
			id, qr, opcode, aa, tc, rd, ra);

	bpf_printk("flags[1] = %x\n", flags1);
	bpf_printk("z: %u, rcode: %u, qdcount = %u, ancount = %u\n", z, rcode, ancount, qdcount);
#endif

    __u32 dns_packet_size = 0;

    const unsigned char *base = data + k_dns_header_size;
    const unsigned char *ptr = base;

    for (__u8 i = 0; i < 4 && i < qdcount; ++i) {
        const __u32 qsection_size = validate_qsection(ctx, ptr);

        if (qsection_size == 0)
            return;

        dns_packet_size += qsection_size;
        ptr += qsection_size;
    }

    bpf_printk("found qsection size = %u\n", dns_packet_size);

#if 0
	for (__u8 i = 0; i < 8 && i < ancount; ++i) {
		const __u32 asection_size = validate_asection(ctx, ptr);

		if (asection_size == 0)
			return;

		dns_packet_size += asection_size;
		ptr += asection_size;
	}
#endif

    const unsigned char *begin = ctx_data(ctx);
    const unsigned char *end = ctx_data_end(ctx);

    __u32 data_len = end - base & 0xffff;

    if (data_len == 0)
        return;

    if (data_len + sizeof(data_len) > rb_record_len)
        return;

    const __u32 data_offset = base - begin;

    unsigned char *buf = bpf_ringbuf_reserve(&ring_buffer, rb_record_len, 0);

    if (!buf) {
        bpf_printk("Failed to reserve %u bytes in the ring buffer\n", rb_record_len);
        return;
    }

    __builtin_memcpy(buf, &data_len, sizeof(data_len));

    bpf_xdp_load_bytes(ctx, data_offset, buf + sizeof(data_len), data_len);

    bpf_ringbuf_submit(buf, 0);
}

SEC("xdp")
int hello(struct xdp_md *ctx) {
    const struct udphdr *udp = udp_header(ctx);

    if (!udp)
        return XDP_PASS;

    const __u16 source = bpf_ntohs(udp->source);

    if (source != 53)
        return XDP_PASS;

    const __u16 udp_len = bpf_ntohs(udp->len);

    bpf_printk("udp_len: %u\n", udp_len);

    if (udp_len < 40) {
        return XDP_PASS;
    }

    if ((void *)udp + 40 > ctx_data_end(ctx)) {
        return XDP_PASS;
    }

    parse_dns_response(ctx, (unsigned char *)(udp) + 8, udp_len - 8);

    return XDP_PASS;
}
