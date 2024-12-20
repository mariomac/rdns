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

enum { DEBUG = 0 };

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ring_buffer SEC(".maps");

enum {
	// the DNS header is made of 6 16-bit words
	DNS_HEADER_SIZE = 6 * sizeof(__u16),
};

enum offsets {
	QR_OFFSET = 7,
	OPCODE_OFFSET = 3,
	OPCODE_MASK = 0xf,
	AA_OFFSET = 2,
	TC_OFFSET = 1,
	RD_OFFSET = 0,
	RA_OFFSET = 7,
	Z_OFFSET = 4,
	Z_MASK = 0x7,
	RCODE_OFFSET = 0,
	RCODE_MASK = 0xf
};

enum { QR_QUERY = 0, QR_RESPONSE = 1 };
enum { OP_QUERY = 0, OP_IQUERY = 1, OP_STATUS = 2 };
enum { RB_RECORD_LEN = 256 };
enum { DNS_PORT = 53 };
enum { UDP_HDR_SIZE = sizeof(struct udphdr), DNS_HDR_SIZE = 12 };

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
			size += sizeof(__u16); // account for QTYPE and QCLASS

			if ((void*)(data + sizeof(__u16)) < ctx_data_end(ctx)) {
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

static __always_inline void submit_dns_packet(struct xdp_md *ctx, const unsigned char * const data) {
	const unsigned char *begin = ctx_data(ctx);
	const unsigned char *end = ctx_data_end(ctx);

	const __u32 data_len = end - data & 0xffff;

	if (data_len == 0 || data_len > RB_RECORD_LEN)
		return;

	const __u32 data_offset = data - begin;

	unsigned char *buf = bpf_ringbuf_reserve(&ring_buffer, RB_RECORD_LEN, 0);

	if (!buf) {
		if (DEBUG) {
			bpf_printk("Failed to reserve %u bytes in the ring buffer\n", RB_RECORD_LEN);
		}

		return;
	}

	bpf_xdp_load_bytes(ctx, data_offset, buf, data_len);

	bpf_ringbuf_submit(buf, 0);
}

static __always_inline void
parse_dns_response(struct xdp_md *ctx, const unsigned char * const data, __u32 size) {
	const __u8 flags0 = *(data + 2);
	const __u8 flags1 = *(data + 3);

	const __u16 id = bpf_ntohs(*(const __be16 *)(data));
	const __u8 qr = get_bit(flags0, QR_OFFSET);
	const __u8 opcode = (flags0 >> OPCODE_OFFSET) & OPCODE_MASK;
	const __u8 aa = get_bit(flags0, AA_OFFSET);
	const __u8 tc = get_bit(flags0, TC_OFFSET);
	const __u8 rd = get_bit(flags0, RD_OFFSET);
	const __u8 ra = get_bit(flags1, RA_OFFSET);
	const __u8 z = (flags1 >> Z_OFFSET) & Z_MASK;
	const __u8 rcode = (flags1 >> RCODE_OFFSET) & RCODE_MASK;
	const __u16 qdcount = bpf_ntohs(*(const __be16 *)(data + 4));
	const __u16 ancount = bpf_ntohs(*(const __be16 *)(data + 6));

	// heuristic check to see if this is a DNS response
	if (qr != QR_RESPONSE || opcode != OP_QUERY || z != 0 || rcode != 0 || qdcount == 0 ||
			ancount == 0) {
		return;
	}

	if (DEBUG) {
		bpf_printk("Found possible DNS response: %x!\n", id);
		bpf_printk("flags[0] = %x\n", flags0);
		bpf_printk("id: %x, qr: %u, opcode: %u, aa: %u, tc: %u, rd: %u, ra: %u\n",
				id, qr, opcode, aa, tc, rd, ra);
		bpf_printk("flags[1] = %x\n", flags1);
		bpf_printk("z: %u, rcode: %u, qdcount = %u, ancount = %u\n", z, rcode, ancount, qdcount);
	}

	__u32 dns_packet_size = 0;

	const unsigned char *ptr = data + DNS_HEADER_SIZE;

	for (__u8 i = 0; i < 4 && i < qdcount; ++i) {
		const __u32 qsection_size = validate_qsection(ctx, ptr);

		if (qsection_size == 0) {
			if (DEBUG) {
				bpf_printk("invalid qsection, bailing...\n");
			}

			return;
		}

		dns_packet_size += qsection_size;
		ptr += qsection_size;
	}

	if (DEBUG) {
		bpf_printk("found qsection size = %u\n", dns_packet_size);
	}

	submit_dns_packet(ctx, data);
}

SEC("xdp")
int dns_response_tracker(struct xdp_md *ctx) {
	const struct udphdr *udp = udp_header(ctx);

	if (!udp)
		return XDP_PASS;

	const __u16 source = bpf_ntohs(udp->source);

	if (source != DNS_PORT)
		return XDP_PASS;

	const __u16 udp_len = bpf_ntohs(udp->len);

	if (DEBUG) {
		bpf_printk("udp_len: %u\n", udp_len);
	}

	if (udp_len < (UDP_HDR_SIZE + DNS_HDR_SIZE)) {
		return XDP_PASS;
	}

	if ((void *)udp + UDP_HDR_SIZE + DNS_HDR_SIZE >= ctx_data_end(ctx)) {
		return XDP_PASS;
	}

	parse_dns_response(ctx, (unsigned char *)(udp) + UDP_HDR_SIZE, udp_len - UDP_HDR_SIZE);

	return XDP_PASS;
}
