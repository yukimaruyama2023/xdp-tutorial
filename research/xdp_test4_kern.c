/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

/* static __always_inline __u16 csum_fold_helper(__u32 csum) */
/* { */
/* 	__u32 sum; */
/* 	sum = (csum >> 16) + (csum & 0xffff); */
/* 	sum += (sum >> 16); */
/* 	return ~sum; */
/* } */

/*
 * The icmp_checksum_diff function takes pointers to old and new structures and
 * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
 * helper to compute the checksum difference. Note that the sizes passed to the
 * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
 * words.
 */
/* static __always_inline __u16 icmp_checksum_diff( */
/* 		__u16 seed, */
/* 		struct icmphdr_common *icmphdr_new, */
/* 		struct icmphdr_common *icmphdr_old) */
/* { */
/* 	/1* __u32 csum, size = sizeof(struct icmphdr_common) + sizeof(long); //modified *1/ */
/* 	__u32 csum, size = sizeof(struct icmphdr_common); */  

/* 	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed); */
/* 	return csum_fold_helper(csum); */
/* } */

/* static __u16 icmp_checksum(__u16 *icmph, __u64 len) */
/* { */
/* 	__u16 ret = 0; */
/* 	__u32 sum = 0; */
/* 	__u16 odd_byte; */
	
/* 	while (len > 1) { */
/* 		sum += *icmph++; */
/* 		len -= 2; */
/* 	} */
	
/* 	if (len == 1) { */
/* 		*(__u8 *)(&odd_byte) = *(__u8 *)icmph; */
/* 		sum += odd_byte; */
/* 	} */
	
/* 	sum =  (sum >> 16) + (sum & 0xffff); */
/* 	sum += (sum >> 16); */
/* 	ret =  ~sum; */
	
/* 	return ret; */ 
/* } */
  
SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	/* __u16 echo_reply, old_csum; */
    __u16 echo_reply;
	struct icmphdr_common *icmphdr;
	/* struct icmphdr_common icmphdr_old; */
	__u32 action = XDP_PASS;

    /* Get metrics */
    long cpu_metrics = 0;
    bpf_get_user_cpu_metrics(&cpu_metrics);
    
	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)
		   && icmp_type == ICMPV6_ECHO_REQUEST) {
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);

    /* load metrics */
    void *icmp_payload = nh.pos;
    if (icmp_payload + sizeof(long) + sizeof(int) > data_end) goto out;
    *(long *) (icmp_payload + 4) = cpu_metrics;

    /* void *icmp_payload = nh.pos; */
    /* if (icmp_payload + sizeof(long) > data_end) goto out; */
    /* *(long *)icmp_payload = cpu_metrics; */

	/* Patch the packet and update the checksum.*/
	icmphdr->cksum = 0;
	icmphdr->type = echo_reply;
	/* icmphdr->type = (u8)8; */
    int len = (int)((__u64)data_end - (__u64)icmphdr);
    __u16 *_icmphdr = (__u16 *)icmphdr;
	/* icmphdr->cksum = __builtin_bswap16(bpf_icmp_checksum(_icmphdr, len)); */
	icmphdr->cksum = bpf_icmp_checksum(_icmphdr, len);

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

