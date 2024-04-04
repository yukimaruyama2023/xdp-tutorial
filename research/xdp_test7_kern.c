/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>
/* #include <string.h> */

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

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
    __u16 echo_reply;
	struct icmphdr_common *icmphdr;
	__u32 action = XDP_PASS;

    /* Remove later */
    /* bpf_store42(); */

    /* Get metrics */
    long all_cpu_metrics[10] = {0, 0 ,0 ,0 ,0 ,0 ,0 ,0 ,0 ,0};
    /* long all_cpu_metrics[10]; */
    bpf_get_all_cpu_metrics(all_cpu_metrics);

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
    void *icmp_id = nh.pos;
    void *icmp_payload = icmp_id + 20;
    void *next_point = icmp_payload;

    for (int i = 0; i < 10; i++) {
        if (next_point + sizeof(long) > data_end) goto out;
        *(long *)next_point = all_cpu_metrics[i];
        next_point += 8;
    }

	/* Patch the packet and update the checksum.*/
	icmphdr->cksum = 0;
	icmphdr->type = echo_reply;
    int len = (int)((__u64)data_end - (__u64)icmphdr);
    __u16 *_icmphdr = (__u16 *)icmphdr;
	icmphdr->cksum = bpf_icmp_checksum(_icmphdr, len);

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

