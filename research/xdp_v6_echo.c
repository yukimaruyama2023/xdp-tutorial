#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline __u16 csum16_add(__u16 a, __u16 b){
  a += b;
  a += (a < b);
  return a;
}

SEC("main")
int nsping_server(struct xdp_md *ctx){
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // examine the ethernet frame
  if(data + sizeof(struct ethhdr) > data_end){
    return XDP_DROP;
  }

  struct ethhdr *ethhdr = data;
  void *ethpayload = data + sizeof(struct ethhdr);

  if (bpf_ntohs(ethhdr->h_proto) != ETH_P_IPV6){
      return XDP_DROP;
  }

  // examine the ip packet
  if(ethpayload + sizeof(struct iphdr) > data_end){
    return XDP_DROP;
  }

  struct iphdr *iphdr = ethpayload;

  if(ethpayload + iphdr->ihl*4 > data_end){
    return XDP_DROP;
  }

  void *ippayload = ethpayload + iphdr->ihl*4;

  if(iphdr->protocol != IPPROTO_ICMPV6){
    return XDP_PASS;
  }

  // examine icmp packet
  if(ippayload + sizeof(struct icmphdr) > data_end){
    return XDP_DROP;
  }

  struct icmphdr *icmphdr = ippayload;

  if(icmphdr->type != ICMP_ECHO){
    return XDP_DROP;
  }

  // swap mac addresses
  unsigned char h_source[ETH_ALEN], h_dest[ETH_ALEN];

  __builtin_memcpy(h_source, ethhdr->h_source, ETH_ALEN);
  __builtin_memcpy(h_dest, ethhdr->h_dest, ETH_ALEN);
  __builtin_memcpy(ethhdr->h_dest, h_source, ETH_ALEN);
  __builtin_memcpy(ethhdr->h_source, h_dest, ETH_ALEN);

  // swap ip addresses; this does not affect checksum
  __be32 saddr, daddr;

  saddr = iphdr->saddr;
  daddr = iphdr->daddr;
  iphdr->daddr = saddr;
  iphdr->saddr = daddr;

  // modify icmp type from ICMP_ECHO to ICMP_ECHOREPLY; this calls
  // checksum recalculation.
  //
  // As only one 16-bit word changed, the sum can be patched using
  // this formula: sum' = ~(~sum + ~m0 + m1), where sum' is a new
  // sum, sum is an old sum, m0 and m1 are the old and new 16-bit
  // words respectively. In the formula above, the + operation is
  // defined as the following function:
  //
  // static __always_inline __u16 csum16_add(__u16 a, __u16 b){
  //   a += b;
  //   a += (a < b);
  //   return a;
  // }
  //
  __u16 m0 = *(__u16 *)icmphdr;
  icmphdr->type = ICMP_ECHOREPLY;
  icmphdr->code = 0;
  __u16 m1 = *(__u16 *)icmphdr;
  icmphdr->checksum = ~(csum16_add(csum16_add(~icmphdr->checksum, ~m0), m1));

  // echo back ping
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
