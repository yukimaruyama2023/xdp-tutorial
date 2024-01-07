/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    long cpu_metrics = 0;
    bpf_get_user_cpu_metrics(&cpu_metrics);
    if (cpu_metrics != 0) action = XDP_DROP;

    return action;
}
char _license[] SEC("license") = "GPL";
