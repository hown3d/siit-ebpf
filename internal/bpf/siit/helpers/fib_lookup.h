#include "vmlinux.h"

#include "../consts.h"
#include "bpf/bpf_endian.h"
#include "linux/icmp.h"
#include "linux/icmp6.h"
#include "linux/if_ether.h"
#include "linux/in6.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph) {
  u32 check = (__u32)iph->check;

  check += (__u32)bpf_htons(0x0100);
  iph->check = (__sum16)(check + (check >= 0xFFFF));
  return --iph->ttl;
}

static int __always_inline fib_lookup(struct __sk_buff *skb, struct ethhdr *eth,
                                      struct bpf_fib_lookup *fib_params,
                                      __u32 fib_flags) {
  if (fib_params == NULL) {
    return -EINVAL;
  }

  fib_params->sport = 0;
  fib_params->dport = 0;
  fib_params->ifindex = skb->ifindex;
  int ret;
  ret = bpf_fib_lookup(skb, fib_params, sizeof(*fib_params), fib_flags);
  if (ret < 0) {
#ifdef DEBUG
    bpf_printk("fib lookup errored, got code %d", ret);
#endif
    return ret;
  }
  bool redirect = false;
  bool redirect_neigh = false;
  switch (ret) {
  case BPF_FIB_LKUP_RET_SUCCESS: /* lookup successful */
    redirect = true;
    __builtin_memcpy(eth->h_source, fib_params->smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib_params->dmac, ETH_ALEN);
#ifdef DEBUG
    bpf_printk("FIB lookup returned success");
    bpf_printk("FIB recieved smac: %02x:%02x:%02x:%02x:%02x:%02x",
               fib_params->smac[0], fib_params->smac[1], fib_params->smac[2],
               fib_params->smac[3], fib_params->smac[4], fib_params->smac[5]);
    bpf_printk("FIB recieved dmac: %02x:%02x:%02x:%02x:%02x:%02x",
               fib_params->dmac[0], fib_params->dmac[1], fib_params->dmac[2],
               fib_params->dmac[3], fib_params->dmac[4], fib_params->dmac[5]);
#endif

    break;
  case BPF_FIB_LKUP_RET_NO_NEIGH:
#ifdef DEBUG
    bpf_printk("FIB lookup returned no neighbor, redirecting with neighbor to "
               "interface %d",
               fib_params->ifindex);
#endif
    break;
  default:
#ifdef DEBUG
    /*
     * BPF_FIB_LKUP_RET_FWD_DISABLED:
     *  The bpf_fib_lookup respect sysctl net.ipv{4,6}.conf.all.forwarding
     *  setting, and will return BPF_FIB_LKUP_RET_FWD_DISABLED if not
     *  enabled this on ingress device.
     */
    bpf_printk("fib lookup was not successfull, got code %d", ret);
#endif
  }

  bpf_printk("new smac: %02x:%02x:%02x:%02x:%02x:%02x", eth->h_source[0],
             eth->h_source[1], eth->h_source[2], eth->h_source[3],
             eth->h_source[4], eth->h_source[5]);
  bpf_printk("new dmac: %02x:%02x:%02x:%02x:%02x:%02x", eth->h_dest[0],
             eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4],
             eth->h_dest[5]);

  if (fib_params->ifindex != skb->ifindex) {
#ifdef DEBUG
    bpf_printk("fib lookup returned different interface. Redirecting to "
               "interface index %d, recieved on interface index %d",
               fib_params->ifindex, skb->ifindex);
#endif
  }
  return ret;
}

static int __always_inline fib_lookup_v4(struct __sk_buff *skb,
                                         struct ethhdr *eth, struct iphdr *ip4,
                                         __u32 *new_ifindex) {

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return -EINVAL;
  }
  if (new_ifindex == NULL) {
    return -EINVAL;
  }

  struct bpf_fib_lookup fib_params = {};
  fib_params.family = AF_INET;
  fib_params.tos = ip4->tos;
  fib_params.l4_protocol = ip4->protocol;
  fib_params.tot_len = bpf_ntohs(ip4->tot_len);
  fib_params.ipv4_src = ip4->saddr;
  fib_params.ipv4_dst = ip4->daddr;

  int ret = fib_lookup(skb, eth, &fib_params, 0);
  if (ret < 0) {
    return ret;
  }
  ip_decrease_ttl(ip4);
  *new_ifindex = fib_params.ifindex;
  return ret;
}

static int __always_inline fib_lookup_v6(struct __sk_buff *skb,
                                         struct ethhdr *eth,
                                         struct ipv6hdr *ip6,
                                         __u32 *new_ifindex) {
  // use if else to allow instantiation inside block
  if (eth->h_proto != bpf_htons(ETH_P_IPV6)) {
    return -EINVAL;
  }
  if (new_ifindex == NULL) {
    return -EINVAL;
  }

  struct bpf_fib_lookup fib_params = {};

  struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
  struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;

  *src = ip6->saddr;
  *dst = ip6->daddr;
  fib_params.family = AF_INET6;
  fib_params.l4_protocol = ip6->nexthdr;
  fib_params.tot_len = bpf_ntohs(ip6->payload_len);
  fib_params.flowinfo = *(__be32 *)(ip6)&IPV6_FLOWINFO_MASK;

  // __u32 fib_flags = BPF_FIB_LOOKUP_DIRECT & BPF_FIB_LOOKUP_OUTPUT;
  // __u32 fib_flags = BPF_FIB_LOOKUP_OUTPUT;
  int ret = fib_lookup(skb, eth, &fib_params, 0);
  if (ret < 0) {
    return ret;
  }
  ip6->hop_limit--;
  *new_ifindex = fib_params.ifindex;
  return ret;
}
