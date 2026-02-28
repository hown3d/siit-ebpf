#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

static __always_inline __wsum csum_add(__wsum csum, __wsum addend) {
  csum += addend;
  return csum + (csum < addend);
}

static __always_inline __wsum csum_sub(__wsum csum, __wsum addend) {
  return csum_add(csum, ~addend);
}

static __always_inline __wsum ip6_pseudohdr_csum(struct ipv6hdr *ip6) {
  __be32 payload_len = bpf_htonl((__u32)bpf_ntohs(ip6->payload_len));
  __be32 nexthdr = bpf_htonl((__u32)ip6->nexthdr);

  __wsum pseudohdr_csum =
      bpf_csum_diff(NULL, 0, (void *)&(ip6->saddr), sizeof(struct in6_addr), 0);
  pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&(ip6->daddr),
                                 sizeof(struct in6_addr), pseudohdr_csum);
  pseudohdr_csum =
      bpf_csum_diff(NULL, 0, (void *)&nexthdr, sizeof(__be32), pseudohdr_csum);
  pseudohdr_csum = bpf_csum_diff(NULL, 0, (void *)&payload_len, sizeof(__be32),
                                 pseudohdr_csum);

  return pseudohdr_csum;
}

static __always_inline __wsum ip6_to_ip4_csum_diff(struct __sk_buff *skb,
                                                   struct ipv6hdr *ip6,
                                                   struct iphdr *ip4) {
  // Subtract 16 bytes of IPv6, add 4 bytes of IPv4
  __wsum diff = bpf_csum_diff((__be32 *)&ip6->saddr, 16, &ip4->saddr, 4, 0);

  // We pass the previous 'diff' as the seed to chain the calculations
  diff = bpf_csum_diff((__be32 *)&ip6->daddr, 16, &ip4->daddr, 4, diff);

  return diff;
}

static __always_inline __wsum ip4_to_ip6_csum_diff(struct __sk_buff *skb,
                                                   struct iphdr *ip4,
                                                   struct ipv6hdr *ip6) {
  __wsum diff = bpf_csum_diff(&ip4->saddr, 4, (__be32 *)&ip6->saddr, 16, 0);
  diff = bpf_csum_diff(&ip4->daddr, 4, (__be32 *)&ip6->daddr, 16, diff);

  return diff;
}

static __always_inline int tcp_csum_replace(struct __sk_buff *skb, __wsum diff,
                                            int ip_offset) {
  // In TC, skb->data starts at the Ethernet header.
  // After adjusting room, your new layout is Eth (14) + iphdr_offset + TCP
  int offset = ip_offset + offsetof(struct tcphdr, check);

  // Apply the diff to the TCP checksum inside the packet buffer
  // BPF_F_PSEUDO_HDR tells the kernel we are updating a pseudo-header
  // dependency
  return bpf_l4_csum_replace(skb, offset, 0, diff, BPF_F_PSEUDO_HDR);
}

static __always_inline int udp_csum_replace(struct __sk_buff *skb, __wsum diff,
                                            int ip_offset) {
  // In TC, skb->data starts at the Ethernet header.
  // After adjusting room, your new layout is Eth (14) + iphdr_offset + UDP
  int offset = ip_offset + offsetof(struct udphdr, check);

  return bpf_l4_csum_replace(skb, offset, 0, diff,
                             BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
}

static __always_inline void calc_ipv4_csum(struct iphdr *iph) {
  iph->check = 0;
  unsigned long long csum = 0;
  unsigned short *next_iph_u16 = (unsigned short *)iph;

#pragma unroll
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
    csum += *next_iph_u16++;
  }

  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16);
  iph->check = ~(unsigned short)csum;
}
