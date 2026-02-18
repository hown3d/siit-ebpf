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
