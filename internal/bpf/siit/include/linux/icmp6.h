/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#define ICMPV6_ROUTER_PREF_LOW 0x3
#define ICMPV6_ROUTER_PREF_MEDIUM 0x0
#define ICMPV6_ROUTER_PREF_HIGH 0x1
#define ICMPV6_ROUTER_PREF_INVALID 0x2

#define ICMPV6_DEST_UNREACH 1
#define ICMPV6_PKT_TOOBIG 2
#define ICMPV6_TIME_EXCEED 3
#define ICMPV6_PARAMPROB 4

#define ICMPV6_ERRMSG_MAX 127

#define ICMPV6_INFOMSG_MASK 0x80

#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_MGM_QUERY 130
#define ICMPV6_MGM_REPORT 131
#define ICMPV6_MGM_REDUCTION 132

#define ICMPV6_NI_QUERY 139
#define ICMPV6_NI_REPLY 140

#define ICMPV6_MLD2_REPORT 143

#define ICMPV6_DHAAD_REQUEST 144
#define ICMPV6_DHAAD_REPLY 145
#define ICMPV6_MOBILE_PREFIX_SOL 146
#define ICMPV6_MOBILE_PREFIX_ADV 147

#define ICMPV6_MRDISC_ADV 151

#define ICMPV6_MSG_MAX 255

/*
 *	Codes for Destination Unreachable
 */
#define ICMPV6_NOROUTE 0
#define ICMPV6_ADM_PROHIBITED 1
#define ICMPV6_NOT_NEIGHBOUR 2
#define ICMPV6_ADDR_UNREACH 3
#define ICMPV6_PORT_UNREACH 4
#define ICMPV6_POLICY_FAIL 5
#define ICMPV6_REJECT_ROUTE 6

/*
 *	Codes for Time Exceeded
 */
#define ICMPV6_EXC_HOPLIMIT 0
#define ICMPV6_EXC_FRAGTIME 1

/*
 *	Codes for Parameter Problem
 */
#define ICMPV6_HDR_FIELD 0
#define ICMPV6_UNK_NEXTHDR 1
#define ICMPV6_UNK_OPTION 2
#define ICMPV6_HDR_INCOMP 3

/* Codes for EXT_ECHO (PROBE) */
#define ICMPV6_EXT_ECHO_REQUEST 160
#define ICMPV6_EXT_ECHO_REPLY 161
/*
 *	constants for (set|get)sockopt
 */

#define ICMPV6_FILTER 1

/*
 *	ICMPV6 filter
 */

#define ICMPV6_FILTER_BLOCK 1
#define ICMPV6_FILTER_PASS 2
#define ICMPV6_FILTER_BLOCKOTHERS 3
#define ICMPV6_FILTER_PASSONLY 4

/*
 *	Definitions for MLDv2
 */
#define MLD2_MODE_IS_INCLUDE 1
#define MLD2_MODE_IS_EXCLUDE 2
#define MLD2_CHANGE_TO_INCLUDE 3
#define MLD2_CHANGE_TO_EXCLUDE 4
#define MLD2_ALLOW_NEW_SOURCES 5
#define MLD2_BLOCK_OLD_SOURCES 6

#define MLD2_ALL_MCR_INIT                                                      \
  {                                                                            \
    { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x16 } }                           \
  }
