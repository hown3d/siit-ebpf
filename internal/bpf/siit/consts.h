// net/ip.h
#define IP_DF 0x4000 /* Flag: "Don't Fragment"	*/

// Success error codes >= 0
#define IP_OK 0
// Failure error codes < 0
#define IP_NOT_SUPPORTED -1
// TODO: differentiate errors between drop and forward?
#define IP_ERROR -2
#define IP_UNDEFINED -127

// Success error codes >= 0
#define ICMP_OK 0
// Failure error codes < 0
#define ICMP_NOT_SUPPORTED -1
// TODO: differentiate errors between drop and forward?
#define ICMP_ERROR -2

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define PACKET_HOST 0
#define DEFAULT_MTU 1500

#define AF_INET 2
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

#define DEBUG 1 // Define DEBUG as 1 for debug mode, 0 for production

#define EINVAL 22
