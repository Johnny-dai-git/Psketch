/*
 * eBPF Headers and Constants
 * Contains all necessary includes and constant definitions
 */

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Protocol Constants
#define TCP_PROTO 6
#define UDP_PROTO 17
#define THRE 3000000
#define VOTE_THRE 3
