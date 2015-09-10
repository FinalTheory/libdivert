#ifndef DIVERT_IPFW_UTILS_H
#define DIVERT_IPFW_UTILS_H

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include "netinet/ip_fw.h"

/*
 * format of filter language:
 *
    rule: proto src dst extras ...
    proto: {ip|tcp|udp|icmp|<number>}
    src: from [not] {me|any|ip[{/bits|:mask}]} [{port|port-port},[port],...]
    dst: to [not] {me|any|ip[{/bits|:mask}]} [{port|port-port},[port],...]
    extras:
        uid {user id}
        fragment     (may not be used with ports or tcpflags)
        in
        out
        {xmit|recv|via} {iface|ip|any}
        {established|setup}
        tcpflags [!]{syn|fin|rst|ack|psh|urg},...
        ipoptions [!]{ssrr|lsrr|rr|ts},...
        tcpoptions [!]{mss|window|sack|ts|cc},...
        icmptypes {type[,type]}...
 */

int ipfw_compile_rule(struct ip_fw *new_rule, u_short divert_port,
                      char *rule_content, char *errmsg);

void ipfw_print_rule(struct ip_fw *chain);

#endif //DIVERT_IPFW_UTILS_H
