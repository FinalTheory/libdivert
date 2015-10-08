//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#ifndef KernFunc_h
#define KernFunc_h

#define IFACE_BUFFER_SIZE 16
#define KEXT_CTL_NAME "org.baidu.PacketPID"

#ifndef SO_PROCINFO
struct so_procinfo {
    pid_t		spi_pid;
    pid_t		spi_epid;
    uuid_t		spi_uuid;
    uuid_t		spi_euuid;
};
#endif

struct qry_data
{
    // store query result
    pid_t pid;
    pid_t epid;
    struct so_procinfo proc;
    // store query info
    char iface[8];
    u_short source;
    u_short dest;
    u_int32_t saddr;
    u_int32_t daddr;
    u_char proto;
};

typedef struct qry_data *qry_data_t;

#define KERN_CTL_OUTBOUND   0x01
#define KERN_CTL_INBOUND    0x02

#ifdef KEXT_PRIVATE
int InitFunctions();
int LoadInterfaces();
errno_t
kern_ctl_getopt_func(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
                     int opt, void *data, size_t *len);
#endif

#endif /* KernFunc_h */
