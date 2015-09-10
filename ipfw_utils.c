#include "ipfw_utils.h"
#include "divert.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <err.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <sys/param.h>
#include <netinet/ip_icmp.h>


struct icmpcode {
    int code;
    char *str;
};

static struct icmpcode icmpcodes[] = {
        {ICMP_UNREACH_NET,               "net"},
        {ICMP_UNREACH_HOST,              "host"},
        {ICMP_UNREACH_PROTOCOL,          "protocol"},
        {ICMP_UNREACH_PORT,              "port"},
        {ICMP_UNREACH_NEEDFRAG,          "needfrag"},
        {ICMP_UNREACH_SRCFAIL,           "srcfail"},
        {ICMP_UNREACH_NET_UNKNOWN,       "net-unknown"},
        {ICMP_UNREACH_HOST_UNKNOWN,      "host-unknown"},
        {ICMP_UNREACH_ISOLATED,          "isolated"},
        {ICMP_UNREACH_NET_PROHIB,        "net-prohib"},
        {ICMP_UNREACH_HOST_PROHIB,       "host-prohib"},
        {ICMP_UNREACH_TOSNET,            "tosnet"},
        {ICMP_UNREACH_TOSHOST,           "toshost"},
        {ICMP_UNREACH_FILTER_PROHIB,     "filter-prohib"},
        {ICMP_UNREACH_HOST_PRECEDENCE,   "host-precedence"},
        {ICMP_UNREACH_PRECEDENCE_CUTOFF, "precedence-cutoff"},
        {0, NULL}
};

static int mask_bits(struct in_addr m_ad) {
    int h_fnd = 0, h_num = 0, i;
    u_long mask;

    mask = ntohl(m_ad.s_addr);
    for (i = 0; i < sizeof(u_long) * CHAR_BIT; i++) {
        if (mask & 1L) {
            h_fnd = 1;
            h_num++;
        } else {
            if (h_fnd) {
                return -1;
            }
        }
        mask = mask >> 1;
    }
    return h_num;
}

static void print_port(u_char prot, u_short port, const char *comma) {
    int printed = 0;

    if (!strcmp(comma, ":")) {
        printf("%s0x%04x", comma, port);
        return;
    }
    if (!printed) {
        printf("%s%d", comma, port);
    }
}

static void print_iface(char *key, union ip_fw_if *un, int byname) {
    char ifnb[FW_IFNLEN + 1];

    if (byname) {
        strncpy(ifnb, un->fu_via_if.name, FW_IFNLEN);
        ifnb[FW_IFNLEN] = '\0';
        if (un->fu_via_if.unit == -1) {
            printf(" %s %s*", key, ifnb);
        } else {
            printf(" %s %s%d", key, ifnb, un->fu_via_if.unit);
        }
    } else if (un->fu_via_ip.s_addr != 0) {
        printf(" %s %s", key, inet_ntoa(un->fu_via_ip));
    } else {
        printf(" %s any", key);
    }
}

static void print_reject_code(int code) {
    struct icmpcode *ic;

    for (ic = icmpcodes; ic->str; ic++) {
        if (ic->code == code) {
            printf("%s", ic->str);
            return;
        }
    }
    printf("%u", code);
}

void ipfw_print_rule(struct ip_fw *chain) {
    char *comma;
    u_long adrt;
    struct hostent *he;
    struct protoent *pe;
    int i, mb;
    int nsp = IP_FW_GETNSRCP(chain);
    int ndp = IP_FW_GETNDSTP(chain);

    setservent(1/*stay open*/);

    printf("%05u ", chain->fw_number);

    if (chain->fw_flg == IP_FW_F_CHECK_S) {
        printf("check-state\n");
        goto done;
    }

    if (chain->fw_flg & IP_FW_F_RND_MATCH) {
        double d = 1.0 * (int)(chain->pipe_ptr);
        d = 1 - (d / 0x7fffffff);
        printf("prob %f ", d);
    }

    switch (chain->fw_flg & IP_FW_F_COMMAND) {
        case IP_FW_F_ACCEPT:
            printf("allow");
            break;
        case IP_FW_F_DENY:
            printf("deny");
            break;
        case IP_FW_F_COUNT:
            printf("count");
            break;
        case IP_FW_F_DIVERT:
            printf("divert %u", chain->fw_divert_port);
            break;
        case IP_FW_F_TEE:
            printf("tee %u", chain->fw_divert_port);
            break;
        case IP_FW_F_SKIPTO:
            printf("skipto %u", chain->fw_skipto_rule);
            break;

        case IP_FW_F_PIPE:
            printf("pipe %u", chain->fw_skipto_rule);
            break;
        case IP_FW_F_QUEUE:
            printf("queue %u", chain->fw_skipto_rule);
            break;
        case IP_FW_F_REJECT:
            if (chain->fw_reject_code == IP_FW_REJECT_RST) {
                printf("reset");
            } else {
                printf("unreach ");
                print_reject_code(chain->fw_reject_code);
            }
            break;
        case IP_FW_F_FWD:
            printf("fwd %s", inet_ntoa(chain->fw_fwd_ip.sin_addr));
            if (chain->fw_fwd_ip.sin_port) {
                printf(",%d", chain->fw_fwd_ip.sin_port);
            }
            break;
        default:
            puts("impossible");
    }

    if (chain->fw_flg & IP_FW_F_PRN) {
        printf(" log");
        if (chain->fw_logamount) {
            printf(" logamount %d", chain->fw_logamount);
        }
    }

    pe = getprotobynumber(chain->fw_prot);
    if (pe) {
        printf(" %s", pe->p_name);
    } else {
        printf(" %u", chain->fw_prot);
    }

    if (chain->fw_flg & IP_FW_F_SME) {
        printf(" from me");
    } else {
        printf(" from %s", chain->fw_flg & IP_FW_F_INVSRC ? "not " : "");

        adrt = ntohl(chain->fw_smsk.s_addr);
        if (adrt == ULONG_MAX) {
            adrt = (chain->fw_src.s_addr);
            he = gethostbyaddr((char *)&adrt,
                               sizeof(u_long), AF_INET);
            if (he == NULL) {
                printf("%s", inet_ntoa(chain->fw_src));
            } else {
                printf("%s", he->h_name);
            }
        } else {
            if (adrt != ULONG_MAX) {
                mb = mask_bits(chain->fw_smsk);
                if (mb == 0) {
                    printf("any");
                } else {
                    if (mb > 0) {
                        printf("%s", inet_ntoa(chain->fw_src));
                        printf("/%d", mb);
                    } else {
                        printf("%s", inet_ntoa(chain->fw_src));
                        printf(":");
                        printf("%s", inet_ntoa(chain->fw_smsk));
                    }
                }
            } else {
                printf("%s", inet_ntoa(chain->fw_src));
            }
        }
    }

    if (chain->fw_prot == IPPROTO_TCP || chain->fw_prot == IPPROTO_UDP) {
        comma = " ";
        for (i = 0; i < nsp; i++) {
            print_port(chain->fw_prot, chain->fw_uar.fw_pts[i], comma);
            if (i == 0 && (chain->fw_flg & IP_FW_F_SRNG)) {
                comma = "-";
            } else if (i == 0 && (chain->fw_flg & IP_FW_F_SMSK)) {
                comma = ":";
            } else {
                comma = ",";
            }
        }
    }

    if (chain->fw_flg & IP_FW_F_DME) {
        printf(" to me");
    } else {
        printf(" to %s", chain->fw_flg & IP_FW_F_INVDST ? "not " : "");

        adrt = ntohl(chain->fw_dmsk.s_addr);
        if (adrt == ULONG_MAX) {
            adrt = (chain->fw_dst.s_addr);
            he = gethostbyaddr((char *)&adrt,
                               sizeof(u_long), AF_INET);
            if (he == NULL) {
                printf("%s", inet_ntoa(chain->fw_dst));
            } else {
                printf("%s", he->h_name);
            }
        } else {
            if (adrt != ULONG_MAX) {
                mb = mask_bits(chain->fw_dmsk);
                if (mb == 0) {
                    printf("any");
                } else {
                    if (mb > 0) {
                        printf("%s", inet_ntoa(chain->fw_dst));
                        printf("/%d", mb);
                    } else {
                        printf("%s", inet_ntoa(chain->fw_dst));
                        printf(":");
                        printf("%s", inet_ntoa(chain->fw_dmsk));
                    }
                }
            } else {
                printf("%s", inet_ntoa(chain->fw_dst));
            }
        }
    }

    if (chain->fw_prot == IPPROTO_TCP || chain->fw_prot == IPPROTO_UDP) {
        comma = " ";
        for (i = 0; i < ndp; i++) {
            print_port(chain->fw_prot, chain->fw_uar.fw_pts[nsp + i], comma);
            if (i == 0 && (chain->fw_flg & IP_FW_F_DRNG)) {
                comma = "-";
            } else if (i == 0 && (chain->fw_flg & IP_FW_F_DMSK)) {
                comma = ":";
            } else {
                comma = ",";
            }
        }
    }

    if (chain->fw_flg & IP_FW_F_UID) {
        struct passwd *pwd = getpwuid(chain->fw_uid);

        if (pwd) {
            printf(" uid %s", pwd->pw_name);
        } else {
            printf(" uid %u", chain->fw_uid);
        }
    }

    if (chain->fw_flg & IP_FW_F_KEEP_S) {
        if (chain->next_rule_ptr) {
            printf(" keep-state %d", (int)chain->next_rule_ptr);
        } else {
            printf(" keep-state");
        }
    }
    /* Direction */
    if (chain->fw_flg & IP_FW_BRIDGED) {
        printf(" bridged");
    }
    if ((chain->fw_flg & IP_FW_F_IN) && !(chain->fw_flg & IP_FW_F_OUT)) {
        printf(" in");
    }
    if (!(chain->fw_flg & IP_FW_F_IN) && (chain->fw_flg & IP_FW_F_OUT)) {
        printf(" out");
    }

    /* Handle hack for "via" backwards compatibility */
    if ((chain->fw_flg & IF_FW_F_VIAHACK) == IF_FW_F_VIAHACK) {
        print_iface("via",
                    &chain->fw_in_if, chain->fw_flg & IP_FW_F_IIFNAME);
    } else {
        /* Receive interface specified */
        if (chain->fw_flg & IP_FW_F_IIFACE) {
            print_iface("recv", &chain->fw_in_if,
                        chain->fw_flg & IP_FW_F_IIFNAME);
        }
        /* Transmit interface specified */
        if (chain->fw_flg & IP_FW_F_OIFACE) {
            print_iface("xmit", &chain->fw_out_if,
                        chain->fw_flg & IP_FW_F_OIFNAME);
        }
    }

    if (chain->fw_flg & IP_FW_F_FRAG) {
        printf(" frag");
    }

    if (chain->fw_ipopt || chain->fw_ipnopt) {
        int _opt_printed = 0;
#define PRINTOPT(x)    {if (_opt_printed) printf(",");\
            printf(x); _opt_printed = 1;}

        printf(" ipopt ");
        if (chain->fw_ipopt & IP_FW_IPOPT_SSRR) PRINTOPT("ssrr");
        if (chain->fw_ipnopt & IP_FW_IPOPT_SSRR) PRINTOPT("!ssrr");
        if (chain->fw_ipopt & IP_FW_IPOPT_LSRR) PRINTOPT("lsrr");
        if (chain->fw_ipnopt & IP_FW_IPOPT_LSRR) PRINTOPT("!lsrr");
        if (chain->fw_ipopt & IP_FW_IPOPT_RR) PRINTOPT("rr");
        if (chain->fw_ipnopt & IP_FW_IPOPT_RR) PRINTOPT("!rr");
        if (chain->fw_ipopt & IP_FW_IPOPT_TS) PRINTOPT("ts");
        if (chain->fw_ipnopt & IP_FW_IPOPT_TS) PRINTOPT("!ts");
    }

    if (chain->fw_ipflg & IP_FW_IF_TCPEST) {
        printf(" established");
    } else if (chain->fw_tcpf == IP_FW_TCPF_SYN &&
               chain->fw_tcpnf == IP_FW_TCPF_ACK) {
        printf(" setup");
    } else if (chain->fw_tcpf || chain->fw_tcpnf) {
        int _flg_printed = 0;
#define PRINTFLG(x)    {if (_flg_printed) printf(",");\
            printf(x); _flg_printed = 1;}

        printf(" tcpflags ");
        if (chain->fw_tcpf & IP_FW_TCPF_FIN) PRINTFLG("fin");
        if (chain->fw_tcpnf & IP_FW_TCPF_FIN) PRINTFLG("!fin");
        if (chain->fw_tcpf & IP_FW_TCPF_SYN) PRINTFLG("syn");
        if (chain->fw_tcpnf & IP_FW_TCPF_SYN) PRINTFLG("!syn");
        if (chain->fw_tcpf & IP_FW_TCPF_RST) PRINTFLG("rst");
        if (chain->fw_tcpnf & IP_FW_TCPF_RST) PRINTFLG("!rst");
        if (chain->fw_tcpf & IP_FW_TCPF_PSH) PRINTFLG("psh");
        if (chain->fw_tcpnf & IP_FW_TCPF_PSH) PRINTFLG("!psh");
        if (chain->fw_tcpf & IP_FW_TCPF_ACK) PRINTFLG("ack");
        if (chain->fw_tcpnf & IP_FW_TCPF_ACK) PRINTFLG("!ack");
        if (chain->fw_tcpf & IP_FW_TCPF_URG) PRINTFLG("urg");
        if (chain->fw_tcpnf & IP_FW_TCPF_URG) PRINTFLG("!urg");
    }
    if (chain->fw_tcpopt || chain->fw_tcpnopt) {
        int _opt_printed = 0;
#define PRINTTOPT(x)    {if (_opt_printed) printf(",");\
            printf(x); _opt_printed = 1;}

        printf(" tcpoptions ");
        if (chain->fw_tcpopt & IP_FW_TCPOPT_MSS) PRINTTOPT("mss");
        if (chain->fw_tcpnopt & IP_FW_TCPOPT_MSS) PRINTTOPT("!mss");
        if (chain->fw_tcpopt & IP_FW_TCPOPT_WINDOW) PRINTTOPT("window");
        if (chain->fw_tcpnopt & IP_FW_TCPOPT_WINDOW) PRINTTOPT("!window");
        if (chain->fw_tcpopt & IP_FW_TCPOPT_SACK) PRINTTOPT("sack");
        if (chain->fw_tcpnopt & IP_FW_TCPOPT_SACK) PRINTTOPT("!sack");
        if (chain->fw_tcpopt & IP_FW_TCPOPT_TS) PRINTTOPT("ts");
        if (chain->fw_tcpnopt & IP_FW_TCPOPT_TS) PRINTTOPT("!ts");
        if (chain->fw_tcpopt & IP_FW_TCPOPT_CC) PRINTTOPT("cc");
        if (chain->fw_tcpnopt & IP_FW_TCPOPT_CC) PRINTTOPT("!cc");
    }

    if (chain->fw_flg & IP_FW_F_ICMPBIT) {
        int type_index;
        int first = 1;

        printf(" icmptype");

        for (type_index = 0; type_index < IP_FW_ICMPTYPES_DIM * sizeof(unsigned) * 8; ++type_index) {
            if (chain->fw_uar.fw_icmptypes[type_index / (sizeof(unsigned) * 8)] &
                (1U << (type_index % (sizeof(unsigned) * 8)))) {
                printf("%c%d", first == 1 ? ' ' : ',', type_index);
                first = 0;
            }
        }
    }
    printf("\n");
    done:
    endservent();
}

static int lookup_host(char *host, struct in_addr *ipaddr) {
    struct hostent *he;

    if (!inet_aton(host, ipaddr)) {
        if ((he = gethostbyname(host)) == NULL) {
            return (-1);
        }
        *ipaddr = *(struct in_addr *)he->h_addr_list[0];
    }
    return (0);
}

static void fill_ip(struct in_addr *ipno, struct in_addr *mask,
                    int *acp, char ***avp, char *errmsg) {
    int ac = *acp;
    char **av = *avp;
    char *p = 0, md = 0;

    if (ac && !strncmp(*av, "any", strlen(*av))) {
        ipno->s_addr = mask->s_addr = 0;
        av++;
        ac--;
    } else {
        p = strchr(*av, '/');
        if (!p) {
            p = strchr(*av, ':');
        }
        if (p) {
            md = *p;
            *p++ = '\0';
        }

        if (lookup_host(*av, ipno) != 0) {
            sprintf(errmsg, "hostname '%s' unknown", *av);
        }
        switch (md) {
            case ':':
                if (!inet_aton(p, mask)) {
                    sprintf(errmsg, "bad netmask '%s'", p);
                }
                break;
            case '/':
                if (atoi(p) == 0) {
                    mask->s_addr = 0;
                } else if (atoi(p) > 32) {
                    sprintf(errmsg, "bad width '%s'", p);
                } else {
                    mask->s_addr = htonl(~0 << (32 - atoi(p)));
                }
                break;
            default:
                mask->s_addr = htonl(~0);
                break;
        }
        ipno->s_addr &= mask->s_addr;
        av++;
        ac--;
    }
    *acp = ac;
    *avp = av;
}

static void add_port(u_short *cnt, u_short *ptr,
                     u_short off, u_short port, char *errmsg) {
    if (off + *cnt >= IP_FW_MAX_PORTS) {
        sprintf(errmsg, "too many ports (max is %d)", IP_FW_MAX_PORTS);
    }
    ptr[off + *cnt] = port;
    (*cnt)++;
}

static int lookup_port(const char *arg, int proto,
                       int test, int nodash, char *errmsg) {
    int val;
    char *earg, buf[32];
    struct servent *s;
    char *p, *q;

    snprintf(buf, sizeof(buf), "%s", arg);

    for (p = q = buf; *p; *q++ = *p++) {
        if (*p == '\\') {
            if (*(p + 1)) {
                p++;
            }
        } else {
            if (*p == ',' || (nodash && *p == '-')) {
                break;
            }
        }
    }
    *q = '\0';

    val = (int)strtoul(buf, &earg, 0);
    if (!*buf || *earg) {
        char *protocol = NULL;

        if (proto != 0) {
            struct protoent *pe = getprotobynumber(proto);

            if (pe) {
                protocol = pe->p_name;
            }
        }

        setservent(1);
        if ((s = getservbyname(buf, protocol))) {
            val = htons(s->s_port);
        } else {
            if (!test) {
                sprintf(errmsg, "unknown port '%s'", buf);
            }
            val = -1;
        }
    } else {
        if (val < 0 || val > 0xffff) {
            if (!test) {
                sprintf(errmsg, "port '%s' out of range", buf);
            }
            val = -1;
        }
    }
    return (val);
}

/*
 * return: 0 normally, 1 if first pair is a range,
 * 2 if first pair is a port+mask
 */
static int fill_port(u_short *cnt, u_short *ptr, u_short off,
                     char *arg, int proto, char *errmsg) {
    char *s;
    int initial_range = 0;

    for (s = arg; *s && *s != ',' && *s != '-' && *s != ':'; s++) {
        if (*s == '\\' && *(s + 1)) {
            s++;
        }
    }
    if (*s == ':') {
        *s++ = '\0';
        if (strchr(arg, ',')) {
            sprintf(errmsg, "port/mask must be first in list");
        }
        add_port(cnt, ptr, off, (u_short)(*arg ? lookup_port(arg, proto, 0, 0, errmsg) : 0x0000), errmsg);
        arg = s;
        s = strchr(arg, ',');
        if (s) {
            *s++ = '\0';
        }
        add_port(cnt, ptr, off, (u_short)(*arg ? lookup_port(arg, proto, 0, 0, errmsg) : 0xffff), errmsg);
        arg = s;
        initial_range = 2;
    } else if (*s == '-') {
        *s++ = '\0';
        if (strchr(arg, ',')) {
            sprintf(errmsg, "port range must be first in list");
        }
        add_port(cnt, ptr, off, (u_short)(*arg ? lookup_port(arg, proto, 0, 0, errmsg) : 0x0000), errmsg);
        arg = s;
        s = strchr(arg, ',');
        if (s) {
            *s++ = '\0';
        }
        add_port(cnt, ptr, off, (u_short)(*arg ? lookup_port(arg, proto, 0, 0, errmsg) : 0xffff), errmsg);
        arg = s;
        initial_range = 1;
    }
    while (arg != NULL) {
        s = strchr(arg, ',');
        if (s) {
            *s++ = '\0';
        }
        add_port(cnt, ptr, off, (u_short)lookup_port(arg, proto, 0, 0, errmsg), errmsg);
        arg = s;
    }
    return initial_range;
}

static void fill_tcpflag(u_char *set, u_char *reset,
                         char **vp, char *errmsg) {
    char *p = *vp, *q;
    u_char *d;

    while (p && *p) {
        struct tpcflags {
            char *name;
            u_char value;
        } flags[] = {
                {"syn", IP_FW_TCPF_SYN},
                {"fin", IP_FW_TCPF_FIN},
                {"ack", IP_FW_TCPF_ACK},
                {"psh", IP_FW_TCPF_PSH},
                {"rst", IP_FW_TCPF_RST},
                {"urg", IP_FW_TCPF_URG}
        };
        int i;

        if (*p == '!') {
            p++;
            d = reset;
        } else {
            d = set;
        }
        q = strchr(p, ',');
        if (q) {
            *q++ = '\0';
        }
        for (i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
            if (!strncmp(p, flags[i].name, strlen(p))) {
                *d |= flags[i].value;
                break;
            }
        }
        if (i == sizeof(flags) / sizeof(flags[0])) {
            sprintf(errmsg, "invalid tcp flag '%s'", p);
        }
        p = q;
    }
}

static void fill_tcpopts(u_char *set, u_char *reset,
                         char **vp, char *errmsg) {
    char *p = *vp, *q;
    u_char *d;

    while (p && *p) {
        struct tpcopts {
            char *name;
            u_char value;
        } opts[] = {
                {"mss",    IP_FW_TCPOPT_MSS},
                {"window", IP_FW_TCPOPT_WINDOW},
                {"sack",   IP_FW_TCPOPT_SACK},
                {"ts",     IP_FW_TCPOPT_TS},
                {"cc",     IP_FW_TCPOPT_CC},
        };
        int i;

        if (*p == '!') {
            p++;
            d = reset;
        } else {
            d = set;
        }
        q = strchr(p, ',');
        if (q) {
            *q++ = '\0';
        }
        for (i = 0; i < sizeof(opts) / sizeof(opts[0]); ++i) {
            if (!strncmp(p, opts[i].name, strlen(p))) {
                *d |= opts[i].value;
                break;
            }
        }
        if (i == sizeof(opts) / sizeof(opts[0])) {
            sprintf(errmsg, "invalid tcp option '%s'", p);
        }
        p = q;
    }
}

static void fill_ipopt(u_char *set, u_char *reset,
                       char **vp, char *errmsg) {
    char *p = *vp, *q;
    u_char *d;

    while (p && *p) {
        if (*p == '!') {
            p++;
            d = reset;
        } else {
            d = set;
        }
        q = strchr(p, ',');
        if (q) {
            *q++ = '\0';
        }
        if (!strncmp(p, "ssrr", strlen(p))) { *d |= IP_FW_IPOPT_SSRR; }
        if (!strncmp(p, "lsrr", strlen(p))) { *d |= IP_FW_IPOPT_LSRR; }
        if (!strncmp(p, "rr", strlen(p))) { *d |= IP_FW_IPOPT_RR; }
        if (!strncmp(p, "ts", strlen(p))) { *d |= IP_FW_IPOPT_TS; }
        p = q;
    }
}

static void fill_icmptypes(u_long *types, char **vp,
                           u_int *fw_flg, char *errmsg) {
    char *c = *vp;

    while (*c) {
        unsigned long icmptype;

        if (*c == ',') {
            ++c;
        }

        icmptype = strtoul(c, &c, 0);

        if (*c != ',' && *c != '\0') {
            sprintf(errmsg, "invalid ICMP type");
        }

        if (icmptype >= IP_FW_ICMPTYPES_DIM * sizeof(unsigned) * 8) {
            sprintf(errmsg, "ICMP type out of range");
        }

        types[icmptype / (sizeof(unsigned) * 8)] |=
                1 << (icmptype % (sizeof(unsigned) * 8));
        *fw_flg |= IP_FW_F_ICMPBIT;
    }
}

static void verify_interface(union ip_fw_if *ifu, char *errmsg) {
    struct ifreq ifr;
    /*
     *	If a unit was specified, check for that exact interface.
     *	If a wildcard was specified, check for unit 0.
     */
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s%d",
             ifu->fu_via_if.name,
             ifu->fu_via_if.unit == -1 ? 0 : ifu->fu_via_if.unit);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (s < 0) {
        sprintf(errmsg, "could not open socket");
        return;
    }

    if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        sprintf(errmsg, "warning: interface '%s' does not exist", ifr.ifr_name);
    }

    close(s);
}

static void fill_iface(char *which, union ip_fw_if *ifu,
                       int *byname, int ac, char *arg, char *errmsg) {
    if (!ac) {
        sprintf(errmsg, "missing argument for '%s'", which);
    }

    /* Parse the interface or address */
    if (!strcmp(arg, "any")) {
        ifu->fu_via_ip.s_addr = 0;
        *byname = 0;
    } else if (!isdigit(*arg)) {
        char *q;

        *byname = 1;
        strncpy(ifu->fu_via_if.name, arg, sizeof(ifu->fu_via_if.name));
        ifu->fu_via_if.name[sizeof(ifu->fu_via_if.name) - 1] = '\0';
        for (q = ifu->fu_via_if.name;
             *q && !isdigit(*q) && *q != '*'; q++) {
            continue;
        }
        ifu->fu_via_if.unit = (*q == '*') ? -1 : atoi(q);
        *q = '\0';
        verify_interface(ifu, errmsg);
    } else if (!inet_aton(arg, &ifu->fu_via_ip)) {
        sprintf(errmsg, "bad ip address '%s'", arg);
    } else {
        *byname = 0;
    }
}


#define WHITESP     " \t\f\v\n\r"
#define MAX_TOKS    256

/*
 * start from:
 * (divert 1234) ip from any to any
 */
int ipfw_compile_rule(struct ip_fw *new_rule, u_short divert_port,
                      char *rule_content, char *errmsg) {
    /* first extract rules from string */
    char *tokens[MAX_TOKS];
    int ac = 0;
    char **av = tokens;
    char *p_tok, *pos;
    // get first token
    p_tok = strtok_r(rule_content, WHITESP, &pos);
    // get remain tokens
    while (p_tok && ac < MAX_TOKS) {
        tokens[ac++] = p_tok;
        p_tok = strtok_r(NULL, WHITESP, &pos);
    }

    errmsg[0] = 0;
    struct ip_fw rule;
    u_char proto;
    struct protoent *pe;
    int saw_xmrc = 0, saw_via = 0;

    memset(&rule, 0, sizeof rule);

    /* rule version */
    rule.version = IP_FW_CURRENT_API_VERSION;

    /* rule number */
    rule.fw_number = DEFAULT_IPFW_RULE_ID;

    /* Action is set to divert */
    rule.fw_flg |= IP_FW_F_DIVERT;
    rule.fw_divert_port = divert_port;

    /* protocol */
    if (ac == 0) {
        sprintf(errmsg, "missing protocol");
        return -1;
    }
    if ((proto = (u_char)atoi(*av)) > 0) {
        rule.fw_prot = proto;
        av++;
        ac--;
    } else if (!strncmp(*av, "all", strlen(*av))) {
        rule.fw_prot = IPPROTO_IP;
        av++;
        ac--;
    } else if ((pe = getprotobyname(*av)) != NULL) {
        rule.fw_prot = (u_char)pe->p_proto;
        av++;
        ac--;
    } else {
        sprintf(errmsg, "invalid protocol %s", *av);
        return -1;
    }

    /* from */
    if (ac && !strncmp(*av, "from", strlen(*av))) {
        av++;
        ac--;
    } else {
        sprintf(errmsg, "missing 'from'");
        return -1;
    }

    if (ac && !strncmp(*av, "not", strlen(*av))) {
        rule.fw_flg |= IP_FW_F_INVSRC;
        av++;
        ac--;
    }
    if (!ac) {
        sprintf(errmsg, "missing arguments");
        return -1;
    }

    if (ac && !strncmp(*av, "me", strlen(*av))) {
        rule.fw_flg |= IP_FW_F_SME;
        av++;
        ac--;
    } else {
        fill_ip(&rule.fw_src, &rule.fw_smsk, &ac, &av, errmsg);
    }

    if (ac && (isdigit(**av) || lookup_port(*av, rule.fw_prot, 1, 1, errmsg) >= 0)) {
        u_short nports = 0;
        int retval;

        retval = fill_port(&nports, rule.fw_uar.fw_pts, 0, *av, rule.fw_prot, errmsg);
        if (retval == 1) {
            rule.fw_flg |= IP_FW_F_SRNG;
        } else if (retval == 2) {
            rule.fw_flg |= IP_FW_F_SMSK;
        }
        IP_FW_SETNSRCP(&rule, nports);
        av++;
        ac--;
    }

    /* to */
    if (ac && !strncmp(*av, "to", strlen(*av))) {
        av++;
        ac--;
    }
    else {
        sprintf(errmsg, "missing 'to'");
        return -1;
    }

    if (ac && !strncmp(*av, "not", strlen(*av))) {
        rule.fw_flg |= IP_FW_F_INVDST;
        av++;
        ac--;
    }
    if (!ac) {
        sprintf(errmsg, "missing arguments");
        return -1;
    }

    if (ac && !strncmp(*av, "me", strlen(*av))) {
        rule.fw_flg |= IP_FW_F_DME;
        av++;
        ac--;
    } else {
        fill_ip(&rule.fw_dst, &rule.fw_dmsk, &ac, &av, errmsg);
    }

    if (ac && (isdigit(**av) || lookup_port(*av, rule.fw_prot, 1, 1, errmsg) >= 0)) {
        u_short nports = 0;
        int retval;

        retval = fill_port(&nports, rule.fw_uar.fw_pts,
                           (u_short)IP_FW_GETNSRCP(&rule), *av, rule.fw_prot, errmsg);
        if (retval == 1) {
            rule.fw_flg |= IP_FW_F_DRNG;
        } else if (retval == 2) {
            rule.fw_flg |= IP_FW_F_DMSK;
        }
        IP_FW_SETNDSTP(&rule, nports);
        av++;
        ac--;
    }

    if ((rule.fw_prot != IPPROTO_TCP) && (rule.fw_prot != IPPROTO_UDP)
        && (IP_FW_GETNSRCP(&rule) || IP_FW_GETNDSTP(&rule))) {
        sprintf(errmsg, "only TCP and UDP protocols are valid"
                " with port specifications");
        return -1;
    }

    while (ac) {
        if (!strncmp(*av, "uid", strlen(*av))) {
            struct passwd *pwd;
            char *end;
            uid_t uid;

            rule.fw_flg |= IP_FW_F_UID;
            ac--;
            av++;
            if (!ac) {
                sprintf(errmsg, "'uid' requires argument");
                return -1;
            }

            uid = (uid_t)strtoul(*av, &end, 0);
            if (*end == '\0') {
                pwd = getpwuid(uid);
            } else {
                pwd = getpwnam(*av);
            }
            if (pwd == NULL) {
                sprintf(errmsg, "uid \"%s\" is nonexistant", *av);
                return -1;
            }
            rule.fw_uid = pwd->pw_uid;
            ac--;
            av++;
            continue;
        }
        if (!strncmp(*av, "in", strlen(*av))) {
            rule.fw_flg |= IP_FW_F_IN;
            av++;
            ac--;
            continue;
        }
        if (!strncmp(*av, "keep-state", strlen(*av))) {
            u_long type;
            rule.fw_flg |= IP_FW_F_KEEP_S;

            av++;
            ac--;
            if (ac > 0 && (type = (u_long)atoi(*av)) != 0) {
                rule.next_rule_ptr = (void *)type;
                av++;
                ac--;
            }
            continue;
        }
        if (!strncmp(*av, "bridged", strlen(*av))) {
            rule.fw_flg |= IP_FW_BRIDGED;
            av++;
            ac--;
            continue;
        }
        if (!strncmp(*av, "out", strlen(*av))) {
            rule.fw_flg |= IP_FW_F_OUT;
            av++;
            ac--;
            continue;
        }
        if (ac && !strncmp(*av, "xmit", strlen(*av))) {
            union ip_fw_if ifu;
            int byname;

            if (saw_via) {
                badviacombo:
                sprintf(errmsg, "'via' is incompatible"
                        " with 'xmit' and 'recv'");
                return -1;
            }
            saw_xmrc = 1;
            av++;
            ac--;
            fill_iface("xmit", &ifu, &byname, ac, *av, errmsg);
            rule.fw_out_if = ifu;
            rule.fw_flg |= IP_FW_F_OIFACE;
            if (byname) {
                rule.fw_flg |= IP_FW_F_OIFNAME;
            }
            av++;
            ac--;
            continue;
        }
        if (ac && !strncmp(*av, "recv", strlen(*av))) {
            union ip_fw_if ifu;
            int byname;

            if (saw_via) {
                goto badviacombo;
            }
            saw_xmrc = 1;
            av++;
            ac--;
            fill_iface("recv", &ifu, &byname, ac, *av, errmsg);
            rule.fw_in_if = ifu;
            rule.fw_flg |= IP_FW_F_IIFACE;
            if (byname) {
                rule.fw_flg |= IP_FW_F_IIFNAME;
            }
            av++;
            ac--;
            continue;
        }
        if (ac && !strncmp(*av, "via", strlen(*av))) {
            union ip_fw_if ifu;
            int byname = 0;

            if (saw_xmrc) {
                goto badviacombo;
            }
            saw_via = 1;
            av++;
            ac--;
            fill_iface("via", &ifu, &byname, ac, *av, errmsg);
            rule.fw_out_if = rule.fw_in_if = ifu;
            if (byname) {
                rule.fw_flg |=
                        (IP_FW_F_IIFNAME | IP_FW_F_OIFNAME);
            }
            av++;
            ac--;
            continue;
        }
        if (!strncmp(*av, "fragment", strlen(*av))) {
            rule.fw_flg |= IP_FW_F_FRAG;
            av++;
            ac--;
            continue;
        }
        if (!strncmp(*av, "ipoptions", strlen(*av))) {
            av++;
            ac--;
            if (!ac) {
                sprintf(errmsg, "missing argument"
                        " for 'ipoptions'");
                return -1;
            }
            fill_ipopt(&rule.fw_ipopt, &rule.fw_ipnopt, av, errmsg);
            av++;
            ac--;
            continue;
        }
        if (rule.fw_prot == IPPROTO_TCP) {
            if (!strncmp(*av, "established", strlen(*av))) {
                rule.fw_ipflg |= IP_FW_IF_TCPEST;
                av++;
                ac--;
                continue;
            }
            if (!strncmp(*av, "setup", strlen(*av))) {
                rule.fw_tcpf |= IP_FW_TCPF_SYN;
                rule.fw_tcpnf |= IP_FW_TCPF_ACK;
                av++;
                ac--;
                continue;
            }
            if (!strncmp(*av, "tcpflags", strlen(*av)) ||
                !strncmp(*av, "tcpflgs", strlen(*av))) {
                av++;
                ac--;
                if (!ac) {
                    sprintf(errmsg, "missing argument"
                            " for 'tcpflags'");
                    return -1;
                }
                fill_tcpflag(&rule.fw_tcpf, &rule.fw_tcpnf, av, errmsg);
                av++;
                ac--;
                continue;
            }
            if (!strncmp(*av, "tcpoptions", strlen(*av)) ||
                !strncmp(*av, "tcpopts", strlen(*av))) {
                av++;
                ac--;
                if (!ac) {
                    sprintf(errmsg, "missing argument"
                            " for 'tcpoptions'");
                    return -1;
                }
                fill_tcpopts(&rule.fw_tcpopt, &rule.fw_tcpnopt, av, errmsg);
                av++;
                ac--;
                continue;
            }
        }
        if (rule.fw_prot == IPPROTO_ICMP) {
            if (!strncmp(*av, "icmptypes", strlen(*av))) {
                av++;
                ac--;
                if (!ac) {
                    sprintf(errmsg, "missing argument"
                            " for 'icmptypes'");
                    return -1;
                }
                fill_icmptypes((u_long *)rule.fw_uar.fw_icmptypes, av, &rule.fw_flg, errmsg);
                av++;
                ac--;
                continue;
            }
        }
        sprintf(errmsg, "unknown argument '%s'", *av);
        return -1;
    }

    /* No direction specified -> do both directions */
    if (!(rule.fw_flg & (IP_FW_F_OUT | IP_FW_F_IN))) {
        rule.fw_flg |= (IP_FW_F_OUT | IP_FW_F_IN);
    }

    /* Sanity check interface check, but handle "via" case separately */
    if (saw_via) {
        if (rule.fw_flg & IP_FW_F_IN) {
            rule.fw_flg |= IP_FW_F_IIFACE;
        }
        if (rule.fw_flg & IP_FW_F_OUT) {
            rule.fw_flg |= IP_FW_F_OIFACE;
        }
    } else if ((rule.fw_flg & IP_FW_F_OIFACE) && (rule.fw_flg & IP_FW_F_IN)) {
        sprintf(errmsg, "can't check xmit interface of incoming packets");
        return -1;
    }

    /* frag may not be used in conjunction with ports or TCP flags */
    if (rule.fw_flg & IP_FW_F_FRAG) {
        if (rule.fw_tcpf || rule.fw_tcpnf) {
            sprintf(errmsg, "can't mix 'frag' and tcpflags");
            return -1;
        }

        if (rule.fw_nports) {
            sprintf(errmsg, "can't mix 'frag' and port specifications");
            return -1;
        }
    }
    if (rule.fw_flg & IP_FW_F_PRN) {
        if (!rule.fw_logamount) {
            size_t len = sizeof(int);

            if (sysctlbyname("net.inet.ip.fw.verbose_limit",
                             &rule.fw_logamount, &len, NULL, 0) == -1) {
                sprintf(errmsg, "sysctlbyname(\"%s\")",
                        "net.inet.ip.fw.verbose_limit");
                return -1;
            }
        } else if (rule.fw_logamount == -1) {
            rule.fw_logamount = 0;
        }
        rule.fw_loghighest = (u_int64_t)rule.fw_logamount;
    }
    *new_rule = rule;
    if (errmsg[0]) {
        return -1;
    } else {
        return 0;
    }
}
