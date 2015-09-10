#include "divert.h"
#include "divert_ipfw.h"
#include "ipfw_utils.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


int ipfw_setup(char *rule, u_short port, char *errmsg) {
    errmsg[0] = 0;
    int ipfw_fd;
    struct ip_fw ipfw_rule;
    /* clear error message */
    errmsg[0] = 0;
    if (rule == NULL || strlen(rule) == 0) {
        /* fill in the rule first */
        bzero(&ipfw_rule, sizeof(struct ip_fw));
        ipfw_rule.version = IP_FW_CURRENT_API_VERSION;
        ipfw_rule.fw_number = DEFAULT_IPFW_RULE_ID;
        ipfw_rule.fw_dst.s_addr = 0u;
        ipfw_rule.fw_dmsk.s_addr = 0u;
        ipfw_rule.fw_flg = IP_FW_F_DIVERT | IP_FW_F_IN | IP_FW_F_OUT;
        ipfw_rule.fw_un.fu_divert_port = port;
        ipfw_rule.fw_nports = 0;
    } else {
        if (ipfw_compile_rule(&ipfw_rule, port, rule, errmsg) != 0) {
            return -1;
        };
    }

    /* open a socket */
    if ((ipfw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        sprintf(errmsg, "Could not create a raw socket: %s", strerror(errno));
        return -1;
    }

    /* write a rule into it */
    if (setsockopt(ipfw_fd, IPPROTO_IP, IP_FW_ADD,
                   &ipfw_rule, sizeof(ipfw_rule)) != 0) {
        sprintf(errmsg, "Could not set rule: %s", strerror(errno));
        return -1;
    }

    /* then close socket */
    close(ipfw_fd);
    return 0;
}

int ipfw_delete(int rule_id, char *errmsg) {
    errmsg[0] = 0;
    int ipfw_fd;

    /* open a socket */
    if ((ipfw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        sprintf(errmsg, "Could not create a raw socket: %s", strerror(errno));
        return -1;
    }

    /* create a rule contains rule id to delete */
    struct ip_fw del_rule;
    memset(&del_rule, 0, sizeof(struct ip_fw));
    del_rule.version = IP_FW_CURRENT_API_VERSION;
    del_rule.fw_number = (u_short)rule_id;

    /* clean the rule */
    if (setsockopt(ipfw_fd, IPPROTO_IP, IP_FW_DEL,
                   &del_rule, sizeof(del_rule)) != 0) {
        sprintf(errmsg, "Could not remove rule: %s\n", strerror(errno));
        return -1;
    }

    /* close socket */
    close(ipfw_fd);
    return 0;
}

int ipfw_flush(char *errmsg) {
    errmsg[0] = 0;
    int ipfw_fd;
    if ((ipfw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        sprintf(errmsg, "Could not create a raw socket: %s", strerror(errno));
        return -1;
    }
    struct ip_fw del_rule;
    memset(&del_rule, 0, sizeof(struct ip_fw));
    del_rule.version = IP_FW_CURRENT_API_VERSION;
    if (setsockopt(ipfw_fd, IPPROTO_IP, IP_FW_FLUSH,
                   &del_rule, sizeof(del_rule)) != 0) {
        sprintf(errmsg, "Could not remove rule: %s\n", strerror(errno));
        return -1;
    }
    close(ipfw_fd);
    return 0;
}
