#include "divert.h"
#include "divert_ipfw.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// TODO: 进一步调整这里的防火墙规则
// 研究一下是不是把icmp加进去
// 能配置需要处理的包自然是最好了
int ipfw_setup(divert_t *handle, char *errmsg) {
    /* clear error message */
    errmsg[0] = 0;
    /* fill in the rule first */
    bzero(&handle->ipfw_rule, sizeof(struct ip_fw));
    handle->ipfw_rule.version = IP_FW_CURRENT_API_VERSION;
    handle->ipfw_rule.fw_number = 1;
    handle->ipfw_rule.fw_dst.s_addr = 0u;
    handle->ipfw_rule.fw_dmsk.s_addr = 0u;
    handle->ipfw_rule.fw_flg = IP_FW_F_DIVERT | IP_FW_F_IN | IP_FW_F_OUT;
    handle->ipfw_rule.fw_un.fu_divert_port = htons(handle->divert_port.sin_port);
    handle->ipfw_rule.fw_nports = 0;

    /* open a socket */
    if ((handle->ipfw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        sprintf(errmsg, "Could not create a raw socket: %s", strerror(errno));
        return -1;
    }

    /* write a rule into it */
    if (setsockopt(handle->ipfw_fd, IPPROTO_IP, IP_FW_ADD,
                   &handle->ipfw_rule, sizeof(handle->ipfw_rule)) != 0) {
        sprintf(errmsg, "Could not set rule: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int ipfw_delete(divert_t *handle, char *errmsg) {
    // IP_FW_FLUSH or IP_FW_DEL
    if (setsockopt(handle->ipfw_fd, IPPROTO_IP, IP_FW_FLUSH,
                   &handle->ipfw_rule, sizeof(handle->ipfw_rule)) != 0) {
        sprintf(errmsg, "Could not remove rule: %s\n", strerror(errno));
        return -1;
    }
    close(handle->ipfw_fd);
    return 0;
}
