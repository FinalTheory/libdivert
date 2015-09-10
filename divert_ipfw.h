#ifndef DIVERT_DIVERT_IPFW_H
#define DIVERT_DIVERT_IPFW_H


int ipfw_setup(char *rule, u_short port, char *errmsg);

int ipfw_delete(int rule_id, char *errmsg);

int ipfw_flush(char *errmsg);

#endif //DIVERT_DIVERT_IPFW_H
