//
// Created by baidu on 15/9/1.
//

#ifndef DIVERT_DIVERT_IPFW_H
#define DIVERT_DIVERT_IPFW_H

#include "divert.h"

int ipfw_setup(divert_t *handle, char *errmsg);
int ipfw_delete(divert_t *handle, char *errmsg);

#endif //DIVERT_DIVERT_IPFW_H
