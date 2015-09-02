//
// Created by baidu on 15/8/30.
//

#ifndef DIVERT_PRINT_DATA_H
#define DIVERT_PRINT_DATA_H

#include <sys/types.h>
#include <stdio.h>

#define APP_NAME        "divert_demo"
#define LIB_NAME        "libdivert"
#define APP_DESC        "Divert packets with process information"
#define APP_COPYRIGHT   "Copyright (c) 2015 Baidu Inc."
#define APP_DISCLAIMER  "USE THIS LIBRARY AT YOUR OWN RISK!"

void print_payload(FILE *fp, const u_char *payload, int len);

void print_hex_ascii_line(FILE *fp, const u_char *payload, int len, int offset);

void print_app_banner(FILE *fp);

void print_app_usage(FILE *fp);

#endif //DIVERT_PRINT_DATA_H
