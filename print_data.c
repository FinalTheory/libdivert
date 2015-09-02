//
// Created by baidu on 15/8/30.
//

#include "print_data.h"
#include <ctype.h>

/*
 * app name/banner
 */
void print_app_banner(FILE * fp) {

    fprintf(fp, "%s - %s\n", LIB_NAME, APP_DESC);
    fprintf(fp, "%s\n", APP_COPYRIGHT);
    fprintf(fp, "%s\n", APP_DISCLAIMER);
    fprintf(fp, "\n");

    return;
}

/*
 * print help text
 */
void print_app_usage(FILE * fp) {
    
    fprintf(fp, "Usage: %s [port_number]\n", APP_NAME);
    fprintf(fp, "\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "\tport number\tListen on <port_number> for diverted packets.\n");
    fprintf(fp, "\n");
    
    return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 * like this:
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(FILE * fp, const u_char *payload, int len, int offset) {

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    fprintf(fp, "%05d   ", offset);

    /* hex */
    ch = payload;
    for (i = 0; i < len; i++) {
        fprintf(fp, "%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7) {
            fprintf(fp, " ");
        }
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8) {
        fprintf(fp, " ");
    }

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            fprintf(fp, "   ");
        }
    }
    fprintf(fp, "   ");

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch)) {
            fprintf(fp, "%c", *ch);
        } else {
            fprintf(fp, ".");
        }
        ch++;
    }

    fprintf(fp, "\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(FILE * fp, const u_char *payload, int len) {

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                    /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0) {
        return;
    }

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(fp, ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (; ;) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(fp, ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(fp, ch, len_rem, offset);
            break;
        }
    }

    return;
}

