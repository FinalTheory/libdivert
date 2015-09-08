
#ifndef PRINT_PACKET_H
#define PRINT_PACKET_H

/*
 * definitions for print flags
 */
#define PRINT_INDEX     (1u)
#define PRINT_NEWLINE   (1u << 1)
#define PRINT_PROC      (1u << 2)
#define PRINT_ADDR      (1u << 3)
#define PRINT_PORT      (1u << 4)
#define PRINT_DATA_LINK (1u << 5)
#define PRINT_PROT      (1u << 6)
#define PRINT_PAYLOAD   (1u << 7)

void divert_print_packet(FILE *fp, u_int32_t flags, packet_hdrs_t *packet_headers);

#endif //DIVERT_PACKET_HANDLER_H
