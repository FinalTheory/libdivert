#include "divert.h"
#include "queue.h"
#include "hash.h"
#include <stdlib.h>
#include <string.h>


struct packet_map_t {
    queue_t **buckets;
    size_t size;
};

typedef struct {
    in_addr_t ip_src, ip_dst;
    u_short port_src, port_dst;
    u_short chksum;
    struct timeval tv;
    struct pktap_header pktap_data;
} __node_data_t;

struct packet_map_t *packet_map_create() {
    struct packet_map_t *result;
    result = malloc(sizeof(struct packet_map_t));
    result->buckets = calloc(HASH_BUCKETS_NUM, sizeof(queue_t *));
    result->size = 0;
    return result;
}

void packet_map_insert(struct packet_map_t *mp,
                       in_addr_t _ip_src,
                       in_addr_t _ip_dst,
                       u_short _port_src,
                       u_short _port_dst,
                       u_short _chksum,
                       struct pktap_header *ptr) {
    int idx = mkhash(_ip_src, _port_src, _ip_dst, _port_dst) % HASH_BUCKETS_NUM;
    queue_t *q = mp->buckets[idx];
    if (q == NULL) {
        mp->buckets[idx] = queue_create();
        q = mp->buckets[idx];
    }
    if (ptr != NULL) {
        struct timezone tz;
        __node_data_t *data = malloc(sizeof(__node_data_t));
        if (gettimeofday(&data->tv, &tz) == 0) {
            data->ip_src = _ip_src;
            data->ip_dst = _ip_dst;
            data->port_src = _port_src;
            data->port_dst = _port_dst;
            data->chksum = _chksum;
            data->pktap_data = *ptr;
            queue_push(q, data);
            mp->size++;
        } else {
            free(data);
        }
    }
}

static int compare_func(void *ptr1, void *ptr2) {
    __node_data_t *data1 = (__node_data_t *)ptr1;
    __node_data_t *data2 = (__node_data_t *)ptr2;
    return (data1->chksum == data2->chksum &&
            data1->ip_src == data2->ip_src &&
            data1->ip_dst == data2->ip_dst &&
            data1->port_src == data2->port_src &&
            data1->port_dst == data2->port_dst);
}

static int should_drop(void *data, void *args) {
    if (args == NULL) {
        return 0;
    }
    return (((struct timeval *)args)->tv_sec -
            ((__node_data_t *)data)->tv.tv_sec > PACKET_TIME_OUT);
}

static void free_packet_data(void *ptr) {
    free(ptr);
}

struct pktap_header *
packet_map_query(struct packet_map_t *mp,
                 in_addr_t _ip_src,
                 in_addr_t _ip_dst,
                 u_short _port_src,
                 u_short _port_dst,
                 u_short _chksum) {
    int idx = mkhash(_ip_src, _port_src, _ip_dst, _port_dst) % HASH_BUCKETS_NUM;
    queue_t *q = mp->buckets[idx];
    if (q != NULL) {
        __node_data_t data;
        data.ip_src = _ip_src;
        data.ip_dst = _ip_dst;
        data.port_src = _port_src;
        data.port_dst = _port_dst;
        data.chksum = _chksum;
        struct timeval tv;
        struct timezone tz;
        queue_node_t *node =
                queue_search_and_drop(q, &data,
                                      gettimeofday(&tv, &tz) == 0 ? &tv : NULL,
                                      compare_func, should_drop, free_packet_data);
        return node == NULL ? NULL : &(((__node_data_t *)node->data)->pktap_data);
    } else {
        return NULL;
    }
}

size_t packet_map_get_size(struct packet_map_t *mp) {
    return mp->size;
}

void packet_map_clean(struct packet_map_t *mp) {
    // this function is not implemented
}

void packet_map_free(struct packet_map_t *mp) {
    if (mp != NULL) {
        free(mp->buckets);
        free(mp);
    }
}
