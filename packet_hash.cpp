#include <unordered_map>
#include <vector>
#include <bitset>
#include <cstdlib>
#include "packet_hash.h"


using std::swap;
using std::pair;
using std::bitset;
using std::vector;
using std::unordered_map;

const int bit_size = 2 * (sizeof(in_addr_t) + sizeof(u_short));
typedef bitset <bit_size> packet_tag_bits;


class packet_tag_t {
public:
    in_addr_t ip_src, ip_dst;
    u_short port_src, port_dst;
    unsigned short chksum;

    packet_tag_t(in_addr_t _ip_src,
                 in_addr_t _ip_dst,
                 u_short _port_src,
                 u_short _port_dst,
                 unsigned short _chksum)
            : ip_src(_ip_src),
              ip_dst(_ip_dst),
              port_src(_port_src),
              port_dst(_port_dst),
              chksum(_chksum) { };

    bool operator==(const packet_tag_t &other) const {
        return other.ip_src == ip_src &&
               other.ip_dst == ip_dst &&
               other.port_src == port_src &&
               other.port_dst == port_dst &&
               other.chksum == chksum;
    }
};

class packet_tag_hash {
public:
    size_t operator()(const packet_tag_t &x) const {
        // fill the bit vector
        packet_tag_bits bitvec;
        size_t p = 0, i;
        for (i = 0; i < sizeof(in_addr_t); i++, p++) {
            if ((x.ip_src >> i) & 1) {
                bitvec.set(p);
            }
        }
        for (i = 0; i < sizeof(in_addr_t); i++, p++) {
            if ((x.ip_dst >> i) & 1) {
                bitvec.set(p);
            }
        }
        for (i = 0; i < sizeof(u_short); i++, p++) {
            if ((x.port_src >> i) & 1) {
                bitvec.set(p);
            }
        }
        for (i = 0; i < sizeof(u_short); i++, p++) {
            if ((x.port_dst >> i) & 1) {
                bitvec.set(p);
            }
        }
        if (p != bit_size) {
            exit(EXIT_FAILURE);
        }
        return std::hash<packet_tag_bits>()(bitvec);
    }

};

typedef unordered_map<packet_tag_t,
        struct pktap_header,
        packet_tag_hash> __packet_map_t;

struct packet_map_t {
    __packet_map_t *packet_map;
    pthread_mutex_t *mutex;
};

packet_map_t *packet_map_create() {
    packet_map_t *new_map = new packet_map_t;
    new_map->packet_map = new __packet_map_t;
    new_map->mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(new_map->mutex, NULL);
    return new_map;
}

void
packet_map_insert(packet_map_t *mp,
                  in_addr_t _ip_src,
                  in_addr_t _ip_dst,
                  u_short _port_src,
                  u_short _port_dst,
                  unsigned short _chksum,
                  struct pktap_header *ptr) {
    pthread_mutex_lock(mp->mutex);
    (*mp->packet_map)[packet_tag_t(_ip_src, _ip_dst, _port_src, _port_dst, _chksum)] = *ptr;
    pthread_mutex_unlock(mp->mutex);
}

struct pktap_header *
packet_map_query(packet_map_t *mp,
                 in_addr_t _ip_src,
                 in_addr_t _ip_dst,
                 u_short _port_src,
                 u_short _port_dst,
                 unsigned short _chksum) {
    pthread_mutex_lock(mp->mutex);
    __packet_map_t::iterator iter;
    struct pktap_header *result = NULL;
    if ((iter = mp->packet_map->find(
            packet_tag_t(_ip_src, _ip_dst, _port_src, _port_dst, _chksum)))
        != mp->packet_map->end()) {
        result = &iter->second;
    }
    pthread_mutex_unlock(mp->mutex);
    return result;
}

size_t packet_map_get_size(packet_map_t *mp) {
    return mp->packet_map->size();
}

void *packet_map_clean_thread(void *data) {
    delete (__packet_map_t *)data;
    return NULL;
}

void packet_map_clean(packet_map_t *mp) {
    auto packet_map = new __packet_map_t;
    pthread_mutex_lock(mp->mutex);
    swap(mp->packet_map, packet_map);
    pthread_mutex_unlock(mp->mutex);
    pthread_t clean_thread;
    pthread_create(&clean_thread, NULL, packet_map_clean_thread, packet_map);
    pthread_detach(clean_thread);
}

void packet_map_free(packet_map_t *mp) {
    delete mp->packet_map;
    delete mp->mutex;
    mp->packet_map = NULL;
    mp->mutex = NULL;
}
