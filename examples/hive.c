#include "hive.h"
#include "swarm.h"
#include "swarm_server_ipc.h"

#include <stdio.h>
#include <glib.h>
#include <inttypes.h>
#include <assert.h>

#if 0
#define ERR(...) { \
    fprintf(stderr, "hive: "); \
    fprintf(stderr, __VA_ARGS__); \
}
#else
#define ERR(...) (void)NULL;
#endif

static GHashTable *hive_table[2];
static in_addr_t ip_address;
uint8_t mac_address[MAC_LEN];

void init_hive(in_addr_t cur_ip_address, uint8_t *cur_mac_address) {
    hive_table[PROTOCOL_TCP] = g_hash_table_new(NULL, NULL);
    hive_table[PROTOCOL_UDP] = g_hash_table_new(NULL, NULL);
    CPYIP(&ip_address, &cur_ip_address);
    CPYMAC(mac_address, cur_mac_address);
}

void shutdown_hive() {
    g_hash_table_unref(hive_table[PROTOCOL_UDP]);
    g_hash_table_unref(hive_table[PROTOCOL_TCP]);
}

#define ETH_HLEN 14
#define IP_HLEN 20
#define UDP_HLEN 8
#define TCP_HLEN 20
#define ARP_LEN 28
// offset of source and destination address in Ethernet
#define ETHEROFF 12

// use memcpy/memcmp for everything above 2 bytes, if possible
//#define LMASK(P, M, S) ntohl((*((uint32_t*) (P)) & (M)) >> (S))
#define MASK(P, M, S) ntohs((*((uint16_t*) (P)) & (M)) >> (S))
#define CMASK(P, M, S) ((*((uint8_t*) (P)) & (M)) >> (S))
#define OFFSET(P, N) (((uint8_t*) (P)) + (N))

#if 0
static void send_arp_reply(void *packet,
        uint8_t *srcmac, uint8_t *srcip) {
    // TODO add IPv6 support
    // turn packet into opposite direction
    CPYMAC(packet, srcmac);
    CPYMAC(OFFSET(packet, MAC_LEN), mac_address);
    uint8_t *curptr = OFFSET(packet, 20);
    // set operation to reply
    uint16_t op = htons(2);
    memcpy(curptr, &op, 2);
    // write source and destination
    curptr += 2;
    CPYMAC(curptr, mac_address);
    curptr += MAC_LEN;
    CPYIP(curptr, &ip_address);
    curptr += IP_LEN;
    CPYMAC(curptr, srcmac);
    curptr += MAC_LEN;
    CPYIP(curptr, srcip);
}

static int handle_arp(uint8_t *packet,
        uint8_t *curptr, uint32_t curlen, bool outgoing) {
    // TODO add IPv6 support
    if (curlen < ARP_LEN) {
        return DROP_FRAME;
    }
    if (MASK(curptr, 0xFFFF, 0) == 1 /*Ethernet*/ &&
            MASK(OFFSET(curptr, 2), 0xFFFF, 0) == 0x0800) {
        curptr += 4;
        if (CMASK(curptr, 0xFF, 0) != MAC_LEN ||
                CMASK(OFFSET(curptr, 1), 0xFF, 0) != IP_LEN) {
            return DROP_FRAME;
        }
        curptr += 2;
        // choose operation
        int op = MASK(curptr, 0xFFFF, 0);
        curptr += 2;
        uint8_t arp_target_mac[MAC_LEN], arp_source_mac[MAC_LEN],
                arp_target_ip[IP_LEN], arp_source_ip[IP_LEN];
        CPYMAC(arp_source_mac, curptr);
        curptr += MAC_LEN;
        CPYIP(arp_source_ip, curptr);
        curptr += IP_LEN;
        CPYMAC(arp_target_mac, curptr);
        curptr += MAC_LEN;
        CPYIP(arp_target_ip, curptr);
        if (op == 1) {
            //handle ARP request
            if (EQIP(arp_target_ip, &ip_address) && !outgoing) {
                send_arp_reply(packet, arp_source_mac, arp_source_ip);
                return FRAME_TO_TAP;
            } else if (outgoing) {
                return FRAME_TO_TAP;
            }
        } else if (op == 2) {
            //handle ARP reply
            if (outgoing) {
                return FRAME_TO_TAP;
            } else {
                return FRAME_TO_ALL;
            }
        }
    }
    return DROP_FRAME;
}
#endif

struct ip_meta {
    int ipm_hlen;
    int ipm_protocol;
    in_addr_t ipm_sender;
    in_addr_t ipm_receiver;
};

static struct ip_meta get_ip_metadata(uint8_t const *curptr, uint32_t pktlen) {
    struct ip_meta result = {0};
    if (pktlen < IP_HLEN) {
        result.ipm_hlen = -2;
        return result;
    }
    //TODO missing IPv6 support:
    if (CMASK(curptr, 0xF0, 4) != 4) {
        result.ipm_hlen = -3;
        return result;
    }
    // retrieve IP header size (bit 4..7)
    int ip_header_size = CMASK(curptr, 0x0F, 0);
    // this value is the word count, each word being 32 bits (4 bytes)
    ip_header_size *= 4;
    result.ipm_hlen = ip_header_size;

    // skip to protocol field
    curptr += 9;
    result.ipm_protocol = CMASK(curptr, 0xFF, 0);

    // skip to addresses
    curptr += 3;
    CPYIP(&result.ipm_sender, curptr);
    curptr += 4;
    CPYIP(&result.ipm_receiver, curptr);
    return result;
}

struct conn_desc {
    uint16_t cd_source_port;
    uint16_t cd_dest_port;
    uint16_t cd_flags;
};

static struct conn_desc get_conn_metadata(
        uint8_t const *curptr, uint32_t pktlen, bool is_tcp) {
    // get the TCP/UDP ports to identify the connection
    // this frame belongs to
    struct conn_desc res = {0};
    if (pktlen < UDP_HLEN || (is_tcp && pktlen < TCP_HLEN)) {
        return res;
    }
    res.cd_source_port = MASK(curptr, 0xFFFF, 0);
    curptr += 2;
    res.cd_dest_port = MASK(curptr, 0xFFFF, 0);
    if (is_tcp) {
        // skip seq/ack number
        curptr += 10;
        res.cd_flags = MASK(curptr, 0x0FFF, 0);
    }
    return res;
}

static int lookup_dest_bus(uint16_t dest_port, int table_idx) {
    int pass;
    int i_lookup = dest_port & 0xFFFF;
    gpointer value = NULL, lookup = GINT_TO_POINTER(i_lookup);
    if (g_hash_table_lookup_extended(
                hive_table[table_idx], lookup, NULL, &value)) {
        pass = GPOINTER_TO_INT(value);
    } else {
        // connection unknown, drop the frame
        pass = DROP_FRAME;
    }

    ERR("%u goes to %d\n", dest_port, pass);
    return pass;
}

void register_connection(struct bufferevent *bev, int bus_id,
        uint32_t protocol, uint32_t resource) {
    int32_t result = -1;
    gpointer key = GINT_TO_POINTER(resource),
        value = GINT_TO_POINTER(bus_id);
    if (protocol < 2 &&
            resource <= UINT16_MAX &&
            !g_hash_table_lookup_extended(
                hive_table[protocol], key, NULL, NULL)) {
        // so there is no entry for that resource, create one
        g_hash_table_insert(hive_table[protocol], key, value);
        result = 0;
    }
    ERR("registered %u/%u for %d\n", protocol, resource, bus_id);
    reply_hive_bind(bev, result);
}

void remove_connection(int bus_id, uint32_t protocol, uint32_t resource) {
    gpointer key = GINT_TO_POINTER(resource),
        value = GINT_TO_POINTER(bus_id);
    if (protocol < 2 &&
            resource <= UINT16_MAX &&
            g_hash_table_lookup(hive_table[protocol], key) == value) {
        // ok, client is allowed to remove this connection -- proceed
        g_hash_table_remove(hive_table[protocol], key);
    }
    ERR("removed %u/%u for %d\n", protocol, resource, bus_id);
}

int pass_for_frame(void const *frame, uint32_t framelen, bool outgoing) {
    int pass = DROP_FRAME;
    if (framelen < ETH_HLEN) {
        return pass;
    }

    // getting protocol type at byte 12
    struct ip_meta pktipm;
    uint16_t frametype = MASK(OFFSET(frame, ETHEROFF), 0xFFFF, 0);
    uint8_t *curptr = OFFSET(frame, ETH_HLEN);
    framelen -= ETH_HLEN;
    //TODO handle more types of non-IP frames
    switch (frametype) {
        case 0x0800:
            // regular IP, see below
            pktipm = get_ip_metadata(curptr, framelen);
            break;
        case 0x0806:
            // ARP
            //pass = handle_arp(frame, curptr, framelen, outgoing);
            if (outgoing) {
                pass = FRAME_TO_TAP;
            } else {
                pass = FRAME_TO_ALL;
            }
        default:
            return pass;
    }

    // handle IP
    if (pktipm.ipm_hlen > 0) {
        bool is_tcp = false;
        curptr += pktipm.ipm_hlen;
        framelen -= pktipm.ipm_hlen;
        switch (pktipm.ipm_protocol) {
            case 6:
                is_tcp = true;
                // fall through:
            case 17:
                {
                    struct conn_desc pktcd = get_conn_metadata(
                            curptr, framelen, is_tcp);
                    /* multicast: */
                    if (CMASK(&pktipm.ipm_receiver, 0xF0, 0) == 0xE0) {
                        if (outgoing) {
                            pass = FRAME_TO_ALL_AND_TAP;
                        } else {
                            pass = FRAME_TO_ALL;
                        }
                    }
                    /* own IP address: */
                    if (EQIP(&pktipm.ipm_receiver, &ip_address)) {
                        /* so the receiver is local */

                        /* make sure packets are not re-sent: */
                        if (!outgoing ||
                                EQIP(&pktipm.ipm_sender, &ip_address)) {
                            pass = lookup_dest_bus(
                                    pktcd.cd_dest_port,
                                    is_tcp ? PROTOCOL_TCP : PROTOCOL_UDP);
                        }
                    } else {
                        /* for remote receivers */
                        if (outgoing &&
                                EQIP(&pktipm.ipm_sender, &ip_address)) {
                            // this is not for our realm -- send it out
                            pass = FRAME_TO_TAP;
                        }
                    }
                }
        }
    }
    return pass;
}

gboolean rm_watch(gpointer key, gpointer value, gpointer watch) {
    (void) key;

    if (value == watch) {
        return true;
    } else {
        return false;
    }
}

void remove_ports_for_watch(int watchfd) {
    g_hash_table_foreach_remove(
            hive_table[PROTOCOL_TCP], rm_watch, GINT_TO_POINTER(watchfd));
    g_hash_table_foreach_remove(
            hive_table[PROTOCOL_UDP], rm_watch, GINT_TO_POINTER(watchfd));
}

