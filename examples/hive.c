#include "hive.h"
#include "swarm.h"
#include "swarm_ipc.h"

#include <stdio.h>
#include <glib.h>
#include <inttypes.h>
#include <assert.h>

#define ERR(...) { \
    fprintf(stderr, "hive: "); \
    fprintf(stderr, __VA_ARGS__); \
}

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

// offset of source and destination address in Ethernet
#define ETHEROFF 12

// use memcpy/memcmp for everything above 2 bytes, if possible
//#define LMASK(P, M, S) ntohl((*((uint32_t*) (P)) & (M)) >> (S))
#define MASK(P, M, S) ntohs((*((uint16_t*) (P)) & (M)) >> (S))
#define CMASK(P, M, S) ((*((uint8_t*) (P)) & (M)) >> (S))
#define OFFSET(P, N) (((uint8_t*) (P)) + (N))

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

static int handle_arp(void *packet, bool outgoing) {
    // TODO add IPv6 support
    uint8_t *curptr = OFFSET(packet, 14);
    if (MASK(curptr, 0xFFFF, 0) == 1 /*Ethernet*/ &&
            MASK(OFFSET(curptr, 2), 0xFFFF, 0) == 0x0800) {
        curptr += 4;
        assert(CMASK(curptr, 0xFF, 0) == MAC_LEN &&
                CMASK(OFFSET(curptr, 1), 0xFF, 0) == IP_LEN);
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
            if (EQIP(arp_target_ip, &ip_address)) {
                if (!outgoing) {
                    send_arp_reply(packet,
                            arp_source_mac, arp_source_ip);
                    return FRAME_TO_TAP;
                }
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

struct ip_meta {
    int ipm_hlen;
    int ipm_protocol;
    in_addr_t ipm_sender;
    in_addr_t ipm_receiver;
};

static struct ip_meta get_ip_metadata(void *packet) {
    struct ip_meta result;
    uint8_t *curptr = OFFSET(packet, ETHEROFF);
    // getting protocol type at byte 12
    // return if payload is not IP
    uint16_t frametype = MASK(curptr, 0xFFFF, 0);
    switch (frametype) {
        case 0x0800:
            // regular IP, see below
            break;
        case 0x0806:
            // ARP
            result.ipm_hlen = -20;
            return result;
        default:
            result.ipm_hlen = -1;
            return result;
    }
    curptr += 2;
    //TODO missing IPv6 support:
    if (CMASK(curptr, 0xF0, 4) > 4) {
        result.ipm_hlen = -2;
        return result;
    }
    result.ipm_hlen = ETHEROFF + 2;
    // retrieve IP header size (bit 4..7)
    int ip_header_size = CMASK(curptr, 0x0F, 0);
    // this value is the word count, each word being 32 bits (4 bytes)
    ip_header_size *= 4;
    result.ipm_hlen += ip_header_size;

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

static struct conn_desc get_conn_metadata(void *packet, bool is_tcp) {
    // get the TCP/UDP ports to identify the connection
    // this frame belongs to
    struct conn_desc res;
    uint8_t *curptr = (uint8_t*) packet;
    res.cd_source_port = MASK(curptr, 0xFFFF, 0);
    curptr += 2;
    res.cd_dest_port = MASK(curptr, 0xFFFF, 0);
    if (is_tcp) {
        // skip seq/ack number
        curptr += 8;
        res.cd_flags = MASK(curptr, 0x0FFF, 0);
    }
    return res;
}

static int lookup_dest_bus(uint16_t dest_port, int table_idx) {
    int pass;
    gpointer key, value;
    int i_lookup = dest_port & 0xFFFF;
    gpointer lookup = GINT_TO_POINTER(i_lookup);
    if (!g_hash_table_lookup_extended(
                hive_table[table_idx], lookup, &key, &value)) {
        // connection unknown, drop the frame
        pass = DROP_FRAME;
    } else {
        pass = GPOINTER_TO_INT(value);
    }

    return pass;
}

void register_connection(int socket, int bus_id,
        uint32_t protocol, uint32_t resource) {
    int32_t result = -1;
    if (protocol < 2 && resource <= UINT16_MAX &&
            !g_hash_table_lookup_extended(
                hive_table[protocol], GINT_TO_POINTER((int) resource),
                NULL, NULL)) {
        g_hash_table_insert(
                hive_table[protocol], GINT_TO_POINTER((int) resource),
                GINT_TO_POINTER(bus_id));
        result = 0;
    }
    reply_hive_bind(socket, result);
}

static int pass_for_port_local(int srcbus_id,
        uint16_t source_port, uint16_t dest_port,
        bool outgoing, bool is_tcp) {
    int pass = DROP_FRAME;
    // dest==source surely is not valid:
    if (source_port != dest_port) {
        if (!is_tcp) {
            // check if this connection exists in the UDP table
            pass = lookup_dest_bus(dest_port, PROTOCOL_UDP);
        } else {
            // check if this connection exists in the TCP table
            pass = lookup_dest_bus(dest_port, PROTOCOL_TCP);
        }
    }
    return pass;
}

int pass_for_frame(void *frame, int srcbus_id, bool outgoing) {
    struct ip_meta pktipm = get_ip_metadata(frame);
    int pass = DROP_FRAME;
    //TODO handle more non-IP frames
    if (pktipm.ipm_hlen == -20) {
        pass = handle_arp(frame, outgoing);
    } else if (pktipm.ipm_hlen > 0) {
        bool is_tcp = false;
        uint8_t *tcp_frame = NULL;
        switch (pktipm.ipm_protocol) {
            case 6:
                is_tcp = true;
                // fall through:
            case 17:
                tcp_frame = OFFSET(frame, pktipm.ipm_hlen);
                struct conn_desc pktcd = get_conn_metadata(
                        tcp_frame, is_tcp);
                // TODO missing IPv6 support
                if ((CMASK(&pktipm.ipm_receiver, 0xFF, 0) == 127 ||
                    EQIP(&pktipm.ipm_receiver, &ip_address)) &&
                    /* make sure packets are not re-sent: */
                    !(outgoing && !EQIP(&pktipm.ipm_sender, &ip_address))) {
                    // TODO add broadcast/multicast/... addresses
                    //FIXME dirty hack, replace ASAP
                    uint8_t custommac[] = {0xB2, 0xA0, 0x30, 0xC8, 0x82, 0xC2};
                    CPYMAC(frame, custommac);
                    pass = pass_for_port_local(
                            srcbus_id,
                            pktcd.cd_source_port,
                            pktcd.cd_dest_port,
                            outgoing, is_tcp);
                } else {
                    if (outgoing && EQIP(&pktipm.ipm_sender, &ip_address)) {
                        // this is not for our realm -- send it out
                        pass = FRAME_TO_TAP;
                    } else {
                        // otherwise we are not responsible -- drop it
                        pass = DROP_FRAME;
                    }
                }
        }
    }
    return pass;
}

gboolean rm_watch(gpointer key, gpointer value, gpointer watch) {
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

