#include "common.h"
#include "hive.h"

#include <stdio.h>
#include <glib.h>
#include <inttypes.h>
#include <arpa/inet.h>

#define ERR(...) { \
    fprintf(stderr, "hive: "); \
    fprintf(stderr, __VA_ARGS__); \
}

static GHashTable *hive_outgoing, *hive_incoming;
static in_addr_t ip_address_numeric;

void init_hive() {
//    hive_outgoing = g_hash_table_new(NULL, NULL);
    hive_incoming = g_hash_table_new(NULL, NULL);
    ip_address_numeric = inet_addr(IP_ADDRESS);
}

void shutdown_hive() {
    g_hash_table_unref(hive_incoming);
//    g_hash_table_unref(hive_outgoing);
}

// offset of source and destination address in Ethernet
#define ETHEROFF 12

#define LMASK(P, M, S) ((*((uint32_t*) (P)) & (M)) >> (S))
#define MASK(P, M, S) ntohs((*((uint16_t*) (P)) & (M)) >> (S))
#define CMASK(P, M, S) ((*((uint8_t*) (P)) & (M)) >> (S))
#define OFFSET(P, N) (((uint8_t*) (P)) + (N))

struct ip_meta {
    int ipm_hlen;
    int ipm_protocol;
    uint32_t ipm_sender;
    uint32_t ipm_receiver;
};

static struct ip_meta get_ip_metadata(void *packet) {
    struct ip_meta result;
    uint8_t *curptr = OFFSET(packet, ETHEROFF);
    // getting protocol type at byte 12
    // return if payload is not IP
    if (MASK(curptr, 0xFFFF, 0) != 0x0800) {
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
    result.ipm_sender = LMASK(curptr, 0xFFFFFFFF, 0);
    curptr += 4;
    result.ipm_receiver = LMASK(curptr, 0xFFFFFFFF, 0);
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

#define TABLE_TCP 0
#define TABLE_UDP 1

static int lookup_dest_bus(short dest_port, int table_idx) {
    int pass;
    gpointer key, value;
    int i_lookup = dest_port & 0xFFFF;
    gpointer lookup = GINT_TO_POINTER(i_lookup);
    if (!g_hash_table_lookup_extended(
                hive_incoming, lookup, &key, &value)) {
        // do not know target bus yet, wait for outgoing
        pass = FRAME_TO_ALL;
    } else {
        pass = GPOINTER_TO_INT(value);
    }

    return pass;
}

static bool connection_ok(int srcbus_id, short source_port) {
    gpointer key, value;
    int i_lookup = source_port & 0xFFFF;
    gpointer lookup = GINT_TO_POINTER(i_lookup);
    if (!g_hash_table_lookup_extended(
            hive_incoming, lookup, &key, &value)) {
        // register connection
        g_hash_table_insert(
            hive_incoming, lookup, GINT_TO_POINTER(srcbus_id));
    } else if (srcbus_id != GPOINTER_TO_INT(value)) {
        // connection not registered
        return false;
    }
    return true;
}

static int pass_for_port_local(int srcbus_id,
        short source_port, short dest_port,
        bool outgoing, bool is_tcp) {
    int pass = DROP_FRAME;
    gpointer key, value, lookup;

    //FIXME insert hive_desc
    if (!is_tcp) {
        //FIXME create UDP remote connection cache
        //as part of GHashTable array (indexes above)
        //(less overhead than total connection cache,
        //should cover most use cases)
        pass = lookup_dest_bus(dest_port, TABLE_UDP);
    } else if (!outgoing || connection_ok(srcbus_id, source_port)) {
        // FIXME is TABLE_TCP correct?
        pass = lookup_dest_bus(dest_port, TABLE_TCP);
    }
    return pass;
}

static int pass_for_port_remote(int srcbus_id,
        short source_port,
        bool outgoing, bool is_tcp) {
    int pass = DROP_FRAME;
    gpointer key, value;
    /* This function only handles outgoing packets
     * because we are not supposed to process packets
     * that belong to other hosts.
     *
     * If they are outgoing, we need to make sure that they are
     * either UDP packets, which are not connection-based,
     * or that their connection data is valid, i.e. the packet
     * starts a new connection or continues an old one.
     */
    if (outgoing) {
        if (!is_tcp) {
            //FIXME table for UDP different from table for TCP
            //TODO register remote UDP connections only
            //in UDP cache: (srcbus_id, source_port)
            // register connection if necessary
            connection_ok(srcbus_id, source_port);
            pass = FRAME_TO_TAP;
        } else if (connection_ok(srcbus_id, source_port)) {
            pass = FRAME_TO_TAP;
        }
    }
    return pass;
}

int pass_for_frame(void *frame, int srcbus_id, bool outgoing) {
    struct ip_meta pktipm = get_ip_metadata(frame);
    // TODO until non-IP frames can be properly handled, we
    // need to pass them on; then we should revert to DROP_FRAME default
    int pass = FRAME_TO_ALL;
    //TODO handle non-IP frames (esp. ARP!)
    if (pktipm.ipm_hlen > 0) {
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
                if (CMASK(&pktipm.ipm_receiver, 0xFF, 0) == 127 ||
                    ((in_addr_t)pktipm.ipm_receiver) == ip_address_numeric) {
                    // TODO add broadcast/multicast/... addresses
                    pass = pass_for_port_local(
                            srcbus_id,
                            pktcd.cd_source_port,
                            pktcd.cd_dest_port,
                            outgoing, is_tcp);
                } else {
                    pass = pass_for_port_remote(
                            srcbus_id,
                            pktcd.cd_source_port,
                            outgoing, is_tcp);
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
    // FIXME delete UDP cache entries too
    g_hash_table_foreach_remove(
            hive_incoming, rm_watch, GINT_TO_POINTER(watchfd));
}
