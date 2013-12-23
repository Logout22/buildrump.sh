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
    hive_outgoing = g_hash_table_new(NULL, NULL);
    hive_incoming = g_hash_table_new(NULL, NULL);
    ip_address_numeric = inet_addr(IP_ADDRESS);
}

void shutdown_hive() {
    g_hash_table_unref(hive_incoming);
    g_hash_table_unref(hive_outgoing);
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

struct ip_meta get_ip_metadata(void *packet) {
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

struct conn_desc get_conn_metadata(void *packet, bool is_tcp) {
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

int pass_for_port(int srcbus_id,
        short source_port, short dest_port,
        bool outgoing, bool is_tcp) {
    gpointer in_key, out_key, orig_key, value;
    GHashTable *in_table, *out_table;
    ERR("outgoing: %s\n", (outgoing ? "true" : "false"));
    if (outgoing) {
        in_table = hive_incoming;
        out_table = hive_outgoing;
        in_key = GINT_TO_POINTER(((glong) dest_port) & 0xFFFF);
        out_key = GINT_TO_POINTER(((glong) source_port) & 0xFFFF);
    } else {
        in_table = hive_outgoing;
        out_table = hive_incoming;
        in_key = GINT_TO_POINTER(((glong) source_port) & 0xFFFF);
        out_key = GINT_TO_POINTER(((glong) dest_port) & 0xFFFF);
    }
#if 0
    if (!g_hash_table_lookup_extended(out_table, out_key,
                &orig_key, &value)) {
        // this connection is unknown -- allocate it
        g_hash_table_insert(
                out_table, out_key, GINT_TO_POINTER(srcbus_id));
        ERR("Inserted bus %d for %d\n",
                srcbus_id, GPOINTER_TO_INT(out_key));
    } else {
        if (srcbus_id != GPOINTER_TO_INT(value)) {
            ERR("Denied bus %d on %d\n",
                    srcbus_id, GPOINTER_TO_INT(out_key));
            // this bus is not allowed to send this frame, so drop it
            // TODO: a separate socket should send an immediate feedback
            // to a failing network client
            return DROP_FRAME;
        }
    }
#endif

    // check if we need to feed it back to one of the
    // busses, otherwise send it out
    if(g_hash_table_lookup_extended(
                in_table, in_key, &orig_key, &value)) {
        int targetbus_id = GPOINTER_TO_INT(value);
        if (targetbus_id == srcbus_id) {
            ERR("Dropped recursive frame from port %d\n",
                    GPOINTER_TO_INT(in_key));
            // avoids recursion due to packets written by Swarm
            // generating inotify wakeup calls
            return DROP_FRAME;
        } else {
            ERR("Packet to bus %d from port %d\n",
                    GPOINTER_TO_INT(value), GPOINTER_TO_INT(in_key));
            return GPOINTER_TO_INT(value);
        }
    } else {
        ERR("Broadcasting from port %d\n", GPOINTER_TO_INT(in_key));
        return PACKET_TO_ALL;
    }
}

int pass_for_frame(void *frame, int srcbus_id, bool outgoing) {
    struct ip_meta pktipm = get_ip_metadata(frame);
    // TODO until non-IP frames can be properly handled, we
    // need to pass them on; then we should revert to DROP_FRAME default
    int pass = PACKET_TO_ALL;
    //TODO handle non-IP frames (esp. ARP!)
    if (pktipm.ipm_hlen > 0) {
        // TODO missing IPv6 support
        if (CMASK(&pktipm.ipm_receiver, 0xFF, 0) == 127 ||
                ((in_addr_t)pktipm.ipm_receiver) == ip_address_numeric) {
            // TODO add broadcast/multicast/... addresses
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
                    pass = pass_for_port(
                            srcbus_id,
                            pktcd.cd_source_port,
                            pktcd.cd_dest_port,
                            outgoing, is_tcp);
            }
        } else {
            pass = PACKET_TO_ALL;
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
            hive_outgoing, rm_watch, GINT_TO_POINTER(watchfd));
    g_hash_table_foreach_remove(
            hive_incoming, rm_watch, GINT_TO_POINTER(watchfd));
}
