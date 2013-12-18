#include "common.h"
#include "hive.h"

#include <glib.h>
#include <inttypes.h>
#include <arpa/inet.h>

static GHashTable *hive_outgoing, *hive_incoming;

void init_hive() {
    hive_outgoing = g_hash_table_new(NULL, NULL);
    hive_incoming = g_hash_table_new(NULL, NULL);
}

// offset of source and destination address in Ethernet
#define ETHEROFF 12

#define MASK(P, M, S) ntohs((*((int16_t*) (P)) & (M)) >> (S))
#define CMASK(P, M, S) ((*((int8_t*) (P)) & (M)) >> (S))
#define OFFSET(P, N) (((int8_t*) (P)) + (N))

struct ip_meta {
    int ipm_hlen;
    int ipm_protocol;
};

struct ip_meta get_ip_metadata(void *packet) {
    struct ip_meta result;
    int8_t *curptr = OFFSET(packet, ETHEROFF);
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
    return result;
}

struct conn_desc {
    short cd_source_port;
    short cd_dest_port;
    short cd_flags;
};

struct conn_desc get_conn_metadata(void *packet, bool is_tcp) {
    // get the TCP/UDP ports to identify the connection
    // this frame belongs to
    struct conn_desc res;
    int8_t *curptr = (int8_t*) packet;
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
        bool outgoing) {
    gpointer in_key, out_key, orig_key, value;
    GHashTable *in_table, *out_table;
    if (outgoing) {
        in_table = hive_incoming;
        out_table = hive_outgoing;
        in_key = GINT_TO_POINTER(dest_port);
        out_key = GINT_TO_POINTER(source_port);
    } else {
        in_table = hive_outgoing;
        out_table = hive_incoming;
        in_key = GINT_TO_POINTER(source_port);
        out_key = GINT_TO_POINTER(dest_port);
    }
    if (!g_hash_table_lookup_extended(out_table, out_key,
            &orig_key, &value)) {
        // this connection is unknown -- allocate it
        g_hash_table_insert(out_table, out_key, GINT_TO_POINTER(srcbus_id));
    } else {
        if (srcbus_id != GPOINTER_TO_INT(value)) {
            // this bus is not allowed to send this frame, so drop it
            // TODO: a separate socket should send an immediate feedback
            // to a failing network client
            return DROP_FRAME;
        }
    }

    // check if we need to feed it back to one of the
    // busses, otherwise send it out
    if(g_hash_table_lookup_extended(
                in_table, in_key, &orig_key, &value)) {
        int targetbus_id = GPOINTER_TO_INT(value);
        if (targetbus_id == srcbus_id) {
            // avoids recursion due to packets written by Swarm
            // generating inotify wakeup calls
            return DROP_FRAME;
        } else {
            return GPOINTER_TO_INT(value);
        }
    } else {
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
        bool is_tcp = false;
        int8_t *tcp_frame = NULL;
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
                        outgoing);
        }
    }
    return pass;
}
