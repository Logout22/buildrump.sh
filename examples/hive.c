#include "common.h"
#include "hive.h"

#include <glib.h>

static GHashTable *hive_outgoing, *hive_incoming;

void init_hive() {
    hive_conns = g_hash_table_new(NULL, NULL);
}

int pass_for_port(int srcbus_id,
        short source_port, short dest_port,
        bool outgoing) {
    gpointer in_key, out_key, orig_key, value;
    GHashTable *in_table, *out_table;
    if (outgoing) {
        in_table = hive_ingoing;
        out_table = hive_outgoing;
        in_key = GINT_TO_POINTER(dest_port);
        out_key = GINT_TO_POINTER(source_port);
    } else {
        in_table = hive_outgoing;
        out_table = hive_ingoing;
        in_key = GINT_TO_POINTER(source_port);
        out_key = GINT_TO_POINTER(dest_port);
    }
    // NOTE: assuming that a pointer is at least 32 bits:
    if (!g_hash_table_lookup_extended(out_table, out_key,
            &orig_key, &value)) {
        // this connection is unknown -- allocate it
        g_hash_table_insert(out_table, out_key, srcbus_id);
    } else {
        // TODO check if srcbus_id == hash table entry
    }

    // check if we need to feed it back to one of the
    // busses, otherwise send it out
    if(g_hash_table_lookup_extended(
                in_table, in_key, &orig_key, &value)) {
        return value;
    } else {
        return PACKET_TO_TAP;
    }
}
