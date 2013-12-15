#include <sys/types.h>
#include <inttypes.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stropts.h>
#include <poll.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stropts.h>

#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/inotify.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <semaphore.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#if !defined(LIBEVENT_VERSION_NUMBER) || LIBEVENT_VERSION_NUMBER < 0x02000100
#error "This version of Libevent is not supported; Get 2.0.1-alpha or later."
#endif

#include <glib.h>

#include "common.h"
#include "shmifvar.h"

#define ERR(...) { \
    fprintf(stderr, "swarm: "); \
    fprintf(stderr, __VA_ARGS__); \
}

// contains the variables necessary to maintain a read state:
struct shmif_handle {
    uint64_t sc_devgen;
    uint32_t sc_nextpacket;
};

/* NOTE: Do NOT instantiate struct tmpbus directly.
 * Use something like:
 *
 * struct tmpbus *myvar = allocate_bus();
 * ...
 * deallocate_bus(myvar);
 */
struct tmpbus {
    char tmpbus_name[10];
    int tmpbus_hdl;
    struct shmif_mem *tmpbus_header;
    struct shmif_handle *tmpbus_position;
    struct event *tmpbus_event;
    sem_t *tmpbus_lock;
};

int unix_socket = 0, tapfd = 0, inotify_hdl = 0;
struct event *unix_socket_listener_event = NULL,
             *tap_listener_event = NULL,
             *inotify_listener_event = NULL;
GHashTable *busses = NULL;
bool terminate = false;
struct event_base *ev_base;

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{
    if (msg)
        warn("%s: %d", msg, e);
    exit(e);
}

void __attribute__((__noreturn__))
cleanup_sig(int signum) {
    die(signum, NULL);
}

struct tmpbus *allocate_bus() {
    struct tmpbus *result = malloc(sizeof(struct tmpbus));
    assert(result);
    memset(result, 0, sizeof(struct tmpbus));

    // essential field initialisation:
    assert(result->tmpbus_position = malloc(sizeof(struct shmif_handle)));
    memset(result, 0, sizeof(struct shmif_handle));
    strcpy(result->tmpbus_name, "busXXXXXX\0");
    assert(*mktemp(result->tmpbus_name) != 0);

    return result;
}

void deallocate_bus(gpointer dataptr) {
    struct tmpbus *busptr = dataptr;

    if (busptr->tmpbus_event) {
        event_free(busptr->tmpbus_event);
    }
    if (busptr->tmpbus_lock) {
        sem_close(busptr->tmpbus_lock);
    }
    if (busptr->tmpbus_header) {
        munmap(busptr->tmpbus_header, BUSMEM_SIZE);
    }
    if (busptr->tmpbus_hdl) {
        close(busptr->tmpbus_hdl);
        unlink(busptr->tmpbus_name);
    }
    free(busptr->tmpbus_position);
    free(busptr);
}

void cleanup() {
    ERR("Exiting\n");
    g_hash_table_unref(busses);
    if (unix_socket_listener_event) {
        event_free(unix_socket_listener_event);
    }
    if (unix_socket) {
        close(unix_socket);
        unlink(SOCK_FN);
    }
    if (inotify_hdl) {
        close(inotify_hdl);
    }
    if (tapfd) {
        close(tapfd);
    }
    if (ev_base) {
        event_base_free(ev_base);
    }
}

int tun_alloc(char *dev)
{
  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
     return -1;

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if( *dev )
     strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
     close(fd);
     return err;
  }
  strcpy(dev, ifr.ifr_name);
  return fd;
}

int initbus(struct shmif_mem **hdrp, int busfd, pid_t caller_pid) {
    if (ftruncate(busfd, BUSMEM_SIZE) != 0) {
        ERR("ftruncate failed\n");
        return errno;
    }

    struct shmif_mem *hdr = mmap(NULL, BUSMEM_SIZE,
            PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED,
            busfd, 0);
    if (hdr == MAP_FAILED) {
        ERR("map failed\n");
        return errno;
    }

	sem_t *shmif_lockall_sem = sem_open("rumpuser_shmif_lockall",
			O_CREAT, 0644, 1);
	assert(shmif_lockall_sem != SEM_FAILED);
	int result;
	do {
		result = sem_wait(shmif_lockall_sem);
	} while (result == EINTR);
	assert(result == 0);

	if (hdr->shm_magic == 0) {
        hdr->shm_magic = SHMIF_MAGIC;
        hdr->shm_first = BUSMEM_DATASIZE;
        hdr->shm_lock = caller_pid;
    }

	assert(sem_post(shmif_lockall_sem) == 0);
	sem_close(shmif_lockall_sem);

    *hdrp = hdr;
    return 0;
}

static void
dowakeup(int busfd)
{
    uint32_t ver = SHMIF_VERSION;
    pwrite(busfd, &ver, sizeof(ver), IFMEM_WAKEUP);
}

static void
shmif_lockbus(sem_t *to_lock)
{
	int result;

	do {
		result = sem_wait(to_lock);
	} while (result == EINTR);
	assert(result == 0);
}

static void
shmif_unlockbus(sem_t *to_unlock)
{
	assert(sem_post(to_unlock) == 0);
}

static void
writebus(struct tmpbus *thisbus,
        void *packet, uint32_t pktsize)
{
    uint32_t dataoff;
    bool wrote = false;
    bool wrap;
    struct shmif_mem *busmem = thisbus->tmpbus_header;

    struct shmif_pkthdr sp = {};

    assert(pktsize <= ETHERMTU + ETHER_HDR_LEN);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    sp.sp_len = pktsize;
    sp.sp_sec = ts.tv_sec;
    sp.sp_usec = ts.tv_nsec / 1000;

    shmif_lockbus(thisbus->tmpbus_lock);
    assert(busmem->shm_magic == SHMIF_MAGIC);
    busmem->shm_last = shmif_nextpktoff(busmem, busmem->shm_last);

    wrap = false;
    dataoff = shmif_buswrite(busmem,
        busmem->shm_last, &sp, sizeof(sp), &wrap);
    dataoff = shmif_buswrite(busmem, dataoff,
        packet, pktsize, &wrap);
    if (wrap) {
        busmem->shm_gen++;
        ERR("bus generation now %" PRIu64 "\n", busmem->shm_gen);
    }
    shmif_unlockbus(thisbus->tmpbus_lock);

    wrote = true;

    ERR("shmif_start: send %d bytes at off %d\n",
        pktsize, busmem->shm_last);

    /* wakeup? */
    if (wrote) {
        dowakeup(thisbus->tmpbus_hdl);
    }
}

/*
 * Check if we have been sleeping too long.  Basically,
 * our in-sc nextpkt must by first <= nextpkt <= last"+1".
 * We use the fact that first is guaranteed to never overlap
 * with the last frame in the ring.
 */
static __inline bool
stillvalid_p(struct shmif_mem *busmem, struct shmif_handle *sc)
{
    unsigned gendiff = busmem->shm_gen - sc->sc_devgen;
    uint32_t lastoff, devoff;

    assert(busmem->shm_first != busmem->shm_last);

    /* normalize onto a 2x busmem chunk */
    devoff = sc->sc_nextpacket;
    lastoff = shmif_nextpktoff(busmem, busmem->shm_last);

    /* trivial case */
    if (gendiff > 1)
        return false;
    assert(gendiff <= 1);

    /* Normalize onto 2x busmem chunk */
    if (busmem->shm_first >= lastoff) {
        lastoff += BUSMEM_DATASIZE;
        if (gendiff == 0)
            devoff += BUSMEM_DATASIZE;
    } else {
        if (gendiff)
            return false;
    }

    return devoff >= busmem->shm_first && devoff <= lastoff;
}

static void
readbus(struct tmpbus *thisbus,
        void **packet, struct shmif_pkthdr *spp)
{
    uint32_t nextpkt;
    bool wrap;
    struct shmif_mem *busmem = thisbus->tmpbus_header;
    struct shmif_handle *sc = thisbus->tmpbus_position;

    /*ERR("waiting %" PRIu32 "/%" PRIu64 "\n",
        sc->sc_nextpacket, sc->sc_devgen);*/

    shmif_lockbus(thisbus->tmpbus_lock);
    assert(busmem->shm_magic == SHMIF_MAGIC);
    assert(busmem->shm_gen >= sc->sc_devgen);

    /* need more data? */
    if (sc->sc_devgen == busmem->shm_gen &&
        shmif_nextpktoff(busmem, busmem->shm_last)
         == sc->sc_nextpacket) {
        shmif_unlockbus(thisbus->tmpbus_lock);
        // nothing to read
        *packet = NULL;
        memset(spp, 0, sizeof(struct shmif_pkthdr));
        return;
    }

    if (stillvalid_p(busmem, sc)) {
        nextpkt = sc->sc_nextpacket;
    } else {
        assert(busmem->shm_gen > 0);
        nextpkt = busmem->shm_first;
        if (busmem->shm_first > busmem->shm_last)
            sc->sc_devgen = busmem->shm_gen - 1;
        else
            sc->sc_devgen = busmem->shm_gen;
        ERR("dev %p overrun, new data: %d/%" PRIu64 "\n",
            sc, nextpkt, sc->sc_devgen);
    }

    /*
     * If our read pointer is ahead the bus last write, our
     * generation must be one behind.
     */
    assert(!(nextpkt > busmem->shm_last
        && sc->sc_devgen == busmem->shm_gen));

    wrap = false;

    nextpkt = shmif_busread(busmem, spp,
        nextpkt, sizeof(struct shmif_pkthdr), &wrap);
    assert(spp->sp_len <= ETHERMTU + ETHER_HDR_LEN);
    /*
     * We need to allocate memory and use shmif_busread because
     * packets might wrap around, so they must be copied anyway.
     */
    *packet = malloc(spp->sp_len);
    assert(*packet);
    nextpkt = shmif_busread(busmem, *packet,
        nextpkt, spp->sp_len, &wrap);

    ERR("shmif_rcv: read packet of length %d at %d\n",
        spp->sp_len, nextpkt);

    sc->sc_nextpacket = nextpkt;
    shmif_unlockbus(thisbus->tmpbus_lock);

    if (wrap) {
        sc->sc_devgen++;
        DPRINTF(("dev %p generation now %" PRIu64 "\n",
            sc, sc->sc_devgen));
    }
}

/*
void *busreadthread(void *ignore) {
    void *packet;
    struct shmif_pkthdr pkthdr = {};
    while (!terminate) {
        readbus(tmpbus_header, &tmpbus_position,
                &packet, &pkthdr);
        if (packet) {
            write(tapfd, packet, pkthdr.sp_len);
        }
    }
    return NULL;
}
*/

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

void handle_busread(evutil_socket_t eventfd, short events, void *ignore) {
    assert(eventfd == inotify_hdl);
    struct inotify_event iEvent;

    while (read(inotify_hdl, &iEvent, sizeof(iEvent)) > 0) {
        struct tmpbus *thisbus = (struct tmpbus *) g_hash_table_lookup(
                busses, GINT_TO_POINTER(iEvent.wd));
        if (thisbus == NULL) {
            ERR("Notified for wrong watch (FD #%d)!\n", iEvent.wd);
            continue;
        }

        void *packet = NULL;
        do {
            struct shmif_pkthdr pkthdr = {};
            readbus(thisbus, &packet, &pkthdr);
            if (packet) {
                // TODO: filter frames here
                // TODO: check for SYNs
                // or first contact (UDP) to implement bind
                // -> hive.c
                struct ip_meta pktipm = get_ip_metadata(packet);
                int pass = DROP_FRAME;
                //TODO handle non-IP frames (esp. ARP!)
                if (pktipm.ipm_hlen > 0) {
                    bool is_tcp = false;
                    switch (pktipm.ipm_protocol) {
                        case 6:
                            is_tcp = true;
                            // fall through:
                        case 17:
                            int8_t *tcp_frame = packet + pktipm.ipm_hlen;
                            struct conn_desc pktcd = get_conn_metadata(
                                    tcp_frame, is_tcp);
                            pass = pass_for_port(
                                    pktcd.cd_source_port,
                                    pktcd.cd_dest_port);
                            ERR("Source Port: %i\n",
                                    MASK(tcp_frame, 0xFFFF, 0));
                    }
                }
                if (pass == PACKET_TO_TAP) {
                    write(tapfd, packet, pkthdr.sp_len);
                } else {
                    struct tmpbus *destbus = (struct tmpbus*)
                        g_hash_table_lookup(busses, GINT_TO_POINTER(pass));
                    writebus(destbus, packet, pkthdr.sp_len);
                }
            }
        } while(packet);
    }
}

/*
void *buswritethread(void *ignore) {
    int const bufsize = 4000;
    char readbuf[bufsize];
    ssize_t pktlen;
    while (!terminate) {
        pktlen = read(tapfd, readbuf, bufsize);
        if (pktlen < 0) {
            //error - quit
            return NULL;
        }
        if (pktlen > 0) {
            writebus(tmpbus_hdl, tmpbus_header,
                    readbuf, pktlen);
        }
    }
    return NULL;
}
*/
void handle_tapread(evutil_socket_t sockfd, short events, void *ignore) {
    assert(sockfd == tapfd);

    int const bufsize = 65*1024;
    int8_t readbuf[bufsize];
    ssize_t pktlen;
    while ((pktlen = read(tapfd, readbuf, bufsize)) > 0) {
        // TODO filter dest buses here
        GHashTableIter it;
        gpointer key, value;
        for(g_hash_table_iter_init(&it, busses);
                g_hash_table_iter_next(&it, &key, &value);
                ) {
            struct tmpbus *thisbus = (struct tmpbus*) value;

            // TODO filter frames here
            writebus((struct tmpbus*) thisbus,
                    readbuf, pktlen);
        }
    }
}

void readstruct(int fd, void* structp, size_t structsize) {
    size_t bytes_total = structsize,
           bytes_to_read = bytes_total;
    // proceed bytewise (int8_t*)
    int8_t *hdrp = structp;
    while (bytes_to_read > 0) {
        ssize_t this_read = read(fd, hdrp, bytes_to_read);
        if (this_read <= 0) {
            die(errno, "read from UNIX socket");
        }
        hdrp += this_read;
        bytes_to_read -= this_read;
    }
    // no negative values (overreads)
    assert(bytes_to_read == 0);
}

void unix_accept(evutil_socket_t sock, short events, void *ignore) {
    int fd = accept(sock, NULL, 0);
    if (fd <= 0) {
        die(errno, "accept");
        return;
    } else if (fd > FD_SETSIZE) {
        close(fd);
        return;
    }

    /* handle clients one by one
     * to avoid races on the process table
     * (registering is not done often, so no need to hurry)
     */
    struct getshm_msg regproc;
    readstruct(fd, &regproc.gs_header, sizeof(regproc.gs_header));
    if (regproc.gs_header.um_ver > USOCK_VERSION ||
            regproc.gs_header.um_msgid != SWARM_GETSHM) {
        ERR("Unsupported client\n");
        close(fd);
        return;
    }
    pid_t caller_pid = -1;
    readstruct(fd, &caller_pid, sizeof(pid_t));
    if (caller_pid < 0) {
        ERR("PID < 0 - Closing\n");
        close(fd);
        return;
    }

    ERR("Creating Bus\n");
    struct tmpbus *newbus = allocate_bus();

    newbus->tmpbus_hdl = open(
            newbus->tmpbus_name,
            O_RDWR | O_CREAT | O_TRUNC,
            0644);
    if (newbus->tmpbus_hdl <= 0) {
        newbus->tmpbus_hdl = 0;
        deallocate_bus(newbus);
        die(errno, "open tmpbus");
    }
    if (initbus(&newbus->tmpbus_header,
                newbus->tmpbus_hdl,
                caller_pid) != 0) {
        deallocate_bus(newbus);
        die(errno, "init tmpbus");
    }

    ERR("Creating semaphore\n");
    int const sem_name_len = 30;
    char shmif_sem_name[sem_name_len];
    snprintf(shmif_sem_name, sem_name_len,
            "rumpuser_shmif_lock_%i", caller_pid);
    newbus->tmpbus_lock = sem_open(shmif_sem_name, O_CREAT, 0644, 1);
    assert(newbus->tmpbus_lock != SEM_FAILED);

    ERR("Add new event\n");
    int new_wd = inotify_add_watch(
            inotify_hdl, newbus->tmpbus_name, IN_MODIFY);
    if (new_wd < 0) {
        deallocate_bus(newbus);
        die(errno, "inotify watch");
    }
    g_hash_table_insert(
            busses, GINT_TO_POINTER(new_wd), newbus);

    /*
    newbus->tmpbus_event = event_new(
        ev_base, newbus->tmpbus_hdl, EV_READ|EV_PERSIST,
        handle_busread, newbus);
    if (newbus->tmpbus_event == NULL) {
        die(0, "event_new");
    }
    event_add(newbus->tmpbus_event, NULL);
    */

    // now answer the client with the bus file name
    write(fd, newbus->tmpbus_name, sizeof(newbus->tmpbus_name));
    close(fd);
}

int main(int argc, char *argv[]) {
    atexit(cleanup);
    struct sigaction sigact = {
        .sa_handler = cleanup_sig
    };
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    //can eventually be disabled
    event_enable_debug_mode();

    busses = g_hash_table_new_full(NULL, NULL, NULL, deallocate_bus);

    ev_base = event_base_new();
    if (ev_base == NULL) {
        die(0, "event_base_new");
    }

    ERR("Allocating TAP device\n");
    char devname[] = "tun0";
    tapfd = tun_alloc(devname);
    if (tapfd <= 0) {
        tapfd = 0;
        die(errno, "open tap");
    }
    evutil_make_socket_nonblocking(tapfd);
    tap_listener_event = event_new(
            ev_base, tapfd, EV_READ|EV_PERSIST,
            handle_tapread, NULL);
    if (tap_listener_event == NULL) {
        die(0, "tap event_new");
    }
    event_add(tap_listener_event, NULL);

    ERR("Initialising inotify\n");
    inotify_hdl = inotify_init1(IN_NONBLOCK);
    if (inotify_hdl <= 0) {
        inotify_hdl = 0;
        die(errno, "inotify");
    }
    ERR("Creating Inotify event\n");
    inotify_listener_event = event_new(
            ev_base, inotify_hdl, EV_READ|EV_PERSIST,
            handle_busread, NULL);
    if (inotify_listener_event == NULL) {
        die(0, "event_new");
    }
    event_add(inotify_listener_event, NULL);

    ERR("Creating UNIX socket\n");
    unix_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_socket <= 0) {
        unix_socket = 0;
        die(errno, "socket");
    }
    evutil_make_socket_nonblocking(unix_socket);

    struct sockaddr_un sockaddr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCK_FN,
    };

    if (bind(unix_socket,
                (struct sockaddr *)&sockaddr,
                sizeof(sockaddr))) {
        perror("bind");
        die(errno, "bind");
    }
    // 128 used to be hard-coded into the linux kernel
    // and is still the default upper limit for the backlog
    assert(listen(unix_socket, 128) == 0);

    ERR("Creating UNIX socket listener event\n");
    unix_socket_listener_event = event_new(
            ev_base, unix_socket, EV_READ|EV_PERSIST,
            unix_accept, NULL);
    if (unix_socket_listener_event == NULL) {
        die(0, "event_new");
    }
    event_add(unix_socket_listener_event, NULL);

    ERR("Waiting for a client to send the bus file name to\n");
    event_base_dispatch(ev_base);

    /*
    ERR("Creating send/receive threads\n");
    pthread_t readthread, writethread;
    pthread_create(&readthread, NULL, busreadthread, NULL);
    pthread_create(&writethread, NULL, buswritethread, NULL);

    sleep(120);

    terminate = true;
    pthread_join(writethread, NULL);
    pthread_join(readthread, NULL);
    */
    die(0, NULL);

}

