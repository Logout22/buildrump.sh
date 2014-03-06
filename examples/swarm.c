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
#include <dirent.h>

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
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <glib.h>

#include "swarm.h"
#include "swarm_server_ipc.h"
#include "hive.h"
#include "shmifvar.h"

in_addr_t ip_addr_num;
uint8_t mac_addr[MAC_LEN];

//defining some BSD specific macros
#include <stddef.h>

#include <linux/if_ether.h>
#ifndef ETHER_HDR_LEN
    #define ETHER_HDR_LEN ETH_HLEN
#endif
#ifndef ETHERMTU
    #define ETHERMTU ETH_DATA_LEN
#endif

#define EQUALS(s1, s2) (strcmp((s1), (s2)) == 0)

#if 0
#define ERR(...) { \
    fprintf(stderr, "swarm: "); \
    fprintf(stderr, __VA_ARGS__); \
}
#else
#define ERR(...) (void)NULL;
#endif

// contains the variables necessary to maintain a read state:
struct shmif_handle {
    uint64_t sc_devgen;
    uint32_t sc_nextpacket;
};

#define TMPBUS_NAME_LEN 256

/* NOTE: Do NOT instantiate struct tmpbus directly.
 * Use something like:
 *
 * struct tmpbus *myvar = allocate_bus();
 * ...
 * deallocate_bus(myvar);
 */
struct tmpbus {
    char tmpbus_name[TMPBUS_NAME_LEN];
    int tmpbus_hdl;
    int tmpbus_wd;
    struct shmif_mem *tmpbus_header;
    struct shmif_handle *tmpbus_position;
    struct bufferevent *tmpbus_bev;
    int32_t tmpbus_lastmsg;
};

static int unix_socket = -1, tapfd = -1, inotify_hdl = -1;
static struct event *unix_socket_listener_event = NULL,
             *tap_listener_event = NULL,
             *inotify_listener_event = NULL;
static GHashTable *busses = NULL;
static struct event_base *ev_base;
static bool hive_initialised = false;

void __attribute__((__noreturn__))
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

void deallocate_bus(gpointer dataptr) {
    struct tmpbus *busptr = dataptr;

    if (busptr->tmpbus_bev) {
        deallocate_bufferevent(busptr->tmpbus_bev);
    }
    if (busptr->tmpbus_header) {
        munmap(busptr->tmpbus_header, BUSMEM_SIZE);
    }
    if (busptr->tmpbus_hdl) {
        close(busptr->tmpbus_hdl);
        // should be left out for debugging purposes:
        //unlink(busptr->tmpbus_name);
    }
    free(busptr->tmpbus_position);
    free(busptr);
}

struct tmpbus *allocate_bus() {
    struct tmpbus *result = malloc(sizeof(struct tmpbus));
    assert(result);
    memset(result, 0, sizeof(struct tmpbus));

    // essential field initialisation:
    result->tmpbus_position = malloc(sizeof(struct shmif_handle));
    assert(result->tmpbus_position);
    memset(result->tmpbus_position, 0, sizeof(struct shmif_handle));
    result->tmpbus_hdl = -1;
    result->tmpbus_wd = -1;
    return result;
}

void deallocate_watch(gpointer arg) {
    int watchfd = GPOINTER_TO_INT(arg);
    // notify Hive
    remove_ports_for_watch(watchfd);
    inotify_rm_watch(inotify_hdl, watchfd);
}

void cleanup() {
    ERR("Screw you guys, I'm going home!\n");
    g_hash_table_unref(busses);
    if (unix_socket_listener_event) {
        event_free(unix_socket_listener_event);
    }
    if (tap_listener_event) {
        event_free(tap_listener_event);
    }
    if (inotify_listener_event) {
        event_free(inotify_listener_event);
    }
    if (unix_socket > 0) {
        //should be handled by swarm_ipc's bufevent:
        //close(unix_socket);
        unlink(SOCK_FN);
    }
    if (inotify_hdl > 0) {
        close(inotify_hdl);
    }
    if (tapfd > 0) {
        close(tapfd);
    }
    if (ev_base) {
        event_base_free(ev_base);
    }
    if (hive_initialised) {
        shutdown_hive();
    }
}

#if 1
int tun_alloc(int *resulting_fd)
{
  *resulting_fd = -1;

  struct ifreq ifr = {
    .ifr_name = "tun0",
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *
     *        IFF_NO_PI - Do not provide packet information
     */
    .ifr_flags = IFF_TAP | IFF_NO_PI,
  };
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
     return -1;

  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
     close(fd);
     return err;
  }

  if ((err = ioctl(fd, SIOCGIFHWADDR, &ifr)) < 0) {
      close(fd);
      return err;
  }
  CPYMAC(mac_addr, ifr.ifr_hwaddr.sa_data);

  *resulting_fd = fd;
  return 0;
}
#else
// macvtap version:
int tun_alloc(int *resulting_fd) {
    *resulting_fd = -1;

    //find out current tap device name
    DIR *macvtap_dir = opendir("/sys/class/macvtap");
    if (macvtap_dir == NULL) {
        return errno;
    }

    struct dirent dir_entry, *result = NULL;
    int error = 0, fd = -1;
    do {
        if ((error = readdir_r(macvtap_dir, &dir_entry, &result))) {
            break;
        }
        if (result != NULL) {
            char start_of_name[] = "123";
            strncpy(start_of_name, dir_entry.d_name, 3);

            if (EQUALS(start_of_name, "tap")) {
                char tap_device_filename[20];
                strcpy(tap_device_filename, "/dev/");
                strncat(tap_device_filename, dir_entry.d_name, 14);

                fd = open(tap_device_filename, O_RDWR);
                if (fd < 0) {
                    error = errno;
                }

                // use the first available tap device
                break;
            }
        }
    } while (result != NULL);

    closedir(macvtap_dir);
    if (error) {
        return error;
    }
    if (fd < 0) {
        die(1, "No tap device found.");
    }

    // now retrieve MAC address and exit
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {
        .ifr_name = "macvtap0"
    };
    if ((error = ioctl(sock, SIOCGIFHWADDR, &ifr)) < 0) {
        close(fd);
        return error;
    }
    CPYMAC(mac_addr, ifr.ifr_hwaddr.sa_data);

    *resulting_fd = fd;
    return 0;
}
#endif

static void
dowakeup(int busfd)
{
    uint32_t ver = SHMIF_VERSION;
    pwrite(busfd, &ver, sizeof(ver), IFMEM_WAKEUP);
}

#define LOCK_UNLOCKED	0
#define LOCK_LOCKED	1
#define LOCK_COOLDOWN	1001

void mfence() {
    asm("mfence");
}

// man, this sucks in Linux
uint32_t compare_exchange(uint32_t *addr, uint32_t old, uint32_t new) {
    uint32_t result;
    asm("lock cmpxchgl %3, %1;"
        : "=a"(result), "+m"(*addr)
        : "a"(old), "r"(new)
        : "memory");
    return result;
}

uint32_t exchange(uint32_t *addr, uint32_t new) {
    uint32_t result = new;
    asm("xchgl %0, %1;"
        : "+r"(result), "+m"(*addr)
        : : "memory", "cc");
    return result;
}

static void
shmif_lockbus(struct shmif_mem *busmem)
{
	int i = 0;

	while (compare_exchange(&busmem->shm_lock,
                LOCK_UNLOCKED, LOCK_LOCKED) == LOCK_LOCKED) {
		if (++i > LOCK_COOLDOWN) {
			/* wait 1ms */
            struct timespec rqt = { .tv_nsec = 1000*1000 };
            struct timespec rmt;
            int rv;
            do {
                rv = nanosleep(&rqt, &rmt);
                rqt = rmt;
            } while (rv == -1 && errno == EINTR);

            // reset cooldown counter
			i = 0;
		}
		continue;
	}
    mfence();
}

static void
shmif_unlockbus(struct shmif_mem *busmem)
{
    mfence();
	uint32_t old = exchange(&busmem->shm_lock, LOCK_UNLOCKED);
    assert(old == LOCK_LOCKED);
}

int initbus(struct tmpbus *newbus, struct bufferevent *bev) {
    newbus->tmpbus_bev = bev;

#if 0
    // default to the current directory
    char *res = getcwd(newbus->tmpbus_name, 245);
    assert(res == newbus->tmpbus_name);
#else
    strcpy(newbus->tmpbus_name, "/run/swarm");
#endif
    strcat(newbus->tmpbus_name, "/busXXXXXX");
    newbus->tmpbus_hdl = mkstemp(newbus->tmpbus_name);
    if (newbus->tmpbus_hdl <= 0) {
        newbus->tmpbus_hdl = 0;
        deallocate_bus(newbus);
        die(errno, "open tmpbus");
    }

    if (ftruncate(newbus->tmpbus_hdl, BUSMEM_SIZE) != 0) {
        ERR("ftruncate failed\n");
        return errno;
    }

    struct shmif_mem *hdr = mmap(NULL, BUSMEM_SIZE,
            PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED,
            newbus->tmpbus_hdl, 0);
    if (hdr == MAP_FAILED) {
        ERR("map failed\n");
        return errno;
    }

	/*
	 * Prefault in pages to minimize runtime penalty with buslock.
	 */
    volatile uint8_t v, *p;
    long pagesize = sysconf(_SC_PAGESIZE);
	for (p = (uint8_t*) hdr;
	    p < ((uint8_t*) hdr) + BUSMEM_SIZE;
	    p += pagesize) {
		v = *p;
        (void)v;
    }

    hdr->shm_magic = SHMIF_MAGIC;
    hdr->shm_gen = 0;
    hdr->shm_first = BUSMEM_DATASIZE;
    hdr->shm_lock = LOCK_UNLOCKED;

    newbus->tmpbus_header = hdr;
    return 0;
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

    shmif_lockbus(thisbus->tmpbus_header);
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
    shmif_unlockbus(thisbus->tmpbus_header);

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

    shmif_lockbus(thisbus->tmpbus_header);
    assert(busmem->shm_magic == SHMIF_MAGIC);
    assert(busmem->shm_gen >= sc->sc_devgen);

    /* need more data? */
    if (sc->sc_devgen == busmem->shm_gen &&
        shmif_nextpktoff(busmem, busmem->shm_last)
         == sc->sc_nextpacket) {
        shmif_unlockbus(thisbus->tmpbus_header);
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
    shmif_unlockbus(thisbus->tmpbus_header);

    if (wrap) {
        sc->sc_devgen++;
        DPRINTF(("dev %p generation now %" PRIu64 "\n",
            sc, sc->sc_devgen));
    }
}

void send_frame_to_all(void *frame, size_t flen) {
    GHashTableIter it;
    gpointer key, value;
    for(g_hash_table_iter_init(&it, busses);
            g_hash_table_iter_next(&it, &key, &value);
       ) {
        struct tmpbus *thisbus = (struct tmpbus*) value;

        writebus((struct tmpbus*) thisbus, frame, flen);
    }
}

void handle_busread(evutil_socket_t eventfd, short events, void *ignore) {
    assert(eventfd == inotify_hdl);
    struct inotify_event iEvent;

    while (read(inotify_hdl, &iEvent, sizeof(iEvent)) > 0) {
        if (iEvent.mask & IN_CLOSE_WRITE) {
            g_hash_table_remove(busses, GINT_TO_POINTER(iEvent.wd));
            continue;
        }

        struct tmpbus *thisbus = (struct tmpbus *) g_hash_table_lookup(
                busses, GINT_TO_POINTER(iEvent.wd));
        if (thisbus == NULL) {
            if (!(iEvent.mask & IN_IGNORED)) {
                // this is no notification for a deleted watch
                ERR("Notified for wrong watch (FD #%d)!\n", iEvent.wd);
            }
            continue;
        }

        void *packet = NULL;
        do {
            struct shmif_pkthdr pkthdr = {};
            readbus(thisbus, &packet, &pkthdr);
            if (packet) {
                int pass = pass_for_frame(
                        packet, pkthdr.sp_len, iEvent.wd, true);
                if (pass == FRAME_TO_TAP) {
                    write(tapfd, packet, pkthdr.sp_len);
                } else if (pass == FRAME_TO_ALL) {
                    send_frame_to_all(packet, pkthdr.sp_len);
                } else if (pass != DROP_FRAME) {
                    struct tmpbus *destbus = (struct tmpbus*)
                        g_hash_table_lookup(busses, GINT_TO_POINTER(pass));
                    if (!destbus) {
                        ERR("busread: Invalid bus at ID %d\n", pass);
                        die(225, NULL);
                    }
                    writebus(destbus, packet, pkthdr.sp_len);
                }
                free(packet);
            }
        } while(packet);
    }
}

void handle_tapread(evutil_socket_t sockfd, short events, void *ignore) {
    assert(sockfd == tapfd);

    int const bufsize = 65*1024;
    int8_t readbuf[bufsize];
    ssize_t pktlen;
    while ((pktlen = read(tapfd, readbuf, bufsize)) > 0) {
        int pass = pass_for_frame(readbuf, pktlen, INVALID_BUS, false);
        if (pass == FRAME_TO_TAP) {
            write(tapfd, readbuf, pktlen);
        } else if (pass == FRAME_TO_ALL) {
            send_frame_to_all(readbuf, pktlen);
        } else if (pass != DROP_FRAME) {
            struct tmpbus *destbus = (struct tmpbus*)
                g_hash_table_lookup(busses, GINT_TO_POINTER(pass));
            if (!destbus) {
                ERR("tapread: Invalid bus at ID %d\n", pass);
                die(226, NULL);
            }
            ERR("Sending to bus %d\n", pass);
            writebus((struct tmpbus*) destbus,
                    readbuf, pktlen);
        }
    }
}

void insert_new_bus(struct tmpbus *newbus, struct bufferevent *bev) {
    ERR("Creating Bus\n");

#if 0
    ERR("Creating semaphore\n");
	size_t sem_name_len = strlen(newbus->tmpbus_name) + PREAMBLE_LEN;
	/*
	 * 2000 characters should be enough for everyone
	 * (simply adjust if not sufficient):
	 */
	assert(sem_name_len < 2022);
	char *shmif_sem_name = malloc(sem_name_len);
	assert(shmif_sem_name);
	sprintf(shmif_sem_name, "%s%s", PREAMBLE, newbus->tmpbus_name);

	newbus->tmpbus_lock = sem_open(shmif_sem_name, O_CREAT, 0644, 1);
    free(shmif_sem_name);
	assert(newbus->tmpbus_lock != SEM_FAILED);
#endif

    if (initbus(newbus, bev) != 0) {
        deallocate_bus(newbus);
        die(errno, "init tmpbus");
    }

    ERR("Add new event\n");
    int new_wd = inotify_add_watch(
            inotify_hdl, newbus->tmpbus_name, IN_MODIFY | IN_CLOSE_WRITE);
    if (new_wd < 0) {
        deallocate_bus(newbus);
        die(errno, "inotify watch");
    }
    newbus->tmpbus_wd = new_wd;

#if 0
    newbus->tmpbus_event = event_new(
            ev_base, fd, EV_READ|EV_PERSIST,
            handle_unixread, newbus);
    if (newbus->tmpbus_event == NULL) {
        die(0, "new bus event_new");
    }
    event_add(newbus->tmpbus_event, NULL);
#endif

    // now answer the client with the bus file name
    int res;
    if ((res = reply_swarm_getshm(
                bev, ip_addr_num, newbus->tmpbus_name))) {
        deallocate_bus(newbus);
        ERR("Error replying the client side: %d\n", -res);
        return;
    }

    g_hash_table_insert(
            busses, GINT_TO_POINTER(new_wd), newbus);
}

void handle_unixread(struct bufferevent *bev, void *data) {
    struct tmpbus *thisbus = (struct tmpbus*) data;

    int res;
    if (!thisbus->tmpbus_lastmsg) {
        if ((thisbus->tmpbus_lastmsg = rcv_message_type_evbuf(bev)) <= 0) {
            res = thisbus->tmpbus_lastmsg;
            goto unixread_error;
        }
        ERR("Received UNXSOCK message type %d\n", thisbus->tmpbus_lastmsg);
        if (evbuffer_get_length(bufferevent_get_input(bev)) >=
                sipc_struct_size(thisbus->tmpbus_lastmsg)) {
            // great, we can already proceed to stage 2
            handle_unixread(bev, data);
        }
    } else {
        int32_t msg = thisbus->tmpbus_lastmsg;
        switch(msg) {
            case SWARM_GETSHM:
                {
                    insert_new_bus(thisbus, bev);
                }
                break;
            case HIVE_BIND:
            case HIVE_UNBIND:
                if (thisbus->tmpbus_wd < 0) {
                    goto hivebind_error;
                }
                uint32_t protocol, resource;
                if ((res = rcv_request_hive_bind_proc(
                                bev, &protocol, &resource))) {
                    goto hivebind_error;
                }

                if (msg == HIVE_UNBIND) {
                    remove_connection(
                        thisbus->tmpbus_wd, protocol, resource);
                } else {
                    register_connection(
                        bev, thisbus->tmpbus_wd, protocol, resource);
                }
                break;
hivebind_error:
                if (msg == HIVE_BIND) {
                    reply_hive_bind(bev, -1);
                }
                goto unixread_error;
        }
        thisbus->tmpbus_lastmsg = 0;
    }
    return;

unixread_error:
    ERR("Received garbage: %d -- closing\n", res);
    g_hash_table_remove(busses, GINT_TO_POINTER(thisbus->tmpbus_wd));
    return;
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

    evutil_make_socket_nonblocking(fd);

    struct tmpbus *newbus = allocate_bus();
    ERR("Creating new bufferevent\n");
    initialise_bufferevent(
            ev_base, fd, handle_unixread, newbus);

    // on freeing the buffer event, the socket will be closed
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

    busses = g_hash_table_new_full(NULL, NULL,
            deallocate_watch, deallocate_bus);

    ev_base = event_base_new();
    if (ev_base == NULL) {
        die(0, "event_base_new");
    }

    ERR("Allocating TAP device\n");
    int error = tun_alloc(&tapfd);
    if (tapfd < 0) {
        tapfd = -1;
        die(error, "open tap");
    }
    if (argc < 2) {
        die(0, "Please supply an IP address for Swarm.");
    }
    ip_addr_num = inet_addr(argv[1]);
    init_hive(ip_addr_num, mac_addr);
    hive_initialised = true;

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
    if (listen(unix_socket, 128) != 0) {
        perror("listen");
        die(errno, "listen");
    }

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

    die(0, NULL);

}

