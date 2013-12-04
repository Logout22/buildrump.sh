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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <pthread.h>

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

#define USOCK_VERSION 1

struct unxsock_msg {
    int um_ver;
    int um_msgid;
}

struct getshm_msg {
    struct unxsockmsg gs_header;
    int gs_pid;
}

struct tmpbus {
    char tmpbus_name[] = "busXXXXXX\0";
    int tmpbus_hdl = 0;
    struct shmif_mem *tmpbus_header = NULL;
    struct shmif_handle tmpbus_position = {};
};

int unix_socket = 0;
struct event *unix_socket_listener_event = NULL;
int tapfd = 0;
GHashTable *processes = NULL;
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

void deallocate_bus(gpointer dataptr) {
    struct tmpbus *busptr = dataptr;
    if (busptr->tmpbus_header) {
        munmap(busptr->tmpbus_header, BUSMEM_SIZE);
    }
    if (busptr->tmpbus_hdl) {
    	close(busptr->tmpbus_hdl);
	    unlink(busptr->tmpbus_name);
    }
    free(busptr);
}

void cleanup() {
    g_hash_table_unref(processes);
    if (unix_socket_listener_event) {
        event_free(unix_socket_listener_event);
    }
    if (unix_socket) {
        close(unix_socket);
        unlink(SOCK_FN);
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

void initbus(struct shmif_mem **hdrp, int busfd) {
    if (ftruncate(busfd, BUSMEM_SIZE) != 0) {
        die(errno, "ftruncate");
    }

	struct shmif_mem *hdr = mmap(NULL, BUSMEM_SIZE,
            PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED,
            busfd, 0);
	if (hdr == MAP_FAILED) {
        die(errno, "map");
    }
    hdr->shm_magic = SHMIF_MAGIC;
    hdr->shm_first = BUSMEM_DATASIZE;
    *hdrp = hdr;
}

static void
dowakeup(int busfd)
{
	uint32_t ver = SHMIF_VERSION;
	pwrite(busfd, &ver, sizeof(ver), IFMEM_WAKEUP);
}

#define LOCK_COOLDOWN	1001
#define LOCK_UNLOCKED	0
#define LOCK_LOCKED	1

/*
 * This locking needs work and will misbehave severely if:
 * 1) the backing memory has to be paged in
 * 2) some lockholder exits while holding the lock
 */
static void
shmif_lockbus(struct shmif_mem *busmem)
{
	int i = 0;

    uint32_t locked = LOCK_LOCKED, unlocked = LOCK_UNLOCKED;
	while (!__atomic_compare_exchange(
                    &busmem->shm_lock,
                    &unlocked, &locked,
                    false,
                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        locked = LOCK_LOCKED;
        unlocked = LOCK_UNLOCKED;
		if (++i > LOCK_COOLDOWN) {
			/* wait 1ms */
            struct timespec rqt = {.tv_sec = 0, .tv_nsec = 1000000}, rmt;
            int rv;
            do {
                rv = nanosleep(&rqt, &rmt);
                rqt = rmt;
            } while (rv == -1 && errno == EINTR);
			i = 0;
		}
		continue;
	}

    // just to make absolutely sure we locked it
    assert(busmem->shm_lock == LOCK_LOCKED);
}

static void
shmif_unlockbus(struct shmif_mem *busmem)
{
	uint32_t old, new = LOCK_UNLOCKED;

	__atomic_exchange(&busmem->shm_lock, &new, &old, __ATOMIC_SEQ_CST);
	assert(old == LOCK_LOCKED);
}

static void
writebus(int memfd, struct shmif_mem *busmem,
        void *packet, uint32_t pktsize)
{
	uint32_t dataoff;
	bool wrote = false;
	bool wrap;

    struct shmif_pkthdr sp = {};

    assert(pktsize <= ETHERMTU + ETHER_HDR_LEN);

    struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
    sp.sp_len = pktsize;
    sp.sp_sec = ts.tv_sec;
    sp.sp_usec = ts.tv_nsec / 1000;

    shmif_lockbus(busmem);
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
    shmif_unlockbus(busmem);

    wrote = true;

    ERR("shmif_start: send %d bytes at off %d\n",
        pktsize, busmem->shm_last);

	/* wakeup? */
	if (wrote) {
		dowakeup(memfd);
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
readbus(struct shmif_mem *busmem, struct shmif_handle *sc,
        void **packet, struct shmif_pkthdr *spp)
{
	uint32_t nextpkt;
	bool wrap;

    /*ERR("waiting %" PRIu32 "/%" PRIu64 "\n",
        sc->sc_nextpacket, sc->sc_devgen);*/

    shmif_lockbus(busmem);
    assert(busmem->shm_magic == SHMIF_MAGIC);
    assert(busmem->shm_gen >= sc->sc_devgen);

    /* need more data? */
    if (sc->sc_devgen == busmem->shm_gen &&
        shmif_nextpktoff(busmem, busmem->shm_last)
         == sc->sc_nextpacket) {
        shmif_unlockbus(busmem);
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
    shmif_unlockbus(busmem);

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

void readstruct(int fd, void* structp, size_t structsize) {
    size_t bytes_total = structsize;
           bytes_to_read = bytes_total;
    // proceed bytewise (int8_t*)
    int8_t *hdrp = structp;
    while (bytes_to_read > 0) {
        ssize_t this_read = read(fd, hdrp, bytes_to_read);
        if (this_read <= 0) {
            die(errno, "read from UNIX socket");
        }
        usm_hdrp += this_read
        bytes_to_read -= this_read;
    }
    // no negative values (overreads)
    assert(bytes_to_read == 0);
}

void unix_accept(evutil_socket_t sock, short events, void *ignore) {
    int fd = accept(sock, NULL, 0);
    if (fd <= 0) {
        die(errno, "accept");
    } else if (fd > FD_SETSIZE) {
        close(fd);
    } else {
        /* handle clients one by one
         * to avoid races on the process table
         * (registering is not done often, so no need to hurry)
         */
        struct getshm_msg regproc;
        readstruct(fd, (void*) &regproc.gs_header, sizeof(regproc.gs_header));
        if (regproc.gs_header.um_ver > USOCK_VERSION ||
                regproc.gs_header.um_msgid != SWARM_GETSHM) {
            ERR("Unsupported client\n");
            close(fd);
            return
        }
        pid_t caller_pid = -1;
        readstruct(fd, &caller_pid, sizeof(pid_t));
        if (caller_pid < 0) {
            ERR("PID < 0 - Closing\n");
            close(fd);
            return;
        }

        ERR("Creating Bus\n");
        struct tmpbus *newbus = malloc(sizeof(struct tmpbus));
        assert(newbus);
        memset(newbus, 0, sizeof(struct tmpbus));
        g_hash_table_insert(
                processes, GINT_TO_POINTER(caller_pid), newbus);

        assert(*mktemp(newbus->tmpbus_name) != 0);
        newbus->tmpbus_hdl = open(
                newbus->tmpbus_name,
                O_RDWR | O_CREAT | O_TRUNC,
                0644);
        if(newbus->tmpbus_hdl <= 0) {
            newbus->tmpbus_hdl = 0;
            die(errno, "open tmpbus");
        }
        initbus(&newbus->tmpbus_header, newbus->tmpbus_hdl);
        // TODO: libevent handlers for bus read/write

        // now answer the client with the bus file name
        write(fd, newbus->tmpbus_name, sizeof(newbus->tmpbus_name));
        close(fd);
    }
}

int __attribute__((__noreturn__))
main(int argc, char *argv[]) {
    atexit(cleanup);
	struct sigaction sigact = {
		.sa_handler = cleanup_sig
	};
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

    //can eventually be disabled
    event_enable_debug_mode();

    processes = g_hash_table_new_full(NULL, NULL, NULL, deallocate_bus);

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

    ERR("Waiting for a client to send the bus file name to\n");
    unix_socket_listener_event = event_new(
            ev_base, unix_socket, EV_READ|EV_PERSIST,
            unix_accept, NULL);
    if (unix_socket_listener_event == NULL) {
        die(0, "event_new");
    }
    event_add(unix_socket_listener_event, NULL);
    event_base_loop(ev_base, EVLOOP_NO_EXIT_ON_EMPTY);

    /*
    ERR("Creating send/receive threads\n");
    pthread_t readthread, writethread;
    pthread_create(&readthread, NULL, busreadthread, NULL);
    pthread_create(&writethread, NULL, buswritethread, NULL);

    sleep(120);

    terminate = true;
    pthread_join(writethread, NULL);
    pthread_join(readthread, NULL);
    die(0, NULL);

    */
}

