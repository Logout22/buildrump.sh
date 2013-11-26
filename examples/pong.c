#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>

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

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rump/rump.h>
#include <rump/netconfig.h>
#include <rump/rump_syscalls.h>
#include <rump/rumpnet_if_pub.h>

#include "common.h"
#include "shmifvar.h"

#define ERR(...) { \
	fprintf(stderr, "srv: "); \
	fprintf(stderr, __VA_ARGS__); \
}

int unix_socket = 0;
char tmpbus_name[] = "busXXXXXX\0";
int tmpbus_hdl = 0;
struct shmif_mem *tmpbus_header = NULL;

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{
	if (msg)
		warnx("%s: %d", msg, e);
	rump_sys_reboot(0, NULL);
	exit(e);
}

void __attribute__((__noreturn__))
cleanup_sig(int signum) {
	die(signum, NULL);
}

void cleanup() {
    // NOTE: Rump kernel is already shut down at this point
    // (although at some point this program should not need
    // a rump kernel any more)

    if (tmpbus_header) {
        munmap(tmpbus_header, BUSMEM_SIZE);
    }
    if (tmpbus_hdl) {
    	close(tmpbus_hdl);
	    unlink(tmpbus_name);
    }
    if (unix_socket) {
        close(unix_socket);
        unlink(SOCK_FN);
    }
}

void initbus(struct shmif_mem **hdrp, int busfd) {
    if (ftruncate(busfd, BUSMEM_SIZE) != 0) {
        die(errno, "ftruncate");
    }

	struct shmif_mem *hdr = mmap(NULL, BUSMEM_SIZE,
            PROT_READ|PROT_WRITE, MAP_FILE|MAP_SHARED,
            busfd, 0);
	if (hdr == MAP_FAILED) {
        perror("map");
        die(errno, "map");
    }
    hdr->shm_magic = SHMIF_MAGIC;
    hdr->shm_first = BUSMEM_DATASIZE;
    *hdrp = hdr;
}

/* TO ADAPT */
static void
dowakeup(struct shmif_sc *sc)
{
	struct rumpuser_iovec iov;
	uint32_t ver = SHMIF_VERSION;
	size_t n;

	iov.iov_base = &ver;
	iov.iov_len = sizeof(ver);
	rumpuser_iovwrite(sc->sc_memfd, &iov, 1, IFMEM_WAKEUP, &n);
}

/*
 * This locking needs work and will misbehave severely if:
 * 1) the backing memory has to be paged in
 * 2) some lockholder exits while holding the lock
 */
static void
shmif_lockbus(struct shmif_mem *busmem)
{
	int i = 0;

	while (__predict_false(atomic_cas_32(&busmem->shm_lock,
	    LOCK_UNLOCKED, LOCK_LOCKED) == LOCK_LOCKED)) {
		if (__predict_false(++i > LOCK_COOLDOWN)) {
			/* wait 1ms */
			rumpuser_clock_sleep(RUMPUSER_CLOCK_RELWALL,
			    0, 1000*1000);
			i = 0;
		}
		continue;
	}
	membar_enter();
}

static void
shmif_unlockbus(struct shmif_mem *busmem)
{
	unsigned int old;

	membar_exit();
	old = atomic_swap_32(&busmem->shm_lock, LOCK_UNLOCKED);
	KASSERT(old == LOCK_LOCKED);
}

static void
shmif_start(struct ifnet *ifp)
{
	struct shmif_sc *sc = ifp->if_softc;
	struct shmif_mem *busmem = sc->sc_busmem;
	struct mbuf *m, *m0;
	uint32_t dataoff;
	uint32_t pktsize, pktwrote;
	bool wrote = false;
	bool wrap;

	ifp->if_flags |= IFF_OACTIVE;

	for (;;) {
		struct shmif_pkthdr sp;
		struct timeval tv;

		IF_DEQUEUE(&ifp->if_snd, m0);
		if (m0 == NULL) {
			break;
		}

		pktsize = 0;
		for (m = m0; m != NULL; m = m->m_next) {
			pktsize += m->m_len;
		}
		KASSERT(pktsize <= ETHERMTU + ETHER_HDR_LEN);

		getmicrouptime(&tv);
		sp.sp_len = pktsize;
		sp.sp_sec = tv.tv_sec;
		sp.sp_usec = tv.tv_usec;

		bpf_mtap(ifp, m0);

		shmif_lockbus(busmem);
		KASSERT(busmem->shm_magic == SHMIF_MAGIC);
		busmem->shm_last = shmif_nextpktoff(busmem, busmem->shm_last);

		wrap = false;
		dataoff = shmif_buswrite(busmem,
		    busmem->shm_last, &sp, sizeof(sp), &wrap);
		pktwrote = 0;
		for (m = m0; m != NULL; m = m->m_next) {
			pktwrote += m->m_len;
			dataoff = shmif_buswrite(busmem, dataoff,
			    mtod(m, void *), m->m_len, &wrap);
		}
		KASSERT(pktwrote == pktsize);
		if (wrap) {
			busmem->shm_gen++;
			DPRINTF(("bus generation now %" PRIu64 "\n",
			    busmem->shm_gen));
		}
		shmif_unlockbus(busmem);

		m_freem(m0);
		wrote = true;

		DPRINTF(("shmif_start: send %d bytes at off %d\n",
		    pktsize, busmem->shm_last));
	}

	ifp->if_flags &= ~IFF_OACTIVE;

	/* wakeup? */
	if (wrote) {
		dowakeup(sc);
	}
}

/*
 * Check if we have been sleeping too long.  Basically,
 * our in-sc nextpkt must by first <= nextpkt <= last"+1".
 * We use the fact that first is guaranteed to never overlap
 * with the last frame in the ring.
 */
static __inline bool
stillvalid_p(struct shmif_sc *sc)
{
	struct shmif_mem *busmem = sc->sc_busmem;
	unsigned gendiff = busmem->shm_gen - sc->sc_devgen;
	uint32_t lastoff, devoff;

	KASSERT(busmem->shm_first != busmem->shm_last);

	/* normalize onto a 2x busmem chunk */
	devoff = sc->sc_nextpacket;
	lastoff = shmif_nextpktoff(busmem, busmem->shm_last);

	/* trivial case */
	if (gendiff > 1)
		return false;
	KASSERT(gendiff <= 1);

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
shmif_rcv(void *arg)
{
	struct ifnet *ifp = arg;
	struct shmif_sc *sc = ifp->if_softc;
	struct shmif_mem *busmem;
	struct mbuf *m = NULL;
	struct ether_header *eth;
	uint32_t nextpkt;
	bool wrap, passup;
	int error;
	const int align
	    = ALIGN(sizeof(struct ether_header)) - sizeof(struct ether_header);

 reup:
	mutex_enter(&sc->sc_mtx);
	while ((ifp->if_flags & IFF_RUNNING) == 0 && !sc->sc_dying)
		cv_wait(&sc->sc_cv, &sc->sc_mtx);
	mutex_exit(&sc->sc_mtx);

	busmem = sc->sc_busmem;

	while (ifp->if_flags & IFF_RUNNING) {
		struct shmif_pkthdr sp;

		if (m == NULL) {
			m = m_gethdr(M_WAIT, MT_DATA);
			MCLGET(m, M_WAIT);
			m->m_data += align;
		}

		DPRINTF(("waiting %d/%" PRIu64 "\n",
		    sc->sc_nextpacket, sc->sc_devgen));
		KASSERT(m->m_flags & M_EXT);

		shmif_lockbus(busmem);
		KASSERT(busmem->shm_magic == SHMIF_MAGIC);
		KASSERT(busmem->shm_gen >= sc->sc_devgen);

		/* need more data? */
		if (sc->sc_devgen == busmem->shm_gen &&
		    shmif_nextpktoff(busmem, busmem->shm_last)
		     == sc->sc_nextpacket) {
			shmif_unlockbus(busmem);
			error = 0;
			rumpcomp_shmif_watchwait(sc->sc_kq);
			if (__predict_false(error))
				printf("shmif_rcv: wait failed %d\n", error);
			membar_consumer();
			continue;
		}

		if (stillvalid_p(sc)) {
			nextpkt = sc->sc_nextpacket;
		} else {
			KASSERT(busmem->shm_gen > 0);
			nextpkt = busmem->shm_first;
			if (busmem->shm_first > busmem->shm_last)
				sc->sc_devgen = busmem->shm_gen - 1;
			else
				sc->sc_devgen = busmem->shm_gen;
			DPRINTF(("dev %p overrun, new data: %d/%" PRIu64 "\n",
			    sc, nextpkt, sc->sc_devgen));
		}

		/*
		 * If our read pointer is ahead the bus last write, our
		 * generation must be one behind.
		 */
		KASSERT(!(nextpkt > busmem->shm_last
		    && sc->sc_devgen == busmem->shm_gen));

		wrap = false;
		nextpkt = shmif_busread(busmem, &sp,
		    nextpkt, sizeof(sp), &wrap);
		KASSERT(sp.sp_len <= ETHERMTU + ETHER_HDR_LEN);
		nextpkt = shmif_busread(busmem, mtod(m, void *),
		    nextpkt, sp.sp_len, &wrap);

		DPRINTF(("shmif_rcv: read packet of length %d at %d\n",
		    sp.sp_len, nextpkt));

		sc->sc_nextpacket = nextpkt;
		shmif_unlockbus(sc->sc_busmem);

		if (wrap) {
			sc->sc_devgen++;
			DPRINTF(("dev %p generation now %" PRIu64 "\n",
			    sc, sc->sc_devgen));
		}

		/*
		 * Ignore packets too short to possibly be valid.
		 * This is hit at least for the first frame on a new bus.
		 */
		if (__predict_false(sp.sp_len < ETHER_HDR_LEN)) {
			DPRINTF(("shmif read packet len %d < ETHER_HDR_LEN\n",
			    sp.sp_len));
			continue;
		}

		m->m_len = m->m_pkthdr.len = sp.sp_len;
		m->m_pkthdr.rcvif = ifp;

		/*
		 * Test if we want to pass the packet upwards
		 */
		eth = mtod(m, struct ether_header *);
		if (memcmp(eth->ether_dhost, CLLADDR(ifp->if_sadl),
		    ETHER_ADDR_LEN) == 0) {
			passup = true;
		} else if (ETHER_IS_MULTICAST(eth->ether_dhost)) {
			passup = true;
		} else if (ifp->if_flags & IFF_PROMISC) {
			m->m_flags |= M_PROMISC;
			passup = true;
		} else {
			passup = false;
		}

		if (passup) {
			KERNEL_LOCK(1, NULL);
			bpf_mtap(ifp, m);
			ifp->if_input(ifp, m);
			KERNEL_UNLOCK_ONE(NULL);
			m = NULL;
		}
		/* else: reuse mbuf for a future packet */
	}
	m_freem(m);
	m = NULL;

	if (!sc->sc_dying)
		goto reup;

	kthread_exit(0);
}
/*END TO ADAPT*/

int main(int argc, char *argv[]) {
    atexit(cleanup);
	struct sigaction sigact = {
		.sa_handler = cleanup_sig
	};
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

	rump_init();

    ERR("Creating UNIX socket\n");
    unix_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_socket <= 0) {
        die(errno, "socket");
    }
    struct sockaddr_un sockaddr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCK_FN,
    };

    if (bind(unix_socket,
                (struct sockaddr *)&sockaddr,
                sizeof(sockaddr))) {
        perror("bind");
        return errno;
    }
    // 128 used to be hard-coded into the linux kernel
    // and is still the default upper limit for the backlog
    assert(listen(unix_socket, 128) == 0);

	ERR("Creating Bus\n");
	assert(*mktemp(tmpbus_name) != 0);
	tmpbus_hdl = open(tmpbus_name, O_RDWR | O_CREAT | O_TRUNC, 0600);
    initbus(&tmpbus_header, tmpbus_hdl);
    sleep(10);

    rump_pub_shmif_create(tmpbus_name, 0);

	char const *ip_address = "10.165.8.1";
	ERR("Setting IP address %s\n", ip_address);
    rump_pub_netconfig_ipv4_ifaddr("shmif0", ip_address, "255.255.255.0");
	rump_pub_netconfig_ifup("shmif0");

	ERR("Creating Socket\n");
    int tcpsock = rump_sys_socket(PF_INET, SOCK_STREAM, 0);
    if (tcpsock <= 0) {
        die(errno, "socket");
    }

	short const portnum = 26417;
	ERR("Binding to port %d\n", portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
	// listen from all addresses
    memset(&sin.sin_addr, 0, sizeof(sin.sin_addr));
    int res = rump_sys_bind(tcpsock, (struct sockaddr*) &sin, sizeof(sin));
    if (res != 0) {
        die(errno, "bind");
    }

	ERR("Listening (Queue length 120)\n");
    res = rump_sys_listen(tcpsock, 120);
    if (res != 0) {
        die(errno, "listen");
    }

    ERR("Waiting for a client to send the bus file name to\n");
    int sndfnamesock = accept(unix_socket, NULL, 0);
    if (sndfnamesock <= 0) {
        die(errno, "accept");
    }
    write(sndfnamesock, tmpbus_name, sizeof(tmpbus_name));
    close(sndfnamesock);

	ERR("Accepting...\n");
    int rcvsock = rump_sys_accept(tcpsock, NULL, 0);
    if (rcvsock <= 0) {
        die(errno, "accept");
    }

	int const bufsize = 50;
    char rbuf[bufsize + 1];
    rbuf[bufsize] = 0;
	//ERR("Reading at most %d bytes\n", bufsize);
	for(;;) {
		res = rump_sys_read(rcvsock, rbuf, bufsize);
		if (res <= 0) {
			die(errno, "read");
		}
		ERR("rcvd %s\n", rbuf);
		sleep(1);
        char const wbuf[] = "Pong.\0";
        res = rump_sys_write(rcvsock, wbuf, sizeof(wbuf));
        if (res <= 0) {
            die(errno, "write");
        }
	}
    rump_sys_close(rcvsock);

	ERR("Closing\n");
    rump_sys_close(tcpsock);

	die(0, NULL);
}

