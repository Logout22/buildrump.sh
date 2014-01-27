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

#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <linux/if.h>
#include <linux/if_tun.h>

#include <rump/rump.h>
#include <rump/netconfig.h>
#include <rump/rump_syscalls.h>
#include <rump/rumpnet_if_pub.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#if !defined(LIBEVENT_VERSION_NUMBER) || LIBEVENT_VERSION_NUMBER < 0x02000100
#error "This version of Libevent is not supported; Get 2.0.1-alpha or later."
#endif
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <glib.h>

#include "swarm.h"
#include "swarm_ipc.h"
#include "hive.h"
#include "shmifvar.h"

#define IP_ADDRESS "10.93.48.100"
in_addr_t ip_addr_num;

#define ERR(...) { \
    fprintf(stderr, "swarm: "); \
    fprintf(stderr, __VA_ARGS__); \
}

#define TMPBUS_NAME_LEN 10

/* NOTE: Do NOT instantiate struct tmpbus directly.
 * Use something like:
 *
 * struct tmpbus *myvar = allocate_bus();
 * ...
 * deallocate_bus(myvar);
 */
struct tmpbus {
    int tmpbus_iface_id;
    int tmpbus_bpf_handle;
    size_t tmpbus_read_len;
    int tmpbus_wd;
    char tmpbus_name[TMPBUS_NAME_LEN];
    struct event *tmpbus_event;
};

static int unix_socket = 0, tapfd = 0, inotify_hdl = 0;
static struct event *unix_socket_listener_event = NULL,
             *tap_listener_event = NULL,
             *inotify_listener_event = NULL;
static GHashTable *busses = NULL;
static struct event_base *ev_base;

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{
    if (msg)
        warn("%s: %d", msg, e);
    rump_sys_reboot(0, NULL);
    exit(e);
}

void __attribute__((__noreturn__))
cleanup_sig(int signum) {
    die(signum, NULL);
}

void deallocate_bus(gpointer dataptr) {
    struct tmpbus *busptr = dataptr;

    if (busptr->tmpbus_bpf_handle) {
        close(busptr->tmpbus_bpf_handle);
    }
    if (busptr->tmpbus_event) {
        event_free(busptr->tmpbus_event);
    }
    free(busptr);
}

struct tmpbus *allocate_bus() {
    struct tmpbus *result = malloc(sizeof(struct tmpbus));
    assert(result);
    memset(result, 0, sizeof(struct tmpbus));

    // essential field initialisation:
    strcpy(result->tmpbus_name, "busXXXXXX");
    int tmpbus_hdl = mkstemp(result->tmpbus_name);
    if (tmpbus_hdl <= 0) {
        die(errno, "open tmpbus");
    }

    rump_pub_shmif_create(result->tmpbus_name, &result->tmpbus_iface_id);
    close(tmpbus_hdl);
    result->tmpbus_bpf_handle = rump_sys_open(
            "/dev/bpf", O_RDWR | O_NONBLOCK);
    if (result->tmpbus_bpf_handle <= 0) {
        die(errno, "open bpf");
    }

    struct ifreq ifr = {};
    sprintf(ifr.ifr_name, "shmif%d", result->tmpbus_iface_id);
    if (rump_sys_ioctl(result->tmpbus_bpf_handle, BIOCSETIF, &ifr) == -1) {
        die(1, "set if");
    }
    if ((result->tmpbus_read_len = rump_sys_ioctl(
                    result->tmpbus_bpf_handle, BIOCGBLEN)) == -1) {
        die(2, "get read len");
    }
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
    shutdown_hive();
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

void readbus(struct tmpbus *thisbus, void **packet, size_t *pktlen) {
    char *readbuffer = malloc(thisbus->tmpbus_read_len);
    // TODO error handling
    read(thisbus->tmpbus_bpf_handle, readbuffer, thisbus->tmpbus_read_len);
    *packet = readbuffer;
    *pktlen = thisbus->tmpbus_read_len;
}

void writebus(struct tmpbus *thisbus, void* packet, size_t pktlen) {
    if (pktlen > thisbus->tmpbus_read_len) {
        ERR("FIXME cannot write packet, too long\n");
        return;
    }
    char *writebuffer = malloc(thisbus->tmpbus_read_len);
    memset(writebuffer, 0, thisbus->tmpbus_read_len);
    memcpy(writebuffer, packet, pktlen);
    // TODO error handling
    write(thisbus->tmpbus_bpf_handle, packet, pktlen);
    free(writebuffer);
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
            size_t pktlen = 0;
            readbus(thisbus, &packet, &pktlen);
            if (packet) {
                int pass = pass_for_frame(packet, iEvent.wd, true);
                if (pass == FRAME_TO_TAP) {
                    write(tapfd, packet, pktlen);
                } else if (pass == FRAME_TO_ALL) {
                    send_frame_to_all(packet, pktlen);
                } else if (pass != DROP_FRAME) {
                    struct tmpbus *destbus = (struct tmpbus*)
                        g_hash_table_lookup(busses, GINT_TO_POINTER(pass));
                    if (!destbus) {
                        ERR("Invalid bus at ID %d\n", pass);
                        die(225, NULL);
                    }
                    writebus(destbus, packet, pktlen);
                }
            }
            free(packet);
        } while(packet);
    }
}

void handle_tapread(evutil_socket_t sockfd, short events, void *ignore) {
    assert(sockfd == tapfd);

    int const bufsize = 65*1024;
    int8_t readbuf[bufsize];
    ssize_t pktlen;
    while ((pktlen = read(tapfd, readbuf, bufsize)) > 0) {
        int pass = pass_for_frame(readbuf, INVALID_BUS, false);
        if (pass == FRAME_TO_ALL) {
            send_frame_to_all(readbuf, pktlen);
        } else if (pass != DROP_FRAME) {
            struct tmpbus *destbus = (struct tmpbus*)
                g_hash_table_lookup(busses, GINT_TO_POINTER(pass));
            if (!destbus) {
                ERR("Invalid bus at ID %d\n", pass);
                die(226, NULL);
            }
            writebus((struct tmpbus*) destbus,
                    readbuf, pktlen);
        }
    }
}

void handle_unixread(evutil_socket_t sockfd, short events, void *data) {
    struct tmpbus *thisbus = (struct tmpbus*) data;

    int res;
    if ((res = rcv_message_type(sockfd)) <= 0) {
        goto unixread_error;
    }

    switch(res) {
        case HIVE_BIND:
            {
                uint32_t protocol, resource;
                if ((res = rcv_request_hive_bind(
                                sockfd, &protocol, &resource))) {
                    goto unixread_error;
                }
                register_connection(
                        sockfd, thisbus->tmpbus_bpf_handle,
                        protocol, resource);
            }
            break;
    }
    return;

unixread_error:
    ERR("Received garbage: %d -- closing\n", res);
    deallocate_watch(GINT_TO_POINTER(thisbus->tmpbus_bpf_handle));
    deallocate_bus(thisbus);
    close(sockfd);
    return;
}

#if 0
#define PREAMBLE "rumpuser_shmif_lock_"
/* includes terminating 0: */
#define PREAMBLE_LEN 21
#endif

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

    /* handle clients one by one
     * to avoid races on the process table
     * (registering is not done often, so no need to hurry)
     */
    int res;
    if ((res = rcv_message_type(fd)) != SWARM_GETSHM) {
        ERR("Invalid GETSHM message: %d. Closing.\n", -res);
        close(fd);
        return;
    }

    ERR("Creating Bus\n");
    struct tmpbus *newbus = allocate_bus();

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

    if (initbus(newbus) != 0) {
        deallocate_bus(newbus);
        die(errno, "init tmpbus");
    }
#endif

    ERR("Add new event\n");
    int new_wd = inotify_add_watch(
            inotify_hdl, newbus->tmpbus_name, IN_MODIFY | IN_CLOSE_WRITE);
    if (new_wd < 0) {
        deallocate_bus(newbus);
        die(errno, "inotify watch");
    }
    newbus->tmpbus_wd = new_wd;

    // now answer the client with the bus file name
    if ((res = reply_swarm_getshm(
                fd, ip_addr_num, newbus->tmpbus_name))) {
        deallocate_bus(newbus);
        ERR("Error replying the client side: %d\n", -res);
    } else {
        g_hash_table_insert(
                busses, GINT_TO_POINTER(new_wd), newbus);
    }

    newbus->tmpbus_event = event_new(
            ev_base, fd, EV_READ|EV_PERSIST,
            handle_unixread, newbus);
    if (newbus->tmpbus_event == NULL) {
        die(0, "new bus event_new");
    }
    event_add(newbus->tmpbus_event, NULL);
}

int main(int argc, char *argv[]) {
    rump_init();

    atexit(cleanup);
    struct sigaction sigact = {
        .sa_handler = cleanup_sig
    };
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    ip_addr_num = inet_addr(IP_ADDRESS);
    init_hive(ip_addr_num);

    //can eventually be disabled
    event_enable_debug_mode();

    busses = g_hash_table_new_full(NULL, NULL,
            deallocate_watch, deallocate_bus);

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

