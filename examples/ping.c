#include <sys/types.h>
#include <sys/cdefs.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rump/rump.h>
#include <rump/netconfig.h>
#include <rump/rump_syscalls.h>
#include <rump/rumpnet_if_pub.h>

#include <rumpnet/rumpnet_if_priv.h>

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{

	if (msg)
		warnx("%s: %d", msg, e);
	rump_sys_reboot(0, NULL);
	exit(e);
}

int main(int argc, char *argv[]) {
	rump_init();

	rump_schedule();
    rump_shmif_create("etherbus", 0);

    struct ifaliasreq ifa = {};
	union {
		struct sockaddr *sa;
		struct sockaddr_in *sin;
	} _s;
	strlcpy(ifa.ifra_name, "shmif0", sizeof(ifa.ifra_name));
#define ADDADDR(_var, _addr) {						      \
		_s.sa = &_var;						      \
		_s.sin->sin_family = AF_INET;				      \
		_s.sin->sin_len = sizeof(*_s.sin);			      \
		memcpy(&_s.sin->sin_addr, _addr, sizeof(_s.sin->sin_addr));   \
	}

	ADDADDR(ifa.ifra_addr, 0x108a50a);
	ADDADDR(ifa.ifra_mask, 0xffffff);
    ADDADDR(ifa.ifra_broadaddr, 0xff08a50a);
#undef ADDADDR

    rump_pub_lwproc_rfork(RUMP_RFCFDG);
    struct lwp *curlwp = rump_pub_lwproc_curlwp();

    struct socket *socket_afnet;
	if ((error = socreate(PF_INET, &socket_afnet, SOCK_DGRAM, 0,
	    curlwp, NULL)) != 0) {
        rump_unschedule();
        die(error, "socreate");
    }

    printf("%d\n", ifioctl(socket_afnet, SIOCDIFADDR, &ifa, curlwp));

	rump_unschedule();

	die(0, NULL);
}
