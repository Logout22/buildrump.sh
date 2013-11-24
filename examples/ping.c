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
#include <stropts.h>

#include <rump/rump.h>
#include <rump/netconfig.h>
#include <rump/rump_syscalls.h>
#include <rump/rumpnet_if_pub.h>

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

    rump_pub_shmif_create("etherbus", 0);

    printf("%d\n",
        rump_pub_netconfig_ipv4_ifaddr("shmif0", "10.165.8.1", "255.255.255.0"));

	die(0, NULL);
}
