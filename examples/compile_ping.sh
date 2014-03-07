if [ "$1" = "d" ]; then OPT="-O0"; else OPT="-O3"; fi
RD=../rump
SHMIFD=../src/sys/rump/net/lib/libshmif
cc -g -Wall -Wextra -Wshadow $OPT ping.c -o ping -I$RD/include -L$RD/lib \
       -Wl,-R$RD/lib -Wl,--no-as-needed \
       -lrumpnet_shmif -lrumpnet_config \
       -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump || exit 1
cc -g -Wall -Wextra -Wshadow $OPT swarm.c hive.c swarm_server_ipc.c \
	   $SHMIFD/shmif_busops.c -o swarm -I$RD/include -I$SHMIFD \
	   -Inetmap/sys -DNO_PCAP \
       `pkg-config --cflags glib-2.0` `pkg-config --cflags libevent` \
       `pkg-config --libs glib-2.0` `pkg-config --libs libevent` -lrt \
       || exit 1
cc -g -Wall -Wextra -Wshadow $OPT pong.c -o pong || exit 1
cc -g -Wall -Wextra -Wshadow $OPT ping_norump.c -o ping_norump || exit 1
cc -g -Wall -Wextra -Wshadow $OPT pong_rump.c \
       -o pong_rump -I$RD/include -L$RD/lib \
       -Wl,-R$RD/lib -Wl,--no-as-needed \
       -lrumpnet_shmif -lrumpnet_config \
       -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump || exit 1

