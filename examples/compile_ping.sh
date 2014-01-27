RD=../rump
SHMIFD=../src/sys/rump/net/lib/libshmif
cc -g -Wall -O0 ping.c swarm_ipc.c -o ping -I$RD/include -L$RD/lib \
       -Wl,-R$RD/lib -Wl,--no-as-needed \
       -lrumpnet_shmif -lrumpnet_config -lrumpdev_bpf \
       -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump || exit 1
cc -g -Wall -O0 swarm.c $SHMIFD/shmif_busops.c hive.c swarm_ipc.c \
       -o swarm -I$RD/include -I$SHMIFD \
       `pkg-config --cflags glib-2.0` `pkg-config --cflags libevent` \
       `pkg-config --libs glib-2.0` `pkg-config --libs libevent` -lrt \
        -lrumpnet_shmif -lrumpnet_config \
        -lrumpvfs -lrumpdev -lrumpdev_bpf \
        -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump \
       || exit 1
cc -g -Wall -O0 pong.c -o pong
