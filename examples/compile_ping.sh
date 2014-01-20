RD=../rump
SHMIFD=../src/sys/rump/net/lib/libshmif
cc -g -Wall -O3 ping.c -o ping -I$RD/include -L$RD/lib -Wl,-R$RD/lib -Wl,--no-as-needed -lrumpnet_shmif -lrumpnet_config -lrumpdev_bpf -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump || exit 1
cc -g -Wall -O3 swarm.c $SHMIFD/shmif_busops.c -o swarm -I$RD/include -I$SHMIFD -lrt || exit 1
#-L$RD/lib -Wl,-R$RD/lib -Wl,--no-as-needed -lrumpnet_shmif -lrumpnet_config -lrumpdev_bpf -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump
cc -g -Wall -O3 ping_norump.c -o ping_norump || exit 1
c99 -g -Wall -O3 pong.c -o pong
