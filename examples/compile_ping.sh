RD=../rump
cc -g -Wall -O3 ping.c -o ping -I$RD/include -L$RD/lib -Wl,-R$RD/lib -Wl,--no-as-needed -lrumpnet_shmif -lrumpnet_config -lrumpdev_bpf -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump || exit 1
cc -g -Wall -O3 pong.c -o pong -I$RD/include -L$RD/lib -Wl,-R$RD/lib -Wl,--no-as-needed -lrumpnet_shmif -lrumpnet_config -lrumpdev_bpf -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump

