#! /bin/sh
if [ ! -d /opt/swarm ]; then
    mkdir /opt/swarm
    chmod 777 /opt/swarm
fi
if [ ! -d /run/swarm ]; then
    mkdir /run/swarm
    chmod 777 /run/swarm
fi
insmod netmap/LINUX/netmap_lin.ko
chmod 666 /dev/netmap
ethtool -K eth0 tso off
ethtool -K eth0 gso off
ethtool -K eth0 gro off

