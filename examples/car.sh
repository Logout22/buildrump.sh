#! /bin/bash
./compile_ping.sh || exit
./pong &
sleep 1
./ping
wait
#read -p 'Truncate?'
#[ "$REPLY" = "Y" -o "$REPLY" = "y" ] && ./tr.sh
