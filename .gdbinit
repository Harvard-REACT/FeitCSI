layout src
set inferior-tty /dev/pts/2
b initInterface
b createMonitorInterface

r --mode inject --frequency 5520 --channel-width 20 --format VHT --inject-delay 15000 --tx-power 20 --mac 11:23:58:13:21:34,2a:2a:2a:2a:2a:2a -v