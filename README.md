# tcpprint
A really simple tcpdump analog made as a kernel module.
It simply waits for packets to arrive and then, if anyone
is reading `/proc/next_packet` formats and outputs
the packet to `/proc/next_packet`.

tcpdump behaviour can be simulated by using this bash script
```bash
while cat /proc/next_packet; do :; done
```
