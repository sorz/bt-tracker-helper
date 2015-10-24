# BitTorrent Tracker Firewall Helper

[Chinese (中文)](https://blog.sorz.org/p/bt-tracker-helper/)

It's known that detecting BT traffic itself is difficult.
However, in most of time, BT client will connect to some tracker servers 
during running. This kind of connections  can be detected easily by a few
of firewall rules.

This program try to simplify the process of configuring firewalls to detect
connections with BT tracker servers by providing the following two functions:

* Reading tracker server addresses from a set of torrents.
* Resolve server name, and generate firewall rules.

Example
-------

Collect tracker servers from torrent files,
then add them to ipset `blacklist`:
```
$ ./trackers.py torrent *.torrent > trackers.txt
$ ./trackers.py ipset blacklist trackers.txt > ipset-rules
# ipset restore -file ipset.rules
```

Or by one line:
```
# ./trackers.py torrent *.torrent | ./trackers.py ipset blacklist - | ipset restore
```

You may use `iptables` to match this ipset, and do filter,
logging or something.

Generating iptables commands directly is also supported by
`./trackers.py iptables` command. If you want more custom,
try `./trackers.py raw`, which print address, protocol
and port number without any other addition information.
