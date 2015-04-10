xsocks
=================
A secure and fast proxy for protect your network traffic

Features
------------
* Transparent Proxy for all tcp traffic and udp packet
* Multithreading

Installation
------------

### Linux

```bash
make && sudo make install
```

### OpenWRT

```bash
# At OpenWRT build root
cd package
git clone https://github.com/xsocks/xsocks.git
cd ..

# Build the package
make package/xsocks/openwrt/compile
```

Usage
------------

### Server

```bash
xsocksd -k PASSWORD
xtunnel -m server -k PASSWORD -t TARGET:PORT
```

Multithreading:
```bash
xsocksd -k PASSWORD -c THREADS
```

Stop:
```bash
xsocksd --signal stop
```

### Client

```bash
xsocks -s SERVER:PORT -k PASSWORD
xforwarder -s SERVER:PORT -k PASSWORD -t TARGET:PORT
xtunnel -m client -k PASSWORD -t TARGET:PORT
```

### Transparent Proxy

Proxy all tcp traffic and udp packet transparently on gateway.

```bash
root@OpenWrt:~# opkg install iptables-mod-tproxy
root@OpenWrt:~# xtproxy -s SERVER:PORT -k PASSWORD
```

tproxy.sh
```bash
#!/bin/sh

LISTEN_PORT=1070
IP_ROUTE_TABLE_NUMBER=100
FWMARK="0x01/0x01"
SETNAME=wall

iptables -t nat -F XSOCKS
iptables -t nat -X XSOCKS

iptables -t mangle -F XSOCKS
iptables -t mangle -X XSOCKS

iptables -t nat -N XSOCKS
iptables -t mangle -N XSOCKS

ipset -F $SETNAME
ipset -X $SETNAME
ipset -N $SETNAME iphash

### TCP
iptables -t nat -A XSOCKS -p tcp -m set --match-set $SETNAME dst -j REDIRECT --to-port $LISTEN_PORT
iptables -t nat -A PREROUTING -p tcp -j XSOCKS

### UDP
ip rule del fwmark $FWMARK table $IP_ROUTE_TABLE_NUMBER
ip route del local 0.0.0.0/0 dev lo table $IP_ROUTE_TABLE_NUMBER

ip rule add fwmark $FWMARK table $IP_ROUTE_TABLE_NUMBER
ip route add local 0.0.0.0/0 dev lo table $IP_ROUTE_TABLE_NUMBER

iptables -t mangle -A XSOCKS -p udp -m set --match-set $SETNAME dst -j TPROXY \
            --on-port $LISTEN_PORT --tproxy-mark $FWMARK
iptables -t mangle -A PREROUTING -j XSOCKS
```

```bash
root@OpenWrt:~# tproxy.sh
```

```bash
root@OpenWrt:~# ipset add SETNAME IP
```

## License

Copyright (C) 2014 Ken <ken.i18n@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
