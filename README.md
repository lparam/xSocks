xsocks
=================
A secure and fast proxy for protect your network traffic

Introdution
------------
* xsocksd: Backend of xsocks, xtproxy, xforwarder
* xsocks: A socks5 server
* xtproxy: A Transparent Proxy
* xforwarder: Forward data to a specific server
* xtunnel: Like xforwarder, but standalone and specify target on server side

Features
------------
* Transparent Proxy for all tcp traffic and udp packet
* Multithreading
* Avaliable on multiple platforms, including PC (Linux), Mobile (Android) and Routers (OpenWRT).

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
git clone https://github.com/lparam/xsocks.git
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
```

/etc/init.d/xsocks
```bash
#!/bin/sh /etc/rc.common
# Copyright (C) 2006-2014 OpenWrt.org

START=72
STOP=30
FIREWALL_RELOAD=0
SERVER=IP:PORT
PASSWORD=PASSWORD

start() {
    tproxy
    mkdir -p /var/run/xsocks
    xsocks -s $SERVER -k $PASSWORD
    xtproxy -s $SERVER -k $PASSWORD
    xforwarder -l 0.0.0.0:5533 -t 8.8.8.8:53 -s $SERVER -k $PASSWORD
}

stop() {
    xsocks --signal stop
    xtproxy --signal stop
    xforwarder --signal stop
}

shutdown() {
    xsocks --signal quit
    xtproxy --signal quit
    xforwarder --signal quit
}

tproxy() {
    local LISTEN_PORT=1070
    local IP_ROUTE_TABLE_NUMBER=100
    local FWMARK="0x01/0x01"
    local SETNAME=wall

    iptables -t nat -D PREROUTING -p tcp -j XSOCKS
    iptables -t nat -F XSOCKS
    iptables -t nat -X XSOCKS

    iptables -t mangle -D PREROUTING -j XSOCKS
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
}
```

```bash
root@OpenWrt:~# /etc/init.d/xsocks start
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
