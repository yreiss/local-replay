#! /usr/bin/env python

from socket import AF_INET
from pyroute2 import IPRoute
ip = IPRoute()


import sys
import argparse
import socket
import select
import errno
import pytun
from scapy.all import *
import time
from topologizer import topologizer
import unshare
import pprint
import lr_common


class TunnelServer(object):

    def __init__(self, taddr, tmask, tmtu, role):
        self._tun = pytun.TunTapDevice(flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
        self._tun.addr = taddr
        self._tun.netmask = tmask
        self._tun.mtu = tmtu
        self._tun.up()
        self._role = role

    def send_pcap(self):
        pkt=IP(src="10.0.1.6", dst="10.0.0.6")/UDP(dport=50000)/("hello")
        self._tun.write(str(pkt))
        print(":".join("{:02x}".format(ord(c)) for c in str(pkt)))
        time.sleep(20)
        
    def run(self):
        mtu = self._tun.mtu
        received=''

        if (self._role == 'client'):
            self.send_pcap()
            exit()

        while True:
            received = self._tun.read(mtu)
            print(":".join("{:02x}".format(ord(c)) for c in str(received)))


def parse_args():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("pcap", help="pcap to replay")
    #argument_parser.add_argument("taddr", help='set tunnel local address')
    argument_parser.add_argument('--tun-netmask', default='255.255.255.0',dest='tmask', help='set tunnel netmask')
    argument_parser.add_argument('--tun-mtu', type=int, default=1500,dest='tmtu', help='set tunnel MTU')
    argument_parser.add_argument("--role", default='client', choices=['client', 'server'], help='send on behalf or client or server')
    argument_parser.add_argument("--max-routes", dest='mroutes',  default=50, type=int, help='maximum number of routes to add for ip addresses in the pcap')

    return argument_parser.parse_args()


def tun_create(address, netmask, mtu):
    _tun = pytun.TunTapDevice(flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
    _tun.addr = address
    _tun.netmask = netmask
    _tun.mtu = mtu
    _tun.up()
    return _tun


def ip_in_subnet(ip, subnet):
    s = subnet.split('/')[0]
    inet = reduce(lambda x, y: (int(x)<<8)+int(y), s.split('.'))
    bits=int(subnet.split('/')[1])
    mask = (2**32) - (2**(32-bits))
    iip = reduce(lambda x, y: (int(x)<<8)+int(y), ip.split('.'))
    return (iip & mask) == (inet & mask)
            
def main():
    
    args = parse_args()

    top = topologizer(args.pcap)
    confirmed_lan, suspected_lan, wan, other, gw, subnet =  top.run()

    if (not gw) or not (subnet):
        print "can't continue without gw and subnet"
        exit(1)

    print "gw: ",
    print gw

    bits=int(subnet.split('/')[1])
    mask = ((2**32)-1) - (2**(32-bits)-1)
    netmask = str(mask>>24) + '.' + str((mask & (0xff0000))>>16) + '.' + str((mask & (0xff00))>>8) + '.' + str(mask & 0xff)

    lan_tun = tun_create(gw, netmask, args.tmtu)
    print lan_tun

    wan_tun = tun_create("100.100.100.100", "255.255.255.0", args.tmtu)
    print wan_tun

    # now let's make wan_tun the default GW
    ip.route("add", dst="0.0.0.0", gateway="100.100.100.100")
    
    pkts = rdpcap(args.pcap)
    for pkt in pkts:
        if 'IP' in pkt:
            pkt = IP(str(pkt[IP])[0:pkt[IP].len])  # get rid of Eth Layer

            if top.is_broadcast_ip(pkt[IP].dst) or lr_common.is_multicast_ip(pkt[IP].dst) or pkt[IP].src == gw or pkt[IP].dst == gw:
                continue

            l = len(str(pkt))
            if l > args.tmtu:
                print "skipping packet of size " + str(l) + " which is bigger than mtu (" + str(args.tmtu) + ")"
                continue

            #  TODO - handle case where source is the GW

            if ip_in_subnet(pkt[IP].src, subnet):
                w = lan_tun.write(str(pkt))
                print "wrote to lan " + str(w) + " bytes"
            else:
                w = wan_tun.write(str(pkt))
                print "wrote to wan " + str(w) + " bytes"

           
            if ip_in_subnet(pkt[IP].dst, subnet):
                print "reading from lan ..."
                r = lan_tun.read(args.tmtu)
                print "read from lan " + str(len(r)) + " bytes"
            else:
                r = wan_tun.read(args.tmtu)
                print "read from wan " + str(len(r)) + " bytes"
            

    print "sleeping ..."

    time.sleep(20)

    exit (0)

    

    try:
        server = TunnelServer(args.taddr, args.tmask, args.tmtu, args.role)
    except (pytun.Error, socket.error), e:
            print >> sys.stderr, str(e)
            return 1
    server.run()
    return 0

if __name__ == '__main__':
    sys.exit(main())

