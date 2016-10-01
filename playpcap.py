#! /usr/bin/env python

import sys
import argparse
import socket
import select
import errno
import pytun
from scapy.all import *
import time

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
        time.sleep(10)
        
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
    argument_parser.add_argument("taddr", help='set tunnel local address')
    argument_parser.add_argument('--tun-netmask', default='255.255.255.0',dest='tmask', help='set tunnel netmask')
    argument_parser.add_argument('--tun-mtu', type=int, default=1500,dest='tmtu', help='set tunnel MTU')
    argument_parser.add_argument("--role", default='client', choices=['client', 'server'], help='send on behalf or client or server')

    return argument_parser.parse_args()

            
def main():
    
    args = parse_args()

    try:
        server = TunnelServer(args.taddr, args.tmask, args.tmtu, args.role)
    except (pytun.Error, socket.error), e:
            print >> sys.stderr, str(e)
            return 1
    server.run()
    return 0

if __name__ == '__main__':
    sys.exit(main())

