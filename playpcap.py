import sys
import optparse
import socket
import select
import errno
import pytun
from scapy.all import *
import time

class TunnelServer(object):

    def __init__(self, taddr, tmask, tmtu, is_writer):
        self._tun = pytun.TunTapDevice(flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
        self._tun.addr = taddr
        self._tun.netmask = tmask
        self._tun.mtu = tmtu
        self._tun.up()
        self._is_writer = is_writer

    def send_pcap(self):
        pkt=IP(src="10.0.1.6", dst="10.0.0.6")/UDP(dport=50000)/("hello")
        self._tun.write(str(pkt))
        print(":".join("{:02x}".format(ord(c)) for c in str(pkt)))
        time.sleep(10)
        
    def run(self):
        mtu = self._tun.mtu
        received=''

        if (self._is_writer):
            self.send_pcap()
            exit()


        while True:
            received = self._tun.read(mtu)
            print(":".join("{:02x}".format(ord(c)) for c in str(received)))
            
def main():
    parser = optparse.OptionParser()
    parser.add_option('--tun-addr', dest='taddr',
                      help='set tunnel local address')
    parser.add_option('--tun-netmask', default='255.255.255.0',dest='tmask',
                      help='set tunnel netmask')
    parser.add_option('--tun-mtu', type='int', default=1500,dest='tmtu',
                      help='set tunnel MTU')
    parser.add_option("-w", action="store_true", dest="writer", help='writer to tun instead of read')
    opt, args = parser.parse_args()
    iswriter = True if opt.writer else False

    if not opt.taddr:
        parser.print_help()
        return 1
    try:
        server = TunnelServer(opt.taddr, opt.tmask, opt.tmtu, iswriter)
    except (pytun.Error, socket.error), e:
            print >> sys.stderr, str(e)
            return 1
    server.run()
    return 0

if __name__ == '__main__':
    sys.exit(main())

