#! /usr/bin/env python

## analyze a pcap file and divides all participating IP addresses into 5 groups - lan, other lan, wan, gw and spoofed
## 
## The analysis is heuristic and based on the more common behavior (e.g. when 'guessing' the subnet, a 255.255.255.0 is more common than 255.255.0.0 or 255.255.252.0).
## The devision is from the perspective of the interface on which the capture was made.
## Captures currently supported are from a devices interface or from a router's lan interface.

## The logic of the topologizer goes like this:
## We go over all of the packets
## For each packet we check the source and destination addresses.

## If one is private (rfc1918) and the other is public (i.e. not private, not broadcast (heuristically) and not multicast), 
## then the destination MAC address is the GW mac address. Also, the private address belongs to the LAN and the public belongs to the WAN.

## If both are private, then there are three options:
## a. Both belong to the LAN
## b. One belongs to the LAN and the other belongs to a different subnet behind the router.
## c. One belongs to the LAN and the other is the GW
## We can't tell which is the case unless we already decided which is the GW mac address. 
## If we did, then if this mac address is used to access one of the nodes then it must be either the GW or on a different subnet. 
## In this case we will put it on the 'other lan' list and try later to check if it's a GW.
## If we did not (find the GW mac address already), then we push both back to the 'unknown'

## If a node sends 'broadcast' or 'multicast' messages, then it's quite safe to assume that it's either on the LAN or the GW, 
## since routers don't normally route (directed) broadcast messages. It's better to look at L2 than at L3 for that matter.

## Once we've gone over all of the packets, if we still have some 'unknown' packets, we make a second path over the packets, this time maybe with more information.

## Once finished, we will go over all of the LAN nodes, and try to check for addresses that don't match the LAN. This can happen either due to spoofing (not so common)
## or due to changes in the address of a device (e.g. a 3G mobile device still uses his old address). 
## So we need to figure out which is the true LAN subnet and which are aliens. We can use several heuristics like whether there was response from the outside to the caller, and if there was none - check the amount of packets from each subnet option. It is not clear how to decide which is the internal subnet. I.e. 10.x.x.x vs. 192.168.x.x is clear. But 192.168.2.x vs 192.168.4.x - are these two subnets, or a big subnet of 192.168.x.x?

## At the end, we still need to decide which of the 'other' nodes is the GW. Note that they all use the GW's mac address so this can't be the way to decide. 
## Once we concluded which is the subnet, we find the 'best match' out of the other, pull it out of the 'other' list, and crown it as the GW.

## Of course, the arguments to the main function (or to the topologizer constructor) allow us to pass the GW and subnet in case they are known.


from scapy.all import *
import argparse
from sets import Set

def is_private(ipv4_addr):
    ad = [int(x) for x in ipv4_addr.split('.')]
    if ad[0] == 10:
        return True
    if ad[0] == 192 and ad[1] == 168:
        return True
    if ad[0] == 172 and (ad[1] >= 16 and ad[1] <= 31):
        return True
    return False

def is_public(ipv4_addr):
    return not is_private(ipv4_addr) and not is_broadcast_ip(ipv4_addr) and not is_multicast_ip(ipv4_addr)

#  this is of course not true, but we are only providing some heuristics as we don't have the subnet configuration.
# Maybe we'll think of a way to improve this later by providing better heuristics based on the collection of packets.
def is_broadcast_ip(ipv4_addr):
    return ipv4_addr.split('.')[3] == '255'

def is_multicast_ip(ipv4_addr):
    high = int(ipv4_addr.split('.')[0])
    return high >= 224 and high <= 239

class topologizer:
    
    def __init__(self, pcap, gw=None, subnet=None):

        self.pcap = pcap

        self.suspected_lan = Set()  # a host is only suspected as belonging to the LAN if it sends packets out or to the broadcast.
                                    # this is because sometimes hosts send from the wrong IP (e.g. mobile devices after moving from provider network to wifi).
        self.confirmed_lan = Set()  # a host is confirmed to be in the LAN if it received traffic from the GW (i.e. from the gw's mac address)
        self.wan = Set()
        self.other_lan = Set()
        self.second_path = []
        self.gw = gw
        self.subnet = subnet

        self.gw_mac=''
        self.gw_ip=''
        self.macs={}



    def add_lan_wan_other(self, suspected_lan_ip=None, wan_ip=None, other_ip=None, confirmed_lan_ip=None):
        if suspected_lan_ip and suspected_lan_ip not in self.confirmed_lan:
            self.suspected_lan.add(suspected_lan_ip)
        if wan_ip:
            self.wan.add(wan_ip)
        if other_ip and (self.gw != other_ip):
            self.other_lan.add(other_ip)
        if confirmed_lan_ip:
            self.confirmed_lan.add(confirmed_lan_ip)
            if confirmed_lan_ip in self.suspected_lan:
                self.suspected_lan.remove(confirmed_lan_ip)

    def set_gw_mac(self, mac):
        if self.gw_mac and self.gw_mac != mac:
            print "gw mac already set to ", self.gw_mac, " not changing to ", mac, " please check why this is happening"
        else:
            self.gw_mac = mac


    def determine_gw_and_subnet(self):
        pass

    def crown_gw(self, gw):
        print "crowning .... "
        if not self.gw:
            self.gw = gw
            if gw in self.other_lan:
                self.other_lan.remove(gw)
        elif self.gw != gw:
            print "warning - gw already set to ", self.gw, " but a new crowning requested to ", gw, " - ignoring second"


    def run(self):
        pkts = rdpcap(self.pcap)  
        self.analyze_packets(pkts)
        self.analyze_packets(self.second_path, True)

        self.determine_gw_and_subnet()
        
        return self.confirmed_lan, self.suspected_lan, self.wan, self.other_lan, self.gw, self.subnet

    def analyze_packets(self, pkts, second_run=False):

        for pkt in pkts:
            if IP in pkt and Ether in pkt:

                # broadcast
                if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
                    if self.gw_mac:
                        if self.gw_mac == pkt[Ether].src:
                            self.crown_gw(pkt[IP].src)
                        elif is_private(pkt[IP].src):
                            self.add_lan_wan_other(suspected_lan_ip=pkt[IP].src)
                    else:
                        self.second_path.append(pkt)

                # LAN to WAN
                elif is_private(pkt[IP].src) and is_public(pkt[IP].dst):
                    self.add_lan_wan_other(suspected_lan_ip=pkt[IP].src, wan_ip=pkt[IP].dst)
                    self.set_gw_mac(pkt[Ether].dst)

                # WAN to LAN
                elif is_private(pkt[IP].dst) and is_public(pkt[IP].src):
                    self.add_lan_wan_other(confirmed_lan_ip=pkt[IP].dst, wan_ip=pkt[IP].src)
                    self.set_gw_mac(pkt[Ether].src)

                # LAN to LAN - could be same subnet or between subnets
                elif is_private(pkt[IP].src) and is_private(pkt[IP].dst):
                    if self.gw_mac:
                        if pkt[Ether].src == self.gw_mac:
                            self.add_lan_wan_other(confirmed_lan_ip=pkt[IP].dst, other_ip=pkt[IP].src)
                        elif pkt[Ether].dst == self.gw_mac:
                            self.add_lan_wan_other(suspected_lan_ip=pkt[IP].src, other_ip=pkt[IP].dst)
                        else:
                            print "strange... ", pkt[IP].src, " and ", pkt[IP].dst, " don't use mac ", self.gw_mac
                    else:
                        self.second_path.append(pkt)


                if not second_run:
                    # add mac addresses and it associations with IP address
                    if pkt[Ether].src not in self.macs:
                        self.macs[pkt[Ether].src] = Set()
                        if pkt[Ether].dst not in self.macs:
                            self.macs[pkt[Ether].dst] = Set()            
                            self.macs[pkt[Ether].src].add(pkt[IP].src)
                            self.macs[pkt[Ether].dst].add(pkt[IP].dst)

        if not second_run:
            # if the gw mac was not found by now, try to guess by the most used mac address
            if not self.gw_mac:
                m = max(self.macs, key=lambda x: len(self.macs[x]))
                if m > 1:
                    self.gw_mac = m





def parse_args():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("pcap", help="pcap to analyze")
    argument_parser.add_argument("--gw", help="specify gw if known")
    argument_parser.add_argument("--subnet", help="specify subnet if known")    

    return argument_parser.parse_args()

def main():

    args = parse_args()
    top = topologizer(args.pcap, args.gw, args.subnet)
    confirmed_lan, suspected_lan, wan, other, gw, subnet = top.run()

    print "confirmed lan", 
    print confirmed_lan
    print
    print "suspected lan", 
    print suspected_lan
    print
    print "wan", 
    print wan
    print
    print "other", 
    print other
    print
    print "gw", 
    print gw
    print
    print "subnet ",
    print subnet


    return 0

if __name__ == '__main__':
    sys.exit(main())
