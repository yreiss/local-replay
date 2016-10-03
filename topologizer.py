#! /usr/bin/env python

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

def remove_from_set(_set, entry):
    try:
        _set.remove(entry)
    except KeyError:
        pass

class topologizer:
    
    def __init__(self, pcap):

        self.pcap = pcap

        self.lan = Set()
        self.wan = Set()
        self.other_lan = Set()
        self.unknown_lan = Set()

        self.gw_mac=''
        self.gw_ip=''
        self.macs={}


    def remove_none(self):
        for s in [self.lan, self.wan, self.other_lan]:
            try:
                s.remove(None)
            except KeyError:
                pass

    def add_lan_wan_other(self, lan_ip=None, wan_ip=None, other_ip=None):
        self.lan.add(lan_ip)
        self.wan.add(wan_ip)
        self.other_lan.add(other_ip)
        remove_from_set(self.unknown_lan, lan_ip)
        remove_from_set(self.unknown_lan, other_ip)    
        self.remove_none()

    def set_gw_mac(self, mac):
        if self.gw_mac and self.gw_mac != mac:
            print "gw mac already set to ", self.gw_mac, " not changing to ", mac, " please check why this is happening"
        else:
            self.gw_mac = mac

    def analyze(self):
        pkts = rdpcap(self.pcap)    

        for pkt in pkts:
            if IP in pkt and Ether in pkt:

                if is_private(pkt[IP].src) and not is_private(pkt[IP].dst):
                    self.add_lan_wan_other(lan_ip=pkt[IP].src, wan_ip=pkt[IP].dst)
                    self.set_gw_mac(pkt[Ether].dst)

                elif is_private(pkt[IP].dst) and not is_private(pkt[IP].src):
                    self.add_lan_wan_other(lan_ip=pkt[IP].dst, wan_ip=pkt[IP].src)
                    self.set_gw_mac(pkt[Ether].src)
                    
                elif is_private(pkt[IP].src) and is_private(pkt[IP].dst):
                    if self.gw_mac and pkt[Ether].src != 'ff:ff:ff:ff:ff:ff' and pkt[Ether].dst != 'ff:ff:ff:ff:ff:ff':
                        if pkt[Ether].src == self.gw_mac:
                            self.add_lan_wan_other(lan_ip=pkt[IP].dst, other_ip=pkt[IP].src)
                        elif pkt[Ether].dst == self.gw_mac:
                            self.add_lan_wan_other(lan_ip=pkt[IP].src, other_ip=pkt[IP].dst)
                        else:
                            print "strange... ", pkt[IP].src, " and ", pkt[IP].dst, " don't use mac ", gw_mac
                    else:
                        check_add_to_unknown([pkt[IP].src, pkt[IP].dst])

                else:
                    print "both ", pkt[IP].src, " and ", pkt[IP].dst, " are public. Where did this pcap come from?"

            
                # add mac addresses and it associations with IP address
                if pkt[Ether].src not in self.macs:
                    self.macs[pkt[Ether].src] = Set()
                if pkt[Ether].dst not in self.macs:
                    self.macs[pkt[Ether].dst] = Set()            
                self.macs[pkt[Ether].src].add(pkt[IP].src)
                self.macs[pkt[Ether].dst].add(pkt[IP].dst)

        # if the gw mac was not found by now, try to guess by the most used mac address
        if not self.gw_mac:
            m = max(self.macs, key=lambda x: len(self.macs[x]))
            if m > 1:
                self.gw_mac = m
    
        
        return self.lan, self.wan, self.other_lan, self.unknown_lan


def parse_args():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("pcap", help="pcap to analyze")

    return argument_parser.parse_args()

def main():

    args = parse_args()
    top = topologizer(args.pcap)
    lan, wan, other, unknown = top.analyze()

    print lan
    print
    print wan
    print
    print other
    print
    print unknown

    return 0

if __name__ == '__main__':
    sys.exit(main())
