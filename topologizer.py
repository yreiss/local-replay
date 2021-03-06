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
import lr_common

def is_private(ipv4_addr):
    ad = [int(x) for x in ipv4_addr.split('.')]
    if ad[0] == 10:
        return True
    if ad[0] == 192 and ad[1] == 168:
        return True
    if ad[0] == 172 and (ad[1] >= 16 and ad[1] <= 31):
        return True
    return False



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

    def get_single_subnet_class(self):
        subnets=Set()
        for ip in self.confirmed_lan:
            ad = [int(x) for x in ip.split('.')]
            if ad[0] == 10:
                subnets.add((10,))
            elif ad[0] == 192 and ad[1] == 168:
                subnets.add((192,168))
            elif ad[0] == 172 and (ad[1] >= 16 and ad[1] <= 31):
                subnets.add((172, ad[1]))

        if len(subnets) == 0:
            print "no confirmed lan ip addresses. cannot find subnet"
            raise Exception('could not find subnet')
        elif len(subnets) > 1:
            print "more than one confirmed subnet type. cannot find subnet."
            raise Exception('too many potential subnets', subnets)

        return next(iter(subnets))


        #  if we got here we have a winning 'subnet class'. Not yet the final subnet.

        '''
        Not sure this is correct. E.g. if the subnet is 192.168.1.0/24 and there are packets from 192.168.4.25 
        that did not receive an answer, not sure we want to confirm them

        for subnet in subnets:
            pass

        for ip in self.suspected_lan:
            ad = [int(x) for x in ip.split('.')]
            if subnet[0] == ad[0] and (len(subnet) == 1 or subnet[1] == ad[1]):
                self.add_lan_wan_other(confirmed_lan_ip = ip)
        '''

    def calc_bits(self, ip_set, base_ip):

        # Now let's try and guess the mask. Basically there is no way to know for sure. So what we're doing is assuming that it's a 24 bit network.
        # Then we go over all of the ip addresses in the confirmed lan. If we see indication that it's less than 24 bits, we reduce the bits.
        # We do assume that there is no <16 bits subnet. So we're only checking the third byte of the IPv4.

        ip_set=Set(self.confirmed_lan)

        bits=24
        ip=next(iter(ip_set))
        initial_ip = [int(x) for x in ip.split('.')]

        for ip in ip_set:
            ad = [int(x) for x in ip.split('.')]
            debt=0
            for i in [2**x for x in range(0, bits-16-1)]:
                if (initial_ip[2] & i) != (ad[2]&i):
                    bits = bits - 1 - debt
                    debt=0
                else:
                    debt += 1

        return bits

    def is_public(self, ipv4_addr):
        return not is_private(ipv4_addr) and not self.is_broadcast_ip(ipv4_addr) and not lr_common.is_multicast_ip(ipv4_addr)
        
    def is_broadcast_ip(self, ipv4_addr):
        bip = self.get_broadcast_ip()
        if bip:
            return ipv4_addr == "255.255.255.255" or ipv4_addr == bip
        else:
            # we don't know the subnet yet - just hope checking last byte is enough
            return ipv4_addr.split('.')[3] == '255'

    def ip_in_subnet_class(self, ip, sn):
        ip = [int(x) for x in ip.split('.')]
        return (ip[0] == sn[0]) and ((sn[0] == 10) or (ip[1] == sn[1]))       

    def determine_gw_and_subnet(self):
        # subnet not received from caller
        if not self.subnet:
            try:
                sn = self.get_single_subnet_class()
            except Exception as e:
                print e
                raise

            ip_set = Set(self.confirmed_lan)
            if self.gw:
                ip_set.add(self.gw)
            base_ip = next(iter(ip_set))
            bits = self.calc_bits(ip_set, base_ip)
            
            #  both subnet and gw were not given by the caller.
            #  checking if other_lan contains something that may be the GW.
            if not self.gw:
                best_bits = 0
                candidates=[]
                for ip in self.other_lan:
                    if self.ip_in_subnet_class(ip, sn):
                        ip_set = Set(self.confirmed_lan)
                        ip_set.add(ip)
                        base_ip = next(iter(ip_set))
                        temp_bits = self.calc_bits(ip_set, base_ip)
                        best_bits = max(best_bits, temp_bits)
                        if temp_bits == best_bits:
                            candidates.append(ip)
                if candidates and len(candidates) == 1:
                    self.crown_gw(candidates[0])
                    bits=best_bits
                
            base_ip = [int(x) for x in next(iter(self.confirmed_lan)).split('.')]
            mask=0xffffffff - (2**(32-bits)-1)
            subnet_address=(base_ip[0]<<24) + (base_ip[1]<<16) + (base_ip[2]<<8) + base_ip[3]
            subnet_address= subnet_address & mask
     
            # s=subnet_address
            self.subnet = lr_common.ip_itoa(subnet_address) + '/' + str(bits)
            # self.subnet=str(s>>24) + '.' + str((s & (0xff0000))>>16) + '.' + str((s & (0xff00))>>8) + '.' + str(s & 0xff) + '/' + str(bits)

        
        elif not self.gw: # subnet was provided but not GW
            sn = self.subnet.split('/')
            bits=int(sn[1])
            third_byte_mask = 0xff - (2**(24-bits)-1)
            snaddr=[int(x) for x in sn[0].split('.')]
            for ip in self.other_lan:
                ad = [int(x) for x in ip.split('.')]
                if (ad[0] == snaddr[0]) and (ad[1] == snaddr[1]) and ((ad[2] & third_byte_mask) == snaddr[2]):
                    self.crown_gw(ip)
                    break

    def get_broadcast_ip(self):
        if self.subnet:
            bcst = lr_common.ip_atoi(self.subnet.split('/')[0])
            bits = int(self.subnet.split('/')[1])
            bcst |= (2**(32-bits)-1)
            return lr_common.ip_itoa(bcst)
        else:
            return None

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
                elif is_private(pkt[IP].src) and self.is_public(pkt[IP].dst):
                    self.add_lan_wan_other(suspected_lan_ip=pkt[IP].src, wan_ip=pkt[IP].dst)
                    self.set_gw_mac(pkt[Ether].dst)

                # WAN to LAN
                elif is_private(pkt[IP].dst) and self.is_public(pkt[IP].src):
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
    argument_parser.add_argument("--subnet", help="specify subnet if known. Subnet should be specified in the CIDR form (x.x.x.x/n, e.g. 192.168.133.0/22)")    

    return argument_parser.parse_args()

def main():

    args = parse_args()
    top = topologizer(args.pcap)
    confirmed_lan, suspected_lan, wan, other, gw, subnet = top.run()
    
    arr = ["confirmed_lan", "suspected_lan", "wan", "other", "gw", "subnet"]
    for e in arr:
        print e + ": ",
        print eval(e)
        print

    return 0

if __name__ == '__main__':
    sys.exit(main())
