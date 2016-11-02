#! /usr/bin/env python

def ip_atoi(aip):
    return reduce(lambda x, y: (int(x)<<8)+int(y), aip.split('.'))

def ip_itoa(iip):
    return str(iip>>24) + '.' + str((iip & (0xff0000))>>16) + '.' + str((iip & (0xff00))>>8) + '.' + str(iip & 0xff)

def is_multicast_ip(ipv4_addr):
    high = int(ipv4_addr.split('.')[0])
    return high >= 224 and high <= 239
