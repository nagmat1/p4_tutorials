#!/usr/bin/env python3
from scapy.all import *
import sys

count=int(sys.argv[1])
out_file=sys.argv[2]

def convert_to_int(list_val):
    return int("".join(list_val), 16)


rcvd_pkts = []
rcvd_packets_loads = []

#sniff(filter='ether proto 0xAAA', count=count, iface="iface1", prn=lambda pkt: rcvd_packets_loads.append(linehexdump(pkt[Raw], dump=True, onlyhex=1)))
sniff(count=count, iface="eth0", prn=lambda pkt: rcvd_packets_loads.append(linehexdump(pkt[Raw], dump=True, onlyhex=1)))
with open(out_file, "w") as out:
    for pkt in rcvd_packets_loads:
        out.write(pkt)
        tokens = pkt.split(" ")
        out.write(f"\nenq_timestamp {convert_to_int(tokens[0:4])}\n")
        out.write(f"enq_depth {convert_to_int(tokens[4:8])}\n")
        out.write(f"deq_timedelta {convert_to_int(tokens[8:12])}\n")
        out.write(f"deq_depth {convert_to_int(tokens[12:16])}\n")
        out.write("***************************************\n")

