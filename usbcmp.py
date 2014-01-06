#!/usr/bin/env python
import pcapy
import csv
import sys
from usbrevue import Packet
pcaps = []
pockets = []
times = []
number = 0
for files in sys.argv[1:]:
    pcaps.append(pcapy.open_offline(files))

while True:
    for pcap in pcaps:
        t=pcap.next()
        pockets.append(t)
        times.append(0)
    if pockets[0][0] is None:
        break
    time=0
    poce=0
    ne = " "
    number += 1
    pack = 0
    pack_tmp = 0
    data = 0
    for pocket in pockets:
        pack = Packet(pocket[0],pocket[1])
        if pack.field_dict['setup'] is None:
            data = data or pack.data_hexdump(64)
            if data != pack.data_hexdump(64):
                ne = "#" 
            print("{} {:7d} Data {}".format(ne, number, pack.data_hexdump(64)))
            ne = " "
            continue
        data = data or pack.field_dict['setup'].fields_to_str()
        if data != pack.field_dict['setup'].fields_to_str():
            ne = "#"
        print("{} {:7d} Setup {}".format(ne, number, pack.field_dict['setup'].fields_to_str()))

        times[time] = times[time] or pack.ts_sec + pack.ts_usec/1e6
        time += 1
        ne = " "

    pockets=[]
    print ""



