import datetime
import sys

import dpkt


pc = dpkt.pcap.Reader(sys.stdin.buffer)

row = []
rf_list = []
sampler = 0

for ts, pkt in pc:
    slave = pkt[0]
    fc = pkt[1]

    if sampler > 1000:
        sampler = 0
        rf_list = []

    if slave != 11 or fc != 3:
        row = []
        continue

    if len(pkt) == 8:
        # query
        dt = datetime.datetime.fromtimestamp(int(ts))
        rf = int.from_bytes(pkt[2:4], byteorder='big')

        if rf in rf_list:
            sampler += 1
            continue
        else:
            rf_list.append(rf)

        if len(row) == 0:
            row.append(dt.isoformat(sep=' '))
            row.append(str(rf))

    elif len(pkt) == 7:
        # response
        byte_count = pkt[2]
        value = int.from_bytes(pkt[3:3+byte_count], byteorder='big', signed=True)

        if len(row) == 2:
            row.append(str(value))
            print(','.join(row))

        row = []
