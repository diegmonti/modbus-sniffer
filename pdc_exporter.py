import sys

import dpkt
import prometheus_client
from prometheus_client import Counter, Gauge, start_http_server

prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)


start_http_server(8000)

current_gauge = None

g = {
    3000: Gauge('immergas_pdc_3000_mandata', 'Temp. mandata'),
    3001: Gauge('immergas_pdc_3001_ritorno', 'Temp. ritorno'),
    3002: Gauge('immergas_pdc_3002_esterna', 'Temp. esterna'),
    3056: Gauge('immergas_pdc_3056_refrigerante', 'Temp. refrigerante'),
    4551: Gauge('immergas_pdc_4551_batteria', 'Temp. batteria'),
    4554: Gauge('immergas_pdc_4554_scarico', 'Temp. scarico'),
    4558: Gauge('immergas_pdc_4558_delta', 'Temp. delta'),
    4585: Gauge('immergas_pdc_4585_compressore', 'Temp. compressore'),
    4586: Gauge('immergas_pdc_4586_modalita', 'Modalità PdC'),
    4587: Gauge('immergas_pdc_4587_frequenza', 'Frequenza PdC')
}

update_counter = Counter('immergas_pdc_update_counter', 'Contatore aggiornamenti di valore')


def get_gauge(rf):
    if rf in g:
        return g[rf]
    else:
        return None


pc = dpkt.pcap.Reader(sys.stdin.buffer)

for ts, pkt in pc:
    slave = pkt[0]
    fc = pkt[1]

    if slave != 11 or fc != 3:
        current_gauge = None
        continue

    if len(pkt) == 8:
        # query
        rf = int.from_bytes(pkt[2:4], byteorder='big')

        if current_gauge == None:
            current_gauge = get_gauge(rf)

    elif len(pkt) == 7:
        # response
        byte_count = pkt[2]
        value = int.from_bytes(pkt[3:3+byte_count],
                               byteorder='big', signed=True)

        if current_gauge != None:
            # fix offset
            if rf <= 4585:
                current_gauge.set(value / 10)
            else:
                current_gauge.set(value)

            update_counter.inc()

        current_gauge = None
