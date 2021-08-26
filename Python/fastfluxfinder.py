from scapy.all import *

dnsRecords = {}

def checkPacket(packet):
    if packet.haslayer(DNSRR):
        rrname = packet.getlayer(DNSRR).rrname
        rdata = packet.getlayer(DNSRR).rdata
        if rrname in dnsRecords:
            if rdata not in dnsRecords[rrname]:
                dnsRecords[rrname].append(rdata)
        else:
            dnsRecords[rrname] = {}
            dnsRecords[rrname].append(rdata)

def main():
    packets = rdpcap('/home/taz/Downloads/fastFlux.pcap')
    for pkt in packets:
        checkPacket(pkt)
    for item in dnsRecords:
        print('[+] ' + item + ' has ' + str(len(dnsRecords[item])) + ' unique IPs')

if __name__ == '__main__':
    main()
