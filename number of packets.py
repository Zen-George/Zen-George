import dpkt
counter=0
ipcounter=0
tcpcounter=0
udpcounter=0
igmpcounter=0
TCP_timestamps = []

for ts, pkt in dpkt.pcap.Reader(open('evidence-packet-analysis.pcap','rb')):


    counter+=1
    eth=dpkt.ethernet.Ethernet(pkt)
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
       continue

 

    ip=eth.data
    ipcounter+=1
    
    packet = eth.data
    packets.append(packet)
    
    ip = eth.data
    if packet.p == dpkt.ip.IP_PROTO_TCP:
        TCP_timestamps.append(ts)

TCP_timestamps.sort()


number_of_tcp_packtes = len(TCP_timestamps)
earliest_TCP = TCP_timestamps[0]
latest_TCP = TCP.timestamps[-1]
 

    if ip.p==dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        tcppacketlength = len(tcp)
        tcpcounter+=1
 

    if ip.p==dpkt.ip.IP_PROTO_UDP:
        udp= ip.data
        udppacketlength = len(udp)
        udpcounter+=1

    if ip.p==dpkt.ip.IP_PROTO_IGMP:
        tcp = ip.data
        tcppacketlength = len(tcp)
        igmpcounter+=1
       


print ("\t Total number of packets in the pcap file: ", ipcounter)
print ("\t Protocol type: \t Number of packets: \t Mean packet length \t First timestamp \t Last timestamp ")
print ("\t TCP: \t\t\t", tcpcounter, "\t\t\t Testmean", "\t\t 00:00", "\t\t\t 00:00")
print ("\t UDP: \t\t\t", udpcounter, "\t\t\t Testmean", "\t\t 00:00", "\t\t\t 00:00")
print ("\t IGMP: \t\t\t", igmpcounter, "\t\t\t Testmean", "\t\t 00:00", "\t\t\t 00:00")