import socket
import time
import matplotlib.pyplot as plt

import networkx as nx
from datetime import datetime
import argparse
import scapy.all as s
parser = argparse.ArgumentParser(description="Parsing packet header")
parser.add_argument('-M','--TTL',type=int,default=32,help='enter the ttl value')
parser.add_argument('-f','--first_ttl',type=int,default=1,help='enter the ttl value')
parser.add_argument('-w','--wait',type=int,default=1,help='enter the timeout value')
parser.add_argument('-q','--nbrSeries',type=int,default=1,help='how many series of packets in step')
parser.add_argument('-p_tcp','--port_tcp',type=int,default=80,help='tcp port number')
parser.add_argument('-p_ucp','--port_ucp',type=int,default=33434,help='tcp port number')
parser.add_argument('-L','--length',type=int,default=40,help='tcp port number')
parser.add_argument('-in','--input_file',help='the input file containing a list of destination addresses (one per line)')
parser.add_argument('-n','--noDns',action='store_true',help='Stop resolving ip addr')




args = parser.parse_args()
if args.input_file:
    with open(args.input_file, 'r') as f:
        tab = [line.strip() for line in f]

else:
    with open("input.txt", 'r') as f:
        tab = [line.strip() for line in f]

tab1 = ["8.8.8.8","145.97.39.155"]
Total = []
Gt = []
class ResultTot():
    def __init__(self,dest,route):
        self.dest = dest
        self.route = route
class Result():
    def __init__(self,ip,dns,rtt1,rtt2,rtt3):
        self.ip = ip
        self.dns = dns
        self.rtt1 = rtt1
        self.rtt2 = rtt2
        self.rtt3 = rtt3


def traceroute(des, max_ttl,first_ttl, n_packets,n_series,pUDP,pTCP, wait_time,p_length):
    """
    Performs a traceroute to the given destination address with the specified options.
    :param destination: the destination address to traceroute to
    :param max_ttl: the maximum TTL to use for packets
    :param n_packets: the number of packets to send for each TTL value
    :param packet_size: the size of the packets to send
    :param wait_time: the time to wait between sending packets
    :return: a list of hops, each containing the IP addresses of the intermediate routers
    """
    hops = []
    IPs = []
    for destination in des:
     ips = []
     for ttl in range(first_ttl, max_ttl + 1):
        ttl_hops = []
        x1 = 0
        for i in range(n_packets):
            # Create the three types of packets to send for each TTL value
          udp_packet = s.IP(dst=destination, ttl=ttl) / s.UDP(dport=pUDP + ttl)
          tcp_packet = s.IP(dst=destination, ttl=ttl) / s.TCP(dport=pTCP)
          icmp_packet = s.IP(dst=destination, ttl=ttl) / s.ICMP()
          if len(udp_packet) < p_length:
                # "\x00" is a single zero byte
                myString = "\x00" * (p_length - len(udp_packet))
                udp_packet = udp_packet/s.Raw(myString)
          if len(tcp_packet) < p_length:
                # "\x00" is a single zero byte
                myString1 = "\x00" * (p_length - len(tcp_packet))
                tcp_packet = tcp_packet/s.Raw(myString1)
          if len(icmp_packet) < p_length:
                # "\x00" is a single zero byte
                myString2 = "\x00" * (p_length - len(icmp_packet))
                icmp_packet = icmp_packet/s.Raw(myString2)
            # Send the packets and wait for a response
          udp_response = s.sr1(udp_packet, verbose=False,retry=n_series, timeout=wait_time)
          tcp_response = s.sr1(tcp_packet, verbose=False,retry=n_series, timeout=wait_time)
          icmp_response = s.sr1(icmp_packet, verbose=False,retry=n_series, timeout=wait_time)

          if udp_response:
                if udp_response.src == destination:
                    x1 = x1 + 1
                sent = datetime.fromtimestamp(udp_packet.sent_time)
                received = datetime.fromtimestamp(udp_response.time)
                rtt1 = received - sent
                d = datetime.strptime(str(rtt1), "%H:%M:%S.%f").strftime('%S.%f')
                rtt1 = str(int(float(d) * 1000))+"ms"
                if tcp_response:
                    if udp_response.src == destination:
                        x1 = x1 + 1
                    sent1 = datetime.fromtimestamp(tcp_packet.sent_time)
                    received1 = datetime.fromtimestamp(tcp_response.time)
                    rtt2 = received1 - sent1
                    d = datetime.strptime(str(rtt2), "%H:%M:%S.%f").strftime('%S.%f')
                    rtt2 = str(int(float(d) * 1000))+"ms"
                else: rtt2 = '*'
                if icmp_response:
                    if icmp_response.src == destination:
                        x1 = x1 + 1
                    sent2 = datetime.fromtimestamp(icmp_packet.sent_time)
                    received2 = datetime.fromtimestamp(icmp_response.time)
                    rtt3 = received2 - sent2
                    d = datetime.strptime(str(rtt3),"%H:%M:%S.%f").strftime('%S.%f')
                    rtt3 = str(int(float(d) * 1000))+"ms"
                else: rtt3 = '*'
                try:
                    if args.noDns:
                        ips.append(Result(udp_response.src, "", rtt1, rtt2, rtt3))
                    else :
                        x = socket.gethostbyaddr(udp_response.src)
                        ips.append(Result(udp_response.src,x[0],rtt1,rtt2,rtt3))
                except Exception as e:
                    ips.append(Result(udp_response.src,"",rtt1,rtt2,rtt3))
          elif tcp_response:
                if tcp_response.src == destination:
                  x1 = x1 + 1
                rtt1 = '*'
                sent1 = datetime.fromtimestamp(tcp_packet.sent_time)
                received1 = datetime.fromtimestamp(tcp_response.time)
                rtt2 = received1 - sent1
                d = datetime.strptime(str(rtt2), "%H:%M:%S.%f").strftime('%S.%f')
                rtt2 = str(int(float(d) * 1000))+"ms"
                if icmp_response:
                    if icmp_response.src == destination:
                        x1 = x1 + 1
                    sent2 = datetime.fromtimestamp(icmp_packet.sent_time)
                    received2 = datetime.fromtimestamp(icmp_response.time)

                    rtt3 = received2 - sent2
                    d = datetime.strptime(str(rtt3), "%H:%M:%S.%f").strftime('%S.%f')
                    rtt3 = str(int(float(d) * 1000))+"ms"
                else: rtt3 = "*"
                try:
                    if args.noDns:
                        ips.append(Result(tcp_response.src, "", rtt1, rtt2, rtt3))
                    else:
                        x = socket.gethostbyaddr(tcp_response.src)
                        ips.append(Result(tcp_response.src, x[0], rtt1, rtt2, rtt3))
                except Exception as e:
                    ips.append(Result(tcp_response.src,"",rtt1,rtt2,rtt3))
          elif icmp_response:
                if icmp_response.src == destination:
                  x1 = x1 + 1
                rtt1 = "*"
                rtt2 = "*"
                sent2 = datetime.fromtimestamp(icmp_packet.sent_time)
                received2 = datetime.fromtimestamp(icmp_response.time)
                rtt3 = received2 - sent2
                d = datetime.strptime(str(rtt3), "%H:%M:%S.%f").strftime('%S.%f')
                rtt3 = str(int(float(d) * 1000))+"ms"
                try:
                    if args.noDns:
                        ips.append(Result(icmp_response.src, "", rtt1, rtt2, rtt3))
                    else:
                        x = socket.gethostbyaddr(icmp_response.src)
                        ips.append(Result(icmp_response.src, x[0], rtt1, rtt2, rtt3))
                except Exception as e:
                    ips.append(Result(icmp_response.src, "", rtt1, rtt2, rtt3))
        if x1 != 0:
            break
     Total.append(ResultTot(destination,ips))
    return Total


x = traceroute(tab,args.TTL,args.first_ttl,1,args.nbrSeries,args.port_ucp,args.port_tcp,args.wait,args.length)
for ip in x:
    with open('output.txt', 'a') as the_file:
        the_file.write(ip.dest+' : \n')
    for rout in ip.route:
        with open('output.txt', 'a') as the_file:
            the_file.write("  "+rout.rtt1+" "+rout.rtt2+" "+rout.rtt3+" "+rout.dns+" "+rout.ip+'\n')

rtt_moy_f = []
for addr in x:
    rtt_moy = 0
    step = 0
    for rtt in addr.route:
        if rtt.rtt1 != "*":
            rtt_moy = rtt_moy + int((rtt.rtt1)[:-2])
            step = step + 1
        if rtt.rtt2 != "*":
            rtt_moy = rtt_moy + int((rtt.rtt2)[:-2])
            step = step + 1
        if rtt.rtt3 != "*":
            rtt_moy = rtt_moy + int((rtt.rtt3)[:-2])
            step = step + 1
    rtt_moy_f.append(rtt_moy // step)
weight_G = []
weight_G1 = []
weight_G2 = []
dns_G = []
dns_G1 = []
dns_G2 = []
v = 0
for add in x:

    G = nx.Graph(name=add.dest)
    G1 = nx.Graph(name=add.dest)
    G2 = nx.Graph(name=add.dest)
    last_hop = None
    last_hop1 = None
    last_hop2 = None
    for n in add.route:
        if n.rtt1 != "*":
            G.add_node(n.ip,dns=n.dns+"\n"+n.ip)
            if last_hop:
                G.add_edge(last_hop, n.ip,weight=abs(int((n.rtt1)[:-2]) - rtt_moy_f[v])//4)
            last_hop = n.ip

        if n.rtt2 != "*":
            G1.add_node(n.ip,dns=n.dns+"\n"+n.ip)
            if last_hop1:
                G1.add_edge(last_hop1, n.ip,weight=abs(int((n.rtt2)[:-2]) - rtt_moy_f[v])//4)
            last_hop1 = n.ip

        if n.rtt3 != "*":
            G2.add_node(n.ip,dns=n.dns+"\n"+n.ip)
            if last_hop2:
                G2.add_edge(last_hop2, n.ip,weight=abs(int((n.rtt3)[:-2]) - rtt_moy_f[v])//4)
            last_hop2 = n.ip
    Gt.append([G,G1,G2])
    weight_G.append(nx.get_edge_attributes(G, 'weight').values())
    weight_G1.append(nx.get_edge_attributes(G1, 'weight').values())
    weight_G2.append(nx.get_edge_attributes(G2, 'weight').values())
    dns_G.append(nx.get_node_attributes(G, 'dns'))
    dns_G1.append(nx.get_node_attributes(G1, 'dns'))
    dns_G2.append(nx.get_node_attributes(G2, 'dns'))

    v = v + 1

z = 0
for graphGroup in Gt:
    plt.figure(z,figsize=(15, 9))
    subax = plt.subplot(221)
    subax.set_title('UDP Route For Destination : '+graphGroup[0].graph["name"])
    nx.draw(graphGroup[0], with_labels=True,width=list(weight_G[z]), labels=dns_G[z], node_size=700,edge_color="blue",font_size=8)
    subax1 = plt.subplot(222)
    subax1.set_title('TCP Route For Destination : '+graphGroup[1].graph["name"])
    nx.draw(graphGroup[1], with_labels=True,width=list(weight_G1[z]), labels=dns_G1[z],node_size=700,edge_color="red",font_size=8)
    subax2 = plt.subplot(223)
    subax2.set_title('ICMP Route For Destination : '+graphGroup[2].graph["name"])
    nx.draw(graphGroup[2], with_labels=True,width=list(weight_G2[z]), labels=dns_G2[z],node_size=700,edge_color="green",font_size=8)
    plt.savefig("dest1 "+str(z))
    z = z+1
plt.show()
