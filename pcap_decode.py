from scapy.all import *
#import scapy_http.http as http
from scapy.layers import http
import time
import datetime


def pkt_detail(pkt):
    data = ""
    if(pkt.haslayer(Ether)):
        ether = pkt.getlayer(Ether)
        data += "Ethernet II:\n"
        data += "\tsrc: %s\n" % ether.src
        data += "\tdst: %s\n" % ether.dst
        data += "\ttype: %s\n" % ether.type
    if(pkt.haslayer(IP)):
        ip = pkt.getlayer(IP)
        data += "Internet Protocol Version 4:\n"
        data += "\tsrc: %s\n" % ip.src
        data += "\tdst: %s\n" % ip.dst
        data += "\tihl: %d bytes (%d)\n" % (ip.ihl*4, ip.ihl)
        data += "\ttos: %s\n" % hex(ip.tos)
        data += "\tlength: %d\n" % ip.len
        data += "\tid: %s (%d)\n" % (hex(ip.id), ip.id)
        data += "\tflags: 0x%04x\n" % ip.flags.value
        data += "\tttl: %d\n" % ip.ttl
        data += "\tprotocol: %s\n" % ip.proto
        data += "\tchecksum: %s\n" % hex(ip.chksum)
    elif(pkt.haslayer(IPv6)):
        ipv6 = pkt.getlayer(IPv6)
        d = {1: "ICMP", 2: "IGMP", 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        data += "Internet Protocol Version 6:\n"
        data += "\tsrc: %s\n" % ipv6.src
        data += "\tdst: %s\n" % ipv6.dst
        data += "\ttraffic class: 0x%02x\n" % ipv6.tc
        data += "\tflow label: %s\n" % hex(ipv6.fl)
        data += "\tpayload length: %d\n" % ipv6.plen
        if(ipv6.nh in d.keys()):
            data += "\tnext header: %s (%d)\n" % (d[ipv6.nh], ipv6.nh)
        else:
            pass
        data += "\thop limit: %d\n" % ipv6.hlim
    if(pkt.haslayer(UDP)):
        data += "User Datagram Protocol:\n"
        udp = pkt.getlayer(UDP)
        data += "\tsrc port: %d\n" % udp.sport
        data += "\tdst port: %d\n" % udp.dport
        data += "\tlength: %d\n" % udp.len
        data += "\tchecksum: %s\n" % hex(udp.chksum)
    elif(pkt.haslayer(TCP)):
        data += "Transmission Control Protocol:\n"
        tcp = pkt.getlayer(TCP)
        data += "\tsrc port: %d\n" % tcp.sport
        data += "\tdst port: %d\n" % tcp.dport
        data += "\tseq: %d\n" % tcp.seq
        data += "\tack: %d\n" % tcp.ack
        data += "\theader length: %s bytes (%d)\n" % (
            hex(tcp.dataofs), tcp.dataofs)
        data += "\tflags : 0x%03x (%s)\n" % (tcp.flags.value, str(tcp.flags))
        data += "\twindow size: %d\n" % tcp.window
        data += "\tchecksum: %s\n" % hex(tcp.chksum)
        data += "\turgent pointer: %d\n" % (tcp.urgptr)
    if(pkt.haslayer(ICMP)):
        data += "Internet Control Message Protocol:\n"
        icmp = pkt.getlayer(ICMP)
        data += "\ttype: %d\n" % icmp.type
        data += "\tcode: %d\n" % icmp.type
        data += "\tchecksum: %s\n" % hex(icmp.chksum)
    if(pkt.haslayer(DNS)):
        data += "Domain Name System\n"
        dns = pkt.getlayer(DNS)
        if(dns.opcode == 0):
            data += "\topcode: %s\n" % "answer"
        else:
            data += "\topcode: %s\n" % "query"
        try:
            data += "\tqname: %s\n" % dns.qd.qname.decode()
        except:
            data += "\rerror\n"
            return data
        for i in range(0, dns.ancount):
            data += "\t===========================\n"
            if(type(dns.an[i].rrname) == bytes):
                data += "\trrname: %s\n" % dns.an[i].rrname.decode()
            else:
                data += "\trrname: %s\n" % dns.an[i].rrname
            if(type(dns.an[i].rdata) == bytes):
                data += "\trdata: %s\n" % dns.an[i].rdata.decode()
            else:
                data += "\trdata: %s\n" % dns.an[i].rdata
    if(pkt.haslayer(http.HTTP)):
        data += "HyperText Transfer Protocol:\n"
        layer = {}
        if(pkt.haslayer(http.HTTPRequest)):
            layer = pkt.getlayer(http.HTTPRequest).fields
        elif(pkt.haslayer(http.HTTPResponse)):
            layer = pkt.getlayer(http.HTTPResponse).fields
        if('Headers' in layer.keys()):
            s = layer['Headers'].decode()
            s.split('\r\n')
            data += "\tHeaders:\n"
            for tmp in s:
                data += "\t\t%s\n" % tmp
        for key in layer.keys():
            if(key == 'Headers'):
                continue
            else:
                data += "\t%s: %s\n" % (key, layer[key].decode())
    return data


class PcapDecode:
    def __init__(self):
        # ETHER:读取以太网层协议配置文件
        with open('./protocol/ETHER', 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]

        # IP:读取IP层协议配置文件
        with open('./protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        # PORT:读取应用层协议端口配置文件
        with open('./protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        # TCP:读取TCP层协议配置文件
        with open('./protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

        # UDP:读取UDP层协议配置文件
        with open('./protocol/UDP', 'r', encoding='UTF-8') as f:
            udps = f.readlines()
        self.UDP_DICT = dict()
        for udp in udps:
            udp = udp.strip().strip('\n').strip('\r').strip('\r\n')
            self.UDP_DICT[int(udp.split(':')[0])] = udp.split(':')[1]

    # 解析以太网层协议
    def ether_decode(self, p):
        data = dict()
        if p.haslayer(Ether):
            data = self.ip_decode(p)
            return data
        else:
            # datetime.datetime.fromtimestamp(p.time).strftime("%H:%M:%S.%f")
            data['time'] = datetime.datetime.fromtimestamp(
                p.time).strftime("%H:%M:%S.%f")
            data['Source'] = 'Unknow'
            data['Destination'] = 'Unknow'
            data['Protocol'] = 'Unknow'
            data['len'] = len(corrupt_bytes(p))
            data['info'] = p.summary()
            return data

    # 解析IP层协议
    def ip_decode(self, p):
        data = dict()
        if p.haslayer(IP):  # 2048:Internet IP (IPv4)
            ip = p.getlayer(IP)
            if p.haslayer(TCP):  # 6:TCP
                data = self.tcp_decode(p, ip)
                return data
            elif p.haslayer(UDP):  # 17:UDP
                data = self.udp_decode(p, ip)
                return data
            else:
                if ip.proto in self.IP_DICT:
                    data['time'] = datetime.datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Protocol'] = self.IP_DICT[ip.proto]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = datetime.datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ip.src
                    data['Destination'] = ip.dst
                    data['Protocol'] = 'IPv4'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        elif p.haslayer(IPv6):  # 34525:IPv6
            ipv6 = p.getlayer(IPv6)
            if p.haslayer(TCP):  # 6:TCP
                data = self.tcp_decode(p, ipv6)
                return data
            elif p.haslayer(UDP):  # 17:UDP
                data = self.udp_decode(p, ipv6)
                return data
            else:
                if ipv6.nh in self.IP_DICT:
                    data['time'] = datetime.datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Protocol'] = self.IP_DICT[ipv6.nh]
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
                else:
                    data['time'] = datetime.datetime.fromtimestamp(
                        p.time).strftime("%H:%M:%S.%f")
                    data['Source'] = ipv6.src
                    data['Destination'] = ipv6.dst
                    data['Protocol'] = 'IPv6'
                    data['len'] = len(corrupt_bytes(p))
                    data['info'] = p.summary()
                    return data
        else:
            if p.type in self.ETHER_DICT:
                data['time'] = datetime.datetime.fromtimestamp(
                    p.time).strftime("%H:%M:%S.%f")
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Protocol'] = self.ETHER_DICT[p.type]
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data
            else:
                data['time'] = datetime.datetime.fromtimestamp(
                    p.time).strftime("%H:%M:%S.%f")
                data['Source'] = p.src
                data['Destination'] = p.dst
                data['Protocol'] = hex(p.type)
                data['len'] = len(corrupt_bytes(p))
                data['info'] = p.summary()
                return data

    # 解析TCP层协议
    def tcp_decode(self, p, ip):
        data = dict()
        tcp = p.getlayer(TCP)
        data['time'] = datetime.datetime.fromtimestamp(
            p.time).strftime("%H:%M:%S.%f")
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if tcp.dport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[tcp.dport]
        elif tcp.sport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[tcp.sport]
        elif tcp.dport in self.TCP_DICT:
            data['Protocol'] = self.TCP_DICT[tcp.dport]
        elif tcp.sport in self.TCP_DICT:
            data['Protocol'] = self.TCP_DICT[tcp.sport]
        else:
            data['Protocol'] = "TCP"
        return data

    # 解析UDP层协议
    def udp_decode(self, p, ip):
        data = dict()
        udp = p.getlayer(UDP)
        data['time'] = datetime.datetime.fromtimestamp(
            p.time).strftime("%H:%M:%S.%f")
        data['Source'] = ip.src + ":" + str(ip.sport)
        data['Destination'] = ip.dst + ":" + str(ip.dport)
        data['len'] = len(corrupt_bytes(p))
        data['info'] = p.summary()
        if udp.dport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[udp.dport]
        elif udp.sport in self.PORT_DICT:
            data['Protocol'] = self.PORT_DICT[udp.sport]
        elif udp.dport in self.UDP_DICT:
            data['Protocol'] = self.UDP_DICT[udp.dport]
        elif udp.sport in self.UDP_DICT:
            data['Protocol'] = self.UDP_DICT[udp.sport]
        else:
            data['Protocol'] = "UDP"
        return data


if __name__ == '__main__':
    PD = PcapDecode()
    pcap_test = sniff(filter="", iface="en0", count=10)
    data_result = dict()
    for p in pcap_test:
        data_result = PD.ether_decode(p)
        print(data_result)
