from scapy.all import *
import collections
from pyecharts import options as opts
from pyecharts.charts import Pie

def pie_rosetype(data,graphname) -> Pie:
    pie = (
        Pie()
        .add(
            "",
            data,
            radius=["20%", "60%"],
            center=["50%", "50%"],
            rosetype="radius",
            label_opts=opts.LabelOpts(is_show=False),
        )
        .set_global_opts(title_opts=opts.TitleOpts(title=graphname))
    )
    return pie

def proto_flow_bytes(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for pcap in PCAPS:
        pcap_len = len(corrupt_bytes(pcap))
        if pcap.haslayer(IP):
            proto_flow_dict['IP'] += pcap_len
        elif pcap.haslayer(IPv6):
            proto_flow_dict['IPv6'] += pcap_len
        if pcap.haslayer(TCP):
            proto_flow_dict['TCP'] += pcap_len
        elif pcap.haslayer(UDP):
            proto_flow_dict['UDP'] += pcap_len
        if pcap.haslayer(ARP):
            proto_flow_dict['ARP'] += pcap_len
        elif pcap.haslayer(ICMP):
            proto_flow_dict['ICMP'] += pcap_len
        elif pcap.haslayer(DNS):
            proto_flow_dict['DNS'] += pcap_len
        elif pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict['HTTP'] += pcap_len
            elif dport == 443 or sport == 443:
                proto_flow_dict['HTTPS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer(UDP):
            udp = pcap.getlayer(UDP)
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict['DNS'] += pcap_len
            else:
                proto_flow_dict['Others'] += pcap_len
        elif pcap.haslayer(ICMPv6ND_NS):
            proto_flow_dict['ICMP'] += pcap_len
        else:
            proto_flow_dict['Others'] += pcap_len
    return proto_flow_dict

def proto_flow_frames(PCAPS):
    proto_flow_dict = collections.OrderedDict()
    proto_flow_dict['IP'] = 0
    proto_flow_dict['IPv6'] = 0
    proto_flow_dict['TCP'] = 0
    proto_flow_dict['UDP'] = 0
    proto_flow_dict['ARP'] = 0
    proto_flow_dict['ICMP'] = 0
    proto_flow_dict['DNS'] = 0
    proto_flow_dict['HTTP'] = 0
    proto_flow_dict['HTTPS'] = 0
    proto_flow_dict['Others'] = 0
    for pcap in PCAPS:
        if pcap.haslayer(IP):
            proto_flow_dict['IP'] += 1
        elif pcap.haslayer(IPv6):
            proto_flow_dict['IPv6'] += 1
        if pcap.haslayer(TCP):
            proto_flow_dict['TCP'] += 1
        elif pcap.haslayer(UDP):
            proto_flow_dict['UDP'] += 1
        if pcap.haslayer(ARP):
            proto_flow_dict['ARP'] += 1
        elif pcap.haslayer(ICMP):
            proto_flow_dict['ICMP'] += 1
        elif pcap.haslayer(DNS):
            proto_flow_dict['DNS'] += 1
        elif pcap.haslayer(TCP):
            tcp = pcap.getlayer(TCP)
            dport = tcp.dport
            sport = tcp.sport
            if dport == 80 or sport == 80:
                proto_flow_dict['HTTP'] += 1
            elif dport == 443 or sport == 443:
                proto_flow_dict['HTTPS'] += 1
            else:
                proto_flow_dict['Others'] += 1
        elif pcap.haslayer(UDP):
            udp = pcap.getlayer(UDP)
            dport = udp.dport
            sport = udp.sport
            if dport == 5353 or sport == 5353:
                proto_flow_dict['DNS'] += 1
            else:
                proto_flow_dict['Others'] += 1
        elif pcap.haslayer(ICMPv6ND_NS):
            proto_flow_dict['ICMP'] += 1
        else:
            proto_flow_dict['Others'] += 1
    return proto_flow_dict