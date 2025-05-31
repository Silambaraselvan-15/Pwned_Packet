import scapy.all as a
from Config import KNOWN_PORTS


def StructResult(pkt):
    line= "\n--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    src_mac = pkt.src if hasattr(pkt, "src") else "N/A"
    dst_mac = pkt.dst if hasattr(pkt, "dst") else "N/A"
    
    src_ip, dst_ip = "N/A", "N/A"
    if pkt.haslayer(a.IP): 
        src_ip = pkt[a.IP].src
        dst_ip = pkt[a.IP].dst
    elif pkt.haslayer(a.IPv6):  
        src_ip = pkt[a.IPv6].src
        dst_ip = pkt[a.IPv6].dst
    
    return "[Source MAC: " + src_mac + "] -> [Destination MAC: " + dst_mac + "] [Source IP: " + src_ip +"] -> [Destination IP: "+ dst_ip + "]" + line

