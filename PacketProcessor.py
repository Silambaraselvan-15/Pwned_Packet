import scapy.all as a
from Config import KNOWN_PORTS


class AnsiColors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    
    ENDC = '\033[0m'

def StructResult(pkt):
    line= f"\n{AnsiColors.BLUE}--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------{AnsiColors.ENDC}"
    
    src_mac_val = pkt.src if hasattr(pkt, "src") else "N/A"
    dst_mac_val = pkt.dst if hasattr(pkt, "dst") else "N/A"
    
    src_ip_val, dst_ip_val = "N/A", "N/A"
    if pkt.haslayer(a.IP): 
        src_ip_val = pkt[a.IP].src
        dst_ip_val = pkt[a.IP].dst
    elif pkt.haslayer(a.IPv6):  
        src_ip_val = pkt[a.IPv6].src
        dst_ip_val = pkt[a.IPv6].dst
    src_mac_label = f"{AnsiColors.YELLOW}Source MAC{AnsiColors.ENDC}"
    dst_mac_label = f"{AnsiColors.YELLOW}Destination MAC{AnsiColors.ENDC}"
    src_ip_label = f"{AnsiColors.YELLOW}Source IP{AnsiColors.ENDC}"
    dst_ip_label = f"{AnsiColors.YELLOW}Destination IP{AnsiColors.ENDC}"


    return (f"[{src_mac_label}: {src_mac_val}] -> [{dst_mac_label}: {dst_mac_val}] "
            f"[{src_ip_label}: {src_ip_val}] -> [{dst_ip_label}: {dst_ip_val}]" 
            f"{line}")
