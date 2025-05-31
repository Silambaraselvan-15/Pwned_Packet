import scapy.all as a
from PacketProcessor import StructResult
import time
import os
from Config import KNOWN_PORTS


class AnsiColors:
    RED = '\033[91m'
    ENDC='\033[0m'

def Sniffer(Time,FileLocation,SpecificProtocol=None):
    def OutPut(pkt):
        protocol_label = f"{AnsiColors.RED} PROTOCOL {AnsiColors.ENDC}"
        if SpecificProtocol:
            TargetPort=KNOWN_PORTS.get(SpecificProtocol.upper())
            if TargetPort is not None:
                if pkt.haslayer(a.TCP):
                    if pkt.dport== TargetPort or pkt.sport==TargetPort:
                            print(f"PROTOCOL :[{SpecificProtocol}] ",StructResult(pkt))
                elif pkt.haslayer(a.UDP):
                    if pkt.dport== TargetPort or pkt.sport==TargetPort:
                        print(f"PROTOCOL :[{SpecificProtocol}] ",StructResult(pkt))
            else:
                print("please enter valid protocol !")
                return " error "
                
        elif SpecificProtocol==None:
            if pkt.haslayer(a.TCP):
                if pkt.dport==443 or pkt.sport==443:
                    print(f"[{protocol_label}: TLS/SSL] ",StructResult(pkt))
                elif pkt.dport == 22 or pkt.sport == 22:
                    print(f"[{protocol_label}: SSH] ", StructResult(pkt))
                elif pkt.dport == 80 or pkt.sport == 80:
                    print(f"[{protocol_label}: HTTP] ", StructResult(pkt))
                elif pkt.dport == 21 or pkt.sport == 21:
                    print(f"[{protocol_label}: FTP] ", StructResult(pkt))
                elif pkt.dport == 23 or pkt.sport == 23:
                    print(f"[{protocol_label}: Telnet] ", StructResult(pkt))
                elif pkt.dport == 25 or pkt.sport == 25:
                    print(f"[{protocol_label}: SMTP] ", StructResult(pkt))
                elif pkt.dport == 110 or pkt.sport == 110:
                    print(f"[{protocol_label}: POP3] ", StructResult(pkt))
                elif pkt.dport == 143 or pkt.sport == 143:
                    print(f"[{protocol_label}: IMAP] ", StructResult(pkt))
                elif pkt.dport == 445 or pkt.sport == 445:
                    print(f"[{protocol_label}: SMB] ", StructResult(pkt))
                elif pkt.dport == 3306 or pkt.sport == 3306:
                    print(f"[{protocol_label}: MySQL] ", StructResult(pkt))
                elif pkt.dport == 5432 or pkt.sport == 5432:
                    print(f"[{protocol_label}: PostgreSQL] ", StructResult(pkt))
                elif pkt.dport == 5060 or pkt.sport == 5060:
                    print(f"[{protocol_label}: SIP] ", StructResult(pkt))
                elif pkt.dport == 179 or pkt.sport == 179:
                    print(f"[{protocol_label}: BGP] ", StructResult(pkt))
            elif pkt.haslayer(a.UDP):
                if pkt.dport==53 or pkt.sport==53:
                    print(f"[{protocol_label}: DNS] ",StructResult(pkt))
                elif pkt.dport == 161 or pkt.sport == 161:
                    print(f"[{protocol_label}: SNMP] ", StructResult(pkt))
                elif pkt.dport == 123 or pkt.sport == 123:
                    print(f"[{protocol_label}: NTP] ", StructResult(pkt))
                elif pkt.dport == 69 or pkt.sport == 69:
                    print(f"[{protocol_label}: TFTP] ", StructResult(pkt))
                elif pkt.dport == 5060 or pkt.sport == 5060:
                    print(f"[{protocol_label}: SIP] ", StructResult(pkt)())
            elif pkt.haslayer(a.ICMP):
                print(f"[{protocol_label}: ICMP] ", StructResult(pkt))   
            elif pkt.haslayer(a.ICMPv6ND_NA):
                print(f"[{protocol_label}: ICMPv6 ND-NA]",StructResult(pkt))
            elif pkt.haslayer(a.ICMPv6ND_NS):
                print(f"[{protocol_label}: ICMPv6 ND-NS] ",StructResult(pkt))
            elif pkt.haslayer(a.ARP):
                print(f"[{protocol_label}: ARP]",StructResult(pkt))
            else:
                print("---------------------------------undefined protocol ! ---------------------------------------------------------------------")
                pkt.show()


    print(f"packet acpturing started , time to complete {Time}")
    Cpackets=a.AsyncSniffer(prn=OutPut,count=0)


    Cpackets.start()


    time.sleep(Time)


    Cpackets.stop()
    


    if not os.path.exists(FileLocation):
        try:
            os.mkdir(FileLocation)
        except OSError as e:
            print(f"Error Creating the directory {FileLocation} as {e}")
            return


    DstDir=os.path.join(FileLocation,f"Captured_Data.pcap")
    print(f"Saving Captured file in {DstDir}")
    a.wrpcap(DstDir,Cpackets.results)