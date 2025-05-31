from Config import KNOWN_PORTS,DEFAULT_DURATION,DEFAULT_LOCATION
from SnifferCore import Sniffer

class AnsiColors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    ENDC = '\033[0m' 


figlet="""
██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗ ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██║  ██║██████╔╝███████║██║     █████╔╝ █████╗     ██║   
██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██║  ██║██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   
██║     ╚███╔███╔╝██║ ╚████║███████╗██████╔╝██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   
╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   

                                                                     By Silambaraselvan R                                                                                                                                                                           
"""

print(f"{AnsiColors.GREEN}{figlet}{AnsiColors.ENDC}")

if __name__=="__main__":
    DEFAULT_LOCATION="capdata/"
    DEFAULT_DURATION=10
    
    try:
        Duration_input=input("How long you want to capture network ?(enter for default:60s) : ")
        if not Duration_input:
            Duration=DEFAULT_DURATION
        else:
            try:
                Duration=int(Duration_input)
                if Duration<=0:
                    print(f"Invalid input(<0) ! Using Default {DEFAULT_DURATION}s")
                    Duration=DEFAULT_DURATION
            except ValueError:
                print(f"Invalid input ! using Default {DEFAULT_DURATION}s")
                Duration=DEFAULT_DURATION
        File_Loc_input=input("where you want to save the captured packets ?(enter for defult: capdata/) : ")
        if not File_Loc_input:
            FileLocation=DEFAULT_LOCATION
        else:
            FileLocation =File_Loc_input
        
        UserChoice=input("default capturing or specific packet capture(Y/N) : ")
        if UserChoice.lower() in {"y","Y"}:
            SpecificPackets=input("what Specific packets you want to capture?(enter for default) :")
            if SpecificPackets not in KNOWN_PORTS:
                print("no protocol found")
                
            else:
                Sniffer(Duration,FileLocation,SpecificPackets)
        else:
            Sniffer(Duration,FileLocation,None)
    except KeyboardInterrupt as e:
        print(f"\n\nExiting the tool with CTRL+C !")