from Config import KNOWN_PORTS,DEFAULT_DURATION,DEFAULT_LOCATION
from SnifferCore import Sniffer


if __name__=="__main__":
    DEFAULT_LOCATION="capdata/"
    DEFAULT_DURATION=10
    Duration_input=input("How long you want to capture network ?(enter for default:60s) : ")
    try:
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
        print(f" Exiting the tool with CTRL+C !")
