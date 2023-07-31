from scapy.all import *
from scapy.all import Dot11,Dot11QoS

def check_mesh_network(pcapng_file):
    packets = rdpcap(pcapng_file)
    mac=[]
    for packet in packets:
        if packet.haslayer(Dot11):
            
            rrc_mac = packet.addr2 # receviver
            src_mac=packet.addr3 #source
            
            dst_mac = packet.addr1 #dest
            mac.append([src_mac,rrc_mac,dst_mac])
    return mac

pcapng_file_path = "capture3.pcapng"
mac_addresses_dict = check_mesh_network(pcapng_file_path)
for x in mac_addresses_dict:
    
    print(x)