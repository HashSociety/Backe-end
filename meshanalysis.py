from scapy.all import *
from scapy.all import Dot11, Dot11Elt, Dot11Beacon, Dot11QoS

def check_mesh_network(pcapng_file):
    packets = rdpcap(pcapng_file)
    is_mesh_network = False
    mesh_beacon_interval_range = (100, 1000)  # Set the desired range for mesh network Beacon Interval
    bssids = set()
    qos_data_present = False

    for packet in packets:
        if packet.haslayer(Dot11):
            bssid = packet.addr3
            if bssid != "ff:ff:ff:ff:ff:ff" and bssid != "00:00:00:00:00:00":
                bssids.add(bssid)
            if packet.haslayer(Dot11Beacon) and 'Mesh' in packet[Dot11Elt].info.decode():
                is_mesh_network = True
            if packet.haslayer(Dot11) and packet.haslayer(Dot11QoS) and packet.type == 0x02:
                qos_data_present = True
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 61:
                is_mesh_network = True
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 192 and packet[Dot11Elt].info.decode() == 'Wi-Fi Direct':
                is_mesh_network = True   
            if packet.haslayer(Dot11Beacon) and hasattr(packet[Dot11Beacon], "beacon_interval"):
                beacon_interval = packet[Dot11Beacon].beacon_interval
                if mesh_beacon_interval_range[0] <= beacon_interval <= mesh_beacon_interval_range[1]:
                    is_mesh_network = True

    if len(bssids) > 1 and qos_data_present and is_mesh_network == True:
        is_mesh_network = True
    else:
        is_mesh_network = False

    return is_mesh_network

pcapng_file_path = "capture3.pcapng"
is_mesh = check_mesh_network(pcapng_file_path)
if is_mesh:
    print("The pcapng file contains packets from a mesh network or Wi-Fi Direct.")
else:
    print("The pcapng file does not contain packets from a mesh network or Wi-Fi Direct.")