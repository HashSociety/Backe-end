import pyshark

def parse_bluetooth_packets(pcap_file):
    # Create a capture object to read packets from the pcap file
    capture = pyshark.FileCapture(pcap_file)

    # Create a list to store Bluetooth packets
    bluetooth_packets = []

    # Iterate through each packet in the capture
    for packet in capture:
        print(packet)
        
        try:
            # Check if the packet contains Bluetooth layers
            if "bthci_acl" in packet or "bthci_cmd" in packet or "btatt" in packet or "btl2cap" in packet:
                # Append the packet to the list of Bluetooth packets
                bluetooth_packets.append(packet.bthci_acl.src)
        except AttributeError:
            pass

    # Close the capture
    capture.close()

    return bluetooth_packets

if __name__ == "__main__":
    pcap_file = "capture1 (1).pcap"
    bluetooth_packets = parse_bluetooth_packets(pcap_file)

    # Do further processing with the Bluetooth packets as needed
    for packet in bluetooth_packets:
        print(packet)
