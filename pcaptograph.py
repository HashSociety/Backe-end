import networkx as nx
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.all import Dot11


def check_mesh_network(pcapng_file):
    packets = rdpcap(pcapng_file)
    mac = []
    for packet in packets:
        if packet.haslayer(Dot11):
            # if packet.addr3 == 'ec:a2:a0:69:b1:f9' or packet.addr3 == 'ea:65:32:28:67:0a':
            #     pass
            # else:
            rrc_mac = packet.addr2  # receiver
            src_mac = packet.addr3  # source
            dst_mac = packet.addr1  # dest
            mac.append([src_mac, rrc_mac, dst_mac])
    return mac


def create_mac_graph(mac_addresses):
    graph = nx.Graph()
    for src_mac, rrc_mac, dst_mac in mac_addresses:
        graph.add_edge(src_mac, rrc_mac, color='red')  # Assign color to the edge
        graph.add_edge(rrc_mac, dst_mac, color='blue')  # Assign color to the edge
    return graph


pcapng_file_path = "capturedemo19.pcapng"
mac_addresses_list = check_mesh_network(pcapng_file_path)
graph = create_mac_graph(mac_addresses_list)

# Draw the graph with edge colors and prevent layer overlap
edge_colors = nx.get_edge_attributes(graph, 'color').values()
pos = nx.spring_layout(graph)
nx.draw(graph, pos, with_labels=True, edge_color=list(edge_colors))
plt.savefig("graph.png")

y = 0
for x in mac_addresses_list:
    y = y + 1
    print(y, x)
