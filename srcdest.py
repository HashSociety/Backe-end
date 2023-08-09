import pyshark
import networkx as nx
import matplotlib.pyplot as plt

# Function to extract source and destination addresses from the pcapng file
def is_multicast_mac(mac_address):
    # Check if the MAC address is in the multicast range (01:00:5e:XX:XX or 33:33:XX:XX)
    return mac_address.startswith("01:00:5e") or mac_address.startswith("33:33:") or mac_address.startswith("00:")
def extract_addresses(pcapng_file):
    capture = pyshark.FileCapture(pcapng_file)
    ls = list()
    ls_qos=list()
    qos_set = set()
    idx = 0
    for packet in capture:
        idx+=1
        if 'wlan' in packet:
            wlan_layer = packet.wlan
            
            wlan_type = wlan_layer.fc_type
            if hasattr(wlan_layer, 'sa') and hasattr(wlan_layer, 'da') and hasattr(wlan_layer, 'ta') and hasattr(wlan_layer, 'ra') :       
                source_address = packet.wlan.sa
                destination_address = packet.wlan.da
                receiver_address = packet.wlan.ra
                transmitter_address = packet.wlan.ta
                if source_address == "ff:ff:ff:ff:ff:ff" or destination_address == "ff:ff:ff:ff:ff:ff" or \
                                    receiver_address == "ff:ff:ff:ff:ff:ff" or transmitter_address == "ff:ff:ff:ff:ff:ff" or \
                                    is_multicast_mac(source_address) or is_multicast_mac(destination_address) or \
                                    is_multicast_mac(receiver_address) or is_multicast_mac(transmitter_address):
                                        continue
                if wlan_type == "2":
                    source_address_qos= packet.wlan.sa
                    destination_address_qos = packet.wlan.da
                    # receiver_address_qos = packet.wlan.ra
                    # transmitter_address_qos = packet.wlan.ta
                    ls_qos.append([source_address_qos,destination_address_qos])
                     
                bss_id = wlan_layer.bssid
                bssids.append(bss_id)
                # ls.append([source_address, receiver_address, transmitter_address, destination_address])
                unique_list_of_lists = []
                seen_sublists = set()

                for sublist in ls_qos:
                    # Convert the sublist to a tuple to make it hashable
                    sublist_tuple = tuple(sublist)
                    
                    if sublist_tuple not in seen_sublists:
                        seen_sublists.add(sublist_tuple)
                        unique_list_of_lists.append(sublist)
                
    capture.close()
    return (unique_list_of_lists)# Function to create a graph from the extracted addresses
def create_graph(edges):
    G = nx.DiGraph()  # Use DiGraph to represent directed edges (transmitter to receiver)

    for edge in edges:
        node1, node2 = edge[0], edge[1]  # transmitter_address, receiver_address
        G.add_edge(node1, node2)
    return G

def create_graph_components(edges):
    G = nx.DiGraph()  # Use DiGraph to represent directed edges (transmitter to receiver)

    for edge in edges[:-1]:
        node1, node2 = edge[0], edge[1]  # transmitter_address, receiver_address
        G.add_edge(node1, node2)
    return G

# Function to count the number of disconnected graphs
def count_disconnected_graphs(G):
    return len(list(nx.weakly_connected_components(G)))

# Function to create components of the graph (disconnected graphs)
def make_components(G,add):
    connected_graphs = {}
    components = nx.weakly_connected_components(G)
    for idx, component in enumerate(components):
        graph_number = idx + 1
        connected_graphs[graph_number] = list(list(G.subgraph(component).edges))
    
    for idx in connected_graphs.keys():
        connected_graphs[idx].append(allocate_bssid(add,bssids,connected_graphs[idx]))
    # print(allocate_bssid(add,bssids,connected_graphs[graph_number][0]))
    return connected_graphs

def allocate_bssid(add, bssids,components):
    bssid = set()
    i = 0
    j = 0

    for i in range(len(components)):
        src = components[i][0]
        dst = components[i][1]
        for j in range(len(add)):
            src2 = add[j][0] 
            dst2 = add[j][1]
            # print(src, dst, src2, dst2)
            if src  == src2 and dst == dst2:
                bssid.add(bssids[j])
                j+=1
                break
            j+=1
        i+=1
    return list(bssid)
# Function to show the graph
def show_graph(G):
    nx.draw(G, with_labels=True, node_color='lightblue', edge_color='gray')
    plt.show()





def calculate_diameter(G):
    return nx.diameter(G.to_undirected())

# Function to calculate the density of a graph
def calculate_density(G):
    num_nodes = G.number_of_nodes()
    num_edges = G.number_of_edges()
    if num_nodes <= 1:
        return 0.0
    max_possible_edges = num_nodes * (num_nodes - 1)
    density = num_edges / max_possible_edges
    return density

# Function to calculate indegree and outdegree for each MAC address
def indegree_outdegree_info(G):
    indegree_data = dict(G.in_degree())
    outdegree_data = dict(G.out_degree())
    return indegree_data, outdegree_data

# Function to find the MAC address with the highest degree (highest connectivity)
def find_mac_with_highest_degree(G):
    degrees = dict(G.degree())
    mac_with_highest_degree = max(degrees, key=degrees.get)
    return mac_with_highest_degree


def is_mesh_topology(graph, required_degree_percent):
    nodes = list(graph.nodes)
    required_degree = len(nodes) * required_degree_percent
    
    for node in nodes:
        if graph.degree(node) < required_degree:
            return False
    return True

def mac_set(data):
    mac_addresses = set()

    for item in data:
        if isinstance(item, tuple):
            for mac in item:
                mac_addresses.add(mac)
        elif isinstance(item, list):
            for inner_item in item:
                mac_addresses.add(inner_item)

    return mac_addresses


import requests

def fetch_mac_vendor(mac_address):
    api_url = f"https://api.macvendors.com/{mac_address}"
    response = requests.get(api_url)

    if response.status_code == 200:
        return response.text.strip()
    else:
        return None



# # Usage
bssids = list()
# pcapng_file = "./capture.pcapng"

# # # fetching add 
# add = extract_addresses(pcapng_file)
# # print(add)

# # # create graph with above add 
# graph = create_graph(add)

# # # create components out of that graph partitioning 
# component = make_components(graph)
# for idx in component.keys():
#     print(component[idx][-1])
# # info1
# disconnected_graphs = count_disconnected_graphs(graph)

# # Print the extracted addresses
# print("Extracted addresses:")
# #print(add)
# print("\n")

# # Print the components (disconnected graphs)
# print(f"Components {components}")
# print("\n")

# print(disconnected_graphs)

# # Print indegree and outdegree information
# indegree_data, outdegree_data = indegree_outdegree_info(graph)
# print("Indegree information:")
# print(indegree_data)
# print("\nOutdegree information:")
# print(outdegree_data)

# # Print the number of disconnected graphs
# print("Number of disconnected graphs:", disconnected_graphs)

# # Find the MAC address with the highest degree
# mac_with_highest_degree = find_mac_with_highest_degree(graph)
# print("MAC address with the highest degree:", mac_with_highest_degree)

# # Show the graph
# show_graph(graph)
