import pyshark
import networkx as nx
import matplotlib.pyplot as plt

# Function to extract source and destination addresses from the pcapng file
def extract_addresses(pcapng_file):
    capture = pyshark.FileCapture(pcapng_file)
    ls = list()
    idx = 0
    for packet in capture:
        idx+=1
        # print(idx,packet)
        if 'wlan' in packet:
            wlan_layer = packet.wlan
            # Extract WLAN details
            wlan_type = wlan_layer.fc_type
            wlan_subtype = wlan_layer.fc_subtype
            if 'wlan_aggregate' in packet :
                continue
            if wlan_type == "2" and wlan_subtype == "12" :        
                # print(idx)
                source_address = packet.wlan.sa
                destination_address = packet.wlan.da
                receiver_address = packet.wlan.ra
                transmitter_address = packet.wlan.ta
                bss_id = wlan_layer.bssid
                bssids.append(bss_id)
                ls.append([source_address, receiver_address, transmitter_address, destination_address])
    capture.close()
    return ls

# Function to create a graph from the extracted addresses
def create_graph(edges):
    G = nx.DiGraph()  # Use DiGraph to represent directed edges (transmitter to receiver)

    for edge in edges:
        node1, node2 = edge[0], edge[3]  # transmitter_address, receiver_address
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
            dst2 = add[j][3]
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
