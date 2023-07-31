import pyshark
import networkx as nx
import matplotlib.pyplot as plt

# Function to extract source and destination addresses from the pcapng file
def extract_addresses(pcapng_file):
    capture = pyshark.FileCapture(pcapng_file)
    ls = list()
    for packet in capture:
        source_address = packet.wlan.sa
        destination_address = packet.wlan.da
        receiver_address = packet.wlan.ra
        transmitter_address = packet.wlan.ta
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
def make_components(G):
    connected_graphs = {}
    components = nx.weakly_connected_components(G)
    for idx, component in enumerate(components):
        graph_number = idx + 1
        connected_graphs[graph_number] = list(G.subgraph(component).edges)

    return connected_graphs

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

# Usage
# pcapng_file = "api/capturedemo19.pcapng"
# # fetching add 
# add = extract_addresses(pcapng_file)

# # create graph with above add 
# graph = create_graph(add)

# # create components out of that graph partitioning 
# components = make_components(graph)

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
