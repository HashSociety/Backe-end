import pyshark

# Path to the pcapng file
file_path = 'capture.pcapng'

# Open the pcapng file
cap = pyshark.FileCapture(file_path)

# Iterate over each packet in the file
for packet in cap:
    # Process each packet as needed
    print(packet)

# Close the file
cap.close()
