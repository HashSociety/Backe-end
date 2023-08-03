DURATION="$1"
OUTPUT_DIR="$(pwd)/output"
CAPTURE_FILE="$OUTPUT_DIR/capture.pcapng"
CAPTURE_FILE_csv="$OUTPUT_DIR/csv"

start_monitor_mode() {
    echo "Starting monitor mode on $INTERFACE..."
    sudo airmon-ng check kill
    sudo airmon-ng start $INTERFACE
    echo "Monitor mode started."
}

create_output_directory() {
    echo "Creating output directory..."
    mkdir -p "$OUTPUT_DIR"
    echo "Output directory created."
    sudo chmod 777 output
}

capture_packets_csv() {
    echo "Capturing packets on $INTERFACE using airodump-ng for $DURATION seconds..."
    sudo airodump-ng -w "$CAPTURE_FILE" --output-format csv "$INTERFACE"&
    sleep "$DURATION"
    sudo killall airodump-ng
    
}
capture_packets() {
    
    echo "Capturing packets on $INTERFACE using tshark for $DURATION seconds..."
    sudo -u sanskar tshark -i "$INTERFACE" -a duration:"$DURATION" -w "$CAPTURE_FILE"
}

INTERFACE=$(iwconfig 2>/dev/null | grep -o '^[a-zA-Z0-9]*')
create_output_directory
sudo rm -rf output/*.csv
capture_packets_csv
sudo chmod 777 output/capture.pcapng-01.csv
capture_packets

