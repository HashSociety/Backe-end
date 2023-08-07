sudo ifconfig wlan0mon down
sudo iwconfig wlan0mon mode managed
sudo ifconfig wlan0mon up
sudo systemctl restart NetworkManager
sudo ip link set wlan0mon name wlan0
echo "Monitor mode stopped"
