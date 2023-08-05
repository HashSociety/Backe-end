time=$1
rfkill unblock 1
sudo ./startmonitor.sh
sudo ./finalscan.sh $time
sleep 2
sudo ./stopmonitor.sh
