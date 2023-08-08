time=$1
sshpass -p '1234' ssh -tt yash@192.168.1.1 "
    cd /home/yash/Desktop/sshakshat/First;
    ./first.sh $time;
    scp ./output/capture ./output/capture.csv akshat@192.168.1.2:/home/akshat/Desktop/Backe-end/fullfinal/output/;
"
