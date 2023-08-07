scp ./output/password.txt yash@192.168.1.1:/home/yash/Desktop/sshakshat/Second/;
sshpass -p '1234' ssh -tt yash@192.168.1.1 "
    cd /home/yash/Desktop/sshakshat/Second;
    ./second.sh;
    scp ./mitm akshat@192.168.1.2:/home/akshat/Desktop/Backe-end/fullfinal/output/;
"
