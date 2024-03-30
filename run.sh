#!/bin/bash
echo "Running Script"

#!/bin/bash

# 杀掉名为 python3 的进程
pids=$(pgrep -f python3)
if [ -n "$pids" ]; then
    echo "Killing python3 processes: $pids"
    kill $pids
else
    echo "No python3 processes found."
fi

# 杀掉名为 tc2 的进程
pids=$(pgrep -f tc2)
if [ -n "$pids" ]; then
    echo "Killing tc2 processes: $pids"
    kill $pids
else
    echo "No tc2 processes found."
fi


nohup python3 -m http.server 80 > ./logs/http.log 2>&1 &

nohup ./tc2 eth0 > ./logs/net.log 2>&1 &

echo "Services started."

# docker run --privileged -v ~/tc2:/root/tc2 -it nssa_container:ver2.0
# cd root/tc2  && ./run.sh
# docker exec -it [name] bash
# http://172.17.0.2:80
# 0. benign: for i in {1..5000}; do curl http://172.17.0.2; done
# 1. Dos Goldeneye: ./goldeneye.py http://172.17.0.2
# 2. Dos Hulk: python2 hulk.py http://172.17.0.2
# 3. Dos slowhttptest(slow read):   slowhttptest -B -c 3000 -g -o logs/output -i 100 -r 300 -s 8192 -t GET -u http://172.17.0.2 -x 20 -p 3
# 4. Dos slowloris:                 slowhttptest -c 1000 -H -g -o logs/my_header_stats -i 10 -r 200 -t GET -u http://172.17.0.2 -x 24 -p 3
# 5. portscan: nmap -sT 172.17.0.2

