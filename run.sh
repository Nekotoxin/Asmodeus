#!/bin/bash

nohup python3 -m http.server 80 > ./logs/http.log 2>&1 &

nohup ./tc2 eth0 > ./logs/net.log 2>&1 &

echo "Services started."

# docker run --privileged -v ~/tc2:/root/tc2 -it nssa_container:ver2.0
# docker exec -it [name] bash
# http://172.17.0.2:80
# slowhttptest -c 1000 -H -g -o my_header_stats -i 10 -r 200 -t GET -u http://172.17.0.2 -x 24 -p 3