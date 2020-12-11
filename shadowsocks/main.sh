#!/bin/bash

# killall python2 process
killall python2

# start the local proxy
python2 "$(dirname "$0")/local.py" -l 1030 &

# start the remote proxy 
python2 "$(dirname "$0")/server.py" &

sleep 2

# Test
curl -v --socks5 127.0.0.1:1030 -U username:password http://www.baidu.com/

 



