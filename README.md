### Usage guide
<<<<<<< HEAD:shadowsocks/README.md
``` 
# dependencies
python=2.7
pip install gevent
# client
python2 local.py -l <local_port> 
# web browser configure socks5 proxy: username/password
# server
python2 server.py
=======
``` markdown
## CLIENT
python local.py -l <local_port> 
# web browser configure socks5 proxy: username/password

## SERVER
python server.py

## TEST
curl -v  --socks5 127.0.0.1:1030 -U username:password http://www.beihai.gov.cn/
```
