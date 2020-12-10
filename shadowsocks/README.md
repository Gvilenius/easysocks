### Usage guide
``` 
# client
python local.py -l <local_port> 
# web browser configure socks5 proxy: username/password
# server
python server.py

#test
curl -v  --socks5 127.0.0.1:1030 -U username:password http://www.beihai.gov.cn/

```
