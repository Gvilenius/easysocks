import requests
 
my_proxies={"http":"http://127.0.0.1:1080","https":"https://127.0.0.1:1080"}
resp=requests.get("https://www.baidu.com",proxies=my_proxies,timeout=5)
print(resp.text)
