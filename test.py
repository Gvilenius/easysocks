from pyDes import des, PAD_PKCS5, ECB

DES_SECRET_KEY = '12345678'

s = """<noscript><meta http-equiv="refresh" content="0; url=http://www.baidu.com/baidu.html?from=noscript" /></noscript></head><body class="">
    <script>
    if (navigator.userAgent.indexOf('Edge') > -1) {
        var body = document.querySelector('body');
        body.className += ' browser-edge';
    }
</script>"""
des_obj = des(DES_SECRET_KEY, padmode=PAD_PKCS5)
secret_bytes = des_obj.encrypt(s)
s = des_obj.decrypt(secret_bytes)
print(secret_bytes)
print("-----")
print(s)