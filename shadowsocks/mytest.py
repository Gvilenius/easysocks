import hashlib
import struct
import string

m = hashlib.md5()
m.update(b"123")
m = hashlib.md5()
m.update(b"12")
a,b = struct.unpack( b"QQ", m.digest())
#for i in range(1, 1024):
#    table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
#print(table)
print '<H'
print '>H'
print '!H'
print b'H'
