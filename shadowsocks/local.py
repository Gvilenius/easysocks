import sys

import gevent, gevent.monkey
gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
import socket
import select
import SocketServer
import struct
import string
import hashlib
import os
import json
import logging
import getopt
from pyDes import des, PAD_PKCS5, ECB
from rsa import RSA
import numpy as np

def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table

def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


def find_random_prime(lower_bound=1, upper_bound=20, seed=0):
    assert (lower_bound >= 1), "Lower_bound must be no less than 1."
    np.random.seed(seed=seed)
    index = np.random.randint(lower_bound, upper_bound)

    prime_list = []
    
    i = 2
    while(True):
        if (len(prime_list) >= index):
            break
        if gmpy.is_prime(i):
            prime_list.append(i)
        i += 1

    return prime_list[index-1]


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):   # Multiple inheritance
    allow_reuse_address = True


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], []) 
                if sock in r:                               # if local socket is ready for reading
                    data = sock.recv(4096)
                    data = self.DES_encrypt(data)
                    if len(data) <= 0:                      # received all data
                        break
                    result = send_all(remote, data)   # send data after encrypting
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:                             # remote socket(proxy) ready for reading
                    data = remote.recv(4096)
                    data = self.DES_decrypt(data)
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)     # send to local socket(application)
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            logging.info("Finishing close tcp")
            sock.close()
            remote.close()
    
    def exchange_key(self, sock, remote):
        self.rsa = RSA()
        try:
            # 1. send public key
            pub_key = (str(self.rsa.e) + '-' + str(self.rsa.n)).encode('utf-8')
            pub_key = pub_key

            result = send_all(remote, self.encrypt(pub_key))
            
            # 2. receive public key
            remote_pubkey = self.decrypt(remote.recv(4096)).decode('utf-8')
            self.remote_pubkey = [int(k) for k in remote_pubkey.decode('utf-8').strip().split('-')]
            logging.info("Local receive pubkey: %s" % remote_pubkey)

            # 3. identification check
            id_seq = str(np.random.randint(0,10000))
            id_msg = '2017013684'

            logging.info("Client send id_data: %s" % id_seq+id_msg)
            
            id_data = self.rsa._encode(id_seq+id_msg, self.remote_pubkey[0], self.remote_pubkey[1], self.rsa.k)
            result = send_all(remote, id_data)

            id_data = remote.recv(4096).decode('utf-8')
            id_data = self.rsa._decode(id_data, self.rsa.d, self.rsa.n, self.rsa.k)
            id_data = id_data.strip()
            if not id_data[:-10] == str(int(id_seq)+1):
                raise Exception("Unknown seq")
            if not id_data[-10:] == '2017011303':
                raise Exception("Unknown partner")

            # 4. exchange des key
            DES_KEY = str(np.random.randint(10000000, 100000000))
            self.des_obj = des(DES_KEY, ECB, DES_KEY, padmode=PAD_PKCS5)

            __DES_KEY = DES_KEY
            ## encrypt by private A
            DES_KEY = self.rsa._encode(DES_KEY, self.rsa.d, self.rsa.n, self.rsa.k)
            ## encrypt by public B
            DES_KEY = self.rsa._encode(DES_KEY, self.remote_pubkey[0], self.remote_pubkey[1], self.rsa.k).encode('utf-8')

            result = send_all(remote, DES_KEY)
            logging.info("Client xchange complete with DES key %s" % __DES_KEY)

        except:
            logging.info("close tcp")
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)
    
    def DES_encrypt(self, data):
        return self.des_obj.encrypt(data)
    
    def DES_decrypt(self, data):
        return self.des_obj.decrypt(data)

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            sock = self.connection        # local socket [127.1:port]
            sock.recv(262)                # Sock5 Verification packet
            sock.send("\x05\x00")         # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            # After Authentication negotiation

            data = self.rfile.read(4)     # Forward request format: VER CMD RSV ATYP (4 bytes)

            # CMD == 0x01 (connect)
            logging.info(data)
            mode = ord(data[1])           
            logging.info('mode=' + str(mode))
            if mode != 1:
                logging.warn('mode != 1')
                return
            # dst addr
            addrtype = ord(data[3])       # indicate destination address type
            addr_to_send = data[3]
            if addrtype == 1 :             # IPv4
                addr_ip = self.rfile.read(4)            # 4 bytes IPv4 address (big endian)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)
                addr_len = self.rfile.read(1)           # Domain name's Length
                addr = self.rfile.read(ord(addr_len))   # Followed by domain name(e.g. www.google.com)
                addr_to_send += addr_len + addr
            elif addrtype ==4:
                addr_ip = self.rfile.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
                addr_to_send += addr_ip
            else:
                logging.warn('addr_type notsupport')
                # not support
                return

            addr_port = self.rfile.read(2)
            addr_to_send += addr_port                   # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            port = struct.unpack('>H', addr_port)       # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            try:
                reply = "\x05\x00\x00\x01"              # VER REP RSV ATYP
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)  # listening on 2222 on all addresses of the machine, including the loopback(127.0.0.1)
                self.wfile.write(reply)                 # response packet
                # reply immediately
                if '-6' in sys.argv[1:]:                # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)       # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))
                
                self.send_encrypt(remote, addr_to_send)      # encrypted
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return

            # TODO
            self.exchange_key(sock, remote)
            
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)

def readConfig():
    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:')
    for key, value in optlist:
        if key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-l':
            PORT = int(value)
        elif key == '-s':
            SERVER = value

    return SERVER, REMOTE_PORT, PORT, KEY 

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print 'naivesocks v0.1'

    SERVER, REMOTE_PORT, PORT, KEY = readConfig()

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    encrypt_table = ''.join(get_table(KEY))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)   
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)

