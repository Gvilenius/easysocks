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
from rsa import RSA
from pyDes import des, PAD_PKCS5, ECB

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


def find_random_prime(lower_bound=20, upper_bound=30, seed=0):
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


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


class Socks5Server(SocketServer.StreamRequestHandler):
    # TODO
    exchanged = False

    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = sock.recv(4096)
                    data = self.DES_decrypt(data)
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(4096)
                    data = self.DES_encrypt(data)
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

        finally:
            sock.close()
            remote.close()
    
    def exchange_key(self, sock, remote):
        self.rsa = RSA()
        try:
            # 1. receive public key
            remote_pubkey = self.decrypt(sock.recv(4096)).decode('utf-8')
            self.remote_pubkey = [int(k) for k in remote_pubkey.decode('utf-8').strip().split('-')]
            logging.info("Server receive pubkey: %s" % remote_pubkey)

            # 2. send public key
            pub_key = (str(self.rsa.e) + '-' + str(self.rsa.n)).encode('utf-8')

            result = send_all(sock, self.encrypt(pub_key))
            
            # 3. identification check
            id_data = sock.recv(4096).decode('utf-8')
            id_data = self.rsa._decode(id_data, self.rsa.d, self.rsa.n, self.rsa.k)
            
            id_data = id_data.strip()
            logging.info("Server receive id_data: %s" % id_data)
            if not id_data[-10:] == '2017013684':
                raise Exception("Unknown partner")
            
            id_seq = str(int(id_data[:-10])+1)
            id_msg = '2017011303'
            id_data = self.rsa._encode(id_seq+id_msg, self.remote_pubkey[0], self.remote_pubkey[1], self.rsa.k).encode('utf-8')
            result = send_all(sock, id_data)
            
            # 4. exchange des key
            DES_KEY = sock.recv(4096).decode('utf-8')
            ## decrypt by private B
            DES_KEY = self.rsa._decode(DES_KEY, self.rsa.d, self.rsa.n, self.rsa.k)
            ## decrypt by public A
            DES_KEY = self.rsa._decode(DES_KEY, self.remote_pubkey[0], self.remote_pubkey[1], self.rsa.k)
            
            logging.info("Server exchange complete with DES key %s" % DES_KEY)
            return DES_KEY

        except socket.error, e:
            logging.warn(e)
            logging.info("Close tcp")
            sock.close()
            remote.close()
            # For safety
            return "12345678"

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def DES_encrypt(self, data):
        return data.translate(self.new_encrypt_table)
    
    def DES_decrypt(self, data):
        return data.translate(self.new_decrypt_table)

    def handle(self):
        try:
            sock = self.connection
            addrtype = ord(self.decrypt(sock.recv(1)))      # receive addr type
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))   # get dst addr
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6, self.decrypt(self.rfile.read(16)))   # get dst addr
            elif addrtype == 3:
                addr = self.decrypt(
                    self.rfile.read(ord(self.decrypt(sock.recv(1)))))       # read 1 byte of len, then get 'len' bytes name
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))    # get dst port into small endian
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                if addrtype == 4:
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.connect((addr, port[0]))         # connect to dst
            except socket.error, e:
                # Connection refused
                logging.warn(e)
                return

            # # TODO
            DES_KEY = self.exchange_key(sock, remote)
            self.new_encrypt_table = ''.join(get_table(DES_KEY))
            self.new_decrypt_table = string.maketrans(self.new_encrypt_table, string.maketrans('', ''))
            
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)


def readConfig():
    with open('config.json', 'rb') as f:
        config = json.load(f)

    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']
    optlist, args = getopt.getopt(sys.argv[1:], 'p:k:')
    for key, value in optlist:
        if key == '-p':
            PORT = int(value)
        elif key == '-k':
            KEY = value

    return SERVER, PORT, KEY

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')

    print 'naivesocks v0.1'
    SERVER, PORT, KEY = readConfig()

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

