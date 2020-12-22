import base64, fractions, argparse, random
import numpy as np
try:
    import gmpy
except ImportError as e:
    try:
        import gmpy2 as gmpy
    except ImportError:
        raise e

from pyasn1.codec.der import encoder
from pyasn1.type.univ import *
import sys

PEM_TEMPLATE = '-----BEGIN RSA PRIVATE KEY-----\n%s-----END RSA PRIVATE KEY-----\n'
DEFAULT_EXP = 65537


def find_random_prime(lower_bound=10, upper_bound=20):
    assert (lower_bound >= 1), "Lower_bound must be no less than 1."
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
        

class RSA:
    def __init__(self, p=None, q=None, e=None, k=20):
        """
        Initialize RSA instance using primes (p, q)
        """
        if not p:
            p = find_random_prime(lower_bound=80000, upper_bound=120000)
        if not q:
            q = find_random_prime(lower_bound=80000, upper_bound=120000)
        if not e:
            e = find_random_prime(lower_bound=80000, upper_bound=120000)

        self.e = e

        if p and q:
            assert gmpy.is_prime(p), 'p is not prime'
            assert gmpy.is_prime(q), 'q is not prime'

            self.p = p
            self.q = q
        else:
            raise ArgumentError('(p, q) must be provided')
            
        
        self.n = self.p * self.q
        self.k = k

        assert 2 ** self.k < self.n, 'k must be less than log_2(n)'

        self._calc_values()

    def _calc_values(self):
        if self.p != self.q:
            phi = (self.p - 1) * (self.q - 1)
        else:
            phi = (self.p ** 2) - self.p

        self.d = gmpy.invert(self.e, phi)

        # CRT-RSA precomputation
        self.dP = self.d % (self.p - 1)
        self.dQ = self.d % (self.q - 1)
        self.qInv = gmpy.invert(self.q, self.p)

    def to_pem(self):
        """
        Return OpenSSL-compatible PEM encoded key
        """
        return (PEM_TEMPLATE % base64.encodestring(self.to_der()).decode()).encode()

    def to_der(self):
        """
        Return parameters as OpenSSL compatible DER encoded key
        """
        seq = Sequence()

        for x in [0, self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv]:
            seq.setComponentByPosition(len(seq), Integer(x))

        return encoder.encode(seq)

    def dump(self, verbose):
        vars = ['n', 'e', 'd', 'p', 'q']

        if verbose:
            vars += ['dP', 'dQ', 'qInv']

        for v in vars:
            self._dumpvar(v)

    def _dumpvar(self, var):
        val = getattr(self, var)

        parts = lambda s, l: '\n'.join([s[i:i+l] for i in range(0, len(s), l)])

        if len(str(val)) <= 40:
            print('%s = %d (%#x)\n' % (var, val, val))
        else:
            print('%s =' % var)
            print(parts('%x' % val, 80) + '\n')
    
    def fast_power(self, base, exp, mod):
        """ Fast power calculation using repeated squaring """
        if exp < 0:
            return 1 / power(base, -exp)
        ans = 1
        while exp:
            if exp & 1:
                ans = (base * ans) % mod
            exp >>= 1
            base = (base * base) % mod
        return ans 

    def _encode(self, data, key_e, key_n, key_k):
        data_split_size = len('{0:0=#b}'.format(key_n)) - 2
        # print(data_split_size)
        # print type(data.encode('utf-8')[0])
        # print 'data_split_size %d' % data_split_size
        data = "".join(['{0:0=#10b}'.format(int(m))[2:] for m in data.encode('utf-8')])
        # print data

        # Add a different bit
        end_bit = '0'
        if (data[-1] == '0'):
            end_bit = '1'

        data += end_bit
        while (len(data) % key_k != 0):
            data += end_bit
        # print data

        encrypt_data = [self.fast_power(int(data[i:i+key_k],2), key_e, key_n)  for i in range(0, len(data), key_k)]
        encrypt_data = ['{0:0=#{width}b}'.format(d, width=(data_split_size+2))[2:] for d in encrypt_data]
        encrypt_data = "".join(encrypt_data)

        return encrypt_data

    def encrypt_data(self, data):
        return self._encode(data=data, key_e=self.e, key_n=self.n, key_k=self.k)

    def _decode(self, data, key_d, key_n, key_k):
        data_split_size = len('{0:0=#b}'.format(key_n)) - 2

        decrypt_data = [data[i:i+data_split_size] for i in range(0, len(data), data_split_size)]

        decrypt_data = [self.fast_power(int(d, 2), key_d, key_n) for d in decrypt_data]

        decrypt_data = "".join(['{0:0=#{width}b}'.format(d, width=key_k+2)[2:] for d in decrypt_data])

        while(decrypt_data[-1] == decrypt_data[-2]):
            decrypt_data = decrypt_data[:-1]
        decrypt_data = decrypt_data[:-1]

        if sys.version_info < (3, 0):
            decrypt_data = [str(int(decrypt_data[i:i+8], 2)) for i in range(0, len(decrypt_data), 8)]
        else:
            decrypt_data = [chr(int(decrypt_data[i:i+8], 2)) for i in range(0, len(decrypt_data), 8)]

        decrypt_data = "".join(decrypt_data)

        return decrypt_data
    
    def decrypt_data(self, data):
        return self._decode(data=data, key_d=self.d, key_n=self.n, key_k=self.k)
    
    def get_stringfied(self, value, interval=8):
        width = len(bin(value))-2
        width = width + (interval - width%interval) + 2
        stringfied = "{0:0=#{width}b}".format(value, width=width)[2:]
        result = ""
        for i in range(0, len(stringfied), gap):
            result += chr(int(stringfied[i:i+gap], 2))
        return result
    
    def unstringfied(self, string, interval=8):
        value = ""
        for c in string:
            value += "{0:0=#{width}b}".format(ord(c), width=interval)[2:]
        result = int(value,2)
        return result




if __name__ == '__main__':
    # parser = argparse.ArgumentParser()

    # parser.add_argument('-p', dest='p', help='prime', type=int, default=9787)
    # parser.add_argument('-q', dest='q', help='prime', type=int, default=9791)
    # parser.add_argument('-k', dest='k', help='integer', type=int, default=20)
    # parser.add_argument('-e', dest='e', help='public exponent (default: %d)' % 65537, type=int, default=65537)
    # parser.add_argument('-f', dest='format', help='output format (DER, PEM) (default: PEM)', default='PEM')
    # parser.add_argument('-v', dest='verbose', help='also display CRT-RSA representation', action='store_true', default=False)


    # try:
    #     args = parser.parse_args()

    #     if args.p and args.q:
    #         print('Using (p, q) to initialise RSA instance\n')
    #         rsa = RSA(p=args.p, q=args.q, e=args.e, k=args.k)
    #     else:
    #         parser.print_help()
    #         parser.error('(p, q) needs to be specified')

    #     rsa.dump(args.verbose)

    #     # print(rsa.fast_power(2,10,2000))

        rsa = RSA(p=9787, q=9791, e=65537, k=20)
        msg = "1002017013684"
        encrypt = rsa.encrypt_data(msg)
        print("Encode: ", encrypt)
        decrypt = rsa.decrypt_data(encrypt)
        print("Decode: ", decrypt)


    # except argparse.ArgumentError as e:
    #     parser.print_help()
    #     parser.error(e.msg)
