from bitarray import bitarray
from math import log
import filecmp
import json
import numpy as np

class LPS(object):
    def __init__(self, n, k, q):
        self.n = n
        # assumes q to be odd
        assert(q % 2 == 1)
        assert(q > 10*n*pow(log(n), 2))
        self.q = q
        self.k = k
    
    def special_op(self, mat, vec):
        tot = 0
        m, n = len(mat), len(vec)
        q_to_m = pow(self.q, m)
        for j in range(n):
            if vec[j] == 1:
                for k in range(m):
                    q_to_k = pow(self.q, k, q_to_m)
                    tot += int(mat[k][j]) * q_to_k
                    tot %= q_to_m
        t = np.zeros(m, dtype=int)
        for l in range(m):
            t[l] = tot % self.q
            tot //= self.q
        return np.array(t)

    def generate_key(self):
        return self.generate_key_inter(self.n, self.q, self.k)
    
    def generate_key_inter(self, n, q, k):
        A_prime = np.random.randint(-(q-1)//2, (q-1)//2+1, (n, n))
        A = np.copy(A_prime)
        ss = []
        for i in range(k):
            s = np.random.randint(2, size=n)
            ss.append(s)
            t = self.special_op(A_prime, s)
            A = np.append(A, np.reshape(t, (n, 1)), axis=1)
        return A, ss

    def encrypt(self, m, pub_key):
        return self.encrypt_inter(m, pub_key, self.n, self.q)

    def encrypt_inter(self, m, pub_key, n, q):
        r = np.random.randint(2, size=n)
        ciphertext = (self.special_op(pub_key.T, r) +
                (q-1)//2*(np.append(np.zeros(n, dtype=np.int),m)))
        ciphertext = [((c + (q-1)//2) % q) - (q-1)//2 for c in ciphertext]
        #print(ciphertext)
        return np.array(ciphertext)
    
    def decrypt(self, c, priv_key):
        return self.decrypt_inter(c, priv_key, self.n, self.q, self.k)

    def decrypt_inter(self, c, priv_key, n, q, k):
        v, w = c[:n], c[n:]
        m = []
        for i in range(k):
            y = ((v.dot(priv_key[i]) - w[i] + (q-1)//2) % q) - (q-1)//2
            if abs(y) < q/4:
                m.append(0)
            else:
                m.append(1)
        return m

def encrypt_file(in_f, out_f, pub_key, n, k, q):
    msg = bitarray(endian="little")
    with open(in_f, "rb") as in_file:
        msg.fromfile(in_file)
    #print(msg)
    msg = list(map(int, msg.tolist()))
    cipher = LPS(n, k, q)
    res = cipher.encrypt(msg, pub_key).tolist()
    with open(out_f, "w") as out_file:
        json.dump(res, out_file)

# This function was written to separately test decryption on test vectors
#def test_decrypt(f_name, priv_key, n, k, q):
#    with open(f_name, "rb") as f:
#        line = f.readlines()[0].rstrip()
#    msg = np.array(list(map(int, line.split())))
#    cipher = LPS(n, k, q)
#    plain = bitarray("".join(list(map(str, cipher.decrypt(msg, priv_key)))),
#            endian="little")
#    print(plain)
#    with open("output.txt", "wb") as f:
#        plain.tofile(f)

def decrypt_file(in_f, out_f, priv_key, n, k, q):
    with open(in_f, "rb") as in_file:
        msg = np.array(json.load(in_file))
    cipher = LPS(n, k, q)
    bits = "".join(list(map(str, cipher.decrypt(msg, priv_key))))
    plaintext = bitarray(bits, endian="little")
    #print(plaintext)
    with open(out_f, "wb") as out_file:
        plaintext.tofile(out_file)

# Methods used for testing
def read_pub_key(pub_key_f):
    with open(pub_key_f, "r") as f:
        lines = [l.rstrip() for l in f.readlines()]
        pub_key = lines[4:]
        n, k, q = map(int, lines[1:4])
        pub = np.array([list(map(int, l.split())) for l in pub_key])
    return pub, n, k, q

def read_priv_key(priv_key_f):
    with open(priv_key_f, "r") as f:
        lines = [l.rstrip() for l in f.readlines()]
        priv_key = lines[3:]
        n, k = map(int, lines[1:3])
        priv = np.array([list(map(int, l.split())) for l in priv_key])
    return priv, n, k

def test_edouard():
    # Tests encryption and decryption with given key
    public, n, k, q = read_pub_key('test-200-64-58001.pub')
    encrypt_file('plain-64-edouard.dat', 'edouard_ciphertext', public, n, k, q)
    private = read_priv_key('test-200-64-58001.priv')[0]
    decrypt_file('edouard_ciphertext', 'edouard_plaintext', private, n, k, q)
    assert(filecmp.cmp('edouard_plaintext', 'plain-64-edouard.dat'))

    # Tests key generation
    lps = LPS(n, k, q)
    public, private = lps.generate_key()
    encrypt_file('plain-64-edouard.dat', 'edouard_ciphertext_own_key', public,
            n, k, q)
    decrypt_file('edouard_ciphertext_own_key', 'edouard_plaintext_own_key',
            private, n, k, q)
    assert(filecmp.cmp('edouard_plaintext_own_key', 'plain-64-edouard.dat'))

test_edouard()
