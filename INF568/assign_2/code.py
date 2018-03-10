from math import log
from random import randint
import codecs
import sys
import time

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        print(g)
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def ladder(N, curve_A, k, x_1, z_1):
    A24 = ((curve_A+2)*modinv(4,N)) % N
    def cswap(swap, x_0, x_1):
        t = swap*(x_0-x_1)
        return x_0-t, x_1+t

    diff = x_1
    x_0, z_0 = 1, 0
    swap = 0

    for t in reversed(range(k.bit_length())):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_0, x_1 = cswap(swap, x_0, x_1)
        z_0, z_1 = cswap(swap, z_0, z_1)

        swap = k_t
    
        A = x_0 + z_0
        AA = pow(A, 2, N)
        B = x_0 - z_0
        BB = pow(B, 2, N)
        E = AA - BB
        C = x_1 + z_1
        D = x_1 - z_1
        DA = (D * A) % N
        CB = (C * B) % N
        x_1 = ((DA+CB)*(DA+CB)) % N
        z_1 = (diff * ((DA-CB)*(DA-CB)) % N) % N
        x_0 = (AA * BB) % N
        z_0 = (E * ((BB + ((A24 * E)%N))%N))%N

    x_0, x_1 = cswap(swap, x_0, x_1)
    z_0, z_1 = cswap(swap, z_0, z_1)
    return x_0, z_0

def ladder_tester():
    A, prime = 682, 1009
    for k in [2, 3, 5, 34, 104, 947]:
        x, z = ladder(prime, A, k, 7, 1)
        print((x * pow(z, prime-2, prime)) % prime)
#ladder_tester()

# Task 1 related
def X25519(k, u):
    bits = 255
    prime = pow(2, 255)-19
    A = 486662
    A24 = 121665
    k = decodeScalar25519(k)
    u = decodeUCoordinate(u, bits)
    res_x, res_z = ladder(prime, A, k, u, 1)
    res = (res_x * pow(res_z, prime-2, prime)) % prime
    return encodeUCoordinate(res, bits, prime)

# Encoding stuff
def decodeLittleEndian(b, bits):
    return sum([b[i] << 8*i for i in range((bits+7)/8)])

def decodeUCoordinate(u, bits):
    u_list = [ord(b) for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1<<(bits%8))-1
    return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits, p):
    u = u % p
    return ''.join([chr((u >> 8*i) & 0xff) for i in range((bits+7)/8)])

# Generating scalars from random bytes
def decodeScalar25519(k):
    k_list = [ord(b) for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)

def X25519_tester():
    scalars = ["a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
               "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"]
    
    u_coordinates = ["e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"]

    expected_outs = ["c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"]

    for i in range(len(scalars)):
        s_decoded = codecs.decode(scalars[i], "hex")
        u_decoded = codecs.decode(u_coordinates[i], "hex")
        out = codecs.encode(X25519(s_decoded, u_decoded), "hex")
        assert (out == expected_outs[i])
#X25519_tester()

# Task 2 related
PRIMES = []
def generate_primes(bound=pow(10,5)):
    bool_primes = [True] * (bound+1)
    for num in range(2, bound+1):
        if bool_primes[num]:
            PRIMES.append(num)
            for i in range(num, bound+1, num):
                bool_primes[i] = False

def trial_division(N):
    if N < 2:
        return []
    prime_factors = []
    for p in PRIMES[:1229]:
        if p > N: break
        exp = 0
        while N % p == 0:
            exp += 1
            N //= p
        if exp != 0:
            prime_factors.append((p, exp))
    if N > 1:
        prime_factors.append((N, 1))
    return prime_factors

def is_probable_prime(m, ntrials):
    # returns true if and only if the integer m passes ntrials iterations of the
    # Miller-Rabin primality test
    if m == 2 or m == 3:
        return True
    if m <= 4:
        return False
    d = m - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for i in range(ntrials):
        a = randint(2, m-2)
        x = pow(a, d, m)
        if x == 1 or x == m-1:
            continue
        nxt = False
        for j in range(r-1):
            x = pow(x, 2, m)
            if x == 1:
                return False
            if x == m-1:
                nxt = True
                break
        if not nxt:
            return False
    return True

def ECMTrial(N, bound, trials):
    def random_curve():
        sigma = randint(6, sys.maxsize)
        u = (sigma*sigma-5) % N
        v = (4*sigma) % N
        x, z = pow(u,3,N), pow(v,3,N)
        inverse = modinv(4*x*v,N)
        A = (pow(v-u,3,N) * (3*u+v) * inverse - 2) % N
        ## check that the elliptic curve equation holds on the projective plane
        #b = (u*modinv(z,N))%N
        #y = ((pow(sigma,2,N)-1)*(pow(sigma,2,N)-25)*(pow(sigma,4,N)-25)) % N
        #left = (b*pow(y,2,N)*z) % N
        #right = (pow(x,3,N) + A*pow(x,2,N)*z + x*pow(z,2,N)) % N
        #print(left, right)
        return A, x, z
    for i in range(trials):
        if i % 10 == 0:
            print(i)
        A, x, z = random_curve()
        sing = egcd((pow(A,2,N)-4)%N, N)[0]
        if sing != 1:
            print(sing)
            return sing
        for p in PRIMES:
            k = pow(p, int(log(bound, p)))
            x, z = ladder(N, A, k, x, z)
        divisor = egcd(z, N)[0]
        if divisor != 1:
            count = 0
            while N % divisor == 0:
                N //= divisor
                count += 1
            return (divisor, count)
    return False
    
def factorization(N):
    bound = pow(10, 4)
    generate_primes(bound)
    factors = trial_division(N)
    N = factors[-1][0]
    factors = factors[:-1]
    while not is_probable_prime(N, 40):
        print(N)
        res = ECMTrial(N, bound, 3000)
        if res:
            print("Found a factor")
            factors.append(res)
            N //= res[0]
        else:
            bound *= 3
            print("New Bound: " + str(bound))
    factors.append((N,1))
    return factors
        
print(factorization(2311513769971995978024))
