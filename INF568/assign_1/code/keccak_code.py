from bitarray import bitarray
from math import log
import itertools
import numpy as np
import sys
import time

SIZE_CONSTANT = 64
WIDTH, CAPACITY = 1600, 512
RATE = WIDTH - CAPACITY

# constants copied from http://keccak.noekeon.org/specs_summary.html
ROUND_CONSTANTS = np.array([
  0x0000000000000001, 0x0000000000008082,
  0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088,
  0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b,
  0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080,
  0x0000000080000001, 0x8000000080008008],
  dtype=np.uint64)

SHIFT_CONSTANTS = np.array([
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14]])

class KeccakState(object):
    def __init__(self, A):
        self.A = np.array(A).reshape(5, 5)

    def set(self, x, y, val):
        self.A[y][x] = val

    def get(self, x, y):
        return self.A[y][x]

# digest_len is in bits
def shake_256(raw_msg, digest_len=4096):
    def sponge(msg, digest_len):
        def get_padded_msg():
            j = (-len(msg)-2) % RATE
            return msg + "1" + "0"*j + "1"

        sponge = np.zeros(WIDTH//64, dtype=np.uint64)
        padded_msg = get_padded_msg()
        msg_arr = bits_to_uint64(padded_msg)
        chunk_size = RATE // 64
        num_chunks = len(padded_msg) // RATE

        # absorbing
        for i in range(num_chunks):
            msg_chunk = msg_arr[i*chunk_size:(i+1)*chunk_size]
            capacity = np.zeros(CAPACITY//64, dtype=np.uint64)
            sponge = keccak_p(np.bitwise_xor(sponge, np.concatenate((msg_chunk,
                capacity))))

        # squeezing
        res = sponge[:chunk_size]
        while len(res)*64 < digest_len:
            sponge = keccak_p(sponge)
            res = np.concatenate((res, sponge[:chunk_size]))
        return ("".join(uint64_to_hex(res))[:digest_len//4],
                "".join(uint64_to_bits(res))[:digest_len])

    def bits_to_uint64(bits):
        num_elems = round(len(bits)/64)
        out = np.zeros(num_elems, dtype=np.uint64)
        for i in range(num_elems):
            out[i] = np.uint64(int(bits[i*64:(i+1)*64][::-1], 2))
        return out

    def uint64_to_bits(arr):
        def convert(num):
            s = "{0:0>64b}".format(num)
            chunks = [s[i:i+8] for i in range(0, len(s), 8)]
            return "".join(chunks[::-1])
        return np.vectorize(convert)(arr)

    def uint64_to_hex(arr):
        def convert(num):
            s = "{0:0>16X}".format(num)
            chunks = [s[i:i+2] for i in range(0, len(s), 2)]
            return "".join(chunks[::-1])
        return np.vectorize(convert)(arr)
    
    def keccak_p(A):
        k_state = KeccakState(A)
        for round_idx in range(24):
            one_round_keccak(k_state, round_idx)
        return k_state.A.reshape(25,)
    
    def one_round_keccak(k_state, round_idx):
        def shift_left(val, offset):
            tot_bits = 64
            if offset == 0 or offset == tot_bits:
                return val
            return (np.uint64(val) << np.uint64(offset)) ^ (np.uint64(val) >>
                    np.uint64(tot_bits - offset))

        # theta
        C_theta = np.zeros(5, dtype=np.uint64)
        for x in range(5):
            for y in range(5):
                C_theta[x] = C_theta[x] ^ k_state.get(x, y)
        D_theta = np.zeros(5, dtype=np.uint64)
        for x in range(5):
            D_theta[x] = C_theta[(x-1)%5] ^ shift_left(C_theta[(x+1)%5], 1)
            for y in range(5):
                k_state.set(x, y, k_state.get(x, y) ^ D_theta[x])

        # rho & pi
        k_state_B = KeccakState(np.zeros(25, dtype=np.uint64))
        for x in range(5):
            for y in range(5):
                k_state_B.set(y, (2*x+3*y)%5, shift_left(k_state.get(x, y),
                    SHIFT_CONSTANTS[y][x]))
        
        # chi
        ones = pow(2,64)-1
        for x in range(5):
            for y in range(5):
                k_state.set(x, y, k_state_B.get(x, y) ^ ((k_state_B.get((x+1)%5, y)
                    ^ ones) & k_state_B.get((x+2)%5, y)))

        # iota
        k_state.set(0, 0, k_state.get(0, 0) ^ ROUND_CONSTANTS[round_idx])

    return sponge(raw_msg+"1111", digest_len)

# digest_len is in bits
def shake_256_from_file(f_name, digest_len):
    bits = bitarray(endian='little')
    with open(f_name, "rb") as f:
        bits.fromfile(f)
        return shake_256(bits.to01(), digest_len)

def find_collisions_naive(in_bits, o_bits):
    h = {}
    count = 0
    for b_s in ["".join(seq) for seq in itertools.product("01",
        repeat=in_bits)]:
        curr_hash = shake_256(b_s, o_bits)[0]
        if curr_hash in h:
            bit_a = bitarray(b_s, endian="little")
            bit_b = bitarray(h[curr_hash], endian="little")
            #print(bit_a, bit_b, curr_hash, shake_256(h[curr_hash], o_bits))
            with open("ex-"+str(count)+".A", "w+b") as f_a:
                bit_a.tofile(f_a)
            with open("ex-"+str(count)+".B", "w+b") as f_b:
                bit_b.tofile(f_b)
            count += 1
        else:
            h[curr_hash] = b_s

def find_collisions_sqrt(in_bits, o_bits):
    def floyd(x0):
        f = lambda s: shake_256(s, o_bits)[1]
        tot, hare = f(x0), f(f(x0))
        while tot != hare:
            tot, hare = f(tot), f(f(hare))
        print("FOUND")
        prev_tot, curr_tot = None, x0
        prev_hare, curr_hare = None, hare
        while curr_tot != curr_hare:
            prev_tot, curr_tot = curr_tot, f(curr_tot)
            prev_hare, curr_hare = curr_hare, f(curr_hare)
        if not prev_tot or not prev_hare:
            return
        pair_l, pair_r = (prev_tot, prev_hare), (prev_hare, prev_tot)
        if pair_l in collision_set or pair_r in collision_set:
            return
        collision_set.add(pair_l)
        collision_set.add(pair_r)
        bit_a = bitarray(prev_tot, endian="little")
        bit_b = bitarray(prev_hare, endian="little")
        nonlocal count
        with open("ex-"+str(count)+".A", "w+b") as f_a:
            bit_a.tofile(f_a)
        with open("ex-"+str(count)+".B", "w+b") as f_b:
            bit_b.tofile(f_b)
        count += 1
        curr_time = time.time()
        nonlocal prev_time
        print(curr_time-prev_time)
        prev_time = curr_time

    count = 0
    prev_time = time.time()
    collision_set = set()
    b_s = "0"*in_bits
    floyd(b_s)

# digest_len in terms of bits
#print(shake_256_from_file("ex-90.B", 8)[0])

#find_collisions_naive(8, 8)

#find_collisions_sqrt(32, 32)
