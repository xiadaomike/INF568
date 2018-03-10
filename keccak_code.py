from math import log
import sys
import numpy as np

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
        self.A = A.reshape(5, 5)

    def set(self, x, y, val):
        self.A[y][x] = val
        #self.A[(y-3)%5][(x-3)%5] = val

    def get(self, x, y):
        return self.A[y][x]
        #return self.A[(y-3)%5][(x-3)%5]

def shake_256(raw_msg, digest_len):
    def sponge(msg, digest_len):
        def get_padded_msg():
            j = (-len(msg)-2) % RATE
            return msg + "1" + "0"*j + "1"

        sponge = np.zeros(WIDTH/64, dtype=np.uint64)
        padded_msg = get_padded_msg()
        msg_arr = bits_to_uint64(padded_msg)
        chunk_size = RATE / 64
        num_chunks = len(padded_msg) // RATE

        #print uint64_to_hex(msg_arr)
        # absorbing
        for i in range(num_chunks):
            msg_chunk = msg_arr[i*chunk_size:(i+1)*chunk_size]
            capacity = np.zeros(CAPACITY/64, dtype=np.uint64)
            #print uint64_to_hex(np.concatenate((msg_chunk, capacity)))
            print uint64_to_hex(np.bitwise_xor(sponge, np.concatenate((msg_chunk,
                capacity))))
            sponge = keccak_p(np.bitwise_xor(sponge, np.concatenate((msg_chunk,
                capacity))))
        print uint64_to_hex(sponge)
        return

        # squeezing
        res = sponge[:chunk_size]
        while len(Z)*64 < digest_len:
            sponge = keccak_p(sponge)
            res = np.concatenate(res, S[:chunk_size])
        return uint64_to_bits(res)

    def bits_to_uint64(bits):
        num_elems = len(bits) / 64
        out = np.zeros(num_elems, dtype=np.uint64)
        for i in range(num_elems):
            out[i] = np.uint64(int(bits[i*64:i*64+64], 2))
        return out

    def uint64_to_bits(arr):
        bit_arr = []
        for long_type in arr:
            bit_arr.extend(list(bin(long_type)[2:]))
        return "".join(bit_arr)

    def uint64_to_hex(arr):
        hex_arr = []
        for long_type in arr:
            byte_nums = np.frombuffer(long_type, np.uint8)[::-1]
            for n in byte_nums:
                b = '{0:08b}'.format(n)[::-1]
                hex_arr.extend(list("{0:0>2X}".format(int(b,2))))
        return "".join(hex_arr)
    
    func = np.vectorize(lambda x: hex(x)[2:])
    def keccak_p(A):
        k_state = KeccakState(A)
        for round_idx in range(24):
            one_round_keccak(k_state, round_idx)
            #if round_idx == 5:
            #    print func(k_state.A)
            #    return
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
        #print func(k_state.A)

    sponge(raw_msg+"1111", digest_len)
    #test_input = np.zeros(25, dtype=np.uint64)
    #keccak_p(test_input)

shake_256("", 0)
