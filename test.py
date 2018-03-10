import numpy as np

def uint64_to_hex(arr):
    hex_arr = []
    for long_type in arr:
        byte_nums = np.frombuffer(long_type, np.uint8)[::-1]
        for n in byte_nums:
            b = '{0:08b}'.format(n)[::-1]
            hex_arr.extend(list(hex(int(b,2))[2:]))
    return "".join(hex_arr)

def uint64_to_bits(arr):
    bit_arr = []
    for long_type in arr:
        bit_arr.extend(list(bin(long_type)[2:]))
    return "".join(bit_arr)

a = np.uint64(14228184772754713258L)
print uint64_to_bits([a])
