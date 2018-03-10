import numpy as np
from bitarray import bitarray
import hashlib

for i in range(90):
    with open("ex-" + str(i) + ".A", "rb") as f_a:
        byte_A = f_a.read()
        m = hashlib.shake_256()
        m.update(byte_A)
        bit_a = bitarray(endian="little")
        bit_a.frombytes(byte_A)
        print(bit_a)
        #print(m.hexdigest(3))
    
    with open("ex-" + str(i) + ".B", "rb") as f_b:
        byte_B = f_b.read()
        n = hashlib.shake_256()
        n.update(byte_B)
        bit_b = bitarray(endian="little")
        bit_b.frombytes(byte_B)
        print(bit_b)
        #print(n.hexdigest(3))
