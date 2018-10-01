# coding: utf-8

import random as rand
import math
import binascii

#encrypting message block m, a list of bits

def app0_error_correcting_encoding(m,n):
    #take m, turn into n length by appending 0's
    return m + (n-len(m))*"0"

#print(app0_error_correcting_encoding(format(44,'0%ib'%8), 100))

def app0_error_correcting_decoding(em,lam):
    return em[:lam]

#print(app0_error_correcting_decoding(app0_error_correcting_encoding(format(44,'0%ib'%8), 100), 8))

#insert primality test
def is_prime(n):
    return True

#KEY GENERATION: inputs lam, outputs pk, sk and T
    #uniformly randomly chosen n-bit string with Hamming weight h
def bit_string_h(n, h):
    #generate h random distinct numbers between 1 and n, put 1's in those positions
    rand_list = "0"*n
    true_list = rand.sample(range(1, n), h)
    for t in true_list:
        rand_list = rand_list[:t] + "1" + rand_list[t+1:]
    return int(rand_list, 2)
#print(bit_string_h(10, 5))
    
    #uniformly randomly chosen n-bit string
def n_bit_num(n):
    rand_num = rand.getrandbits(n)
    return rand_num


def key_gen(lam):
    h = lam

    #Choose a Mersenne prime such that h = lam and 16*(lam^2) >= n > 10*(lam^2)
    n_high = 16*(h**2)
    n_low = 10*(h**2)+1
    p_not_prime = True
    while p_not_prime:
        #print(' in prime checking loop')
        n = rand.randint(n_low, n_high) #randomly chosen between n_low and n_high
        p = 2**n - 1 #CHECK PRIMALITY
        p_not_prime = False
        if is_prime(n):
            p_not_prime = False

    F = bit_string_h(n, h) #uniformly randomly chosen n-bit string with Hamming weight h
    G = bit_string_h(n, h) #uniformly randomly chosen n-bit string with Hamming weight h

    R = n_bit_num(n) #uniformly randomly chosen n-bit string.
    #public key
    pk = (format(R,'0%ib'%n), (F*R + G) % p) #mod p
    #secret key
    sk = F
    return (pk, sk) #as well as lam and n


#ENCRYPTION: Inputs message m, public key pk and the error-correcting encoding algorithm E.
#            Outputs encrypted message (C1, C2)
def Mersenne_encrypt(m, pk, E):
    h = len(m)
    n = len(pk[0])
    A = bit_string_h(n, h) #uniformly randomly chosen n-bit string with Hamming weight h
    B1 = bit_string_h(n, h) #uniformly randomly chosen n-bit string with Hamming weight h
    B2 = bit_string_h(n, h) #uniformly randomly chosen n-bit string with Hamming weight h
    C1 = A*(int(pk[0])) + B1 #DEFINE R
    Em = E(m) #error correcting code
    ecl = len(Em) #number to binary string of length
    C2 = eval("0b" + format(A*pk[1] + B2,'0%ib'%ecl)) ^ eval("0b" + Em)
    return (C1, C2)

#DECRYPTION: Inputs the coded message (C1, C2), the secret key F and the error-correcting decoding algorithm D.
#            Outputs message m.
def Mersenne_decrypt(F, C1, C2, D):
    #bitwise XOR operation
    bin_len = max(math.ceil(math.log(F*C1, 2)), math.ceil(math.log(C2, 2)))
    output = eval("0b" + format(F*C1,'0%ib'%bin_len)) ^ eval("0b" + format(C2,'0%ib'%bin_len))
    return D(format(output,'0%ib'%bin_len))

pk, sk = key_gen(6)
print("Key generated")


#Run an example
m = "101110110100010110"

def string_to_bin(s):
    return bin(int.from_bytes(s.encode(), 'big'))[2:]

def bin_to_string(b):
    return b.to_bytes((n.bit_length() + 7) // 8, 'big').decode()

app100_enc = lambda x: app0_error_correcting_encoding(x, 10000)
app100_dec = lambda x: app0_error_correcting_decoding(x, len(m))

enc_m1, enc_m2 = Mersenne_encrypt(m, pk, app100_enc)
#print(enc_m1, enc_m2)
dec_m = Mersenne_decrypt(sk, enc_m1, enc_m2, app100_dec)

print("Original m:              ", m)
print("Encoded, then decoded m: ", dec_m)