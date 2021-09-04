import libpts
import pdb
import numpy as np
import time

a = np.asarray([[i for i in range(100)],[i for i in range(100)]], np.int64)
start_time = time.time()
key = libpts.paillier_generate_key_pair(2048)
print("秘钥生成时间:", time.time()-start_time)
start_time = time.time()
b = libpts.paillier_batch_encrypt(a,key,1)
print("加密时间:", time.time()-start_time)
start_time = time.time()
c = libpts.paillier_sum(key,b)
print("求和时间:", time.time()-start_time)
start_time = time.time()
d = libpts.paillier_decrypt(key,c)
print("解密时间:", time.time()-start_time)
print(d)