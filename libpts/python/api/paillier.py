import libpts
import numpy as np


class Paillier(object):

    def __init__(self, key_size=2048, parallel=24):
        self.key_size = key_size
        self.parallel = parallel

    def gen_key_generate_key_pair(self):
        """
        Generate paillier public key and private key
        Parameters
        ----------
        Returns
        ----------
        pk_vk: public key:[n, g, n2, maxInt]
               private key: [p, q, p^2, q^2, hp, hq, lambda, mu, n, n2, maxInt]
        """
        pk_vk = libpts.paillier_generate_key_pair(self.key_size)
        pk = self.concatenate_to_arr(pk_vk[:4], self.key_size//4+1)
        vk = self.concatenate_to_arr(pk_vk[4:], self.key_size//4+1)
        return pk, vk

    def encrypt(self, value):
        """

        """
        pass

    def batch_encrypt(self, value, pk):
        """
        Encrypt batch value with public key
        Parameters
        ----------
        value: 2-d int64 type array, shape=[M, N]
        pk: pk is a numpy array, need to convert to list for c

        Returns
        ----------
        cipher: 2-d uint8 numpy array, shape=[M*N, (self.key_size//8+1)*2+1]
        """
        pk = [row for row in pk]
        value = value.reshape(-1)
        cipher_text = libpts.paillier_batch_encrypt(value, pk, self.parallel)
        return np.asarray(cipher_text)

    def cipher_sum(self, value, pk):
        """
        Sum of encrypt value
        Parameters
        ----------
        value: 2-d uint8 numpy array
        pk: public key

        Returns
        ----------
        cipher_text: uint8 numpy array
        """
        pk = [row for row in pk]
        value = [row for row in value]
        cipher_text = libpts.paillier_sum(pk, value)
        return cipher_text

    def decrypt(self, cipher_text, pk, vk):
        """
        Decrypt cipher text with private value
        Parameters
        ----------
        cipher_text: uint8 numpy array
        vk: private key
        pk: public key
        Returns
        ----------
        value: uint8 numpy array
        """
        vk = [row for row in pk] + [row for row in vk]
        value = libpts.paillier_decrypt(vk, cipher_text)
        return value

    def batch_decrypt(self, value, pk, vk):
        """

        """

        vk = [row for row in pk] + [row for row in vk]
        value = [row for row in value]
        plain_text = libpts.paillier_batch_decrypt(vk, value, self.parallel)
        return plain_text

    def batch_mul(self, value, plain, pk):
        """

        """
        pk = [row for row in pk]
        value = [row for row in value]
        plain = plain.astype(np.str)
        plain = [row for row in plain]
        cipher_text = libpts.paillier_batch_mul(pk, value, plain, self.parallel)
        return np.asarray(cipher_text)

    @staticmethod
    def concatenate_to_arr(value, max_size):
        con_list = []
        for i in value:
            con_list.append(
                np.pad(i, (0, max_size - i.shape[0]), 'constant'))
        return np.asarray(con_list)

