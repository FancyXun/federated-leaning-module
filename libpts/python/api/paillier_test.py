import unittest
import numpy as np
import time

import paillier


class PaiTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(PaiTestCase, self).__init__(*args, **kwargs)
        self.pai = paillier.Paillier(2048, 10)
        pk, vk = self.pai.gen_key_generate_key_pair()
        self.pk = pk
        self.vk = vk
        self.row = 10
        self.col = 10
        self.value = np.random.randint(-100000, 100000, (self.row, self.col))
        self.plain = np.random.randint(-100000, 100000, (self.row * self.col,))

    def test_pai_batch_enc(self):
        # encrypt
        cipher_text = self.pai.batch_encrypt(self.value, self.pk)
        self.assertEqual(cipher_text.shape[0], self.row*self.col)

    def test_pai_batch_dec(self):
        # encrypt
        cipher_text = self.pai.batch_encrypt(self.value, self.pk)
        # decrypt self.value
        decrypt_value = self.pai.batch_decrypt(cipher_text, self.pk, self.vk)
        self.value = self.value.astype(np.str).flatten().tolist()
        self.assertEqual(decrypt_value, self.value)

    def test_pai_sum(self):
        # encrypt
        cipher_text = self.pai.batch_encrypt(self.value, self.pk)
        # encrypt sum
        cipher_sum = self.pai.cipher_sum(cipher_text, self.pk)
        decrypt_sum = self.pai.decrypt(cipher_sum, self.pk, self.vk)
        self.assertEqual(decrypt_sum, np.sum(self.value).astype(np.str))

    def test_pai_batch_mul(self):
        # encrypt
        cipher_text = self.pai.batch_encrypt(self.value, self.pk)
        # encrypt self.value * plain
        cipher_mul_plain = self.pai.batch_mul(cipher_text, self.plain, self.pk)
        # decrypt self.value * plain
        decrypt_mul_plain = self.pai.batch_decrypt(cipher_mul_plain, self.pk, self.vk)
        for i in range(self.row):
            for j in range(self.col):
                self.assertEqual(decrypt_mul_plain[i*self.row+j], str(self.value[i][j]*self.plain[i*self.row+j]))


class PaiTimeTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(PaiTimeTestCase, self).__init__(*args, **kwargs)
        self.pai = paillier.Paillier(2048, 32)
        pk, vk = self.pai.gen_key_generate_key_pair()
        self.pk = pk
        self.vk = vk
        self.row = 100
        self.col = 100
        self.value = np.random.randint(-100000, 100000, (self.row, self.col))
        self.plain = np.random.randint(-100000, 100000, (self.row * self.col,))

    def setUp(self):
        self.startTime = time.time()

    def tearDown(self):
        t = time.time() - self.startTime
        print('%s: %.3f' % (self.id(), t))

    def test_pai_batch_enc_time(self):
        self.pai.batch_encrypt(self.value, self.pk)

    def test_pai_batch_dec(self):
        # encrypt
        cipher_text = self.pai.batch_encrypt(self.value, self.pk)
        # decrypt self.value
        self.startTime = time.time()
        self.pai.batch_decrypt(cipher_text, self.pk, self.vk)

    def test_pai_sum(self):
        # encrypt
        cipher_text = self.pai.batch_encrypt(self.value, self.pk)
        # encrypt sum
        self.startTime = time.time()
        self.pai.cipher_sum(cipher_text, self.pk)

    def test_pai_batch_mul(self):
        # encrypt
        cipher_text = self.pai.batch_encrypt(self.value, self.pk)
        # encrypt self.value * plain
        self.startTime = time.time()
        self.pai.batch_mul(cipher_text, self.plain, self.pk)


def pai_suite():
    suite = unittest.TestSuite()
    suite.addTest(PaiTestCase("test_pai_batch_enc"))
    suite.addTest(PaiTestCase("test_pai_batch_dec"))
    suite.addTest(PaiTestCase("test_pai_sum"))
    suite.addTest(PaiTestCase("test_pai_batch_mul"))
    return suite


def pai_time_suite():
    suite = unittest.TestSuite()
    suite.addTest(PaiTimeTestCase("test_pai_batch_enc_time"))
    suite.addTest(PaiTimeTestCase("test_pai_batch_dec"))
    suite.addTest(PaiTimeTestCase("test_pai_sum"))
    suite.addTest(PaiTimeTestCase("test_pai_batch_mul"))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=0)
    runner.run(pai_suite())
    runner.run(pai_time_suite())

