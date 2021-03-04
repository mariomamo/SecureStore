import os
import traceback

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cipher import Cipher


class RSACipher(Cipher):
    __private_key = None
    __private_key_path = None
    __public_key_path = None
    __default_private_key_path = "private_key.pem"
    __default_public_key_path = "public_key.pem"

    def __init__(self, private_key_path=None, public_key_path=None):
        if private_key_path is not None:
            if os.path.exists(private_key_path):
                self.__private_key_path = private_key_path
                self.__private_key = RSA.importKey(open(private_key_path).read())
            else:
                self.__private_key_path = private_key_path
        else:
            self.__private_key_path = self.__default_private_key_path

        if public_key_path is None:
            self.__public_key_path = self.__default_public_key_path
        else:
            self.__public_key_path = public_key_path

    def encrypt(self, text, public_key_path):
        key = RSA.importKey(open(public_key_path).read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(text.encode())
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = PKCS1_OAEP.new(self.__private_key)
        message = cipher.decrypt(ciphertext)
        return message.decode()

    def generateKeys(self):
        key = RSA.generate(2048)
        with open(self.__private_key_path, 'wb') as file:
            file.write(key.export_key('PEM'))

        with open(self.__public_key_path, 'wb') as file:
            file.write(key.public_key().export_key('PEM'))


if __name__ == '__main__':
    try:
        public_key_path = '../public_key.pem'
        private_key_path = '../private_key.pem'

        cripter = RSACipher(private_key_path)
        ciphertext = cripter.encrypt("Ciao", public_key_path)
        print(f'CIFRATO: {ciphertext}')

        decripter = RSACipher(private_key_path)
        message = cripter.decrypt(ciphertext)
        print(f'DECIFRATO: {message}')
    except Exception as ex:
        traceback.print_exc()
