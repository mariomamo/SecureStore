import traceback

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cipher import Cipher


class RSACipher(Cipher):
    __key = None

    def __init__(self, public_key_path=None):
        self.__public_key_path = public_key_path
        if public_key_path:
            try:
                self.__key = RSA.importKey(open(public_key_path).read())
            except Exception as ex:
                # traceback.print_exc()
                pass
        else:
            self.generateKeys()

    def encrypt(self, text, public_key_path):
        key = RSA.importKey(open(public_key_path).read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(text.encode())
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = PKCS1_OAEP.new(self.__key)
        message = cipher.decrypt(ciphertext)
        return message.decode()

    def generateKeys(self):
        key = RSA.generate(2048)
        with open('private_key.pem', 'wb') as file:
            file.write(key.export_key('PEM'))

        with open('public_key.pem', 'wb') as file:
            file.write(key.public_key().export_key('PEM'))

        self.__key = RSA.importKey(open(self.__public_key_path).read())


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
