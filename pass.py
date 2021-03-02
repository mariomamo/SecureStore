#!/usr/bin/python
import argparse
import os
import traceback

import pyperclip as pyperclip
import yaml
from cipher import Cipher

from cipher.RSACipher import RSACipher


def getPublicKey():
    return 'public_key.pem'


def getPrivateKey():
    return 'private_key.pem'


def putPassword(name, password, cripter: Cipher):
    ciphertext = cripter.encrypt(password, public_key_path)
    if not os.path.exists('keys'):
        os.makedirs('keys')

    with open("./keys/" + name, "wb") as f:
        f.write(ciphertext)


def getPassword(name, cripter: Cipher):
    if not os.path.exists('keys'):
        os.makedirs('keys')

    try:
        with open("./keys/" + name, "rb") as f:
            ciphertext = f.read()

        c = RSACipher(private_key_path)
        message = c.decrypt(ciphertext)
        return message
    except Exception as ex:
        print("Key error!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gestisce le password.')

    parser.add_argument('-get', metavar='nome utenza', dest='get', type=str, nargs='+',
                        help='Restituisce una password')

    parser.add_argument('-put', metavar='nome utenza, password', dest='put', type=str, nargs='+',
                        help='Inserisce una password')

    parser.add_argument('-generate', dest='generate', help='Genera la coppia di chiavi', action="store_true")

    args = parser.parse_args()

    try:
        private_key_path = getPrivateKey()

        public_key_path = getPublicKey()
        cipher = RSACipher(private_key_path)

        if args.generate:
            cipher.generateKeys()
            print("Key pair generated")

        if args.get is not None:
            nome = args.get[0]
            password = getPassword(nome, cipher)
            pyperclip.copy(password)
            print(f'Password copyed to clipoard! Press ctrl+V for paste')
        elif args.put is not None:
            nome = args.put[0]
            password = args.put[1]
            putPassword(nome, password, cipher)
            print("Passowrd saved!")

    except Exception as ex:
        # traceback.print_exc()
        print(f"An error occurred.\nPassword for '{nome}' not found.\nMake sure you've generated a key pair.")
        pass
