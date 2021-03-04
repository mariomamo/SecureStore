#!/usr/bin/python
import argparse
import os
import sys
import traceback
import yaml
import pyperclip as pyperclip
from cipher import Cipher

from cipher.RSACipher import RSACipher


def getPublicKey():
    return 'public_key.pem'


def getPrivateKey():
    return 'private_key.pem'


def putPassword(name, password, cripter: Cipher, password_dir: str):
    ciphertext = cripter.encrypt(password, public_key_path)
    if not os.path.exists(password_dir):
        os.makedirs(password_dir)

    if not os.path.exists(password_dir + "/" + name,):
        with open(password_dir + "/" + name, "wb") as f:
            f.write(ciphertext)
    else:
        print(f"Password file already exitst. Delete it manually and retry.")
        sys.exit(-1)


def getPassword(name, cipher: Cipher, password_dir: str):
    if not os.path.exists(password_dir):
        os.makedirs(password_dir)

    try:
        with open(password_dir + "/" + name, "rb") as f:
            ciphertext = f.read()

        message = cipher.decrypt(ciphertext)
        return message
    except Exception as ex:
        # traceback.print_exc()
        print("Key error!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gestisce le password.')

    parser.add_argument('-get', metavar='nome utenza', dest='get', type=str, nargs='+',
                        help='Restituisce una password')

    parser.add_argument('-put', metavar='nome utenza, password', dest='put', type=str, nargs='+',
                        help='Inserisce una password')

    parser.add_argument('-generate', dest='generate', help='Genera la coppia di chiavi', action="store_true")

    args = parser.parse_args()

    accountName = None

    try:
        with open('config.yml') as file:
            config = yaml.full_load(file)

        if config is None:
            print(f"configuration.yml file not found")
            sys.exit(-1)

        private_key_path = config["privateKeyPath"]
        public_key_path = config["publicKeyPath"]
        password_dir = config["encriptedKeyPath"]

        cipher = RSACipher(private_key_path, public_key_path)

        if args.generate:
            cipher.generateKeys()
            print("Key pair generated")
            sys.exit(1)

        error = False
        if not os.path.exists(private_key_path):
            print(f"Private key path not found >> {private_key_path}")
            error = True
        if not os.path.exists(public_key_path):
            print(f"Public key path not found >> {public_key_path}")
            error = True
        if not os.path.exists(password_dir):
            os.mkdir(password_dir)
            print(f"Password dir not found >> {password_dir}")
            print(f"Password folder '{password_dir}' created")

        if error:
            sys.exit(-1)

        if args.get is not None:
            accountName = args.get[0]
            password = getPassword(accountName, cipher, password_dir)
            pyperclip.copy(password)
            print(f'Password copyed to clipoard! Press ctrl+V for paste')
        elif args.put is not None:
            accountName = args.put[0]
            password = args.put[1]
            putPassword(accountName, password, cipher, password_dir)
            print("Password saved!")

    except Exception as ex:
        # traceback.print_exc()
        if accountName is not None:
            print(f"An error occurred.\nPassword for '{accountName}' not found.\nMake sure you've generated a key pair.")
        else:
            print(f"An error occurred.\nMake sure you've generated a key pair.")
