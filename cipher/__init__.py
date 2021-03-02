from abc import ABC, abstractmethod


class Cipher(ABC):

    @abstractmethod
    def encrypt(cls, text, key): pass

    @abstractmethod
    def decrypt(cls, text): pass

    @abstractmethod
    def generateKeys(cls): pass
