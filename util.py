import base64
from ipaddress import IPv4Address
import os
from typing import NamedTuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597

'''
Hashes a password with a given salt to store in the password database
'''
def scrypt(salt: bytes, pwd: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(pwd)

'''
Derives a key using some information
'''
def hkdf(n: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"salt", info=b"info"
    ).derive(n.to_bytes(2048, "big"))

'''
Authenticated encryption of a message with some information p
'''
def auth_encrypt(k: bytes, p: bytes) -> bytes:
    aesgcm = AESGCM(k)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, p, None)

'''
Authenticated decryption of a message
'''
def auth_decrypt(k: bytes, nc: bytes) -> bytes:
    aesgcm = AESGCM(k)
    nonce, ciphertext = nc[:12], nc[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

'''
Getting a set of bits to base64 encoding
'''
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

'''
Packing a string into a base64 encoding
'''
def u64(b64: str) -> bytes:
    return base64.b64decode(b64)

'''
A base class for a host on the app
'''
class Host(NamedTuple):
    """
    Helper class to define a host on our chat platform.
    """

    address: IPv4Address
    port: int

    def __str__(self) -> str:
        return f"{self.address}:{self.port}"

    @classmethod
    def from_str(cls, s: str) -> str:
        address, port = s.split(":")
        return cls(address, int(port))
