#! /bin/env python3
import random
from binascii import hexlify

import tinyec.ec
from Crypto.Util.Padding import pad, unpad
from tinyec import registry
import secrets
import socket
from threading import Thread
from Crypto.Cipher import AES
import argparse
import os

from ecdsa import SigningKey, VerifyingKey
from ecdsa.der import encode_sequence, encode_integer
import hashlib
import random

IP = "178.128.200.134"
PORT = 6073
KEY = None
PUB_KEY = None

class SendThread(Thread):
    def __init__(self, conn, secret, iv):
        Thread.__init__(self)
        self.conn = conn
        self.secret = secret
        self.cipher = AES.new(secret, AES.MODE_CBC, iv)

    def run(self):
        while True:
            self.conn.send(self.cipher.encrypt(pad(input().encode('utf-8'), AES.block_size)))


class ReceiveThread(Thread):
    def __init__(self, conn, secret, iv):
        Thread.__init__(self)
        self.conn = conn
        self.secret = secret
        self.cipher = AES.new(secret, AES.MODE_CBC, iv)

    def run(self):
        while True:
            from_server = self.conn.recv(AES.block_size)
            if len(from_server) > 0:
                print(unpad(self.cipher.decrypt(from_server), AES.block_size).decode())


def compress(pub_key):
    return hex(pub_key.x) + hex(pub_key.y % 2)[2:]


def gen_key(mypriv, curve):
    return (mypriv * curve.g)

parser = argparse.ArgumentParser(description='etedex')
parser.add_argument("-i", "--ip", dest='ip',
                    help="specify the ip", type=str)
parser.add_argument("-k", dest='key',
                    help="user private ecc key", type=str)

if __name__ == '__main__':
    args = parser.parse_args()
    ip = args.ip
    if ip: IP = ip

    with open(args.key, 'r') as key_f:
        private_key = "".join(key_f.readlines())
        key = SigningKey.from_pem(private_key)
        # print(key.privkey.secret_multiplier)
        h = hashlib.sha256()
        h.update(private_key.encode())
        h.update(random.Random().randint(0, 2**31).to_bytes(4, byteorder='big'))
        id = h.digest().hex()
        print("YOUR_ID", id)
        del private_key
        
    oth_id = input("other's id?>")

    curve = registry.get_curve('secp256r1')
    session_key = secrets.randbelow(curve.field.n)
    session_pub = (session_key * curve.g)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, PORT))
    
    client.send(id.encode()) #me
    client.send(oth_id.encode()) #hashwanted

# my identity
    my_der = key.verifying_key.to_der()
    print(hexlify(my_der))

    client.send(my_der)
    sig = key.sign(session_pub.x.to_bytes(32, byteorder='big')+session_pub.y.to_bytes(32, byteorder='big'), hashfunc=hashlib.sha256)
    client.send(len(sig).to_bytes(1, byteorder='big'))
    client.send(sig)

    client.send(session_pub.x.to_bytes(32, byteorder='big')+session_pub.y.to_bytes(32, byteorder='big'))

    if client.recv(1) != b'\x30':
        exit(-255)
    der_len = int.from_bytes(client.recv(1), byteorder='big')
    oth_der = client.recv(der_len)

    data_len = int.from_bytes(client.recv(1), byteorder='big')
    oth_sig = client.recv(data_len)

    othpubx = client.recv(32)
    othpuby = client.recv(32)

#get other identity
    oth_pub = VerifyingKey.from_der(b'\x30' + der_len.to_bytes(1, byteorder='big') + oth_der)
    oth_pub.verify(oth_sig, othpubx+othpuby, hashfunc=hashlib.sha256)

    ecdh = tinyec.ec.Point(curve, int.from_bytes(othpubx, byteorder='big'), int.from_bytes(othpuby, byteorder='big'))
    secret = session_key * ecdh

    print("session info: ")
    print("session key (mine/theirs): (", session_pub.x, session_pub.y, ") / (", othpubx, othpuby, ") ")

    SendThread(client, secret.x.to_bytes(32, byteorder='big'), secret.y.to_bytes(32, byteorder='big')[:16]).start()
    ReceiveThread(client, secret.x.to_bytes(32, byteorder='big'), secret.y.to_bytes(32, byteorder='big')[:16]).start()

