#! /bin/env python3
import tinyec.ec
from Crypto.Util.Padding import pad, unpad
from tinyec import registry
import secrets
import socket
from threading import Thread
from Crypto.Cipher import AES
import argparse

IP = "87.2.93.135"
PORT = 6073

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



parser = argparse.ArgumentParser(description='etedex')
parser.add_argument("-i", "--ip", dest='ip',
                    help="increase output verbosity", type=str)
ip = parser.parse_args().ip
if ip: IP = ip



curve = registry.get_curve('brainpoolP256r1')
mypriv = secrets.randbelow(curve.field.n)
print("mypub ", compress(mypriv * curve.g))


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((IP, PORT))
client.send(10.to_bytes(32, byteorder='big'))
client.send(11.to_bytes(32, byteorder='big'))

client.send((mypriv * curve.g).x.to_bytes(32, byteorder='big'))
client.send((mypriv * curve.g).y.to_bytes(32, byteorder='big'))

othpubx = client.recv(32)
othpuby = client.recv(32)
othpub = tinyec.ec.Point(curve, int.from_bytes(othpubx, byteorder='big'), int.from_bytes(othpuby, byteorder='big'))

print("othpub ", compress(othpub))
secret = mypriv * othpub

SendThread(client, secret.x.to_bytes(32, byteorder='big'), secret.y.to_bytes(32, byteorder='big')[:16]).start()
ReceiveThread(client, secret.x.to_bytes(32, byteorder='big'), secret.y.to_bytes(32, byteorder='big')[:16]).start()