#! /bin/env python3
import socket
import argparse
from threading import Thread
from collections import defaultdict

connected_users = defaultdict(int)


class ConnectionProxy(Thread):
    def __init__(self, conns: tuple, addrs: tuple):
        Thread.__init__(self)
        self.conns = conns
        self.addrs = addrs

    def run(self):
        print(f"{self.conns[0]} connected to {self.conns[1]}")  # from 0 to 1 // outbound
        # from_client = b""
        while True:
            data = self.conns[0].recv(4096)
            print(data)
            self.conns[1].send(data)
            if not data: break
    # from_client += data
    # print(from_client.decode())


if __name__ == '__main__':
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind(('0.0.0.0', 6073))
    serv.listen(1000)

    while True:
        conn, addr = serv.accept()
        hash_mine = conn.recv(64)
        print(hash_mine)
        hash_wanted = conn.recv(64)
        print(hash_wanted)
        if hash_wanted not in connected_users:
            connected_users[hash_mine] = (conn, addr, hash_wanted)
        else:
            (c, a, h) = connected_users[hash_wanted]
            if h == hash_mine:
                connected_users.pop(hash_wanted)
                ConnectionProxy((conn, c), (addr, a)).start()
                ConnectionProxy((c, conn), (a, addr)).start()
