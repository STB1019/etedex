#! /bin/env python3
import socket
import argparse
from threading import Thread



class ConnectionProxy(Thread):
	def __init__(self, conns: tuple, addrs: tuple):
		Thread.__init__(self)
		self.conns = conns
		self.addrs = addrs

	def run(self):
		print(f"{self.conns[0]} connected to {self.conns[1]}") #from 0 to 1 // outbound
		#from_client = b""
		while True:
			data = self.conns[0].recv(4096)
			print(data)
			self.conns[1].send(data)
			if not data: break
			#from_client += data
			#print(from_client.decode())
			

serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind(('0.0.0.0', 6073))
serv.listen(2)


args = parser.parse_args()
print(args.accumulate(args.integers))

while True:
	conn, addr = serv.accept()
	print(f"{conn} connected") 
	conn2, addr2 = serv.accept()
	print(f"{conn} connected") 
	conn_th1 = ConnectionProxy((conn, conn2), (addr, addr2))
	conn_th2 = ConnectionProxy((conn2, conn), (addr2, addr))
	conn_th1.start()
	conn_th2.start()
