import socket
from tinyec import registry
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('87.2.93.135', 6073))
while True:
	msg = str(input())
	client.send(msg.encode())
	from_server = client.recv(4096)
client.close()
print(from_server)