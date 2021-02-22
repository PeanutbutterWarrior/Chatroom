import socket
import time

HOST = 'localhost'
PORT = 56789

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        message = input('message: ')
        s.sendall(message.encode('utf-8'))
