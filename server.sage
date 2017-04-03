#!/usr/bin/env sage
from socket import socket, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, AF_INET
from argparse import ArgumentParser
from threading import Lock, Thread
from datetime import datetime
from struct import unpack, pack
from re import search

parser = ArgumentParser(description="Multi-threaded TCP Server")
parser.add_argument("-p", "--port", default=9000, type=int, help="Port over which to connect")
args = parser.parse_args()

counter = 0
thread_lock = Lock()

s = socket(AF_INET, SOCK_STREAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.bind(("10.1.2.4", args.port))

threads = []


class ClientHandler(Thread):
    def __init__(self, address, port, socket, lock):
        Thread.__init__(self)
        self.address = address
        self.port = port
        self.socket = socket
        self.lock = lock
        print "[+] : {0}:{1} connected".format(self.address, self.port)

    def send(self, message):
        message = pack('>I', len(message)) + message
        self.socket.sendall(message)

    def recv_message(self):
        raw_message_len = self.recvall(4)
        if not raw_message_len:
            return ""
        message_len = unpack('>I', raw_message_len)[0]
        return self.recvall(message_len)

    def recvall(self, n):
        data = ""
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return ""
            data += packet
        return data

    def run(self):
        global counter
        with self.lock:
            counter += 1

        try:
            data = self.recv_message()
            self.send(str(sage_eval(data)))
        except Exception as e:
            print e
        finally:
            print "[-] : {0}:{1} disconnected".format(self.address, self.port)
            self.socket.close()

while True:
    try:
        s.listen(1)
        sock, addr = s.accept()
        newThread = ClientHandler(addr[0], addr[1], sock, thread_lock)
        newThread.start()
        threads.append(newThread)
    except KeyboardInterrupt:
        print "\nExiting Server\n"
        break

for item in threads:
    item.join()
