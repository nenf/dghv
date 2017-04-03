#!/usr/bin/env sage
from socket import socket, SOCK_STREAM, AF_INET
from argparse import ArgumentParser
from struct import pack, unpack
from re import findall, search
from ast import literal_eval
from itertools import izip
from time import time
from os import path

SERVER_IP = "10.1.2.4"
SERVER_PORT = 9000

class DGHV:
    def __init__(self, parameters_dghv):
          self.lam = parameters_dghv["lam"]
          self.rho = parameters_dghv["rho"]
          self.eta = parameters_dghv["eta"]
          self.gamma = parameters_dghv["gamma"]
          self.alpha = parameters_dghv["alpha"]
          self.tao = parameters_dghv["tao"]
          self.rho_ = 0
          self.pk = []
          self.sk = 0

    def key_generation(self):
        set_random_seed(time())

        #Generate secret key
        p = random_prime(2^(self.eta), lbound=2^(self.eta-1), proof=False)

        #Choose random odd q_0
        q_0 = ZZ.random_element((2^self.gamma)//p)
        while q_0 % 2 == 0:
            q_0 = ZZ.random_element((2^self.gamma)//p)
        x_0 = q_0 * p

        #Set seed for recovery of X_i at encryption
        seed = 0
        set_random_seed(seed)

        # 0 <= X_i < 2^gamma
        X_i = [ZZ.random_element(2^self.gamma) for i in range(self.tao)]

        #Continue normal random
        set_random_seed(time())

        d_i = []
        for i in range(self.tao):
            r_i = ZZ.random_element((-2^self.rho) + 1, 2^self.rho)
            e_i = ZZ.random_element((2^(self.lam + self.eta)) // p)
            d_i.append((X_i[i] % p + (e_i * p) - r_i))

        #Return private and secret key pairs
        self.pk = [seed, x_0, d_i]
        self.sk = p
        return 0

    def encrypt(self, m):
        seed = self.pk[0]
        x_0 = self.pk[1]
        d_i = self.pk[2]

        #Recover X_i from seed
        set_random_seed(seed)
        X_i = []
        x_i = []
        for i in range(self.tao):
            X_i.append(ZZ.random_element(2^(self.gamma)))
            x_i.append(X_i[i] - d_i[i])

        #randomize
        set_random_seed(time())
        b_i = [ZZ.random_element(2^(self.alpha)) for i in range(self.tao)]

        self.rho_ = self.rho+self.alpha
        r = ZZ.random_element(-2^(self.rho_)+1, 2^(self.rho_))

        c = 0
        for i in range(self.tao):
            c = (c + x_i[i]*b_i[i])
        c = (m + 2*r + 2*c) % x_0
        return c

    def decrypt(self, c):
        return (c-self.sk*((c/self.sk).round()))%2


class Client:
    def __init__(self, server_ip, server_port):
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.connect((server_ip, server_port))

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


def arg_parse():
    parser = ArgumentParser(description="DGHV client side")
    parser.add_argument("-g", "--generate", type=str, help="Generate keys")
    parser.add_argument("-o", "--output", type=str, default="dghv.keys", help="Path to file for save keys")
    parser.add_argument("-i", "--input", type=str, help="Path to file with keys")
    parser.add_argument("-t", "--type", type=str, help="Parameters type for DGHV")
    parser.add_argument("-e", "--expression", type=str, help="Expression for compute")
    return parser.parse_args()


def get_parameters(parameters_type):
    if parameters_type == "toy":
        parameters = {"lam": 42, "rho": 27, "eta": 1026, "gamma": 150000, "alpha": 200, "tao": 158}
    elif parameters_type == "small":
        parameters = {"lam": 52, "rho": 41, "eta": 1558, "gamma": 830000, "alpha": 1476, "tao": 572}
    elif parameters_type== "medium":
        parameters = {"lam": 65, "rho": 56, "eta": 2128, "gamma": 4200000, "alpha": 2016, "tao": 1972}
    else:
        print "Unknown parameters type: {0}".format(parameters_type)
        exit(1)
    return parameters


def key_generator(args):
    parameters = get_parameters(args.generate)
    dghv = DGHV(parameters)
    dghv.key_generation()
    with open(args.output, "w+") as f:
        f.write("{0}\n".format(args.generate))
        f.write("{0}\n{1}\n{2}\n".format(*dghv.pk))
        f.write("{0}".format(dghv.sk))


def key_read(args):
    if not path.exists(args.input):
       print "File {0} doesn't exist".format(args.input)
       exit(1)

    with open(args.input, "r") as f:
        l = [l.rstrip() for l in f.readlines()]
        try:
            parameters_type = l[0]
            seed = literal_eval(l[1])
            x_0 = literal_eval(l[2])
            d_i = literal_eval(l[3])

            pk = [seed, x_0, d_i]
            sk = Integer(literal_eval(l[4]))
        except Exception as e:
            print "[-] : {0}".format(e)
            exit(1)
        else:
            return get_parameters(parameters_type), pk, sk


def cloud_computing(expression):
    try:
        client = Client(SERVER_IP, SERVER_PORT)
        client.send(expression)
        c = client.recv_message()
    except Exception as e:
        print "[-] : {0}".format(e)
        exit(1)
    return c


if __name__ == "__main__":
    args = arg_parse()
    if args.generate:
        key_generator(args)
        exit(0)

    if args.input:
        parameters, pk, sk = key_read(args)

        dghv = DGHV(parameters)
        dghv.pk = pk
        dghv.sk = sk
    elif args.type:
        parameters = get_parameters(args.type)
        dghv = DGHV(parameters)
        dghv.key_generation()
    else:
        print "[-] : Should be set one of the parameter input\\type"
        exit(1)

    if args.expression:
        expression = args.expression
        if search("[2-9]+|[a-zA-Z]", expression):
            print "[-] : Invalid expression: {0}".format(expression)
            exit(1)
    else:
        expression = "(1 * 1) + 0"

    M = [int(m) for m in findall("1|0", expression)]
    C = [dghv.encrypt(m) for m in M]
    F = expression
    for m, c in izip(M, C):
        F = F.replace(str(m), str(c), 1)

    result = dghv.decrypt(int(cloud_computing(F)))
    computed = int(eval(expression))

    print "{0} = {1}".format(expression, result)


'''
Examples:
1)
# sage client_improve.sage -g toy -o dghv.keys 
# sage client_improve.sage -i dghv.keys -e "(1 * 1) + 0"
(1 * 1) + 0 = 1

2)
# sage client_improve.sage -t toy -e "(1 + 1) + 1"
(1 + 1) + 1 = 1

toy_parameters = {"lam": 42, "rho": 27, "eta": 1026, "gamma": 150000, "alpha": 200, "tao": 158}
small_parameters = {"lam": 52, "rho": 41, "eta": 1558, "gamma": 830000, "alpha": 1476, "tao": 572}
medium_parameters = {"lam": 65, "rho": 56, "eta": 2128, "gamma": 4200000, "alpha": 2016, "tao": 1972}

dghv_client = DGHV(toy_parameters)
dghv_client.key_generation()

M = [1, 1, 0]
C = [dghv_client.encrypt(m) for m in M]
F = "({0} * {1}) + {2}"

client = Client("10.1.2.4", 9000)
client.send(F.format(*C))

c3 = int(client.recv_message())
m3 = dghv_client.decrypt(c3)

print int(eval(F.format(*M))) == m3
'''