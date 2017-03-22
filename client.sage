#!/usr/bin/env sage
from socket import socket, SOCK_STREAM, AF_INET
from struct import pack, unpack
from time import time

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
        #random_prime returns a random prime p between lbound and n (i.e. lbound <= p <= n)
        #proof - bool or None (default: None) If False, the function uses a pseudo-primality test, 
        #which is much faster for really big numbers but does not provide a proof of primality
        p = random_prime(2^(self.eta), lbound=2^(self.eta-1), proof=False)

        #Choose random odd q_0
        #while q_0%2 == 0:
            #ZZ.random_element return an integer uniformly distributed between 0 and n-1, inclusive
        q_0 = ZZ.random_element((2^self.gamma)//p)
        x_0 = q_0*p

        #Set seed for recovery of X_i at encryption
        seed = 0
        set_random_seed(seed)

        # 0 <= X_i < 2^gamma
        X_i = [ZZ.random_element(2^self.gamma) for i in range(self.tao)]

        #Continue normal random
        set_random_seed(time())

        # 0 <= E < 2^(lam+eta)//p
        E=[ZZ.random_element((2^(self.lam+self.eta))//p) for i in range(self.tao)]

        # -2^rho < r < 2^rho
        r_i = [ZZ.random_element((-2^self.rho)+1,2^self.rho) for i in range(self.tao)]

        # Construct d_i
        d_i = [(X_i[i]%p + (E[i]*p) - r_i[i]) for i in range(self.tao)]

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
        X_i = [ZZ.random_element(2^(self.gamma)) for i in range (self.tao)]

        #Generate x_i from X_i and d_i
        x_i = [X_i[i]-d_i[i] for i in range(self.tao)]

        #randomize
        set_random_seed(time())
        b_i = [ZZ.random_element(2^(self.alpha)) for i in range(self.tao)]  

        self.rho_ = self.rho+self.alpha
        r = ZZ.random_element(-2^(self.rho_)+1, 2^(self.rho_))

        c = 0
        for i in range(self.tao):
            c = (c + x_i[i]*b_i[i])
        c=(m + 2*r + 2*c)%x_0
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


toy_parameters = {"lam": 42, "rho": 27, "eta": 1026, "gamma": 150000, "alpha": 200, "tao": 158}
small_parameters = {"lam": 52, "rho": 41, "eta": 1558, "gamma": 830000, "alpha": 1476, "tao": 572}
medium_parameters = {"lam": 65, "rho": 56, "eta": 2128, "gamma": 4200000, "alpha": 2016, "tao": 1972}

dghv_client = DGHV(toy_parameters)
dghv_client.key_generation()

m1 = 1
m2 = 0
c1 = dghv_client.encrypt(m1)
c2 = dghv_client.encrypt(m2)
data = "{0} + {1}".format(c1, c2)

client = Client("10.1.2.4", 9000)
client.send(data)

c3 = int(client.recv_message())
m3 = dghv_client.decrypt(c3)

print (m1 + m2) == m3
