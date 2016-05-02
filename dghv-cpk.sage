#!/usr/bin/env sage
from time import time

class Profiler(object):
    def __init__(self, message_format='Elapsed time: {:.5f} sec'):
        self._message_format = message_format

    def __enter__(self,):
        self._startTime = time()

    def __exit__(self, rtype, value, traceback):
        print(self._message_format.format(time() - self._startTime))

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

def operation_test(dghv_parameters, test_number):
    dghv = DGHV(dghv_parameters)

    set_random_seed(time())
    b1 = ZZ.random_element(2)
    b2 = ZZ.random_element(2)

    dghv.key_generation()

    c1 = dghv.encrypt(b1)
    c2 = dghv.encrypt(b2)

    if ZZ.random_element(2) == 0:
        result = dghv.decrypt(c1 + c2)
        if (b1 + b2)%2 != result:
            print "[-] : Test #{0} failed: {1} + {2} != {3}".format(test_number, b1, b2, result)
        else:
            print "[+] : Test #{0} passed: {1} + {2} == {3}".format(test_number, b1, b2, result)
    else:
        result = dghv.decrypt(c1 * c2)
        if (b1 * b2)%2 != result:
            print "[-] : Test #{0} failed: {1} * {2} != {3}".format(test_number, b1, b2, result)
        else:
            print "[+] : Test #{0} passed: {1} * {2} == {3}".format(test_number, b1, b2, result)
    print "\n"

def time_test(dghv_parameters):
    dghv = DGHV(dghv_parameters)

    set_random_seed(time())
    b1 = ZZ.random_element(2)
    b2 = ZZ.random_element(2)

    with Profiler() as p:
        dghv.key_generation()
        print "key generation",

    with Profiler() as p:
        c1 = dghv.encrypt(b1)
        print "Encryption b1 = {0}".format(b1),

    with Profiler() as p:
        c2 = dghv.encrypt(b2)
        print "Encryption b2 = {0}".format(b2),

    with Profiler() as p:
        result = dghv.decrypt(c1 * c2)
        print "Decrypt c1 * c2 = {0}".format(result),

    with Profiler() as p:
        result = dghv.decrypt(c1 + c2)
        print "Decrypt c1 + c2 = {0}".format(result),

    print "\n"

toy_parameters = {"lam": 42, "rho": 27, "eta": 1026, "gamma": 150000, "alpha": 200, "tao": 158}
small_parameters = {"lam": 52, "rho": 41, "eta": 1558, "gamma": 830000, "alpha": 1476, "tao": 572}
medium_parameters = {"lam": 65, "rho": 56, "eta": 2128, "gamma": 4200000, "alpha": 2016, "tao": 1972}

for dghv_parameters in [toy_parameters, small_parameters, medium_parameters]:
    for test_number in range(10):
        operation_test(dghv_parameters, test_number)

