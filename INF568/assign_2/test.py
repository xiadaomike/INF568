import random
 
class Montgomery:
 
    #     B*v^2 = u^3 + A*u^2 + u
 
    def __init__(self, A, B, p):
        self.A = A
        self.B = B
        self.p = p
        self.a24 = ((A+2)*pow(4,self.p-2,self.p)) % self.p
        self.mask = pow(2, self.p.bit_length() +1) - 1
 
    def mladder(self, x1, n):
        x2,z2,x3,z3 = 1,0,x1,1
        for i in reversed(range(n.bit_length())):
            bit = 1 & (n >> i)
            x2,x3 = self.cswap(x2,x3,bit)
            z2,z3 = self.cswap(z2,z3,bit)
            # x3, z3 = (pow((x2*x3%self.p) - (z2*z3%self.p), 2, self.p),
            #     x1*pow((x2*z3%self.p)-(z2*x3%self.p), 2, self.p)%self.p)
            # x2, z2 = (pow(pow(x2,2,self.p) - pow(z2,2,self.p) %self.p, 2 ,self.p),
            #     (4*x2*z2* ( pow(x2,2, self.p) + (self.A*x2*z2%self.p) + pow(z2,2, self.p)) % self.p))
            (x2, z2, x3, z3) = self.ladderstep(x1, x2, z2, x3, z3)
            x2,x3 = self.cswap(x2,x3,bit)
            z2,z3 = self.cswap(z2,z3,bit)
        return x2 * pow(z2, self.p-2, self.p) % self.p
 
    def ladderstep(self, XQmP , XP , ZP , XQ, ZQ):
        t1 = XP + ZP % self.p
        t6 = pow(t1, 2, self.p)
        t2 = XP - ZP % self.p
        t7 = pow(t2, 2, self.p)
        t5 = t6 - t7 % self.p
        t3 = XQ + ZQ % self.p
        t4 = XQ - ZQ % self.p
        t8 = t4 * t1 % self.p
        t9 = t3 * t2 % self.p
        XPpQ = pow(t8 + t9 % self.p, 2, self.p)
        ZPpQ = XQmP * pow(t8 - t9 % self.p, 2, self.p) % self.p
        X2P = t6 * t7 % self.p
        Z2P = t5 * ((t7 + (self.a24 * t5 % self.p)) % self.p) % self.p
        return (X2P , Z2P , XPpQ, ZPpQ)
 
 
    def generate_keypair(self, base, baseorder):
        secret = random.randint(1, baseorder)
        public = self.mladder(base, secret)
        return (secret, public)
 
    def compute_secret(self, peer_public, self_secret):
        return self.mladder(peer_public, self_secret)
  
    #def cswap(self, a, b, c):
    #    mask = c * self.mask
    #    return (a & ~mask) | (b & mask)  , (b & ~mask) | (a & mask) 
    def cswap(self, x_0, x_1, swap):
        mask = pow(2, max(x_0, x_1).bit_length())-1
        mask *= swap
        dummy = mask & (x_0 ^ x_1)
        return x_0^dummy, x_1^dummy

m = Montgomery(49, 50, 101)
print m.mladder(2, 2)
