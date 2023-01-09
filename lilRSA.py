import base64
import math
import textwrap

from pyasn1.codec.der import encoder
from pyasn1.type.univ import Sequence, Integer
import gmpy2


class LilRSA:
    """
    LilRSA class contains all params and methods 
    for creating a simple RSA cryptography and
    data signature. 
    """
    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.e = None
        self.d = None
        self.phi = None
    
    
    def GenPair(self, d:int=64):
        self.e = 65537
        if self.p == None and self.q == None:
            self.GenPQ(d)
        self.n = self.p*self.q
        self.phi = (self.p-1)*(self.q - 1)
        self.FindInversePow()
    
    
    def GenPQ(self,d:int):
        if d == 8:
            self.p = 71113279
            self.q = 98327129
        elif d == 16:
            self.p = 4056555933657341
            self.q = 6724511755459679
        elif d == 32:
            self.p = 79307298401562156961148089405447
            self.q = 30824043223426789498907784588361
        elif d == 64:
            self.p = 7102262139724624880661914991820000585426491086958693095823804547
            self.q = 9624173466341420108973789000052858499246519294416603422050306371
        elif d == 128:
            self.p = 16597851732664653479832539660899561330259392364110018498996055891314649436595410983338022590661762428883019671437525654600861057
            self.q = 26305498302333606880949544266347706296712431827799414362091494761777430020407232134152351823286246308962513557102167215124195273
        elif d == 256:
            self.p = 1494141398186731653850514987267408927569873751155410628462374810781689195252894947623071823909741383002264677034397536166343876340283991986185661247650812329538341475803424385956284593384660162773739760431285922187951996647131291980033184374696301250481281
            self.q = 6906414688542351682351348704539988550153260283951024160479187151343342136778937789242493569107382338173944334435575451178720924585783852825022281979577396849283335836228286320731973604676992365450113566848563058793848424591430799085267913687835022417560673
        else:
            self.p = 87022637054203236686730522290129
            self.q = 73945383878180463602657782738853

    # Find inverse of e in group phi(n)
    # The inverse of e + phi(n) = private key
    def FindInverse(self):
        x = 1
        t = True
        while t:
            z = (x*self.e)%self.phi
            if z == 1:
                t=False
            else:
                x = x+1
        self.d = x+self.phi

    def FindInversePow(self):
        self.d = pow(self.e,-1,self.phi)

    def Encry(self,m:str)->int:
        i = self.s2i(m)
        return pow(i,self.e,self.n)

    def Decry(self,c:int)->str:
        c = pow(c,self.d,self.n)
        return self.i2s(c)

    # Sing will just encrypt with the private key
    def Sign(self,m:str)->int:
        i = self.s2i(m)
        return pow(i,self.d,self.n)

    # Validate will just decrypt using the pubkey
    def Validate(self,m:int,hash:str)->bool:
        ass = pow(m,self.e,self.n)
        return self.i2s(ass) 

    def s2i(self,s:str) -> int:
        """
        Convert string of characters into its integer format.
        
        @param s: The string to be converted
        @type s: str
        @returns: A big integer joining all bytes from text string
        @rtype: int
        """
        return int.from_bytes(s.encode(), byteorder='big')


    def i2s(self,i:int) -> str:
        """
        Convert a big integer into its string format.

        @param i: Bit integer
        @type i: int
        @returns: A string of characters
        @rtype: str
        """
        leng = math.ceil(i.bit_length() / 8)
        return i.to_bytes(leng, byteorder='big').decode()

    def to_pem(self):
        PEM_TEMPLATE = (
    '-----BEGIN RSA PRIVATE KEY-----\n'
    '%s\n'
    '-----END RSA PRIVATE KEY-----\n'
        )
        b64 = base64.b64encode(self.to_der()).decode()
        b64w = "\n".join(textwrap.wrap(b64, 64))
        return (PEM_TEMPLATE % b64w).encode()

    def to_der(self):
        seq = Sequence()
        self.dP = self.d % (self.p - 1)
        self.dQ = self.d % (self.q - 1)
        self.qInv = gmpy2.invert(self.q, self.p)
        for idx, x in enumerate(
            [0, self.n, self.e, self.d, self.p, self.q, self.dP, self.dQ, self.qInv]
        ):
            seq.setComponentByPosition(idx, Integer(x))

        return encoder.encode(seq)

if __name__=="__main__":
    x = LilRSA()
    x.GenPair()
    print("Public key: (",x.n,",",x.e,")")
    print("Private key: (",x.n,",",x.d,")")

    m = "Hi. It is a secret. Keep secure!"
    c = x.Encry(m)
    print("Encrypting message \""+m+"\" with the public key: ",c)
    print("Decrypting cyphered message",c,"with private key: ",x.Decry(c))
