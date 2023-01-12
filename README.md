# LilRSA

When it comes to asymmetric cryptography, RSA (Rivest-Shamir-Adleman) is the default example to explain concepts regarding the topic. The algorithm is one of the first invented (1978) to do so work, rely on a pair of keys, and yhe reversible property of the key to encrypt with one key and roll back to the original message using the other key.

The basic principle behind RSA is the multiplication of two factors $p$ and $q$, applying operations on these numbers it is practical to find three very large positive numbers $e$, $d$ and $n$. With these three numbers, it is possible to apply modular exponentiation to reach a strongly cyphered message. To discover the message that originated the cypher text the $p$ and $q$ would be needed, it is possible of factorizing $n$, but $n$ is a large integer, so the process is computationally inviable turning it into a $NP-Complete$ problem.

### The lib

LilRSA is a simple RSA library for studying purpose. The goal is not to create a reliable encryptation function using this almost pure python implementation. You can learn how RSA works under the hood by reading the [jupyter RSA](RSA.ipynb) which will explain using mathematical operations concatenated with python codes. The goal is to have something readable and interactive.

1. Import the library.
2. Make an instance of the class `LilRSA`.
3. Generate the key pair. Do it by specifying the number of digits of each factor `p` and `q`. If the factors have _32_ digits, the final module contains _64_ digits. The factors are not random prime numbers.

```
>>> import lilRSA as rsa
>>> x = rsa.LilRSA()
>>> x.GenPair(32)
>>> x.e
65537
>>> x.n
2444571593862958259036071898156097394153021932606491330126202367
>>> c = x.Encry("HI!")
>>> c
582782624632987655950005284831611630067944829631703443063072197
>>> x.Decry(c)
'HI!'
>>> x.d
1251883849325245358954005295419552993186690025834535752726744033
>>>
```

1. Import the library.
2. Make an instance of the class `LilRSA`.
3. Generate the key pair. Do it by specifying the number of digits of each factor `p` and `q`. If the factors have _32_ digits, the final module contains _64_ digits. The factors are not random prime numbers.

Basic functions:

```
class LilRSA(builtins.object)
 |  LilRSA class contains all params and methods 
 |  for creating a simple RSA cryptography and
 |  data signature.
 |  
 |  Methods defined here:
 |  
 |  Decry(self, c: int) -> str
 |  
 |  Encry(self, m: str) -> int
 |  
 |  GenPair(self, d: int = 64)
 |  
 |  Sign(self, m: str) -> int
 |      # Sing will just encrypt with the private key
 |  
 |  Validate(self, m: int, hash: str) -> bool
 |      # Validate will just decrypt using the public
```