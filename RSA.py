import random

# compute gcd
# gcd(a,b)=gcd(b, a%b)
def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a % b) if a % b else b

def is_prime(n):
    """Primality test using 6k+-1 optimization."""
    if n <= 3:
        return n > 1
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i ** 2 <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

class RSA(object):
    def __init__(self, prime_length=1000) -> None:
        self.prime_length = prime_length
    # Beforehand:
    # 1. Generate two distinct p,q, check their primality. 
    # and let n=pq.
    def generate_primes(self):
        while True:
            p=random.randint(0, self.prime_length)
            q=random.randint(0, self.prime_length)
            if is_prime(p) & is_prime(q):
                n = p * q
                return p, q, n

    # 2. Find e in [0,n) that is relatively prime to (p-1)(q-1), i.e., 
    # gcd(e, (p-1)(q-1))=1. Then store (e, n) as the public key.
    def get_public_key(self, p, q, n):
        while True:
            e = random.randint(0, n-1)
            if gcd(e, (p-1)*(q-1)) == 1:
                return (e, n)

    # 3. Compute d in [0,n) for de is congruent to 1 mod (p-1)(q-1), 
    # keep (d, n) as the secret key.
    def get_private_key(self, e, p, q, n):
        while True:
            d = random.randint(0, n-1)
            if (d*e) % ((p-1)*(q-1)) == 1:
                return (d, n)

    # Encryption: m^= rem(m**e, n)
    def encrpt(self, m, e, n):
        return m**e % n
    
    # Decryption: m = rem((m^)**d, n)
    def decrypt(self, m_hat, d, n):
        return m_hat**d % n

def main():
    rsa = RSA()
    p, q, n = rsa.generate_primes()
    e, _ = rsa.get_public_key(p, q, n)
    d, _ = rsa.get_private_key(e, p, q, n)
    m = int(input("input m:"))
    if m >= n :
        print("your input is out of bounds")
        raise ValueError
    me = rsa.encrpt(m, e, n)
    print("original and encrpyted message: ", m, me)
    print("decrypted messege: ", rsa.decrypt(me, d, n))

if __name__ == "__main__":
    main()