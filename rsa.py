# Skyler Stewart
# skmastew@ucsc.edu
# CS42 Winter 2019
# Assignment 1: RSA

import random
import rsa_cli

def mod_pow(a, b, n):
    # Compute a ^ b mod n.
    # Must be done efficiently in O(log b) time
    # fast powering algorithm

    total = 1
    while b > 0:
        if b % 2 == 1:
            total = (total * a) % n
        b = b / 2
        a = (a * a) % n
    return total


def gcd(a, b):
    # computes the greatest common divisor of a and b using Euclidean algorithm
    if a == 0:
        return b
    return gcd(b % a, a)


def test_prime(p, chance_false):
    # Test the primality of p.
    # The chance of p not being prime should be less than chance_false.
    # Should be an implementation of the Miller-Rabin primality test.

    # handle base cases
    if p % 2 == 0 or p == 1 or p == 4:
        return 0
    if p == 2 or p == 3:
        return 1

    # find p-1 = 2^k * m
    k = 0
    m = (p - 1)
    while m % 2 == 0:
        m = m / 2

    # set count so that (3/4)^n < chance_false
    numberofruns = 1
    counter = 0.75 ** numberofruns
    while counter > chance_false:
        numberofruns += 1
        counter = 0.75 ** numberofruns

    # run Miller-Rabin test count times
    for i in range(0, numberofruns):
        if millerRabin(p, k, m) == 0:
            return 0
    return 1


def millerRabin(p, k, m):

    # choose random a s.t. 1 < a < p-1
    a = random.randint(2, p - 1)

    # calculate b0 = a^m (mod p)
    x = mod_pow(a, m, p)
    if x == 1 or x == p - 1:
        return 1

    # calculate b1 ... if needed
    while m != p - 1:
        x = mod_pow(x, 2, p)
        m *= 2
        if x == 1:
            return 0
        elif x == p - 1:
            return 1

    return 0


def inverse(x, p):
    # Compute the inverse of x mod p.
    # Can be done using the Euclidean Algorithm
    a1 = 0
    a0 = 1
    b1 = 1
    b0 = 0

    c1 = p
    c0 = x

    while c1 != 0:
        q = c0 / c1
        c0, c1 = c1, c0 - q * c1
        a0, a1 = a1, a0 - q * a1
        b0, b1 = b1, b0 - q * b1

    if a0 < 0:
        a0 += p
    return a0


def encrypt(m, kpub):
    # encrypts message m using the public key kpub
    # returns a numerical ciphertext.
    ciphertext = mod_pow(m, kpub[1], kpub[0])
    return ciphertext


def decrypt(c, kpriv):
    # Decrypt a ciphertext c using the private key kpriv
    # Returns a numerical plaintext message.
    decipheredtext = mod_pow(c, kpriv[2], kpriv[0])
    return decipheredtext


def key_gen(keylength):
    # Generate a private and public key pair in the format described above.
    # return a list [private, public]

    plength = int((0.5 * keylength))
    qlength = keylength - plength

    # generate p, q
    p = get_prime(2 ** (plength - 1), (2 ** plength) - 1)
    q = get_prime(2 ** (qlength - 1), (2 ** qlength) - 1)
    n = p * q

    # Check if n.bitlength = keylength. If not, generate another pair and recalculate n
    while n.bit_length() != keylength:
        p = get_prime(2 ** (plength - 1), (2 ** plength) - 1)
        q = get_prime(2 ** (qlength - 1), (2 ** qlength) - 1)
        n = p * q

    # generate phi
    phi = (p - 1) * (q - 1)

    # generate e (making sure it is coprime to n and phi) and d
    coprime = 0
    while coprime == 0:
        e = random.randint(1, phi)
        if gcd(e, n) == 1 and gcd(e, phi) == 1:
            coprime = 1

    d = inverse(e, phi)

    # generate other stuff for private key
    x = d % (p - 1)
    y = d % (q - 1)
    i1 = inverse(p, q)
    i2 = inverse(q, p)

    public = [n, e]
    private = [n, e, d, p, q, x, y, i1, i2]

    rsa_cli.putKey(public, "mykey.pub")
    rsa_cli.putKey(private, "mykey")

    return [private, public]


def get_prime(min_val, max_val):
    # generate a 'random' prime number in the range [min_val, max_val]
    # return the prime
    result = 0
    while result == 0:
        number = random.randint(min_val, max_val)
        if test_prime(number, 0.2) == 1:
            return number



