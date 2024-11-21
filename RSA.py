import random
from math import gcd

# Fungsi untuk mengecek apakah sebuah bilangan adalah prima
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

# Fungsi untuk menghasilkan bilangan prima
def generate_prime(start=100, end=1000):
    primes = [i for i in range(start, end) if is_prime(i)]
    return random.choice(primes)

# Fungsi untuk menghitung invers modular
def modular_inverse(e, phi):
    # Extended Euclidean Algorithm
    t, new_t = 0, 1
    r, new_r = phi, e
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("e is not invertible")
    if t < 0:
        t = t + phi
    return t

# Fungsi untuk menghasilkan kunci publik dan privat RSA
def generate_rsa_keys():
    p = generate_prime()
    q = generate_prime()
    while q == p:  # Pastikan p dan q berbeda
        q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    # Pilih e yang coprime dengan phi dan 1 < e < phi
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    # Hitung d sebagai invers modular dari e mod phi
    d = modular_inverse(e, phi)
    return (e, n), (d, n)  # Kunci publik (e, n), kunci privat (d, n)

# Fungsi enkripsi
def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [(ord(char) ** e) % n for char in plaintext]
    return cipher

# Fungsi dekripsi
def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    plain = [chr((char ** d) % n) for char in ciphertext]
    return ''.join(plain)

