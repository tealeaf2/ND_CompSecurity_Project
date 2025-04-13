def gcd(a, b):
  while b != 0:
    a, b = b, a % b
  return a

def modinv(a, m):
  m0, x0, x1 = m, 0, 1
  if gcd(a, m) != 1:
    return None
  while a > 1:
    q = a // m
    a, m = m, a % m
    x0, x1 = x1 - q * x0, x0
  return x1 + m0 if x1 < 0 else x1

def is_prime(n):
  if n < 2: return False
  for i in range(2, int(n ** 0.5) + 1):
    if n % i == 0: return False
  return True
def find_coprimes(number):
  coprimes = []
  for i in range(1, number + 1):
    if gcd(i, number) == 1:
      coprimes.append(i)
    if len(coprimes)>=10:
      break
  return coprimes

def encrypt(message, public_key):
  e, n = public_key
  return [pow(ord(char), e, n) for char in message]

def decrypt(ciphertext, private_key):
  d, n = private_key
  return ''.join([chr(pow(char, d, n)) for char in ciphertext])

def main():
  try:
    print("=== RSA Key Setup ===")
    p = int(input("Enter a prime number p: "))
    q = int(input("Enter a different prime number q: "))

    if not (is_prime(p) and is_prime(q)):
      raise ValueError("Both numbers must be prime.")
    if p == q:
      raise ValueError("p and q must be different.")
    if p*q <=127:
      raise ValueError("p*q must be greater than 127")

    n = p * q
    phi = (p - 1) * (q - 1)

    print(f"n = {n}, φ(n) = {phi}")
    d = int(input(f"Enter your private key exponent d (must be coprime with φ(n))\nHere are some coprime numbers: {find_coprimes(phi)}\nInput: "))

    if gcd(d, phi) != 1:
      raise ValueError(f"d = {d} is not coprime with φ(n) = {phi}. Try another d.")

    e = modinv(d, phi)
    if e is None:
      raise ValueError("Could not compute modular inverse of d. Try a different value.")

    print(f"Public key: (e = {e}, n = {n})")
    print(f"Private key: (d = {d}, n = {n})")

    message = input("Enter message to encrypt: ")
    cipher = encrypt(message, (e, n))
    print(f"Encrypted: {cipher}")

    plain = decrypt(cipher, (d, n))
    print(f"Decrypted: {plain}")

  except ValueError as ve:
      print(f"[ERROR] {ve}")

if __name__ == '__main__':
  main()