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

def pad(data: bytes):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)
  
def unpad(data: bytes):
    pad_len = data[-1]
    return data[:-pad_len]

def binary_to_bytes(binary_string):
    return binary_string.to_bytes(len(binary_string) // 8, byteorder='big')

def bytes_to_binary(byte_data):
    return ''.join(format(byte, '08b') for byte in byte_data)
  
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

def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
        ciphertext = [pow(byte, e, n) for byte in plaintext]
        return " ".join(map(str, ciphertext))
    else:
        ciphertext = bytes([pow(byte, e, n) for byte in plaintext])
        return ciphertext
    
def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    decode=False
    if isinstance(ciphertext, str):
        encrypted_bytes = list(map(int, ciphertext.split()))
        decode=True
    else:
        encrypted_bytes = ciphertext

    decrypted_bytes = [pow(byte, d, n) for byte in encrypted_bytes]
    byte_result = bytes(decrypted_bytes)

    return byte_result.decode() if decode else byte_result



def main():
  try:
    print("=== RSA Key Setup ===")
    p = int(input("Enter a prime number p: "))
    q = int(input("Enter a different prime number q: "))

    if not (is_prime(p) and is_prime(q)):
      raise ValueError("Both numbers must be prime.")
    if p == q:
      raise ValueError("p and q must be different.")
    
    n = p * q
    if n<=127:
      raise ValueError("Prime numbers are too small. The product must be at least 128")
    phi = (p - 1) * (q - 1)

    print(f"n = {n}, φ(n) = {phi}")
    e = int(input(f"Enter your private key exponent d (must be coprime with φ(n))\nHere are some coprime numbers: {find_coprimes(phi)}\nInput: "))

    if gcd(e, phi) != 1:
      raise ValueError(f"e = {e} is not coprime with φ(n) = {phi}. Try another d.")

    d = modinv(e, phi)
    if d is None:
      raise ValueError("Could not compute modular inverse of d. Try a different value.")

    print(f"Public key: (e = {e}, n = {n})")
    print(f"Private key: (d = {d}, n = {n})")

    message = input("Enter message to encrypt: ")
    cipher = rsa_encrypt(message, (e, n))
    print(f"Encrypted: {cipher}")

    plain = rsa_decrypt(cipher, (d, n))
    print(f"Decrypted: {plain}")

  except ValueError as ve:
      print(f"[ERROR] {ve}")

if __name__ == '__main__':
  main()