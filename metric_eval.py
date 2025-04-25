import time
import matplotlib.pyplot as plt
from algorithms.vigenere.vigenere import encode_vigenere, decode_vigenere
from algorithms.triple_des.triple_des import triple_des_encrypt, triple_des_decrypt
from algorithms.aes.aes import aes_encrypt, aes_decrypt
from algorithms.rsa.rsa import rsa_encrypt, rsa_decrypt
import pandas as pd

enc_keys = {"AES": "thisisakey123456", "RSA": (247,3953),"3DES": "Key1Key1Key2Key2Key3Key3","Vigenere": "abcdef"}
dec_keys = {"AES": "thisisakey123456", "RSA": (31, 3953),"3DES": "Key1Key1Key2Key2Key3Key3","Vigenere": "abcdef"}


# Data sizes to test (in bytes)
data_sizes = [10, 100, 1000, 10000, 100000]

# Store results
encrypt_results = {
    "AES": [], "RSA": [], "3DES": [], "Vigenere": []
}
decrypt_results = {
    "AES": [], "RSA": [], "3DES": [], "Vigenere": []
}

records = []

# Benchmark
for size in data_sizes:
    data = "a" * size
    for name, enc_func, dec_func in [
        ("AES", aes_encrypt, aes_decrypt),
        ("RSA", rsa_encrypt, rsa_decrypt),
        ("3DES", triple_des_encrypt, triple_des_decrypt),
        ("Vigenere", encode_vigenere, decode_vigenere)
    ]:
        # Encryption time
        start = time.time()
        encrypted = enc_func(data, enc_keys[name])
        encrypt_time = time.time() - start
        encrypt_results[name].append(encrypt_time)

        # Decryption time
        start = time.time()
        dec_func(encrypted, dec_keys[name])
        decrypt_time = time.time() - start
        decrypt_results[name].append(decrypt_time)

        records.append({
            "Algorithm": name,
            "Input Length": size,
            "Encryption Time (s)": encrypt_time,
            "Decryption Time (s)": decrypt_time
        })

df = pd.DataFrame(records)
print(df.head(28))

# Plot encryption time
plt.figure(figsize=(10, 5))
for name in encrypt_results:
    plt.plot(data_sizes, encrypt_results[name], label=name, marker='o')
plt.title("Encryption Time vs Data Size")
plt.xlabel("Data Size (bytes)")
plt.ylabel("Time (seconds)")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

# Plot decryption time
plt.figure(figsize=(10, 5))
for name in decrypt_results:
    plt.plot(data_sizes, decrypt_results[name], label=name, marker='s')
plt.title("Decryption Time vs Data Size")
plt.xlabel("Data Size (bytes)")
plt.ylabel("Time (seconds)")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()
