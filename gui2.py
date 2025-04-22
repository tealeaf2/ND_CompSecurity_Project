import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from algorithms.vigenere.vigenere import encode_vigenere, decode_vigenere
from algorithms.triple_des.triple_des import triple_des_encrypt, triple_des_decrypt
from algorithms.aes.aes import aes_encrypt, aes_decrypt
from algorithms.rsa.rsa import rsa_encrypt, rsa_decrypt, is_prime, gcd, find_coprimes, modinv
import time

input_is_bytes = False
output_is_bytes = False
raw_input_data = b''
raw_output_data = b''

def placeholder_encrypt(data, algorithm, key):
    if algorithm == "Vigenere":
        return encode_vigenere(key, data.decode('utf-8'))
    elif algorithm == "3DES":
        return triple_des_encrypt(data, key)
    elif algorithm == "AES":
        return aes_encrypt(data, key)
    elif algorithm == "RSA":
        e,n = key[0], key[2]
        return rsa_encrypt(data.decode('utf-8'), (e,n))
    else:
        return b""

def placeholder_decrypt(data, algorithm, key):
    if algorithm == "Vigenere":
        return decode_vigenere(key, data.decode('utf-8'))
    elif algorithm == "3DES":
        return triple_des_decrypt(data, key)
    elif algorithm == "AES":
        return aes_decrypt(data, key)
    elif algorithm == "RSA":
        d,n =key[1], key[2]
        return rsa_decrypt(data.decode('utf-8'),(d,n))

    else:
        return b""

def process_data():
    global raw_input_data, input_is_bytes, raw_output_data, output_is_bytes
    key = key_text.get("1.0", tk.END).strip()
    algorithm = algorithm_var.get()
    operation = operation_var.get()

    if not raw_input_data:
        text_data = input_text.get("1.0", tk.END).strip()
        if not text_data:
            messagebox.showwarning("Warning", "Please enter some data or upload a file.")
            return
        raw_input_data = text_data.encode()
        input_is_bytes = False

    if not key:
        messagebox.showwarning("Warning", "Please enter or upload a key.")
        return

    if algorithm == "3DES" and len(key) != 24:
        messagebox.showwarning("Warning", "Key must be 24 characters long to use 3DES algorithm.")
        return
    elif algorithm == "AES" and len(key) != 16:
        messagebox.showwarning("Warning", "Key must be 16 characters long to use AES algorithm.")
        return
    elif algorithm == "RSA":
        if len(key.split())!=3:
            messagebox.showwarning("Warning", "Key must have 3 values to use RSA algorithm.")
        p, q, e = list(map(int, key.split(" ")))
        if not is_prime(p) or not is_prime(q):
            messagebox.showwarning("Warning","p and q must both be prime")
        n=p*q
        phi = (p-1)*(q-1)    
        if gcd(e, phi) != 1:
            messagebox.showwarning("Warning",f"Selected private key must be coprime with phi ({phi})\n Examples: {" ".join(list(map(str,find_coprimes(phi))))}")
        d = modinv(e,phi)
        key = (e,d,n)
        
        
    start_time = time.time()
    if operation == "Encrypt":
        result = placeholder_encrypt(raw_input_data, algorithm, key)
    else:
        result = placeholder_decrypt(raw_input_data, algorithm, key)
    end_time = time.time()

    execution_time = (end_time - start_time) * 1000  # ms
    execution_time_label.config(text=f"{execution_time:.2f} ms")

    output_text.delete("1.0", tk.END)
    if isinstance(result, bytes):
        output_is_bytes = True
        raw_output_data = result
        output_text.insert(tk.END, result.hex())
    else:
        output_text.insert(tk.END, str(result))

    update_metrics()

def upload_file():
    global raw_input_data, input_is_bytes
    algorithm = algorithm_var.get()
    file_types = [("All files", "*.*")]
    if algorithm == "Vigenere":
        file_types = [("Text files", "*.txt")]

    file_path = filedialog.askopenfilename(filetypes=file_types)
    if file_path:
        with open(file_path, "rb") as file:
            raw_input_data = file.read()
            input_is_bytes = not file_path.endswith(".txt")
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, raw_input_data.hex() if input_is_bytes else raw_input_data)
    update_metrics()

def upload_key():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            key_text.delete("1.0", tk.END)
            key_text.insert(tk.END, file.read())
    update_metrics()

def download_file():
    global input_is_bytes, raw_output_data
    file_path = filedialog.asksaveasfilename(defaultextension=".bin" if input_is_bytes else ".txt", filetypes=[("All files", "*.*")])
    if file_path:
        data = output_text.get("1.0", tk.END).strip()
        if output_is_bytes:
            with open(file_path, "wb") as file:
                file.write(raw_output_data)
        else:
            with open(file_path, "w") as file:
                file.write(data)

def update_metrics():
    input_size = len(input_text.get("1.0", tk.END).strip())
    key_size = len(key_text.get("1.0", tk.END).strip())
    output_size = len(output_text.get("1.0", tk.END).strip())
    input_size_label.config(text=str(input_size))
    key_size_label.config(text=str(key_size))
    output_size_label.config(text=str(output_size))


# --- GUI setup ---
root = tk.Tk()
root.title("Data Encryption/Decryption Tool")
root.geometry("600x800")
root.configure(bg="#f5f5f5")

HEADER_FONT = ("Segoe UI", 12, "bold")
LABEL_FONT = ("Calibri", 10)
BUTTON_FONT = ("Calibri", 10)

algorithm_frame = tk.Frame(root, bg="#f5f5f5")
algorithm_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
tk.Label(algorithm_frame, text="Select Algorithm:", font=HEADER_FONT, bg="#f5f5f5").pack(side=tk.LEFT)
algorithm_var = tk.StringVar(value="AES")
algorithm_menu = tk.OptionMenu(algorithm_frame, algorithm_var, "AES", "3DES", "RSA", "Vigenere")
algorithm_menu.config(font=LABEL_FONT)
algorithm_menu.pack(side=tk.LEFT, padx=10)

tk.Label(root, text="Input Data:", font=HEADER_FONT, bg="#f5f5f5").pack(anchor="w", padx=10, pady=(10, 0))
input_text = scrolledtext.ScrolledText(root, height=6, font=("Consolas", 10))
input_text.pack(fill=tk.BOTH, padx=10, pady=5)
tk.Button(root, text="Upload File", command=upload_file, font=BUTTON_FONT).pack(pady=(0, 10))

tk.Label(root, text="Enter Key:", font=HEADER_FONT, bg="#f5f5f5").pack(anchor="w", padx=10)
key_text = scrolledtext.ScrolledText(root, height=2, font=("Consolas", 10))
key_text.pack(fill=tk.BOTH, padx=10, pady=5)
tk.Button(root, text="Upload Key File", command=upload_key, font=BUTTON_FONT).pack(pady=(0, 10))

operation_frame = tk.Frame(root, bg="#f5f5f5")
operation_frame.pack(fill=tk.X, padx=10, pady=10)
tk.Label(operation_frame, text="Operation:", font=HEADER_FONT, bg="#f5f5f5").pack(anchor="w")
operation_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(operation_frame, text="Encrypt", variable=operation_var, value="Encrypt", bg="#f5f5f5", font=LABEL_FONT).pack(anchor="w")
tk.Radiobutton(operation_frame, text="Decrypt", variable=operation_var, value="Decrypt", bg="#f5f5f5", font=LABEL_FONT).pack(anchor="w")

tk.Button(root, text="Process", command=process_data, bg="#4CAF50", fg="white", font=BUTTON_FONT).pack(pady=10)

tk.Label(root, text="Output:", font=HEADER_FONT, bg="#f5f5f5").pack(anchor="w", padx=10)
output_text = scrolledtext.ScrolledText(root, height=6, font=("Consolas", 10))
output_text.pack(fill=tk.BOTH, padx=10, pady=5)
tk.Button(root, text="Download Output", command=download_file, font=BUTTON_FONT).pack(pady=10)

tk.Label(root, text="Data Metrics:", font=HEADER_FONT, bg="#f5f5f5").pack(anchor="w", padx=10)
metrics_frame = tk.Frame(root, bg="#f5f5f5")
metrics_frame.pack(fill=tk.BOTH, padx=10, pady=5)

labels = ["Input Size", "Key Size", "Output Size", "Execution Time"]
metrics = [tk.Label(metrics_frame, text=label, font=LABEL_FONT, bg="#f5f5f5") for label in labels]
for i, label in enumerate(metrics):
    label.grid(row=0, column=i, padx=10, pady=5)

input_size_label = tk.Label(metrics_frame, text="0", font=LABEL_FONT, bg="#f5f5f5")
key_size_label = tk.Label(metrics_frame, text="0", font=LABEL_FONT, bg="#f5f5f5")
output_size_label = tk.Label(metrics_frame, text="0", font=LABEL_FONT, bg="#f5f5f5")
execution_time_label = tk.Label(metrics_frame, text="0 ms", font=LABEL_FONT, bg="#f5f5f5")

for i, label in enumerate([input_size_label, key_size_label, output_size_label, execution_time_label]):
    label.grid(row=1, column=i, padx=10, pady=5)

input_text.bind("<KeyRelease>", lambda event: update_metrics())
key_text.bind("<KeyRelease>", lambda event: update_metrics())
output_text.bind("<KeyRelease>", lambda event: update_metrics())

root.mainloop()
