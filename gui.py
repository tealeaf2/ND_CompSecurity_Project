import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from algorithms.vigenere.vigenere import encode_vigenere, decode_vigenere
from algorithms.triple_des.triple_des import triple_des_encrypt, triple_des_decrypt
from algorithms.aes.aes import aes_encrypt, aes_decrypt
import time

def placeholder_encrypt(data, algorithm, key):
    if algorithm == "Vigenere":
        return encode_vigenere(key, data)
    elif algorithm == "3DES":
        return triple_des_encrypt(data, key).hex()
    elif algorithm == "AES":
        return aes_encrypt(data, key)
    else:
        return f"Encrypted({data}) with {algorithm} using key {key}"

def placeholder_decrypt(data, algorithm, key):
    if algorithm == "Vigenere":
        return decode_vigenere(key, data)
    elif algorithm == "3DES":
        return triple_des_decrypt(data, key)
    elif algorithm == "AES":
        return aes_decrypt(data, key)
    else:
        return f"Decrypted({data}) with {algorithm} using key {key}"

def process_data():
    data = input_text.get("1.0", tk.END).strip()
    key = key_text.get("1.0", tk.END).strip()
    algorithm = algorithm_var.get()
    operation = operation_var.get()
    
    if not data:
        messagebox.showwarning("Warning", "Please enter some data or upload a file.")
        return

    if not key:
        messagebox.showwarning("Warning", "Please enter or upload a key.")
        return
    
    if algorithm == "3DES" and len(key) != 24:
        messagebox.showwarning("Warning", "Key must be 24 characters long to use 3DES algorithm.")
        return
    elif algorithm == "AES" and len(key) != 16:
        messagebox.showwarning("Warning", "Key must be 16 characters long to use AES algorithm.")
    
    start_time = time.time()
    if operation == "Encrypt":
        result = placeholder_encrypt(data, algorithm, key)
    else:
        result = placeholder_decrypt(data, algorithm, key)
    end_time = time.time()
    
    execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
    execution_time_label.config(text=f"{execution_time:.2f} ms")
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, result)

    update_metrics()

def upload_file():
    algorithm = algorithm_var.get()
    if algorithm == "Vigenere":
        file_types = [("Text files", "*.txt")]
    else:
        file_types = [("Text files", "*.txt"), ("Image files", "*.png;*.jpg;*.jpeg"), ("Binary files", "*.bin")]
    file_path = filedialog.askopenfilename(filetypes=file_types)
    if file_path:
        with open(file_path, "rb") as file:
            text = file.read()
            #text = file.read().hex() # TODO: Not sure if we should read images and stuff in hex
        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, text)
    update_metrics()

def upload_key():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            key_text.delete("1.0", tk.END)
            key_text.insert(tk.END, file.read())
    update_metrics()

def download_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("All files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(output_text.get("1.0", tk.END).strip())

def update_metrics():
    input_size = len(input_text.get("1.0", tk.END).strip())
    key_size = len(key_text.get("1.0", tk.END).strip())
    output_size = len(output_text.get("1.0", tk.END).strip())
    input_size_label.config(text=str(input_size))
    key_size_label.config(text=str(key_size))
    output_size_label.config(text=str(output_size)) 


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
