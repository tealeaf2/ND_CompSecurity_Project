import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
#TODO: IMPORT ALGORITHMS
from algorithms.vigenere.vigenere import encode_vigenere, decode_vigenere
from algorithms.triple_des.triple_des import triple_des_encrypt, triple_des_decrypt
from algorithms.aes.aes import aes_encrypt, aes_decrypt
import time

def placeholder_encrypt(data, algorithm, key):
    #TODO: IMPLEMENT THE CORRECT ALGORITHM
    if algorithm == "Vigenere":
        return encode_vigenere(key, data)
    elif algorithm == "3DES":
        return triple_des_encrypt(data, key).hex()
    elif algorithm == "AES":
        return aes_encrypt(data, key)
    else:
        return f"Encrypted({data}) with {algorithm} using key {key}"

def placeholder_decrypt(data, algorithm, key):
    #TODO: IMPLEMENT THE CORRECT ALGORITHM
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
    
    if operation == "Encrypt":
        result = placeholder_encrypt(data, algorithm, key)
    else:
        result = placeholder_decrypt(data, algorithm, key)
    
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, result)

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

def upload_key():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            key_text.delete("1.0", tk.END)
            key_text.insert(tk.END, file.read())

def download_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(output_text.get("1.0", tk.END).strip())


root = tk.Tk()
root.title("Data Encryption/Decryption")
#root.geometry("500x700")

tk.Label(root, text="Select Algorithm:").pack()
algorithm_var = tk.StringVar(value="AES")
algorithm_menu = tk.OptionMenu(root, algorithm_var, "AES", "3DES", "RSA", "Vigenere")
algorithm_menu.pack()

tk.Label(root, text="Input Data:").pack()
input_text = scrolledtext.ScrolledText(root, height=5)
input_text.pack(fill=tk.BOTH, padx=10, pady=5)

tk.Button(root, text="Upload File", command=upload_file).pack()

tk.Label(root, text="Enter Key:").pack()
key_text = scrolledtext.ScrolledText(root, height=2)
key_text.pack(fill=tk.BOTH, padx=10, pady=5)

tk.Button(root, text="Upload Key File", command=upload_key).pack()

tk.Label(root, text="Operation:").pack()
operation_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(root, text="Encrypt", variable=operation_var, value="Encrypt").pack()
tk.Radiobutton(root, text="Decrypt", variable=operation_var, value="Decrypt").pack()

tk.Button(root, text="Process", command=process_data).pack(pady=5)

tk.Label(root, text="Output:").pack()
output_text = scrolledtext.ScrolledText(root, height=5)
output_text.pack(fill=tk.BOTH, padx=10, pady=5)

tk.Button(root, text="Download Output", command=download_file).pack()
tk.Label(root, text="Data Metrics:").pack()
metrics_frame = tk.Frame(root)
metrics_frame.pack(fill=tk.BOTH, padx=10, pady=5)

tk.Label(metrics_frame, text="Input Size").grid(row=0, column=0, padx=5, pady=5)
tk.Label(metrics_frame, text="Key Size").grid(row=0, column=1, padx=5, pady=5)
tk.Label(metrics_frame, text="Output Size").grid(row=0, column=2, padx=5, pady=5)
output_size_label = tk.Label(metrics_frame, text="0")
output_size_label.grid(row=1, column=2, padx=5, pady=5)

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
    
    # Update output size
    output_size = len(result)
    output_size_label.config(text=str(output_size))
tk.Label(metrics_frame, text="Execution Time").grid(row=0, column=3, padx=5, pady=5)

input_size_label = tk.Label(metrics_frame, text="0")
input_size_label.grid(row=1, column=0, padx=5, pady=5)

key_size_label = tk.Label(metrics_frame, text="0")
key_size_label.grid(row=1, column=1, padx=5, pady=5)

output_size_label = tk.Label(metrics_frame, text="0")
output_size_label.grid(row=1, column=2, padx=5, pady=5)

execution_time_label = tk.Label(metrics_frame, text="0 ms")
execution_time_label.grid(row=1, column=3, padx=5, pady=5)

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

def update_metrics():
    input_size = len(input_text.get("1.0", tk.END).strip())
    key_size = len(key_text.get("1.0", tk.END).strip())
    output_size = len(output_text.get("1.0", tk.END).strip())
    input_size_label.config(text=str(input_size))
    key_size_label.config(text=str(key_size))
    output_size_label.config(text=str(output_size))

input_text.bind("<KeyRelease>", lambda event: update_metrics())
key_text.bind("<KeyRelease>", lambda event: update_metrics())
output_text.bind("<KeyRelease>", lambda event: update_metrics())
root.mainloop()
