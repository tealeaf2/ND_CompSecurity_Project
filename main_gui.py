# libraries Import
from tkinter import * 
import customtkinter
from tkinter import filedialog, messagebox
from algorithms.vigenere.vigenere import encode_vigenere, decode_vigenere
from algorithms.triple_des.triple_des import triple_des_encrypt, triple_des_decrypt
from algorithms.aes.aes import aes_encrypt, aes_decrypt
from algorithms.rsa.rsa import rsa_encrypt, rsa_decrypt, is_prime, gcd, find_coprimes, modinv

# Main Window Properties
window = Tk()
window.title("Data Encryption/Decryption Tool")
window.geometry("800x600")
window.configure(bg="#3e3e3e")

selected_file_data = None
selected_key_data = None
output_file_data = None

# Running the algorithm based on encryption or decryption
def process():
    global output_file_data
    key = Entry_id13.get("1.0", "end-1c")
    data = selected_file_data if input_type_var.get() == 1 else Entry_id10.get("1.0", "end-1c")
    algorithm = selected_algorithm.get()

    print(data, key, input_type_var.get(), operation_var.get(), selected_algorithm.get())

    if not data:
        messagebox.showwarning("Warning", "Please enter some data or upload a file.")
        return
    if not key:
        messagebox.showwarning("Warning", "Please enter or upload a key.")
        return
    if not algorithm:
        messagebox.showwarning("Warning", "Please select an algorithm.") 


    if algorithm == "3DES" and len(key) != 24:
        messagebox.showwarning("Warning", "Key must be 24 characters long to use 3DES algorithm.")
        return
    elif algorithm == "AES" and len(key) != 16:
        messagebox.showwarning("Warning", "Key must be 16 characters long to use AES algorithm.")
        return
    elif algorithm == "RSA":
        if len(key.split())!=3:
            messagebox.showwarning("Warning", "Key must have 3 values to use RSA algorithm.")
            return
        p, q, e = list(map(int, key.split(" ")))
        if not is_prime(p) or not is_prime(q):
            messagebox.showwarning("Warning","p and q must both be prime")
            return
        n=p*q
        if input_type_var.get() == 0 and n<128:
            messagebox.showwarning("Warning", "For safe text encryption and decryption, please make sure p*q>=128")
            return
        elif input_type_var.get() == 1:
            messagebox.showwarning("Warning", "RSA cannot do file encryption.")
            return
        
        phi = (p-1)*(q-1)    
        if gcd(e, phi) != 1:
            messagebox.showwarning("Warning",f"Selected private key must be coprime with phi ({phi})\n Examples: {" ".join(list(map(str,find_coprimes(phi))))}")
            return
        d = modinv(e,phi)
        key = (e,d,n)
    elif algorithm == "Vigenere" and input_type_var.get() == 1:
        messagebox.showwarning("Warning", "Vigenere cannot do file encryption.")
        return

    if operation_var.get() == 0:
        if algorithm == "Vigenere":
            result = encode_vigenere(key, data)
        elif algorithm == "3DES":
            result = triple_des_encrypt(data, key)
        elif algorithm == "AES":
            result = aes_encrypt(data, key)
        elif algorithm == "RSA":
            e,n = key[0], key[2]
            result =  rsa_encrypt(data, (e,n))
        else:
            result = "Failed to encrypt"
    else:
        if algorithm == "Vigenere":
            result = decode_vigenere(key, data)
        elif algorithm == "3DES":
            result = triple_des_decrypt(data, key)
        elif algorithm == "AES":

            result = aes_decrypt(data, key)
        elif algorithm == "RSA":
            d,n = key[1], key[2]
            result = rsa_decrypt(data ,(d,n))
        else:
            result = "Failed to decrypt"
        
    Entry_id18.delete("1.0", "end")
    Entry_id18.insert("1.0", result)

    output_file_data = result

    if input_type_var.get() == 1:
        Button_download_output.place(x=170, y=360)
    else:
        Button_download_output.place_forget()


# Track selected algorithm
selected_algorithm = StringVar(value="")

# Change button color when selected
def set_active(buttons, selected_name):
    for name, button in buttons.items():
        if name == selected_name:
            button.configure(fg_color="#686868")  # Active color
        else:
            button.configure(fg_color="#292929")  # Inactive color
    selected_algorithm.set(selected_name)

    if selected_name in ["Vigenere", "RSA"]:
        for widget in window.winfo_children():
            if widget == RadioButton_id9:
                widget.place_forget() 
    else:
        RadioButton_id9.place(x=350, y=30)
        Entry_id13.place(x=260, y=270)


def update_input_ui():
    for widget in window.winfo_children():
        if isinstance(widget, customtkinter.CTkTextbox) and widget != Entry_id13:
            widget.place_forget()
        elif isinstance(widget, customtkinter.CTkButton) and widget.cget("text") == "Select File":
            widget.place_forget()
        elif isinstance(widget, customtkinter.CTkLabel) and widget == Label_file_name:
            widget.place_forget()

        
    if input_type_var.get() == 0:  # "Text" selected
        Entry_id10.place(x=260, y=80)
        Entry_id18.place(x=170, y=360)
        Button_download_output.place_forget()
    elif input_type_var.get() == 1:  # "File" selected
        Button_id19.place(x=170, y=80)
        Label_file_name.place(x=170, y=115)


def select_file():
    global selected_file_data
    file_path = filedialog.askopenfilename(title="Select a file")
    if file_path:
        with open(file_path, "rb") as f:
            selected_file_data = f.read()
            Label_file_name.configure(text=f"Selected: {file_path.split('/')[-1]}")

def import_key():
    file_path = filedialog.askopenfilename(
        title="Import Key File", filetypes=[("Text files", "*.txt")]
    )
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                key = file.read().strip()
                Entry_id13.delete("1.0", "end")
                Entry_id13.insert("1.0", key)
        except Exception as e:
            print("Failed to read key file:", e)

def import_input():
    file_path = filedialog.askopenfilename(
        title="Import Key File", filetypes=[("Text files", "*.txt")]
    )
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                data = file.read().strip()
                Entry_id10.delete("1.0", "end")
                Entry_id10.insert("1.0", data)
        except Exception as e:
            print("Failed to read input file:", e)

def download_output_file():
    global output_file_data
    file_path = filedialog.asksaveasfilename(
        defaultextension=".dat",
        filetypes=[("Data files", "*.dat")],
        title="Save Output File"
    )
    if file_path:
        try:
            with open(file_path, "wb") as f:
                f.write(output_file_data)  # Writing binary content
        except Exception as e:
            print("Failed to save file:", e)

# Sidebar button placeholders
sidebar_buttons = {}

# Sidebar Buttons
Button_id1 = customtkinter.CTkButton(
    master=window,
    text="3DES",
    font=("Arial", 18),
    text_color="#fafafa",
    hover_color="#686868",
    height=150,
    width=90,
    border_width=0,
    corner_radius=0,
    fg_color="#292929",
    command=lambda: set_active(sidebar_buttons, "3DES")
)
Button_id1.place(x=0, y=0)
sidebar_buttons["3DES"] = Button_id1

Button_id2 = customtkinter.CTkButton(
    master=window,
    text="AES",
    font=("Arial", 18),
    text_color="#fafafa",
    hover_color="#686868",
    height=150,
    width=90,
    border_width=0,
    corner_radius=0,
    fg_color="#292929",
    command=lambda: set_active(sidebar_buttons, "AES")
)
Button_id2.place(x=0, y=150)
sidebar_buttons["AES"] = Button_id2

Button_id4 = customtkinter.CTkButton(
    master=window,
    text="RSA",
    font=("Arial", 18),
    text_color="#fafafa",
    hover_color="#686868",
    height=150,
    width=90,
    border_width=0,
    corner_radius=0,
    fg_color="#292929",
    command=lambda: set_active(sidebar_buttons, "RSA")
)
Button_id4.place(x=0, y=300)
sidebar_buttons["RSA"] = Button_id4

Button_id5 = customtkinter.CTkButton(
    master=window,
    text="Vigenere",
    font=("Arial", 18),
    text_color="#fafafa",
    hover_color="#686868",
    height=150,
    width=90,
    border_width=0,
    corner_radius=0,
    fg_color="#292929",
    command=lambda: set_active(sidebar_buttons, "Vigenere")
)
Button_id5.place(x=0, y=450)
sidebar_buttons["Vigenere"] = Button_id5

# Other UI Elements
input_type_var = IntVar(value=0)
operation_var = IntVar(value=0)

"""
For the different types of inputs (Text/File)
"""
RadioButton_id9 = customtkinter.CTkRadioButton(
    master=window,
    variable=input_type_var,
    value=1,
    text="File",
    text_color="#fafafa",
    border_color="#fafafa",
    fg_color="#686868",
    hover_color="#2F2F2F",
    command=update_input_ui
)
RadioButton_id9.place(x=350, y=30)

RadioButton_id7 = customtkinter.CTkRadioButton(
    master=window,
    variable=input_type_var,
    value=0,
    text="Text",
    text_color="#fafafa",
    border_color="#fafafa",
    fg_color="#686868",
    hover_color="#2F2F2F",
    command=update_input_ui
)
RadioButton_id7.place(x=240, y=30)

"""
UI for text input
"""
RadioButton_id14 = customtkinter.CTkRadioButton(
    master=window,
    variable=operation_var,
    value=0,
    text="Encrypt",
    text_color="#fafafa",
    border_color="#fafafa",
    fg_color="#686868",
    hover_color="#2F2F2F",
)
RadioButton_id14.place(x=580, y=270)

RadioButton_id15 = customtkinter.CTkRadioButton(
    master=window,
    variable=operation_var,
    value=1,
    text="Decrypt",
    text_color="#fafafa",
    border_color="#fafafa",
    fg_color="#686868",
    hover_color="#2F2F2F",
)
RadioButton_id15.place(x=680, y=270)

Entry_id10 = customtkinter.CTkTextbox(
    master=window,
    font=("Arial", 14),
    text_color="#131313",
    height=160,
    width=510,
    border_width=0,
    corner_radius=0,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    wrap="word"
)
Entry_id10.place(x=260, y=80)

Button_id20 = customtkinter.CTkButton(
    master=window,
    text="Import",
    font=("Arial", 14),
    text_color="#131313",
    hover_color="#949494",
    height=30,
    width=50,
    border_width=0,
    corner_radius=15,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    command=import_input
)
Button_id20.place(x=170, y=80)

Entry_id13 = customtkinter.CTkTextbox(
    master=window,
    font=("Arial", 14),
    text_color="#000000",
    height=60,
    width=310,
    border_width=0,
    corner_radius=0,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    wrap="word"
)
Entry_id13.place(x=260, y=270)

Button_id16 = customtkinter.CTkButton(
    master=window,
    text="Import",
    font=("Arial", 14),
    text_color="#131313",
    hover_color="#949494",
    height=30,
    width=50,
    border_width=0,
    corner_radius=15,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    command=import_key
)
Button_id16.place(x=170, y=270)

Entry_id18 = customtkinter.CTkTextbox(
    master=window,
    font=("Arial", 14),
    text_color="#131313",
    height=180,
    width=600,
    border_width=0,
    corner_radius=0,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    wrap="word"
)
Entry_id18.place(x=170, y=360)

Button_id16 = customtkinter.CTkButton(
    master=window,
    text="Process",
    font=("Arial", 16),
    text_color="#131313",
    hover_color="#949494",
    height=30,
    width=170,
    border_width=0,
    corner_radius=15,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    command=process
)
Button_id16.place(x=590, y=300)

Label_id8 = customtkinter.CTkLabel(
    master=window,
    text="Type of Input:",
    font=("Courier New", 14),
    text_color="#fafafa",
    height=30,
    width=130,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)
Label_id8.place(x=100, y=30)

Label_id11 = customtkinter.CTkLabel(
    master=window,
    text="Input:",
    font=("Courier New", 14),
    text_color="#fafafa",
    height=30,
    width=60,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)
Label_id11.place(x=100, y=80)

Label_id12 = customtkinter.CTkLabel(
    master=window,
    text="Key:",
    font=("Courier New", 14),
    text_color="#fafafa",
    height=30,
    width=40,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)
Label_id12.place(x=100, y=270)

Label_id17 = customtkinter.CTkLabel(
    master=window,
    text="Output:",
    font=("Courier New", 14),
    text_color="#fafafa",
    height=30,
    width=65,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)
Label_id17.place(x=100, y=360)

"""
UI for file input
"""

Button_id19 = customtkinter.CTkButton(
    master=window,
    text="Select File",
    font=("Arial", 16),
    text_color="#131313",
    hover_color="#949494",
    height=30,
    width=170,
    border_width=0,
    corner_radius=15,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    command=select_file
)

Label_file_name = customtkinter.CTkLabel(
    master=window,
    text="",  # Start with no text
    font=("Courier New", 12),
    text_color="#dcdcdc",
    height=30,
    width=100,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)

Button_download_output = customtkinter.CTkButton(
    master=window,
    text="Download Output",
    font=("Arial", 14),
    text_color="#131313",
    hover_color="#949494",
    height=30,
    width=170,
    border_width=0,
    corner_radius=15,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    command=lambda: download_output_file()
)

"""
For RSA Input
"""
Entry_id21 = customtkinter.CTkTextbox(
    master=window,
    font=("Arial", 14),
    text_color="#000000",
    height=30,
    width=100,
    border_width=0,
    corner_radius=0,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    wrap="word"
)

Entry_id24 = customtkinter.CTkTextbox(
    master=window,
    font=("Arial", 14),
    text_color="#000000",
    height=30,
    width=100,
    border_width=0,
    corner_radius=0,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    wrap="word"
)

Entry_id26 = customtkinter.CTkTextbox(
    master=window,
    font=("Arial", 14),
    text_color="#000000",
    height=30,
    width=200,
    border_width=0,
    corner_radius=0,
    border_color="#000000",
    bg_color="#3e3e3e",
    fg_color="#fafafa",
    wrap="word"
)

Label_id22 = customtkinter.CTkLabel(
    master=window,
    text="p:",
    font=("Courier New", 14),
    text_color="#fafafa",
    height=30,
    width=30,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)

Label_id23 = customtkinter.CTkLabel(
    master=window,
    text="q:",
    font=("Courier New", 14),
    text_color="#fafafa",
    height=30,
    width=30,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)

Label_id25 = customtkinter.CTkLabel(
    master=window,
    text="d:",
    font=("Courier New", 14),
    text_color="#fafafa",
    height=30,
    width=30,
    bg_color="#3e3e3e",
    fg_color="#3e3e3e",
)
#Entry_id21.place(x=260, y=270)

# Run the main loop
window.mainloop()