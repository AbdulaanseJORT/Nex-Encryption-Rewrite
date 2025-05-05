import subprocess, time
from tkinter import *
import tkinter as tk
import hashlib, base64
from cryptography.fernet import Fernet

def show_popup():
    popup = tk.Toplevel(root)
    popup.title("Please Accept")

    popup.geometry("800x250")

    label = tk.Label(popup, text="You must accept before proceeding.", padx=10, pady=20)
    disclaim = Label(popup, text='DISCLAIMER: Nex Encryption is designed as a tool for securing and protecting personal data. It is intended solely for lawful and ethical use. We do not condone or support the use of this tool in any criminal, illegal, or harmful activities. By using this tool, you agree to take full responsibility for your actions and ensure compliance with applicable laws and regulations.', font=("Arial Bold", 10), wraplength=550)
    disclaim.pack(pady=20)
    label.pack()

    def close_popup():
        popup.destroy()
        root.deiconify()

    accept_button = tk.Button(popup, text="I Acknowledge And Accept", command=close_popup, width=30)
    accept_button.pack(pady=1)

    root.withdraw()

def encryption():
    message = message_e.get()
    r_token = token_e.get()

    if not message or not r_token:
        subprocess.run(['konsole', '--hold', '-e', 'bash', '-c', 'echo -e "\033[31mError: Both fields must be filled in!"; sleep 2; exit'])
        return

    hashed = hashlib.sha256(r_token.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(hashed)

    f = Fernet(fernet_key)

    result = f.encrypt(message.encode())

    string = result.decode()

    popup_encrypt = tk.Toplevel(root)
    popup_encrypt.title("Encryption Succesful")
    popup_encrypt.geometry("800x250")

    encrypted_message = Text(popup_encrypt, width=95,height=5, wrap="word")
    encrypt_discl = Label(popup_encrypt, text="WARNING: Beyond this point if you forget your token, it cannot be decrypted. Ensure you save it securely")

    def close_encrypt_pop():
        popup_encrypt.destroy()

        message_e.delete(0, tk.END)
        token_e.delete(0, tk.END)

        root.deiconify()

    closer = Button(popup_encrypt, text="Accept and return", command=close_encrypt_pop, width=30)

    encrypted_message.grid(row=0, column=0, sticky="w", padx=5, pady=10)
    encrypt_discl.grid(row=1, column=0, sticky="w", padx=5, pady=5)
    closer.grid(row=3, column=0, sticky="sw", pady=60)

    encrypted_message.delete(1.0, tk.END)
    encrypted_message.insert(tk.END, string)
    encrypted_message.config(state='disabled')

    root.withdraw()

def decryption():
    m_d = message_d.get()
    r_t_d = token_d.get()

    if not m_d or not r_t_d:
        subprocess.run(['konsole', '--hold', '-e', 'bash', '-c', 'echo -e "\033[31mError: Both fields must be filled in!"; sleep 2; exit'])
        return

    hashed_d = hashlib.sha256(r_t_d.encode()).digest()
    fernet_key_d = base64.urlsafe_b64encode(hashed_d)

    f = Fernet(fernet_key_d)

    finished = f.decrypt(m_d.encode())

    result_d = finished.decode()

    decrypt_pop = tk.Toplevel(root)
    decrypt_pop.title("Decryption succesful")
    decrypt_pop.geometry("800x250")

    decrypted_message = Text(decrypt_pop, width=95,height=5, wrap="word")

    def close_decrypt_pop():
        decrypt_pop.destroy()

        message_d.delete(0, tk.END)
        token_d.delete(0, tk.END)

        root.deiconify()

    closer_d = Button(decrypt_pop, text="Accept and return", command=close_decrypt_pop, width=30)

    decrypted_message.grid(row=0, column=0, sticky="w", padx=5, pady=10)
    closer_d.grid(row=3, column=0, sticky="sw", pady=80)

    decrypted_message.delete(1.0, tk.END)
    decrypted_message.insert(tk.END, result_d)
    decrypted_message.config(state='disabled')

    root.withdraw()


root = tk.Tk()
root.title("Nex Encryption V2.2.6")
root.geometry("1200x700")

root.grid_rowconfigure(0, weight=0)
root.grid_rowconfigure(1, weight=0)
root.grid_rowconfigure(2, weight=0)
root.grid_rowconfigure(3, weight=0)
root.grid_rowconfigure(4, weight=0)
root.grid_rowconfigure(5, weight=0)
root.grid_rowconfigure(15, weight=1)
root.grid_columnconfigure(0, weight=0, minsize=100)

title = Label(root, text='Welcome to Nex Encryption', font=("Arial Bold", 35), padx=5)
trademark = Label(root, text='V2.2.6 Nex encryptionￂﾮ')

title.grid(row=0, column=0, sticky="w")
trademark.grid(row=15, column=0, sticky="sw")

# ^^ Main information, below is the entries and buttons etc

show_popup()

# Hieronder is de encryption sectie

encrypt = Label(root, text="Message encryption: ", font=("Arial Narrow Italic", 17))
encrypt_m = Label(root, text="Message", font=("Arial CE Italic",12))
encrypt_k = Label(root, text="Token", font=("Arial CE Italic",12))

message_e = Entry(root, relief="solid", justify=tk.LEFT)
token_e = Entry(root, relief="solid", justify=tk.LEFT)

encrypt_b = Button(root, text="Encrypt message", width=17, command=encryption)

encrypt.grid(row=2, column=0, sticky="w", padx=5, pady=15)
encrypt_m.grid(row=3, column=0, sticky="w", padx=5)
encrypt_k.grid(row=4, column=0, sticky="w", padx=5)

message_e.grid(row=3, column=0, sticky="w", padx=80)
token_e.grid(row=4, column=0, sticky="w", padx=80)

encrypt_b.grid(row=5, column=0, sticky="w", pady=2, padx=80)

# Hieronder is de decryption sectie

decrypt = Label(root, text="Message decryption: ", font=("Arial Narrow Italic", 17))
decrypt_m = Label(root, text="Message", font=("Arial CE Italic",12))
decrypt_k = Label(root, text="Token", font=("Arial CE Italic",12))

message_d = Entry(root, relief="solid", justify=tk.LEFT)
token_d = Entry(root, relief="solid", justify=tk.LEFT)

decrypt_b = Button(root, text="Decrypt message", width=17, command=decryption)

decrypt.grid(row=6, column=0, sticky="w", padx=5, pady=15)
decrypt_m.grid(row=7, column=0, sticky="w", padx=5)
decrypt_k.grid(row=8, column=0, sticky="w", padx=5)

message_d.grid(row=7, column=0, sticky="w", padx=80)
token_d.grid(row=8, column=0, sticky="w", padx=80)

decrypt_b.grid(row=9, column=0, sticky="w", pady=2, padx=80)

root.mainloop(
