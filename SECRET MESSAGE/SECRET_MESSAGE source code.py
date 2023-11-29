import tkinter as tk
from tkinter import messagebox

def to_binary(secret_message):
    mapping = {chr(i + 96): format(i, '05b') for i in range(1, 27)}
    return ''.join(mapping[char] for char in secret_message if char in mapping)

def from_binary(binary):
    reverse_mapping = {format(i, '05b'): chr(i + 96) for i in range(1, 27)}
    return ''.join(reverse_mapping[binary[i:i+5]] for i in range(0, len(binary), 5))

def xor_operation(text, key):
    return ''.join(str(int(a) ^ int(b)) for a, b in zip(text, key))

def on_encrypt():
    secret_message = secret_message_entry.get().lower()
    key = key_entry.get()

    plaintext = to_binary(secret_message)
    extended_key = (key * (len(plaintext) // len(key) + 1))[:len(plaintext)]

    ciphertext = xor_operation(plaintext, extended_key)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, ciphertext)

def on_decrypt():
    ciphertext = ciphertext_entry.get()
    key = key_entry.get()

    if not all(char in '01' for char in ciphertext):
        messagebox.showerror("Error", "Ciphertext must be a binary string.")
        return

    if not all(char in '01' for char in key):
        messagebox.showerror("Error", "Key must be a binary string.")
        return

    extended_key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
    binary_secret_message = xor_operation(ciphertext, extended_key)
    secret_message = from_binary(binary_secret_message)
    decrypted_text.delete(1.0, tk.END)
    decrypted_text.insert(tk.END, secret_message)

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_text.get("1.0", tk.END))

def paste_from_clipboard():
    try:
        ciphertext_entry.delete(0, tk.END)
        pasted_text = root.clipboard_get().strip()  # Strip whitespace from both ends of the pasted text
        ciphertext_entry.insert(tk.END, pasted_text)
    except tk.TclError:
        messagebox.showerror("Error", "No text in clipboard or invalid format")

# Set up the GUI
root = tk.Tk()
root.title("SECRET MESSAGE")

tk.Label(root, text="Secret Message:").pack()
secret_message_entry = tk.Entry(root)
secret_message_entry.pack()

tk.Label(root, text="Key (Binary):").pack()
key_entry = tk.Entry(root)
key_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt", command=on_encrypt)
encrypt_button.pack()

tk.Label(root, text="Ciphertext:").pack()
result_text = tk.Text(root, height=4, width=50)
result_text.pack()

copy_button = tk.Button(root, text="Copy Ciphertext", command=copy_to_clipboard)
copy_button.pack()

tk.Label(root, text="Paste Ciphertext Here:").pack()
ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

paste_button = tk.Button(root, text="Paste Ciphertext", command=paste_from_clipboard)
paste_button.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=on_decrypt)
decrypt_button.pack()

tk.Label(root, text="Decrypted Secret Message:").pack()
decrypted_text = tk.Text(root, height=4, width=50)
decrypted_text.pack()

root.mainloop()
