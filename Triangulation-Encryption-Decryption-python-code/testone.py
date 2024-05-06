from tkinter import *
import tkinter.messagebox as messagebox

root = Tk()
root.title("Triangulation Encryption & Decryption Data")
root.geometry("1920x1000+0+0")

#======================================================================================================


def encrypt_decrypt(text, key):
    encrypted = ''.join(chr(ord(x) ^ key) for x in text)
    return encrypted



def encrypt():
    try:
        key = int(key_entry.get())
        plaintext = plaintext_text.get("1.0", END).strip()
        #Define your encrypt_decrypt function here
        encrypted = encrypt_decrypt(plaintext, key)
        plaintext_text.delete("1.0", END)
        plaintext_text.insert("1.0", encrypted)
        key_entry.delete(0, END)
    except Exception as e:
        messagebox.showerror('Error', str(e))

def decrypt():
    try:
        key = int(key_entry.get())
        encrypted_text = plaintext_text.get("1.0", END).strip()
        decrypted_text = encrypt_decrypt(encrypted_text, key)  # Use the same key for decryption
        plaintext_text.delete("1.0", END)
        plaintext_text.insert("1.0", decrypted_text)
        key_entry.delete(0, END)
    except Exception as e:
        messagebox.showerror('Error', str(e))


def reset():
    key_entry.delete(0, END)
    key_entry.focus()
    plaintext_text.delete("1.0", END)

def iexit():
    iexit = messagebox.askyesno("XOR Encryption/Decryption", "Confirm if you want to exit")
    if iexit > 0:
        root.destroy()
        return

#======================================================================================================

button_frame = Frame(root)
button_frame.pack()

Encryption_button = Button(button_frame, font=('arial',24,'bold'), width=10, text="Encrypt", command=encrypt)
Encryption_button.pack(side=LEFT, padx=10)

Decryption_button = Button(button_frame, font=('arial',24,'bold'), width=10, text="Decryption", command=decrypt)
Decryption_button.pack(side=LEFT, padx=10)

Reset_button = Button(button_frame, font=('arial',24,'bold'), width=10, text="Reset", command=reset)
Reset_button.pack(side=LEFT, padx=10)

Exit_button = Button(button_frame, font=('arial',24,'bold'), width=10, text="Exit", command=iexit)
Exit_button.pack(side=LEFT, padx=10)

#======================================================================================================

key_frame = Frame(root)
key_frame.pack(pady=20)

key_label = Label(key_frame, font=('arial',24,'bold'), text="Enter Key:")
key_label.pack(side=LEFT, padx=10)
key_entry = Entry(key_frame, font=('arial',24,'bold'), width=12, justify='center', show="*")
key_entry.pack(side=LEFT, padx=10)

plain_frame = Frame(root)
plain_frame.pack(pady=20)

plaintext_label = Label(plain_frame, font=('arial',24,'bold'), text="Enter Plain Text:")
plaintext_label.pack(side=LEFT, padx=10)

plaintext_text = Text(plain_frame, font=('arial',24,'bold'), width=50, height=10)
plaintext_text.pack(pady=20)

root.mainloop()
