import os
from tkinter import *
from tkinter import filedialog
from functools import partial
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


global filename
button_height = 2
button_width = 25

def browseFiles():
    browseFiles.filename = filedialog.askopenfilename(initialdir="/", title="Select a File from Internal Memory",)
    label_file_explorer.configure(text="File Selected: " + browseFiles.filename)

    pass_label.pack()
    password.pack()
    temp_label.pack()
    button_encrypt.pack()
    button_decrypt.pack()

#Encryption of File
def encrypt_file(p_word):
    temp_key = p_word.get() #getting the key from the user
    password=temp_key.encode()#Convert to type bytes
    salt=b'\xaes\xff\x80\xe2((\xfcG\xbdk\xed\xb9\x15n7'
    kdf=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key=base64.urlsafe_b64encode(kdf.derive(password))#can only use kdf once
    fernet= Fernet(key)         

    with open(browseFiles.filename, 'rb') as file:  original = file.read() #opening the file to encrypt
    encrypted = fernet.encrypt(original)
    
    with open(browseFiles.filename, 'wb') as encrypted_file:    encrypted_file.write(encrypted)

    status_label.configure(text="Encrypted")
    status_label.pack()

#Decryption of File
def decrypt_file(p_word):
    temp_key = p_word.get()
    password=temp_key.encode()#Convert to type bytes
    salt=b'\xaes\xff\x80\xe2((\xfcG\xbdk\xed\xb9\x15n7'
    kdf=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key=base64.urlsafe_b64encode(kdf.derive(password))#can only use kdf once
    fernet=Fernet(key)
    with open(browseFiles.filename, 'rb') as enc_file:  encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)

    with open(browseFiles.filename, 'wb') as dec_file:  dec_file.write(decrypted)

    status_label.configure(text="Decrypted")
    status_label.pack()


window = Tk()

window.title('Visual Cryptography')
window.geometry("940x740")

#Head of the UI
main_title = Label(window, text="Image Encryption and Decryption", width=100, height=2,font =("Comic Sans MS",30))
passwd = StringVar()

submit_para_en = partial(encrypt_file, passwd)
submit_para_de = partial(decrypt_file, passwd)


credit = Label(window,text = "Developed by Shreeyansh Singh",height=2,font =("Comic Sans MS",15))

#Name of the file
label_file_explorer = Label(window, text="File Name : ", width=100, height=2,font =("Comic Sans MS",20))

#Password Heading 
pass_label = Label(window, text="Password for encryption/decryption : ", width=100, height=2,font =("Comic Sans MS",20))
temp_label = Label(window, text="", height=3,)

#Browsing of file from Internal
button_explore = Button(window, text="Browse File", command=browseFiles, width=button_width, height=button_height, font =("Comic Sans MS",15))

#Enter Password
password = Entry(window, textvariable=passwd,show="*")

#Option1: Encryption 
button_encrypt = Button(window, text="Encrypt",bg="yellow",fg="black",  command=submit_para_en, width=button_width, height=button_height, font =("Comic Sans MS",15))

#Option2: Decryption
button_decrypt = Button(window, text="Decrypt",bg="green",fg="black", command=submit_para_de, width=button_width, height=button_height, font =("Comic Sans MS",15))

status_label = Label(window, text="", width=100, height=4,font =("",17))

credit.pack()
main_title.pack()
label_file_explorer.pack()
button_explore.pack()
window.mainloop()
