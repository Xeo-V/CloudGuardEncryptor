from tkinter import Tk, Label, Button, filedialog
import metadata_storage
from plyer import notification
import pygame
import file_encryption
import key_management
import os
import base64

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor")
        master.geometry("400x400")
        master.configure(bg="black")

        self.label = Label(master, text="File Encryptor", fg="white", bg="black")
        self.label.pack()

        self.select_encrypt_button = Button(master, text="Select File to Encrypt 🔒", command=self.select_encrypt_file)
        self.select_encrypt_button.pack()

        self.encrypt_button = Button(master, text="Encrypt 🔒", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.select_decrypt_button = Button(master, text="Select File to Decrypt 🔑", command=self.select_decrypt_file)
        self.select_decrypt_button.pack()

        self.decrypt_button = Button(master, text="Decrypt 🔑", command=self.decrypt_file)
        self.decrypt_button.pack()

    def select_encrypt_file(self):
        self.encrypt_file_path = filedialog.askopenfilename()
        print(f"Selected {self.encrypt_file_path} for encryption.")

    def encrypt_file(self):
        try:
            salt = file_encryption.generate_unique_salt()
            aes_key = os.urandom(32)
            public_key_pem = key_management.load_key("public_key.pem")
            encrypted_aes_key = key_management.encrypt_aes_key(aes_key, public_key_pem)
            file_encryption.encrypt_file(self.encrypt_file_path, aes_key, salt)

            salt_base64 = base64.b64encode(salt).decode('utf-8')
            encrypted_aes_key_base64 = base64.b64encode(encrypted_aes_key).decode('utf-8')

            metadata_storage.save_metadata({
                'path': self.encrypt_file_path,
                'salt': salt_base64,
                'encrypted_aes_key': encrypted_aes_key_base64
            })

            print(f"Encryption logic executed for {self.encrypt_file_path}")

            notification.notify(
                title='Encryption Complete',
                message='Your file has been successfully encrypted.',
                app_name='FileEncryptor'
            )
            pygame.mixer.init()
            pygame.mixer.music.load("D:/github projects/cloud/mixkit-click-error-1110.wav")
            pygame.mixer.music.play()
        except Exception as e:
            print(f"Error during encryption: {e}")

    def select_decrypt_file(self):
        self.decrypt_file_path = filedialog.askopenfilename()
        print(f"Selected {self.decrypt_file_path} for decryption.")

    def decrypt_file(self):
        try:
            metadata = metadata_storage.load_metadata()
            salt_base64 = metadata.get('salt')
            encrypted_aes_key_base64 = metadata.get('encrypted_aes_key')

            salt = base64.b64decode(salt_base64.encode('utf-8'))
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_base64.encode('utf-8'))

            private_key_pem = key_management.load_key("private_key.pem")
            aes_key = key_management.decrypt_aes_key(encrypted_aes_key, private_key_pem)
            file_encryption.decrypt_file(self.decrypt_file_path, aes_key, salt)

            print(f"Decryption logic executed for {self.decrypt_file_path}")

            notification.notify(
                title='Decryption Complete',
                message='Your file has been successfully decrypted.',
                app_name='FileEncryptor'
            )
            pygame.mixer.init()
            pygame.mixer.music.load("D:/github projects/cloud/mixkit-click-error-1110.wav")
            pygame.mixer.music.play()
        except Exception as e:
            print(f"Error during decryption: {e}")

if __name__ == "__main__":
    # Determine the directory of the current script
    current_dir = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(current_dir, "private_key.pem")
    public_key_path = os.path.join(current_dir, "public_key.pem")

    # Generate keys if they don't exist
    if not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
        key_management.generate_rsa_keys()

    # Load existing JSON metadata if it exists
    metadata_path = os.path.join(current_dir, "metadata.json")
    if os.path.exists(metadata_path):
        existing_metadata = metadata_storage.load_metadata(file_path=metadata_path)
    else:
        existing_metadata = {}

    root = Tk()
    app = FileEncryptorApp(root)
    root.mainloop()

