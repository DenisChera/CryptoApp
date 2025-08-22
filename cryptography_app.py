import time

from Cryptodome.Cipher import AES, PKCS1_OAEP, ChaCha20
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from tkinter import Tk, StringVar, filedialog, messagebox, ttk, Canvas
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image, ImageTk


class CryptographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoApp")

        # Setting background image
        self.root.geometry("800x600")
        self.bg_image_path = "leadspace.png"
        self.background_image = Image.open(self.bg_image_path)

        self.canvas = Canvas(root)
        self.canvas.pack(fill="both", expand=True)

        self.update_background_image()

        self.last_resize_time = time.time()
        self.resize_interval = 0  # Minimum interval between resizes (in seconds)

        self.algorithm_var = StringVar()
        self.message_var = StringVar()
        self.result_var = StringVar()

        # Label and combobox to select the algorithm
        self.algorithm_label = ttk.Label(root, text="Algorithm:", font=("Snap ITC", 15), foreground="yellow",
                                         background="black")
        self.algorithm_dropdown = ttk.Combobox(root, textvariable=self.algorithm_var, state="readonly", width=30,
                                               font=("Tahoma", 12),
                                               values=["AES", "RSA", "ChaCha20"])

        # Label and input field for the message
        self.message_label = ttk.Label(root, text="Message:", font=("Snap ITC", 14), foreground="yellow",
                                       background="black")
        self.message_entry = ttk.Entry(root, textvariable=self.message_var, width=30, font=("Tahoma", 12))

        # Label and input field for the result
        self.result_label = ttk.Label(root, text="Result:", font=("Snap ITC", 14), foreground="yellow",
                                      background="black")
        self.result_entry = ttk.Entry(root, textvariable=self.result_var, state="readonly", width=70,
                                      font=("Tahoma", 12))

        # Creating buttons for encryption and decryption
        self.encrypt_button = ttk.Button(root, text="Encrypt", command=self.encrypt_message, style="Red.TButton")
        self.decrypt_button = ttk.Button(root, text="Decrypt", command=self.decrypt_message, style="Green.TButton")

        # Placing components in the main window, centered
        self.algorithm_label.place(relx=0.32, rely=0.3, anchor="center")
        self.algorithm_dropdown.place(relx=0.3, rely=0.35, anchor="center")

        self.message_label.place(relx=0.7, rely=0.3, anchor="center")
        self.message_entry.place(relx=0.7, rely=0.35, anchor="center")

        self.result_label.place(relx=0.5, rely=0.7, anchor="center")
        self.result_entry.place(relx=0.5, rely=0.75, anchor="center")

        self.encrypt_button.place(relx=0.5, rely=0.45, anchor="center")
        self.decrypt_button.place(relx=0.5, rely=0.55, anchor="center")

        self.root.bind("<Configure>", self.on_resize)

        # Button styling
        style = ttk.Style()
        style.configure("Red.TButton",
                        font=("Britannic Bold", 15),
                        padding=10,
                        width=20,
                        foreground="red",
                        background="red")

        style.configure("Green.TButton",
                        font=("Britannic Bold", 15),
                        padding=10,
                        width=20,
                        foreground="green",
                        background="green")

    def encrypt_message(self):
        algorithm = self.algorithm_var.get()
        message = self.message_var.get()

        if algorithm == "AES":
            # Generate random AES key
            key = self.generate_AES_key()
            # Encrypt message with generated AES key
            ciphertext = self.encrypt_AES(message.encode(), key)
            # Set the result in the output field
            self.result_var.set(ciphertext.hex())
        elif algorithm == "RSA":
            # Generate RSA key pair
            public_key = self.generate_RSA_keys()
            # Encrypt message with RSA public key
            ciphertext = self.encrypt_RSA(message, public_key)
            # Set the result in the output field
            self.result_var.set(ciphertext.hex())
        elif algorithm == "ChaCha20":
            # Generate random ChaCha20 key
            key = self.generate_ChaCha20_key()
            # Encrypt message with ChaCha20 key
            ciphertext = self.encrypt_ChaCha20(message.encode(), key)
            # Set the result in the output field
            self.result_var.set(ciphertext.hex())


    def decrypt_message(self):
        algorithm = self.algorithm_var.get()  # Get the selected algorithm from `algorithm_var`
        ciphertext = bytes.fromhex(self.result_var.get())  # Convert ciphertext from hex to bytes

        if algorithm == "AES":
            key = self.load_AES_key()  # Load AES key from file
            if key:
                plaintext = self.decrypt_AES(ciphertext, key)  # Decrypt using AES key
                if plaintext is not None:
                    self.result_var.set(plaintext.decode())  # Set decrypted text as result
            else:
                messagebox.showwarning("Warning", "Key not loaded!")  # Show warning if key not loaded
        elif algorithm == "RSA":
            private_key = self.load_RSA_private_key()  # Load RSA private key from file
            if private_key:
                plaintext = self.decrypt_RSA(ciphertext, private_key)  # Decrypt using RSA private key
                if plaintext is not None:
                    self.result_var.set(plaintext.decode())  # Set decrypted text as result
            else:
                messagebox.showwarning("Warning", "Private key not loaded!")  # Show warning if private key not loaded
        elif algorithm == "ChaCha20":
            key = self.load_ChaCha20_key()  # Load ChaCha20 key from file
            if key:
                plaintext = self.decrypt_ChaCha20(ciphertext, key)  # Decrypt using ChaCha20 key
                if plaintext is not None:
                    self.result_var.set(plaintext.decode())  # Set decrypted text as result
            else:
                messagebox.showwarning("Warning", "Key not loaded or incorrect!")  # Show warning if key missing/invalid
        else:
            messagebox.showwarning("Warning", "Unsupported algorithm.")  # Show warning if algorithm not supported

    def encrypt_AES(self, message, key):
        # Generate a random Initialization Vector (IV) of 16 bytes
        iv = get_random_bytes(16)
        # Create AES cipher in CBC mode with the generated key and IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Encrypt message with proper padding
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        # Return IV concatenated with ciphertext
        return iv + ciphertext

    def decrypt_AES(self, ciphertext, key):
        try:
            # Extract IV from the first 16 bytes
            iv = ciphertext[:16]
            # Extract ciphertext without IV
            ciphertext = ciphertext[16:]
            # Initialize AES cipher for decryption
            cipher = AES.new(key, AES.MODE_CBC, iv)
            # Decrypt and unpad message
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext
        except ValueError:
            messagebox.showwarning("Warning", "Invalid key.")

    def pad_message(self, message):
        # Calculate padding length for AES block size
        padding_length = AES.block_size - (len(message) % AES.block_size)
        # Create padding with the padding length
        padding = bytes([padding_length]) * padding_length
        # Return message + padding
        return message + padding

    def unpad_message(self, padded_message):
        # Get last byte (padding length)
        padding_length = padded_message[-1]
        # Remove padding
        return padded_message[:-padding_length]

    def encrypt_RSA(self, message, public_key):
        # Create cipher using public key
        cipher = PKCS1_OAEP.new(public_key)
        # Encrypt message
        ciphertext = cipher.encrypt(message.encode())
        return ciphertext

    def decrypt_RSA(self, ciphertext, private_key):
        # Import private RSA key
        key = RSA.import_key(private_key)
        # Create cipher with private key
        cipher = PKCS1_OAEP.new(key)

        try:
            # Decrypt ciphertext
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        except ValueError:
            messagebox.showwarning("Warning", "Invalid key!")
        except TypeError:
            messagebox.showwarning("Warning", "Key is not private!")

    def encrypt_ChaCha20(self, message, key):
        # Create ChaCha20 cipher with generated key
        cipher = ChaCha20.new(key=key)
        # Generate nonce
        nonce = cipher.nonce
        # Encrypt message
        ciphertext = cipher.encrypt(message)
        return nonce + ciphertext

    def decrypt_ChaCha20(self, ciphertext, key):
        # Extract nonce from ciphertext
        nonce = ciphertext[:8]
        ciphertext = ciphertext[8:]
        # Create cipher with key and nonce
        cipher = ChaCha20.new(key=key, nonce=nonce)

        try:
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        except ValueError:
            messagebox.showwarning("Warning", "Invalid key!")
        except UnicodeDecodeError:
            messagebox.showwarning("Warning", "Invalid key!")


    def generate_AES_key(self):
        # Generate random AES key of 32 bytes
        key = get_random_bytes(32)
        # Open dialog to save key
        file_path = filedialog.asksaveasfilename(title="Save key", defaultextension=".pem",
                                                 filetypes=[("Key files", "*.pem")])
        if file_path:
            # Save AES key to file
            self.save_aes_chacha_key_to_file(file_path, key)
        return key

    def load_AES_key(self):
        # Open dialog to load AES key
        file_path = filedialog.askopenfilename(title="Load key", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Load AES key from file
            key = self.load_aes_chacha_key_from_file(file_path)
            return key
        return None

    def generate_RSA_keys(self):
        # Generate RSA key pair (2048 bits)
        key = RSA.generate(2048)

        # Export private and public keys
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Open dialogs to save private and public keys
        private_key_path = filedialog.asksaveasfilename(title="Save private key", defaultextension=".pem",
                                                        filetypes=[("Key files", "*.pem")])
        if private_key_path:
            # Save private key
            self.save_key_to_file(private_key_path, private_key)
        public_key_path = filedialog.asksaveasfilename(title="Save public key", defaultextension=".pem",
                                                       filetypes=[("Key files", "*.pem")])
        if public_key_path:
            # Save public key
            self.save_key_to_file(public_key_path, public_key)
        # Mark key as loaded
        self.key_loaded = True
        # Return public key
        return key.publickey()

    def load_RSA_private_key(self):
        # Open dialog to load RSA private key
        file_path = filedialog.askopenfilename(title="Load private key", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Load private key from file
            private_key = self.load_key_from_file(file_path)
            return private_key
        return None

    def load_RSA_public_key(self):
        # Open dialog to load RSA public key
        file_path = filedialog.askopenfilename(title="Load public key", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Load public key from file
            public_key = self.load_key_from_file(file_path)
            return public_key
        return None

    def generate_ChaCha20_key(self):
        # Generate random ChaCha20 key
        key = get_random_bytes(32)
        # Open dialog to save key
        file_path = filedialog.asksaveasfilename(title="Save key", defaultextension=".pem",
                                                 filetypes=[("Key files", "*.pem")])
        if file_path:
            # Save key to file
            self.save_aes_chacha_key_to_file(file_path, key)
        return key

    def load_ChaCha20_key(self):
        # Open dialog to load ChaCha20 key
        file_path = filedialog.askopenfilename(title="Load key", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Load key from file
            key = self.load_aes_chacha_key_from_file(file_path)
            return key
        return None

    def save_key_to_file(self, file_path, key):
        # Save key to binary file
        with open(file_path, "wb") as file:
            file.write(key)

    def save_aes_chacha_key_to_file(self, file_path, key):
        # Convert key to hex representation
        key_hex = key.hex()
        # Save key as text
        with open(file_path, "w") as file:
            file.write(key_hex)
        return key

    def load_key_from_file(self, file_path):
        # Load key from binary file
        with open(file_path, "rb") as file:
            key = file.read()
        return key

    def load_aes_chacha_key_from_file(self, file_path):
        # Load key from text file
        with open(file_path, "r") as file:
            key_hex = file.read()
        # Convert hex key to bytes
        key = bytes.fromhex(key_hex)
        return key

    def update_background_image(self):
        # Update background image
        width, height = self.root.winfo_width(), self.root.winfo_height()
        resized_image = self.background_image.resize((width, height), Image.ANTIALIAS)
        self.background_photo = ImageTk.PhotoImage(resized_image)
        self.canvas.create_image(0, 0, image=self.background_photo, anchor="nw")

    def on_resize(self, event):
        # Resize background when window size changes
        current_time = time.time()
        if current_time - self.last_resize_time > self.resize_interval:
            self.update_background_image()
            self.last_resize_time = current_time


root = Tk()
app = CryptographyApp(root)
root.mainloop()
