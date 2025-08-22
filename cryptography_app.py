
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

        # Setarea imaginii de fundal
        self.root.geometry("800x600")
        self.bg_image_path = "leadspace.png"
        self.background_image = Image.open(self.bg_image_path)

        self.canvas = Canvas(root)
        self.canvas.pack(fill="both", expand=True)

        self.update_background_image()

        self.last_resize_time = time.time()
        self.resize_interval = 0  # Intervalul minim între redimensionări (în secunde)

        self.algorithm_var = StringVar()
        self.message_var = StringVar()
        self.result_var = StringVar()

        # Eticheta și combobox pentru a selecta algoritmul
        self.algorithm_label = ttk.Label(root, text="Algoritm:", font=("Snap ITC", 15), foreground="yellow",
                                         background="black")
        self.algorithm_dropdown = ttk.Combobox(root, textvariable=self.algorithm_var, state="readonly", width=30,
                                               font=("Tahoma", 12),
                                               values=["AES", "RSA", "ChaCha20"])

        # Eticheta și câmpul de intrare pentru mesaj
        self.message_label = ttk.Label(root, text="Mesaj:", font=("Snap ITC", 14), foreground="yellow",
                                       background="black")
        self.message_entry = ttk.Entry(root, textvariable=self.message_var, width=30, font=("Tahoma", 12))

        # Eticheta și câmpul de intrare pentru rezultat
        self.result_label = ttk.Label(root, text="Rezultat:", font=("Snap ITC", 14), foreground="yellow",
                                      background="black")
        self.result_entry = ttk.Entry(root, textvariable=self.result_var, state="readonly", width=70,
                                      font=("Tahoma", 12))

        # crearea butoanelor pentru criptare și decriptare
        self.encrypt_button = ttk.Button(root, text="Criptare", command=self.encrypt_message, style="Red.TButton")
        self.decrypt_button = ttk.Button(root, text="Decriptare", command=self.decrypt_message, style="Green.TButton")

        # Plasarea componentelor în fereastra principală, în centrul acesteia
        self.algorithm_label.place(relx=0.32, rely=0.3, anchor="center")
        self.algorithm_dropdown.place(relx=0.3, rely=0.35, anchor="center")

        self.message_label.place(relx=0.7, rely=0.3, anchor="center")
        self.message_entry.place(relx=0.7, rely=0.35, anchor="center")

        self.result_label.place(relx=0.5, rely=0.7, anchor="center")
        self.result_entry.place(relx=0.5, rely=0.75, anchor="center")

        self.encrypt_button.place(relx=0.5, rely=0.45, anchor="center")
        self.decrypt_button.place(relx=0.5, rely=0.55, anchor="center")

        self.root.bind("<Configure>", self.on_resize)

        # Stilizare butoane
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
            # Generare cheie aleatoare pentru AES
            key = self.generate_AES_key()
            # Criptare mesaj cu cheia AES generata
            ciphertext = self.encrypt_AES(message.encode(), key)
            # Setează rezultatul în câmpul aferent
            self.result_var.set(ciphertext.hex())
        elif algorithm == "RSA":
            # Generare pereche de chei RSA
            public_key = self.generate_RSA_keys()
            # Criptare mesaj cu cheia publică RSA
            ciphertext = self.encrypt_RSA(message, public_key)
            # Setează rezultatul în câmpul aferent
            self.result_var.set(ciphertext.hex())
        elif algorithm == "ChaCha20":
            # Generare cheie aleatoare pentru ChaCha20
            key = self.generate_ChaCha20_key()
            # Criptare mesaj cu cheia ChaCha20
            ciphertext = self.encrypt_ChaCha20(message.encode(), key)
            # Setează rezultatul în câmpul aferent
            self.result_var.set(ciphertext.hex())


    def decrypt_message(self):
        algorithm = self.algorithm_var.get() # Obține algoritmul selectat din variabila `algorithm_var`
        ciphertext = bytes.fromhex(self.result_var.get()) # Converteste textul cifrat din formatul hexazecimal la bytes

        if algorithm == "AES":
            key = self.load_AES_key() # Încarcă cheia AES din fisier
            if key:
                plaintext = self.decrypt_AES(ciphertext, key) # Decriptează textul folosind cheia AES
                if plaintext is not None:
                    self.result_var.set(plaintext.decode()) # Setează textul decriptat ca rezultat
            else:
                messagebox.showwarning("Avertisment", "Cheia nu a fost încărcată!") # Afișează un avertisment dacă cheia nu a fost încărcată
        elif algorithm == "RSA":
            private_key = self.load_RSA_private_key() # Încarcă cheia privată RSA din fisier
            if private_key:
                plaintext = self.decrypt_RSA(ciphertext, private_key) # Decriptează textul folosind cheia privată RSA
                if plaintext is not None:
                    self.result_var.set(plaintext.decode()) # Setează textul decriptat ca rezultat
            else:
                messagebox.showwarning("Avertisment", "Cheia privată nu a fost încărcată!") # Afișează un avertisment dacă cheia privată nu a fost încărcată
        elif algorithm == "ChaCha20":
            key = self.load_ChaCha20_key() # Încarcă cheia ChaCha20 din fisier
            if key:
                plaintext = self.decrypt_ChaCha20(ciphertext, key) # Decriptează textul folosind cheia ChaCha20
                if plaintext is not None:
                    self.result_var.set(plaintext.decode())  # Setează textul decriptat ca rezultat
            else:
                messagebox.showwarning("Avertisment", "Cheia nu a fost încărcată sau este incorecta!") # Afișează un avertisment dacă cheia nu a fost încărcată sau este incorectă
        else:
            messagebox.showwarning("Avertisment", "Algoritmul nu este suportat.")  # Afișează un avertisment dacă algoritmul nu este suportat

    def encrypt_AES(self, message, key):
        # Generăm un vector de inițializare aleatoriu (IV) de dimensiune 16 bytes
        iv = get_random_bytes(16)
        # Creăm o instanță a obiectului de criptare AES, utilizând cheia și modul CBC (Cipher-Block Chaining)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Criptăm mesajul aplicând padding corespunzător dimensiunii blocului AES
        # Utilizăm funcția `pad` din modulul `Cryptodome.Util.Padding` pentru a adăuga padding
        # La final, obținem textul criptat
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        # Returnam IV-ul concatenat cu textul criptat
        return iv + ciphertext

    def decrypt_AES(self, ciphertext, key):
        try:
            # Extragem IV-ul din textul criptat (primii 16 bytes)
            iv = ciphertext[:16]
            # Extragem textul criptat fără IV
            ciphertext = ciphertext[16:]
            # Initializam un obiect de decriptare AES, utilizand cheia, modulul CBC si IV-ul
            cipher = AES.new(key, AES.MODE_CBC, iv)
            # Decriptam textul criptat, eliminand padding-ul adaugat la criptare
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext
        except ValueError:
            messagebox.showwarning("Avertisment", "Cheia nu este corectă.")

    def pad_message(self, message):
        # Calculăm lungimea padding-ului necesar pentru ca mesajul să fie multiplu al mărimii blocului AES
        padding_length = AES.block_size - (len(message) % AES.block_size)
        # Creăm un șir de bytes cu lungimea padding-ului și valorile padding-ului
        padding = bytes([padding_length]) * padding_length
        # Concatenăm mesajul original cu padding-ul generat
        return message + padding

    def unpad_message(self, padded_message):
        # Extragem ultimul byte din mesajul cu padding, care reprezintă lungimea padding-ului
        padding_length = padded_message[-1]
        # Eliminăm padding-ul din mesajul cu padding
        return padded_message[:-padding_length]

    def encrypt_RSA(self, message, public_key):
        # Cream un obiect cipher folosind cheia publica primita
        cipher = PKCS1_OAEP.new(public_key)
        # Criptam mesajul utilizand cipher-ul si returnam rezultatul
        ciphertext = cipher.encrypt(message.encode())
        return ciphertext

    def decrypt_RSA(self, ciphertext, private_key):
        # Importam cheia privata din formatul specific RSA
        key = RSA.import_key(private_key)
        # Cream un obiect cipher folosind cheia privata
        cipher = PKCS1_OAEP.new(key)

        try:
            # Decriptam textul cifrat folosind cipher-ul
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        except ValueError:
            messagebox.showwarning("Avertisment", "Cheia nu este corectă!")
        except TypeError:
            messagebox.showwarning("Avertisment", "Cheia nu este privată!")

    def encrypt_ChaCha20(self, message, key):
        # Cream un obiect cipher de tip ChaCha20 folosind cheia generata
        cipher = ChaCha20.new(key=key)
        # Generam un nonce (numar o singura utilizare) asociat cu cipher-ul
        nonce = cipher.nonce
        # Criptam mesajul folosind cipher-ul si returnam rezultatul
        ciphertext = cipher.encrypt(message)
        return nonce + ciphertext

    def decrypt_ChaCha20(self, ciphertext, key):
        # Extragem nonce-ul din textul cifrat
        nonce = ciphertext[:8]
        ciphertext = ciphertext[8:]
        # Cream un obiect cipher de tip ChaCha20 folosind cheia si nonce-ul
        cipher = ChaCha20.new(key=key, nonce=nonce)

        try:
            plaintext = cipher.decrypt(ciphertext)
            return plaintext
        except ValueError:
            messagebox.showwarning("Avertisment", "Cheia nu este corectă!")
        except UnicodeDecodeError:
            messagebox.showwarning("Avertisment", "Cheia nu este corectă!")


    def generate_AES_key(self):
        # Generăm o cheie AES aleatorie de 32 de octeți
        key = get_random_bytes(32)
        # Se deschide o fereastră de dialog pentru salvarea cheii într-un fișier
        file_path = filedialog.asksaveasfilename(title="Salvează cheia", defaultextension=".pem",
                                                 filetypes=[("Key files", "*.pem")])
        if file_path:
            # Salvăm cheia AES în fișierul specificat
            self.save_aes_chacha_key_to_file(file_path, key)
        return key

    def load_AES_key(self):
        # Se deschide o fereastră de dialog pentru încărcarea cheii dintr-un fișier
        file_path = filedialog.askopenfilename(title="Încarcă cheia", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Se încarcă cheia AES din fișierul specificat
            key = self.load_aes_chacha_key_from_file(file_path)
            return key
        return None

    def generate_RSA_keys(self):
        # Generăm o pereche de chei RSA cu o lungime de 2048 de biți
        key = RSA.generate(2048)

        # Exportăm cheia privată și cheia publică în formatele necesare
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Se deschid ferestre de dialog pentru salvarea cheii private și cheii publice în fișiere separate
        private_key_path = filedialog.asksaveasfilename(title="Salvează cheia privată", defaultextension=".pem",
                                                        filetypes=[("Key files", "*.pem")])
        if private_key_path:
            # Salvăm cheia privată în fișierul specificat
            self.save_key_to_file(private_key_path, private_key)
        public_key_path = filedialog.asksaveasfilename(title="Salvează cheia publică", defaultextension=".pem",
                                                       filetypes=[("Key files", "*.pem")])
        if public_key_path:
            # Salvăm cheia publică în fișierul specificat
            self.save_key_to_file(public_key_path, public_key)
        # Marcăm faptul că, cheia a fost încărcată
        self.key_loaded = True
        # Returnăm cheia publică
        return key.publickey()

    def load_RSA_private_key(self):
        # Se deschide o fereastră de dialog pentru încărcarea cheii private dintr-un fișier
        file_path = filedialog.askopenfilename(title="Încarcă cheia privată", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Se încarcă cheia privată din fișierul specificat
            private_key = self.load_key_from_file(file_path)
            return private_key
        return None

    def load_RSA_public_key(self):
        # Se deschide o fereastră de dialog pentru încărcarea cheii publice dintr-un fișier
        file_path = filedialog.askopenfilename(title="Încarcă cheia publică", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Se încarcă cheia publică din fișierul specificat
            public_key = self.load_key_from_file(file_path)
            return public_key
        return None

    def generate_ChaCha20_key(self):
        # Generează o cheie aleatoare pentru algoritmul ChaCha20
        key = get_random_bytes(32)
        # Se deschide o fereastră de dialog pentru a permite utilizatorului să salveze cheia într-un fișier
        file_path = filedialog.asksaveasfilename(title="Salvează cheia", defaultextension=".pem",
                                                 filetypes=[("Key files", "*.pem")])
        if file_path:
            # Salvează cheia în fișierul specificat utilizând metoda save_aes_chacha_key_to_file
            self.save_aes_chacha_key_to_file(file_path, key)
        return key

    def load_ChaCha20_key(self):
        # Se deschide o fereastră de dialog pentru încărcarea cheii pentru algoritmul ChaCha20 dintr-un fișier
        file_path = filedialog.askopenfilename(title="Încarcă cheia", filetypes=[("Key files", "*.pem")])
        if file_path:
            # Se încarcă cheia din fișierul specificat utilizând metoda load_aes_chacha_key_from_file
            key = self.load_aes_chacha_key_from_file(file_path)
            return key
        return None

    def save_key_to_file(self, file_path, key):
        # Salvează cheia într-un fișier binar
        with open(file_path, "wb") as file:
            file.write(key)

    def save_aes_chacha_key_to_file(self, file_path, key):
        # Convertșe cheia în reprezentarea hexadecimală
        key_hex = key.hex()
        # Salvează cheia într-un fișier text
        with open(file_path, "w") as file:
            file.write(key_hex)
        return key

    def load_key_from_file(self, file_path):
        # Încarcă cheia dintr-un fișier binar
        with open(file_path, "rb") as file:
            key = file.read()
        return key

    def load_aes_chacha_key_from_file(self, file_path):
        # Încarcă cheia dintr-un fișier text
        with open(file_path, "r") as file:
            key_hex = file.read()
        # Convertește cheia din reprezentarea hexadecimală în bytes
        key = bytes.fromhex(key_hex)
        return key

    def update_background_image(self):
        # Actualizează imaginea de fundal
        width, height = self.root.winfo_width(), self.root.winfo_height()
        resized_image = self.background_image.resize((width, height), Image.ANTIALIAS)
        self.background_photo = ImageTk.PhotoImage(resized_image)
        self.canvas.create_image(0, 0, image=self.background_photo, anchor="nw")

    def on_resize(self, event):
        # Redimensionează imaginea de fundal dacă s-a schimbat dimensiunea ferestrei
        current_time = time.time()
        if current_time - self.last_resize_time > self.resize_interval:
            self.update_background_image()
            self.last_resize_time = current_time


root = Tk()
app = CryptographyApp(root)
root.mainloop()
