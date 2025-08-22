# Description
This project is a Python desktop application that provides a user-friendly graphical interface for encrypting and decrypting messages using modern cryptographic algorithms.

Key Features:

  -Support for 3 encryption algorithms:
  
      - AES (Advanced Encryption Standard) – with CBC mode and 256-bit keys.
  
  `   - RSA – key pair generation (public/private), encryption with the public key, and decryption with the private key.
  
      - ChaCha20 – modern and efficient stream cipher with random key and nonce generation.
  
  -Key management – generate, save, and load keys in .pem file format.
  
  -Bidirectional encryption & decryption (text → encrypted text → original text).
  
  -Graphical User Interface (GUI) built with Tkinter, featuring a dynamic resizable background.
  
  -Intuitive Encrypt and Decrypt buttons with dedicated input/output fields.
  
  -Error handling with warnings for invalid or missing keys, unsupported algorithms, etc.

Technologies Used:

  -Python 3
    
  -PyCryptodome – for AES, RSA, and ChaCha20 encryption.
    
  -Tkinter – for the graphical interface.
    
  -Pillow (PIL) – for background image handling and resizing.

Design Highlights:

  -Main window with a centered, responsive layout.

  -Custom-styled buttons (colors, fonts, padding).
  
  -Automatically resizable background image for a polished look.
