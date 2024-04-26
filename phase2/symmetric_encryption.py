import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from queue import Queue
from cryptography.hazmat.backends import default_backend
from pyDes import des, CBC, PAD_PKCS5


def generate_random_key(key_size=32):
    """Generates a random key of the specified size (in bytes)."""
    return os.urandom(key_size)

def generate_random_iv():
    """Generates a random initialization vector (IV) for AES-CBC."""
    backend = default_backend()
    return os.urandom(16)  # 16 bytes for AES-CBC

def encrypt_des(data, key):
    """Encrypts data using DES with the given key."""
    cipher = des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    return cipher.encrypt(data)

def decrypt_des(encrypted_data, key):
    """Decrypts encrypted data using DES with the given key."""
    cipher = des(key, CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    return cipher.decrypt(encrypted_data)

def encrypt(plaintext, key):
    """Encrypts a plaintext message using AES-CBC with the given key and PKCS#7 padding."""
    try:
        # Generate a new IV for each encryption
        iv = generate_random_iv()

        # Create the cipher object with AES-CBC mode and the generated IV
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv)
        )

        # Create the encryptor object
        encryptor = cipher.encryptor()

        # Pad the plaintext to a multiple of the block size using PKCS#7
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return the IV concatenated with the ciphertext
        return iv + ciphertext
    except ValueError as e:
        print("Error during encryption:", e)
        return None
    
def decrypt(ciphertext, key, iv, algorithm='AES'):
    """Decrypts a ciphertext message using AES-CBC or DES-CBC with the given key and IV."""
    try:
        if algorithm == 'AES':
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv)
            )
            block_size = 16
        elif algorithm == 'DES':
            cipher = Cipher(
                algorithms.DES(key),
                modes.CBC(iv)
            )
            block_size = 8
        else:
            raise ValueError("Unsupported algorithm. Supported algorithms are 'AES' and 'DES'.")

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS#7 padding
        unpadder = padding.PKCS7(block_size * 8).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return plaintext
    except ValueError as e:
        print("Error during decryption:", e)
        return None



