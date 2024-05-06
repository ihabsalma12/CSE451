# # symmetric encryption example usage
# from queue import Queue
# from phase2 import symmetric_encryption as sym

# # Generate keys for AES and DES
# aes_key = sym.generate_random_key(32)  # 32 bytes key for AES
# des_key = sym.generate_random_key(8)   # 8 bytes key for DES
# plaintext_queue = Queue()
# ciphertext_queue = Queue()

# # Choose the algorithm here
# algorithm = input("Choose encryption algorithm (AES/DES): ").upper()
# if algorithm not in ['AES', 'DES']:
#     print("Invalid algorithm. Please choose AES or DES.")

# plaintexts = []
# while True:
#     plaintext = input("Enter the plaintext message (or type 'done' to finish): ")
#     if plaintext.lower() == 'done':
#         break
#     plaintexts.append(plaintext.encode())

# for plaintext in plaintexts:
#     if algorithm == 'AES':
#         ciphertext = sym.encrypt(plaintext, aes_key)
#     elif algorithm == 'DES':
#         ciphertext = sym.encrypt_des(plaintext, des_key)
#     else:
#         raise ValueError("Unsupported algorithm. Supported algorithms are 'AES' and 'DES'.")

#     if ciphertext:
#         print("Ciphertext:", ciphertext)  # This line is added for debugging
#         plaintext_queue.put(plaintext)
#         ciphertext_queue.put(ciphertext)  # Store both ciphertext and original plaintext

# while not ciphertext_queue.empty():
#     plaintext = plaintext_queue.get()
#     ciphertext = ciphertext_queue.get()
#     iv = ciphertext[:16]  # Extract IV from ciphertext
#     if algorithm == 'AES':
#         decrypted_plaintext = sym.decrypt(ciphertext[16:], aes_key, iv, algorithm)
#     elif algorithm == 'DES':
#         decrypted_plaintext = sym.decrypt_des(ciphertext, des_key)
#     else:
#         raise ValueError("Unsupported algorithm. Supported algorithms are 'AES' and 'DES'.")
#     if decrypted_plaintext:
#         print("Decrypted message:", decrypted_plaintext)
#         # Check for byte-by-byte equality
#         if decrypted_plaintext != plaintext:
#             print("Decryption mismatch!")
#         else:
#             print("Original message:", plaintext.decode())



""""""

# asymmetric_encryption example usage
# from phase2 import ECC

# encryptKey, decryptKey = ECC.get_my_keys()

# # Example message to encrypt
# message = "Hello, this is a ECC asymetric Encryption 123@."
# print("Original: ", message)

# # Encrypt the message
# ciphertext = ECC.ecc_encrypt_message(message, encryptKey)
# print("Encrypted:", ciphertext)

# # Decrypt the message
# decrypted_message = ECC.ecc_decrypt_message(ciphertext, decryptKey)
# print("Decrypted:", decrypted_message)




# asymmetric encryption rsa usage example
"""
Step 1. Choose two prime numbers p, q. You can generate random numbers in the selected range by using the buttons "Random p", "Random q" or enter your own prime numbers.
Step 2. Compute the RSA modulus, n = p*q and Eulers function phi = (p-1)*(q-1) by using the respective buttons.
Step 3. Calculate public key e: Choose a number e that is relatively prime to phi. In this step, the public key is chosen randomly from a list of candidates for e.
Step 4. Calculate private key d: Determine the inverse modulo phi of e, that is a number d, such that d*e mod phi == 1. The inverse modulo phi of e is found using the extended euclidian algorithm.
Then (e, n) is the public key and (d, n) the private key.
"""
# from queue import Queue
# from phase2_module import asymmetric_encryption, hashing

# plaintext_queue = Queue()
# ciphertext_queue = Queue()



# # Calculate phi(n)
# phi = (asymmetric_encryption.p - 1) * (asymmetric_encryption.q - 1)

# # e is public key
# e_candidates = asymmetric_encryption.calculate_e_candidates(phi)
# e = e_candidates[0]  

# # d is the private key
# d = asymmetric_encryption.modular_inverse(e, phi)


# n = asymmetric_encryption.p * asymmetric_encryption.q


# # Original plaintext message
# original_messages = ['Helloworld', 'hello universe', 'HelloRSA', "crypto#& system* $12@*"]
# print('Original Text: ', original_messages)


# for message in original_messages:
#     plaintext_queue.put(message)
# print('\n')



# while not plaintext_queue.empty():
#     plaintext = plaintext_queue.get()
#     # Convert the plaintext message to its ASCII representation
#     plaintext_num = asymmetric_encryption.to_ascii(plaintext)
#     print('Text, ASCII-Encoded: ', plaintext_num)
#     # cut the numerical message into 8-digit blocks
#     plaintext_list = asymmetric_encryption.to_block(plaintext_num)
#     # Encrypt the plaintext message using the RSA algorithm
#     cipher_list = asymmetric_encryption.encrypt(plaintext_list, e, n)
#     print('Cipher List:', cipher_list)
#     if cipher_list:
#         # print("Ciphertext:", cipher_list)  # This line is added for debugging
#         ciphertext_queue.put((cipher_list, plaintext))  # Store both ciphertext and original plaintext

#     print("\n")


# while not ciphertext_queue.empty():
#     cipher_list, original_plaintext = ciphertext_queue.get()
#     # Decrypt the ciphertext using the RSA algorithm
#     decrypted_plaintext_list = asymmetric_encryption.encrypt(cipher_list, d, n)
#     print("Dec plain list: ", decrypted_plaintext_list)
#     decrypted_plaintext = asymmetric_encryption.to_letters(decrypted_plaintext_list)
#     print('Decrypted message:', decrypted_plaintext)


#     if decrypted_plaintext:
#         # print("Decrypted message:", decrypted_plaintext)
#         # Check for byte-by-byte equality
#         if hashing.compare_messages(decrypted_plaintext.upper(), original_plaintext.upper()) == False:
#             print("Decryption mismatch!")
#         else:
#             print("Original message:", original_plaintext)
    
#     print("\n")
""""""""
# asymmetric encryption example usage without queues
# from phase2 import asymmetric_encryption as asy

# d, e = asy.generate_rsa_keys()

# public_key = e
# private_key = d

# # Original plaintext message
# print("------")
# plaintext = '12345dsjlkfahu32y387992quijwkdfu39028jcwdh0 83rxndij67890&;}'
# print("plaintext for RSA enciphering: ", plaintext)


# cipher_list = asy.encrypt_rsa(plaintext, public_key)
# print('Cipher List:', cipher_list)

# decrypted_plaintext = asy.decrypt_rsa(cipher_list, private_key)
# print('Decrypted message:', decrypted_plaintext)

""""""""







# # hashing example usage
# from phase2_module import hashing

# hashing.run_hashmsg()
# hashing.run_msgs()

