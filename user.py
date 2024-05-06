from phase2 import asymmetric_encryption as asy, ECC as ecc, symmetric_encryption as sym, hashing
import binascii



class User:
    def __init__(self, sync_alg, async_alg, hash_alg):
        # init the user's secure environment
        self.messages = [] # encrypted messages, can be transmitted, as a tuple (msg, hash)
        self.received_messages = [] # decrypted messages received, as a tuple (msg, verified=True or False)
        self.symmetric_key = ""
        self.public_key = ""
        self.private_key = ""
        self.preferred_algs = {"symmetric_encryption": sync_alg, "asymmetric_encryption": async_alg, "hashing": hash_alg}


    def encrypt_message(self, plaintext):
        if self.preferred_algs["symmetric_encryption"] == 'AES':
            self.symmetric_key = sym.generate_random_key(32)  # 32 bytes key for AES
            ciphertext = sym.encrypt(plaintext.encode(), self.symmetric_key)

            msg_hash = hashing.generate_hash(plaintext + self.symmetric_key.hex(), alg=self.preferred_algs["hashing"])

            self.messages.append((ciphertext, msg_hash))
        
        elif self.preferred_algs["symmetric_encryption"] == 'DES':
            self.symmetric_key = sym.generate_random_key(8)   # 8 bytes key for DES
            ciphertext = sym.encrypt_des(plaintext, self.symmetric_key)
        
            msg_hash = hashing.generate_hash(plaintext + self.symmetric_key.hex(), alg=self.preferred_algs["hashing"])

            self.messages.append((ciphertext, msg_hash))
            #TODO optionally save the key to a file... so we can transmit it. for now, we just save it in self.symmetric_key
        
        
    def decrypt_message(self, ciphertext):
        if self.preferred_algs["symmetric_encryption"] == 'AES':
            decrypted_plaintext = sym.decrypt(ciphertext[16:], self.symmetric_key, ciphertext[:16], 'AES')
            self.received_messages.append((decrypted_plaintext, False))
        elif self.preferred_algs["symmetric_encryption"] == 'DES':
            decrypted_plaintext = sym.decrypt_des(ciphertext, self.symmetric_key)
            self.received_messages.append((decrypted_plaintext, False))


    def receive_shared_keys(self, user1, secret_key=None): # self receives encrypted key. user1 sends message + key. message: sym_enc, key: asym_enc
        if secret_key is None:
            secret_key = user1.symmetric_key
        # The common way, to use Python-RSA for larger file encryption , is to use a block cypher like AES or DES3 to encrypt the file with a random key, then encrypt the random key with RSA. Refer to here for more details. https://stuvel.eu/python-rsa-doc/usage.html#working-with-big-files
        # RSA Example usage
        if self.preferred_algs["asymmetric_encryption"] == "RSA": 
            # # Alice and Bob generate their RSA key pairs
            self.private_key, self.public_key = asy.generate_rsa_keys()
            # user2.private_key, user2.public_key = asy.generate_rsa_keys()

            # # Alice wants to send a secret key to Bob securely
            # # secret_key = "ThisIsASecretKey123"

            # # Alice encrypts the secret key with Bob's public key
            encrypted_key = asy.encrypt_rsa(secret_key, self.public_key)
            print("encrypted key sent: ", encrypted_key)

            # # Bob decrypts the encrypted key using his private key
            decrypted_key = asy.decrypt_rsa(encrypted_key, self.private_key)
            print("decrypted key received: ", decrypted_key)
            
            self.symmetric_key = bytes.fromhex(decrypted_key)



        # # ECC example usage
        elif self.preferred_algs["asymmetric_encryption"] == "ECC":
            self.public_key, self.private_key = ecc.get_my_keys()

            encrypted_key = ecc.ecc_encrypt_message(secret_key, self.public_key)
            print("encrypted key sent:", encrypted_key)

            # transmission here... from user1 to self(user2)..... such as sockets.......

            decrypted_key = ecc.ecc_decrypt_message(encrypted_key, self.private_key)
            print("decrypted key received:", decrypted_key)
            
            self.symmetric_key = bytes.fromhex(decrypted_key)



    def verify_message(self, msg_id, sender):
        flag = hashing.compare_hashes(self.received_messages[msg_id][0].decode() + self.symmetric_key.hex(), sender.messages[msg_id][1], self.preferred_algs["hashing"])
        self.received_messages[msg_id] = (self.received_messages[msg_id][0], flag)
        return flag

def main():
    # init a User instance, or multiple instances. you will need to put the User class in a separate file if you get to this point
    # do some kind of threading
    # RSA is used to transmit shared keys for symmetric-key cryptography, which are then used for bulk encryption–decryption.
    user1 = User("DES", "RSA", "SHA256")
    user2 = User("AES", "ECC", "MD5")
    user3 = User("DES", "RSA", "SHA256")
    user4 = User("AES", "ECC", "MD5")


    # Example encryption of messages to be transmitted
    msg = "hello world"
    print(msg)
    user1.encrypt_message(msg)
    print("message sent: ", user1.messages[0][0].hex())

    # Example 2 message encryption
    msg = "hello world"
    print(msg)
    user2.encrypt_message(msg)
    print("message sent: ", user2.messages[0][0].hex())


    print("\n-----\n")


    # Example sharing keys
    user3.receive_shared_keys(user1, user1.symmetric_key.hex()) 
    user4.receive_shared_keys(user2, user2.symmetric_key.hex())
    # print("SYM KEY USER1: ", user1.symmetric_key.hex()) # ignore this
    # print("SYM KEY USER2: ", user2.symmetric_key.hex()) # ignore this
    # print("SYM KEY USER3: ", user3.symmetric_key.hex()) # ignore this
    # print("SYM KEY USER4: ", user4.symmetric_key.hex()) # ignore this


    # this can be a symmetric key that is being shared!!


    print("\n-----\n")

    # Note: after sharing keys, second user can decrypt first user's messages.
    # suppose user1 message transmitted to user3.
    print("original key: ", user1.symmetric_key)
    print("transmitted key: ", user3.symmetric_key)
    user3.decrypt_message(user1.messages[0][0])
    print("decrypted: ", user3.received_messages[0][0]) # here, we are putting the sent messages array from user1 as parameter, because we don't actually have a framework to send the encrypted message.
    # suppose user1 message transmitted to user3.
    print("original key: ", user2.symmetric_key)
    print("transmitted key: ", user4.symmetric_key)
    user4.decrypt_message(user2.messages[0][0])
    print("decrypted: ", user4.received_messages[0][0])


    print("\n-----\n")

    # ignore this
    # notice how hash shows up, because it is saved as the message is encrypted.
    # print(user1.messages[0]) 
    # print(user2.messages[0])


    # Note: after decrypting the message, second user can verify the received message. The first user sends a hash with each message.
    # e.g. user 1 sends message to user 3 => user 3 wants to verify received message
    # suppose for example. that the send_msg function for user1 does this:
    # user1.generate_hash()
    # and the receive_msg function for user3 does this:
    # encrypted_aes_key = "something returned from receive_shared_keys()..."
    # user3.verify_message(msg_id=0, received_hash=user1.messages[0][1], shared_key=encrypted_aes_key, user=user1)

    print("message is verified: ", user3.verify_message(msg_id=0, sender=user1)) # again, we take the easy way and pass the user instead of actually sending a message over some kind of network.
    print("message is verified: ", user4.verify_message(msg_id=0, sender=user2))


    



if __name__ == "__main__":
    main()

