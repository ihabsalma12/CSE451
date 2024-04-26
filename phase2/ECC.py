from tinyec import registry
import secrets

'''
we retrieved the parameters of the elliptic curve named 'brainpoolP256r1' using 
the get_curve method from the registry object provided by the tinyec library. 

'brainpoolP256r1' refers to a specific elliptic curve defined by the Brainpool standard with a 256-bit prime field.
'''
curve = registry.get_curve('brainpoolP256r1')


'''
This function takes a point on the elliptic curve (point) and compresses it into a single string representation. 
It concatenates the hexadecimal representation of the x-coordinate of the point (point.x) with the least significant
bit of the y-coordinate (point.y % 2).
'''
def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]


'''
This function generates encryption keys. It first generates a random integer (ciphertextPrivKey) 
smaller than the order of the elliptic curve's field (curve.field.n). It then calculates the ciphertext public key
by multiplying the base point (curve.g) by ciphertextPrivKey. Finally, it computes the shared ECC key 
by multiplying the recipient's public key (pubKey) by ciphertextPrivKey.
'''
def ecc_calc_encryption_keys(pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    sharedECCKey = pubKey * ciphertextPrivKey
    return (sharedECCKey, ciphertextPubKey)


'''
This function generates the decryption key. It calculates the shared ECC key by multiplying the ciphertext public key (received by the recipient) 
by the recipient's private key (privKey).
'''
def ecc_calc_decryption_key(privKey, ciphertextPubKey):
    sharedECCKey = ciphertextPubKey * privKey
    return sharedECCKey


'''
random private key (privKey) is generated, and the corresponding public key (pubKey) 
is computed by multiplying the base point (curve.g) by privKey.
'''
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g
# print("private key:", hex(privKey))
# print("public key:", compress_point(pubKey))

(encryptKey, ciphertextPubKey) = ecc_calc_encryption_keys(pubKey)
# print("ciphertext pubKey:", compress_point(ciphertextPubKey))
# print("encryption key:", compress_point(encryptKey))

decryptKey = ecc_calc_decryption_key(privKey, ciphertextPubKey)
# print("decryption key:", compress_point(decryptKey))



def ecc_encrypt_message(plaintext, encryptKey):
    '''
    convert the plaintext message into bytes using the encode() method. 
    This step ensures that the plaintext can be processed as binary data.
    '''
    plaintext_bytes = plaintext.encode()
    
    '''
    converts the plaintext bytes into an integer using int.from_bytes(). 
    This integer representation is necessary for performing bitwise operations required for encryption.
    '''
    plaintext_int = int.from_bytes(plaintext_bytes, 'big')
    
    '''
    The actual encryption is performed using a bitwise XOR operation (^).
    The plaintext integer is XORed with another integer derived from the 
    x-coordinate of the encryptKey (the public key).
    '''
    ciphertext = plaintext_int ^ int.from_bytes(encryptKey.x.to_bytes(32, 'big'), 'big')
    return ciphertext

def ecc_decrypt_message(ciphertext, decryptKey):
    '''
    performing the inverse operation of the encryption process. 
    It XORs the ciphertext integer with another integer derived from the x-coordinate of the decryptKey (the private key).
    '''
    plaintext_int = ciphertext ^ int.from_bytes(decryptKey.x.to_bytes(32, 'big'), 'big')

    '''
    The resulting integer is then converted back into bytes using to_bytes() method. 
    This step restores the original binary representation of the plaintext message.
    '''
    plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big')
    '''the bytes are decoded back'''
    plaintext = plaintext_bytes.decode()
    return plaintext


def get_my_keys(): # TODO double check 
# # Generate keys
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    (encryptKey, ciphertextPubKey) = ecc_calc_encryption_keys(pubKey)
    decryptKey = ecc_calc_decryption_key(privKey, ciphertextPubKey)
    
    return encryptKey, decryptKey

