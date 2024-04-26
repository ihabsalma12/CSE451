# https://medium.com/@emrehangorgec/implementing-rsa-for-digital-signature-from-scratch-f6f416d9878f
import numpy as np
import math # 
import random # Random number creation
import re # Regular expressions
from sympy import * # isprime

def get_primes(minimum=5000000, maximum=6000000):
    '''
    Calculate all prime numbers in the given range.
    
    Parameters:
        minimum (int): The lower bound of the range to search for primes (inclusive).
        maximum (int): The upper bound of the range to search for primes (exclusive).
        
    Returns:
        list: A list of prime numbers found within the specified range.
    '''
    primes = []  # Initialize an empty list to store prime numbers
    
    # Iterate through each number in the specified range
    for i in range(minimum, maximum):
        # Check if the current number is prime using the isprime function
        if isprime(i):
            primes.append(i)  # If prime, add it to the list of primes
    
    return primes  # Return the list of prime numbers


def calculate_e_candidates(phi):
    possible_e_values = [] #store the potential candidate values for e
    '''Iterations over numbers starting from 7 up to ϕ(n)−1. 
       This range is chosen to avoid commonly used values for 
       e like 2 and 3.'''
    for i in range(7, phi-1): 
        '''For each number in the range, we check if the number is relatively prime to 
           ϕ(n) using the math.gcd() function, which calculates the greatest common divisor. If the greatest common divisor is 1, 
           then the number is relatively prime to 
           ϕ(n), making it a potential candidate for e. '''
        if math.gcd(i, phi) == 1:
            possible_e_values.append(i)  
            '''The loop continues until 100 potential candidates are found or until the range is exhausted.'''
        if len(possible_e_values) == 100:
            break         
    return possible_e_values

''' extended_euclid function implements the extended Euclidean algorithm, which is used to find the modular multiplicative inverse 
of two numbers 
a and b such that ax + by = gcd(a,b), where gcd(a,b)  is the greatest common divisor of a and b.   
'''
def extended_euclid(phi, e): 
   ''' Carry out the extended Euclidean algorithm to find the modular multiplicative inverse.'''
    # Base case: If e is 0, phi is the greatest common divisor, 
    # so return the modular multiplicative inverse of phi modulo e (1) and 0 for e's modular multiplicative inverse.
   if e == 0:
        return (1, 0, phi)
   else :
        # Recursive case: Call extended_euclid with arguments e and phi % e.
        # Swap the roles of phi and e in each recursive call to progress through the algorithm.
        k, d, gcd = extended_euclid(e, phi % e) 
        # Compute the modular multiplicative inverse of e modulo phi and update variables accordingly.
        return d, k - d * (phi // e), gcd           

def modular_inverse(e, phi):
    ''' Calculate the modular inverse of e modulo phi  '''
    # Use extended_euclid to calculate the modular multiplicative inverse of e modulo phi.
    k, d, gcd = extended_euclid(phi, e) 
    # If the greatest common divisor of phi and e is 1 (e is coprime with phi), return the modular multiplicative inverse.
    if gcd == 1 :
        return d % phi
    else:
      # If e is not coprime with phi (gcd != 1), return None (indicating no modular inverse exists).
        return None 
    
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
def get_ascii():
    #Return a dictionary mapping characters to their ASCII values.
    ascii_dict = {}  # Initialize an empty dictionary to store ASCII mappings
    offset = 32  # Set the initial ASCII value for space ' '
    
    # Iterate through each character from space to 'z'
    for char_code in range(offset, ord('z') + 1):
        # Map the character to its ASCII value and store it in the dictionary
        ascii_dict[chr(char_code)] = char_code
    
    return ascii_dict

def to_ascii(text):
    #Convert a string to its corresponding ASCII representation.
    ascii_mapping = get_ascii()  # Get the ASCII mapping dictionary
    ascii_text = ""  # Initialize an empty string to store the ASCII representation
    
    # Iterate through each character in the input text
    for char in str(text).upper():
        # If the character is in the ASCII mapping, append its ASCII value to the ASCII text
        if char in ascii_mapping:
            ascii_text += str(ascii_mapping[char])
        # If the character is a number, append its ASCII value directly
        elif char.isdigit():
            ascii_text += char
        # If the character is a space, append its ASCII value directly
        elif char == ' ':
            ascii_text += '32'  # ASCII value of space
        # If the character is not supported, ignore it
    
    return ascii_text


def to_block(text_num):
    # Split a numerical string into chunks of 8 digits 
    cp = str(text_num)  # Convert the numerical string to a regular string
    blocklist = []  # Initialize an empty list to store the chunks
    # Split the string into blocks of 8 digits each
    for i in range(0, len(cp), 8):
        blocklist.append(cp[i:i+8])
    return blocklist

def to_letters(lst):
    # Transform numerical message back to alphabet
    plaintext = ""  # Initialize an empty string to store the decrypted plaintext
    for block in lst:
        # Check if the block is an integer (representing a number)
        if isinstance(block, int):
            # If it's a number, convert it to a string and append it to the plaintext
            plaintext += str(block)
        else:
            # If it's a string, treat it as a sequence of ASCII values and convert them back to characters
            for i in range(0, len(block), 2):
                ascii_value = int(block[i:i+2])
                char = chr(ascii_value)
                if char.isalpha():
                    # Preserve the case of the original plaintext
                    if block.isupper():
                        plaintext += char.upper()
                     
                    else:
                        plaintext += char.lower()
                else:
                    plaintext += char
    return plaintext


def encrypt(lst, key, n):
    # Encrypt a list of blocks using the RSA algorithm 
    retlist = []  # Initialize an empty list to store the encrypted blocks
    for block in lst:  # Iterate through each block in the input list
        # Convert the block to an integer
        num = int(block)
        # Use the RSA encryption formula to compute the ciphertext block
        encrypted_block = pow(num, key, n)
        # Convert the encrypted block back to a string and append it to the result list
        retlist.append(str(encrypted_block))
    return retlist  # Return the list of encrypted blocks


def generate_rsa_keys():
    # Calculate phi(n)
    phi = (p - 1) * (q - 1)
    e_candidates = calculate_e_candidates(phi)
    e = e_candidates[0]  
    d = modular_inverse(e, phi)

    return d, e # private key, public key



def encrypt_rsa(plaintext, public_key):
    # print('Original Text: ', plaintext)

    # Convert the plaintext message to its ASCII representation
    plaintext_num = to_ascii(plaintext)
    # print('Text, ASCII-Encoded: ', plaintext_num)

    # cut the numerical message into 8-digit blocks
    plaintext_list = to_block(plaintext_num)

    # Encrypt the plaintext message using the RSA algorithm
    cipher_list = encrypt(plaintext_list, public_key, n)
    # print('Cipher List:', cipher_list)
    return cipher_list


def decrypt_rsa(cipher_list, private_key):
    # Decrypt the ciphertext using the RSA algorithm
    plaintext_list2 = encrypt(cipher_list, private_key, n)
    plaintext2 = to_letters(plaintext_list2)
    # print('Decrypted message:', plaintext2)
    return plaintext2


#two prime numbers
p = 10559
q = 13903
n = p * q