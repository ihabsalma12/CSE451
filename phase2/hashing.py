#source: https://kinsta.com/blog/python-hashing/
import hashlib


def generate_hash(message, alg="SHA256"):   
    # message.encode() : string in python is stored as Unicode. this converts it to UTF-8 bytes sequence.
    # Check if data is a string
    if isinstance(message, str):
        # Encode string data to bytes using UTF-8 encoding (you can change the encoding if needed)
        data_bytes = message.encode()
    elif isinstance(message, bytes):
        # If data is already bytes, use it directly
        data_bytes = message
    else:
        raise TypeError("Unsupported data type. Only strings or bytes are supported.")

    # Hash the data using SHA-256 or MD5 algorithm and return the hexdigest
    if alg == "SHA256":
        return hashlib.sha256(data_bytes).hexdigest()
    elif alg == "MD5":
        return hashlib.md5(data_bytes).hexdigest()
    


def compare_messages(original_message, transmitted_message):
    orig_message_hash = generate_hash(original_message)
    trans_message_hash = generate_hash(transmitted_message)

    if orig_message_hash == trans_message_hash:
        return True #they're the same
    return False

def compare_hashes(transmitted_message, orig_message_hash, alg):
    if orig_message_hash == generate_hash(transmitted_message, alg):
        return True
    return False


# TODO 
# fix .encode('utf-8') thing In python 2, strings and bytes objects are the same. In python 3, they are not. Hashlib requires bytes objects, not strings. Strings can be turned into bytes by calling their .encode method.
# add salt
# file input with open. save to file as well.
# maybe we can create user class for the use cases.






def run_msgs():
    setup()
    msg1 = input("Enter original message. ")
    msg2 = input("Enter transmitted message. ")
    print(compare_messages(msg1, msg2))

def run_hashmsg():
    setup()
    msg2 = input("Enter transmitted message. ")
    hash1 = input("Enter original message HASH. ")
    print(compare_hashes(msg2, hash1))


def setup():
    print("Welcome, user! Verify the integrity of your message.")

    alg_input = input("Enter data integrity algorithm (SHA256/ MD5). Press ENTER for default SHA256. ")

    if alg_input in ["MD5", "SHA256", ""]:
        alg = alg_input
        if alg == "":
            alg = "SHA256"
    else:
        raise ValueError("Invalid algorithm. Please choose SHA256 or MD5.")
        
