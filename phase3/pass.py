"""This file is now outdated, use as DRAFT ONLY."""
# import getpass
# import csv
# from phase2 import hashing

# # Data to be saved in CSV format
# data = {'Alice': '1234', 'Bob': '123456', 'Charlie': 'abcdefg'} # TODO please hide this or something

# # File path to save the CSV data
# filepath = "data.csv"

# # Data to be read from CSV file
# PASSWORDS = {}


# authenticated_clients = {} # TODO finish this in client.py and server.py


# def password_auth():
    
#     username = input("Enter username: ")
#     password = getpass.getpass("Enter your password: ")

#     # Send username and password to server for authentication
#     # Check if username and password are correct
#     if username.lower() in PASSWORDS and hashing.compare_hashes(password, PASSWORDS[username], alg="SHA256"):
#         auth_result = 'OK'
#         # Store authenticated client socket
#     else:
#         auth_result = 'FAIL'

#     # Send the authentication result back to the client
#     # Receive authentication result from server

#     if auth_result == 'OK':
#         # Receive and process messages from authenticated client
#         print("Authentication successful.")
#         return True
#     else:
#         print("Authentication failed.")
#         return False




# def save_passwords_to_file(data, filepath):
#     # Hash all passwords
#     for user, password in data.items():
#         data[user] = hashing.generate_hash(password, alg="SHA256")

#     # Writing CSV data to a file
#     with open(filepath, mode="w", newline="") as file:
#         writer = csv.DictWriter(file, fieldnames=["username", "hashed_password"])
#         writer.writeheader()  # Write CSV header
#         for user, hashed_password in data.items():
#             writer.writerow({"username": user.lower(), "hashed_password": hashed_password})

# def load_passwords_from_file(filepath):
#     # Loading CSV data into a Python dictionary
#     data_read = {}
#     with open(filepath, mode="r") as file:
#         reader = csv.DictReader(file)
#         for row in reader:
#             # Assuming CSV columns are "username" and "hashed_password"
#             username = row["username"]
#             hashed_password = row["hashed_password"]
#             data_read[username] = hashed_password

#     return data_read


# def main():
#     global PASSWORDS
#     save_passwords_to_file(data=data, filepath=filepath)
#     PASSWORDS = load_passwords_from_file(filepath=filepath)
#     print(PASSWORDS)
#     authenticated = password_auth()
#     if authenticated:
#         input("Enter your message. ")

        

# if __name__ == "__main__":
#     main()