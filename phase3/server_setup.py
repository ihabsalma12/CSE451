"""This file is important for integration."""
import csv
from phase2 import hashing # TODO fix this import

# Data to be saved in CSV format
_PASSWORDS = {'Alice': '1234', 'Bob': '123456', 'Charlie': 'abcdefg'} # NOTE this should be private

# File path to save the CSV data
PASSWORD_FILEPATH = "data.csv"



def save_passwords_to_file(data, filepath):
    """ Saves passwords ('data' param) in .csv file ('filepath' param) """
    # Hash all passwords
    for user, password in data.items():
        data[user] = hashing.generate_hash(password, alg="SHA256")

    # Writing hashed passwords to a CSV file
    with open(filepath, mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "hashed_password"])
        writer.writeheader()  # Write CSV header
        for user, hashed_password in data.items():
            writer.writerow({"username": user.lower(), "hashed_password": hashed_password})


def main():
    # TODO create preferred algorithms, do more integration for phase 4
    save_passwords_to_file(data=_PASSWORDS, filepath=PASSWORD_FILEPATH)
        

if __name__ == "__main__":
    main()