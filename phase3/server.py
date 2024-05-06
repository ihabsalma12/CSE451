import csv
import socket
import threading
from phase2 import hashing # TODO fix this import


# Server configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
BUFFER_SIZE = 1024

clients = [] # List to keep track of connected clients
PASSWORDS = {} # Hashed passwords loaded from file.
authenticated_clients = {}  # Dictionary to store authenticated client sockets



# Function to handle client connections
def handle_client(client_socket, address):
    """Logic to handle client"""
    try:
        global PASSWORDS

        print(f"Connection from {address}")

        # Receive data from the client (username:password)
        credentials = client_socket.recv(1024).decode().strip()
        username, password = credentials.split(':')

        # Check if username and password are correct
        if username.lower() in PASSWORDS and hashing.compare_hashes(password, PASSWORDS[username], alg="SHA256"):
            auth_result = 'OK'
            authenticated_clients[username] = client_socket  # Store authenticated client socket
        else:
            auth_result = 'FAIL'

        # Send the authentication result back to the client
        client_socket.sendall(auth_result.encode())

        if auth_result == 'OK':
            while True:
                # Receive and process messages from authenticated client
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break

                message = data.decode("utf-8")
                print(f"Received message from {address}: {message}")

                # Echo the message back to all clients
                for other_username, client_socket in authenticated_clients.items():
                    if other_username != username:
                        try:
                            # Send the message to other authenticated clients
                            client_socket.sendall(f"Broadcast from {username}: {message}".encode())
                        except Exception as e:
                            print(f"Error broadcasting message to {other_username}: {e}")


        
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        print(f"Connection from {address} closed.")
        if client_socket in authenticated_clients:
            del authenticated_clients[client_socket]
        client_socket.close()


def load_passwords_from_file(filepath):
    """Returns passwords from csv filepath"""
    # Loading CSV data into a Python dictionary
    data_read = {}
    with open(filepath, mode="r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Assuming CSV columns are "username" and "hashed_password"
            username = row["username"]
            hashed_password = row["hashed_password"]
            data_read[username] = hashed_password

    return data_read


def start_server():
    """Server initialization code"""
    # pref_sym, pref_asy, pref_hash = input("Enter preferred algorithms. ") # TODO implement user.py
    
    # Load passwords database
    global PASSWORDS
    PASSWORDS = load_passwords_from_file(filepath='data.csv')
    
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    
    # Main server loop
    server_socket.listen(5)
    print("Server is listening...")

    while True:
        client_socket, address = server_socket.accept()
        clients.append(client_socket)
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()    


def main():
    start_server()


if __name__ == "__main__":
    main()