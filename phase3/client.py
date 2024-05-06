import socket
import threading
import getpass

# Client configuration
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
BUFFER_SIZE = 1024


def authenticate_user(client_socket):
    """Logic to authenticate connecting client socket"""
    try:
        username = input("Enter username: ")
        password = getpass.getpass("Enter your password: ")

        # Send username and password to server for authentication
        credentials = f"{username}:{password}"
        client_socket.sendall(credentials.encode())

        # Receive authentication result from server
        auth_result = client_socket.recv(1024)
        if auth_result.decode() == 'OK':
            print("Authentication successful.")
            return True
        else:
            print("Authentication failed.")
            return False

    except Exception as e:
        print(f"Error during authentication: {e}")
        return False


def receive_messages(client_socket):
    """Logic to receive messages from the server"""
    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break
            print(data.decode("utf-8"))

    except ConnectionResetError:
        print("Connection with server reset.")
    except Exception as e:
        print(f"Error receiving messages: {e}")

    finally:
        client_socket.close()


def send_messages(client_socket):
    """Thread function to send messages to the server"""
    try:
        while True:
            message = input("Enter a message to send (or 'exit' to quit): ")
            if message.lower() == "exit":
                break
            client_socket.sendall(message.encode("utf-8"))

    except Exception as e:
        print(f"Error sending message: {e}")

    finally:
        client_socket.close()


def connect_to_server():
    """Client connection logic"""
    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        authenticated = authenticate_user(client_socket)
        if authenticated:
            # Start a thread to receive messages
            receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
            receive_thread.start()

            # Start a thread to send messages
            send_thread = threading.Thread(target=send_messages, args=(client_socket,))
            send_thread.start()

            # Wait for both threads to finish
            receive_thread.join()
            send_thread.join()

    except ConnectionRefusedError:
        print("Connection refused. Make sure the server is running.")
    except Exception as e:
        print(f"Error during client operation: {e}")

    finally:
        client_socket.close()


def main():
    connect_to_server()


if __name__ == "__main__":
    main()
