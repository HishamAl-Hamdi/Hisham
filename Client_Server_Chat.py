import threading
import socket
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Global variables to manage clients and their names
clients = []
client_names = {}
public_keys = {}

# Function to generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Caesar cipher encryption function
def caesar_encrypt(message, shift):
    encrypted = []
    for char in message:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted.append(chr(shifted))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

# Caesar cipher decryption function
def caesar_decrypt(encrypted_message, shift):
    decrypted = []
    for char in encrypted_message:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            decrypted.append(chr(shifted))
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# Function to handle each client connection
def handle_client(client_socket):
    private_key, public_key = generate_rsa_keys()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Send public key to client
    client_socket.send(public_key_bytes)

    # Receive the client's public key
    client_public_key_bytes = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes,
        backend=default_backend()
    )

    # Generate shared key
    shared_key = os.urandom(32)  # AES-256 key
    encrypted_shared_key = client_public_key.encrypt(
        shared_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send(encrypted_shared_key)

    # Store client information
    name = client_socket.recv(1024).decode()
    client_names[client_socket] = name
    clients.append(client_socket)
    public_keys[client_socket] = public_key

    print(f"{name} has joined the chat!")
    broadcast(f"{name} has joined the chat!", exclude=client_socket)

    while True:
        try:
            # Receive encrypted message
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            
            # Decrypt the message using the shared key
            cipher = Cipher(algorithms.AES(shared_key), modes.CBC(encrypted_message[:16]))
            decryptor = cipher.decryptor()
            message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
            message = message.decode().strip()

            if message.lower() == 'end':
                broadcast(f"{name} has left the chat!", exclude=client_socket)
                clients.remove(client_socket)
                del client_names[client_socket]
                client_socket.close()
                print(f"{name} has left the chat.")
                break
            else:
                broadcast(f"{name}: {message}", exclude=client_socket)
                print(f"{name}: {message}")  # Server displays the message
        except Exception as e:
            print(f"Error: {e}")
            break

# Function to broadcast messages to all clients
def broadcast(message, exclude=None):
    # Encrypt the message using Caesar cipher before broadcasting
    encrypted_message = caesar_encrypt(message, shift=3)
    for client in clients:
        if client != exclude:  # Exclude the sender
            try:
                client.send(encrypted_message.encode())
            except:
                client.close()
                clients.remove(client)

# Function to start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8888))
    server.listen()
    print("Server is listening for connections...")
    
    while True:
        client_socket, addr = server.accept()
        print(f"Connection from {addr} accepted.")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

# Function for clients to send messages
def sending_messages(client_socket, name, shared_key):
    while True:
        message = input(">> ")
        if message.lower() == 'end':
            client_socket.send(message.encode())
            client_socket.close()
            break
        
        # Encrypt message
        iv = os.urandom(16)  # IV for AES
        cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Pad the message to be a multiple of the block size
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        
        encrypted_message = iv + encryptor.update(padded_message) + encryptor.finalize()
        
        client_socket.send(encrypted_message)

# Function for clients to receive messages
def receiving_messages(client_socket):
    while True:
        try:
            encrypted_message = client_socket.recv(1024).decode()
            # Decrypt the received encrypted message
            decrypted_message = caesar_decrypt(encrypted_message, shift=3)
            print(decrypted_message)
        except:
            print("Disconnected from server.")
            break

# Function to start the client
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 8888))

    # Receive the server's public key
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_bytes,
        backend=default_backend()
    )

    # Generate client's RSA keys
    private_key, public_key = generate_rsa_keys()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_key_bytes)

    # Receive the encrypted shared key
    encrypted_shared_key = client_socket.recv(1024)
    shared_key = private_key.decrypt(
        encrypted_shared_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    name = input("Enter your name: ")
    client_socket.send(name.encode())

    threading.Thread(target=sending_messages, args=(client_socket, name, shared_key)).start()
    threading.Thread(target=receiving_messages, args=(client_socket,)).start()

# Main function to choose server or client mode
def main():
    choice = input("Do you want to host (1) or connect (2): ")

    if choice == "1":
        start_server()
    elif choice == "2":
        start_client()
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()