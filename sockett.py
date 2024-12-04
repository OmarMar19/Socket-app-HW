import socket
import threading
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate shared symmetric key
shared_symmetric_key = Fernet.generate_key()
fernet = Fernet(shared_symmetric_key)

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serialize public key
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

peer_public_key = None  # To store the peer's public key

# Networking setup
PORT = 65432

def handle_receive(sock):
    """Receive messages from the peer."""
    global peer_public_key, shared_symmetric_key, fernet
    while True:
        data = sock.recv(4096)
        if not data:
            break

        # Handle peer public key exchange
        if peer_public_key is None:
            peer_public_key = serialization.load_pem_public_key(data)
            print("Peer's public key received.")
            continue

        # Handle symmetric key exchange
        if len(data) == 44:  # Symmetric key length is 44 bytes
            shared_symmetric_key = data
            fernet = Fernet(shared_symmetric_key)
            print("Symmetric key received.")
            continue

        # Handle received messages
        try:
            # Check if message is prefixed with "NORMAL:" to detect normal messages
            if data.decode().startswith("NORMAL:"):
                print(f"\n[Normal] Received: {data.decode()[7:]}")
                continue

            # Symmetric decryption
            decrypted_message = fernet.decrypt(data)
            print(f"\n[Symmetric Decrypted] Received: {decrypted_message.decode()}")
        except Exception:
            try:
                # Asymmetric decryption
                decrypted_message = private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"\n[Asymmetric Decrypted] Received: {decrypted_message.decode()}")
            except Exception:
                print(f"\n[Encrypted] Received: {data.hex()} (Could not decrypt)")

def send_messages(sock):
    """Send messages to the peer."""
    global peer_public_key
    print("Public key sent to the peer.")
    sock.sendall(public_key_pem)

    # Send symmetric key to the other peer (only once)
    sock.sendall(shared_symmetric_key)
    print("Symmetric key sent to peer.")
    
    while True:
        print("\nChoose message mode:")
        print("1. Normal Message")
        print("2. Symmetric Encryption")
        print("3. Asymmetric Encryption")
        choice = input("Enter choice (1/2/3): ")
        
        message = input("Enter your message: ")
        
        if choice == "1":
            # Normal message: prefix with "NORMAL:" to indicate no encryption
            encrypted_message = f"NORMAL:{message}".encode()
            print(f"\n[Normal] Sending: {message}")
        elif choice == "2":
            # Symmetric encryption
            encrypted_message = fernet.encrypt(message.encode())
            print(f"\n[Symmetric Encrypted] Sending: {encrypted_message.hex()}")
        elif choice == "3":
            if peer_public_key:
                # Asymmetric encryption
                encrypted_message = peer_public_key.encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"\n[Asymmetric Encrypted] Sending: {encrypted_message.hex()}")
            else:
                print("Peer's public key not received yet. Sending as normal message.")
                encrypted_message = f"NORMAL:{message}".encode()
        else:
            print("Invalid choice. Sending as normal message.")
            encrypted_message = f"NORMAL:{message}".encode()
        
        sock.sendall(encrypted_message)

def start_peer(is_host, peer_ip=None):
    """Start the peer-to-peer messaging."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    if is_host:
        # Act as host
        sock.bind(('0.0.0.0', PORT))
        sock.listen(1)
        print("Waiting for connection...")
        conn, addr = sock.accept()
        print(f"Connected by {addr}")
    else:
        # Connect to the host
        sock.connect((peer_ip, PORT))
        conn = sock
    
    # Start threads for sending and receiving
    threading.Thread(target=handle_receive, args=(conn,), daemon=True).start()
    send_messages(conn)

if __name__ == "__main__":
    print("Are you hosting the connection?")
    print("1. Yes (Host)")
    print("2. No (Connect to peer)")
    choice = input("Enter choice (1/2): ")
    
    if choice == "1":
        start_peer(is_host=True)
    elif choice == "2":
        peer_ip = input("Enter the host's IP address: ")
        start_peer(is_host=False, peer_ip=peer_ip)
    else:
        print("Invalid choice. Exiting.")
