import socket
import secrets
import random
from DES import DES
from RSA import generate_rsa_keys, rsa_encrypt, rsa_decrypt
import pickle
import struct

PKA_HOST = "localhost"
PKA_PORT = 6000

def request_pka(action, entity_id=None, public_key=None):
    """Request to PKA service"""
    with socket.socket() as pka_socket:
        pka_socket.connect((PKA_HOST, PKA_PORT))
        request = {"action": action, "entity_id": entity_id, "public_key": public_key}
        pka_socket.sendall(pickle.dumps(request))
        response = pka_socket.recv(2048)
        return pickle.loads(response) if action in ["get_key", "get_pka_key"] else response.decode()

def generate_nonce():
    """Generate a random nonce"""
    return random.randint(100000, 999999)

def Server_program():
    # Generate RSA keys for server
    public_key_server, private_key_server = generate_rsa_keys()

    # Request PKA public key
    pka_response = request_pka(action="get_pka_key")
    pka_public_key = pka_response.get("public_key")
    if not pka_public_key:
        print("Failed to retrieve PKA public key.")
        return

    # Register server's public key with PKA
    request_pka(action="register", entity_id="Server", public_key=public_key_server)
    print(f"Server Public Key: {public_key_server}")

    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    print("Server is listening...")

    conn, address = server_socket.accept()
    print(f"Connection from: {address}")

    # Request client's encrypted public key from PKA
    client_response = request_pka(action="get_key", entity_id="Client")
    encrypted_client_public_key = client_response.get("public_key")
    if not encrypted_client_public_key:
        print("Client's public key not found in PKA.")
        conn.close()
        return

    # Decrypt client's public key using PKA's public key
    client_public_key = rsa_decrypt(pka_public_key, encrypted_client_public_key)
    print(f"Decrypted Client Public Key: {client_public_key}")

    # Generate N1 nonce
    N1 = generate_nonce()
    print(f"Generated N1: {N1}")

    # Send N1 to client
    conn.sendall(pickle.dumps({"N1": N1}))

    # Receive N1 + N2 from client
    response = pickle.loads(conn.recv(2048))
    received_N1 = response.get("N1")
    N2 = response.get("N2")

    if received_N1 != N1:
        print("N1 verification failed! Aborting connection.")
        conn.close()
        return

    print(f"Received and verified N1: {received_N1}, and received N2: {N2}")

    # Generate DES key
    key = ''.join(secrets.choice('01') for _ in range(64))
    print(f"Generated DES Key: {key}")

    # Encrypt DES Key with private key Server
    encrypted_key_server = rsa_encrypt(private_key_server, key)
    print(f"Encrypted DES Key with Server Private Key: {encrypted_key_server}")

    # Encrypt result with public key Client
    encrypted_key_double = rsa_encrypt(eval(client_public_key), str(encrypted_key_server))
    print(f"Encrypted DES Key with Client Public Key: {encrypted_key_double}")

    # Send data length as header
    data_to_send = pickle.dumps({"encrypted_key": encrypted_key_double})
    data_length = len(data_to_send)
    conn.sendall(struct.pack('!I', data_length))
    conn.sendall(data_to_send)

    des = DES(role="Server", key=key)

    while True:
        data = conn.recv(1024)
        if not data:
            break

        raw_message = data.decode('utf-8')
        des.log_with_timestamp(f"Cipher text received: {raw_message}")

        if raw_message.lower() == 'stop':
            print("Stop signal received from sender. Closing connection.")
            conn.sendall(bytes("stop", 'utf-8'))
            break

        plain_text = des.decryption_cbc(raw_message)
        des.log_with_timestamp(f"Plain text received: {plain_text}")
        print("Plain text received: " + str(plain_text))

        message = input(' -> ')
        cipher_text = des.encryption_cbc(message, output_format="hex")
        des.log_with_timestamp(f"Cipher text sent: {cipher_text}")

        if message.lower() == 'stop':
            conn.sendall(bytes("stop", 'utf-8'))
            print("Stop signal sent to sender. Closing connection.")
            break

        conn.sendall(bytes(cipher_text, 'utf-8'))

    conn.close()
    print("Connection fully closed by both parties.")


if __name__ == '__main__':
    Server_program()