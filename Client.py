import socket
from DES import DES
from RSA import generate_rsa_keys, rsa_encrypt, rsa_decrypt
import pickle
import random
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

def client_program():
    # Generate RSA keys for client
    public_key_client, private_key_client = generate_rsa_keys()

    # Request PKA public key
    pka_response = request_pka(action="get_pka_key")
    pka_public_key = pka_response.get("public_key")
    if not pka_public_key:
        print("Failed to retrieve PKA public key.")
        return

    # Register client's public key with PKA
    request_pka(action="register", entity_id="Client", public_key=public_key_client)
    print(f"Client Public Key: {public_key_client}")

    # Request Server's public key from PKA
    server_response = request_pka(action="get_key", entity_id="Server")
    encrypted_server_public_key = server_response.get("public_key")

    if not encrypted_server_public_key:
        print("Server's public key not found in PKA.")
        return

    # Decrypt Server's public key using PKA's public key
    server_public_key = rsa_decrypt(pka_public_key, encrypted_server_public_key)
    print(f"Decrypted Server Public Key: {server_public_key}")

    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Receive N1 from server
    response = pickle.loads(client_socket.recv(2048))
    N1 = response.get("N1")
    print(f"Received N1: {N1}")

    # Generate N2 and send back N1 + N2
    N2 = generate_nonce()
    print(f"Generated N2: {N2}")
    client_socket.sendall(pickle.dumps({"N1": N1, "N2": N2}))

    # Receive encrypted DES key
    header = client_socket.recv(4)
    if not header:
        print("Failed to receive data header.")
        return

    data_length = struct.unpack('!I', header)[0]
    data_received = b""
    while len(data_received) < data_length:
        packet = client_socket.recv(min(2048, data_length - len(data_received)))
        if not packet:
            raise ConnectionError("Connection lost while receiving data.")
        data_received += packet

    # Load data with pickle
    response = pickle.loads(data_received)
    encrypted_key_double = response.get("encrypted_key")
    print(f"Received Double Encrypted DES Key: {encrypted_key_double}")

    # Decrypt with private key Client
    decrypted_key_client = rsa_decrypt(private_key_client, encrypted_key_double)
    print(f"Decrypted Key with Client Private Key (as string): {decrypted_key_client}")

    # Convert string back to list of numbers
    decrypted_key_list = eval(decrypted_key_client)

    # Decrypt with public key Server
    decrypted_key_final = rsa_decrypt(eval(server_public_key), decrypted_key_list)
    print(f"Decrypted Key with Server Public Key: {decrypted_key_final}")

    key = ''.join(format(ord(char), '08b') for char in decrypted_key_final)

    des = DES(role="Client", key=key)

    while True:
        message = input(" -> ")
        if message.lower().strip() == 'stop':
            des.log_with_timestamp("Stop signal sent.")
            client_socket.sendall(bytes("stop", 'utf-8'))
            print("Stop signal sent to receiver. Closing connection.")
            break

        cipher_text = des.encryption_cbc(message, output_format="hex")
        des.log_with_timestamp(f"Cipher text sent: {cipher_text}")
        client_socket.sendall(bytes(cipher_text, 'utf-8'))

        data = client_socket.recv(1024)
        raw_message = data.decode('utf-8')
        des.log_with_timestamp(f"Cipher text received: {raw_message}")

        if raw_message.lower() == 'stop':
            print("Stop signal received from receiver. Closing connection.")
            break

        plain_text = des.decryption_cbc(raw_message, output_format="text")
        des.log_with_timestamp(f"Plain text: {plain_text}")
        print(f'Plain Text: {plain_text}')

    client_socket.close()
    print("Connection fully closed by both parties.")


if __name__ == '__main__':
    client_program()