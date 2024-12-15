import socket
from DES import DES
from RSA import generate_rsa_keys, rsa_decrypt
import pickle

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

    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Request server's encrypted public key from PKA
    server_response = request_pka(action="get_key", entity_id="Server")
    encrypted_server_public_key = server_response.get("public_key")
    if not encrypted_server_public_key:
        print("Server's public key not found in PKA.")
        client_socket.close()
        return

    # Decrypt server's public key using PKA's public key
    server_public_key = rsa_decrypt(pka_public_key, encrypted_server_public_key)
    print(f"Decrypted Server Public Key: {server_public_key}")

    # Receive encrypted DES key
    encrypted_key = client_socket.recv(2048).decode('utf-8')
    encrypted_key = list(map(int, encrypted_key.split()))
    print(f"Encrypted DES Key Received: {encrypted_key}")

    # Decrypt DES key using client's private key
    key = rsa_decrypt(private_key_client, encrypted_key)
    print(f"Decrypted DES Key: {key}")

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