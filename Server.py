import socket
import secrets
from DES import DES
from RSA import generate_rsa_keys, rsa_encrypt
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
        return pickle.loads(response) if action == "get_key" else response.decode()

def Server_program():
    # Generate RSA keys for server
    public_key_server, private_key_server = generate_rsa_keys()
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

    # Request client's public key from PKA
    client_public_key = request_pka(action="get_key", entity_id="Client").get("public_key")
    if not client_public_key:
        print("Client's public key not found in PKA.")
        conn.close()
        return

    # Generate DES key
    key = ''.join(secrets.choice('01') for _ in range(64))
    print(f"Kunci DES yang dihasilkan di Server: {key}")

    # Encrypt DES key with client's public key
    encrypted_key = rsa_encrypt(client_public_key, key)
    print(f"Encrypted DES Key: {encrypted_key}")

    # Send encrypted DES key to client
    conn.sendall(' '.join(map(str, encrypted_key)).encode('utf-8'))

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
