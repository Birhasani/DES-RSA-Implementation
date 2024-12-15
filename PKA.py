import socket
import threading
import pickle
from RSA import generate_rsa_keys, rsa_encrypt, rsa_decrypt

class PKA:
    def __init__(self):
        self.key_store = {}
        self.private_key, self.public_key = generate_rsa_keys()

    def register_key(self, entity_id, public_key):
        """Register an entity's public key"""
        self.key_store[entity_id] = public_key
        print(f"Registered public key for {entity_id}: {public_key}")

    def get_key(self, entity_id):
        """Provide public key of an entity encrypted with PKA's private key"""
        public_key = self.key_store.get(entity_id, None)
        if public_key:
            # Enkrip kunci publik dengan kunci privat PKA
            encrypted_key = rsa_encrypt(self.private_key, str(public_key))
            return encrypted_key
        return None

def handle_client(conn, addr, pka):
    print(f"Connection from: {addr}")
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break

            request = pickle.loads(data)
            action = request.get("action")
            entity_id = request.get("entity_id")
            public_key = request.get("public_key")

            if action == "register":
                pka.register_key(entity_id, public_key)
                conn.sendall(b"Key registered successfully.")
            elif action == "get_key":
                encrypted_key = pka.get_key(entity_id)
                if encrypted_key:
                    conn.sendall(pickle.dumps({"public_key": encrypted_key}))
                else:
                    conn.sendall(b"Entity not found.")
            elif action == "get_pka_key":
                # Kirim kunci publik PKA ke client
                conn.sendall(pickle.dumps({"public_key": pka.public_key}))
            else:
                conn.sendall(b"Invalid action.")
        except Exception as e:
            print(f"Error handling client: {e}")
            break

    conn.close()

def start_pka_server():
    host = "localhost"
    port = 6000
    pka = PKA()

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("PKA Service is running...")

    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr, pka)).start()

if __name__ == "__main__":
    start_pka_server()