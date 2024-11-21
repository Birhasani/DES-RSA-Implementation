import socket
import threading
import pickle  # Untuk mengirim objek Python melalui socket

class PKA:
    def __init__(self):
        self.key_store = {}

    def register_key(self, entity_id, public_key):
        """Register an entity's public key"""
        self.key_store[entity_id] = public_key
        print(f"Registered public key for {entity_id}: {public_key}")

    def get_key(self, entity_id):
        """Provide public key of an entity"""
        return self.key_store.get(entity_id, None)

def handle_client(conn, addr, pka):
    print(f"Connection from: {addr}")
    while True:
        try:
            # Terima data dari client
            data = conn.recv(1024)
            if not data:
                break

            request = pickle.loads(data)
            action = request.get("action")
            entity_id = request.get("entity_id")
            public_key = request.get("public_key")

            if action == "register":
                # Register kunci publik
                pka.register_key(entity_id, public_key)
                conn.sendall(b"Key registered successfully.")
            elif action == "get_key":
                # Ambil kunci publik
                key = pka.get_key(entity_id)
                conn.sendall(pickle.dumps({"public_key": key}))
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
