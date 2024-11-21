import socket
import secrets
from DES import DES

def Server_program():
    key = ''.join(secrets.choice('01') for _ in range(64))
    print(f"Kunci yang dihasilkan di Server: {key}")

    des = DES(role="Server", key=key)  # Berikan kunci ke DES
    
    host = socket.gethostname()
    port = 5000 

    server_socket = socket.socket() 
    server_socket.bind((host, port)) 

    server_socket.listen(2)
    conn, address = server_socket.accept() 
    print("Connection from: " + str(address))

     # Kirim kunci ke klien setelah koneksi terbentuk
    conn.sendall(key.encode('utf-8'))  # Tambahkan ini untuk mengirim kunci ke klien
    des.log_with_timestamp(f"Key sent to client: {key}")
    
    while True:
        data = conn.recv(1024)
        if not data:
            break

        raw_message = data.decode('utf-8')
        des.log_with_timestamp(f"Cipher text received: {raw_message}")

        if raw_message.lower() == 'stop':
            print("Stop signal received from sender. Closing connection.")
            conn.sendall(bytes("stop", 'utf-8'))  # Kirim sinyal “stop” kembali ke sender
            break  # Akhiri loop untuk menutup koneksi

        plain_text = des.decryption_cbc(raw_message)
        des.log_with_timestamp(f"Plain text received: {plain_text}")
        print("Plain text received: " + str(plain_text))

        message = input(' -> ')
        cipher_text = des.encryption_cbc(message, output_format="hex")
        des.log_with_timestamp(f"Cipher text sent: {cipher_text}")

        if message.lower() == 'stop':
            conn.sendall(bytes("stop", 'utf-8'))  # Kirim sinyal “stop” ke sender
            print("Stop signal sent to sender. Closing connection.")
            break  # Akhiri loop untuk menutup koneksi

        conn.sendall(bytes(cipher_text, 'utf-8'))

    conn.close()
    print("Connection fully closed by both parties.")



if __name__ == '__main__':
    Server_program()
    
    
    
    