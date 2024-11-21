import socket
from DES import DES


def client_program():

    
    # Konfigurasi host dan port yang akan terhubung dengan server
    host = socket.gethostname()  # Mendapatkan nama host dari mesin saat ini
    port = 5000  # Port yang sesuai dengan server

    # Membuat dan menghubungkan socket client ke host dan port server
    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Terima kunci dari server setelah koneksi terbentuk
    key = client_socket.recv(1024).decode('utf-8')
    print(f"Kunci diterima dari server: {key}")
    
    des = DES(role="Client", key=key)  # Gunakan kunci yang diterima untuk DES

    while True:
        # Ambil input pesan dari pengguna untuk dikirim ke server
        message = input(" -> ")
        if message.lower().strip() == 'stop':
            # Jika pesan adalah "stop", kirim sinyal berhenti ke server
            des.log_with_timestamp("Stop signal sent.")
            client_socket.sendall(bytes("stop", 'utf-8'))
            print("Stop signal sent to receiver. Closing connection.")
            break  # Keluar dari loop

        # Enkripsi pesan yang akan dikirim dan kirim ke server
        cipher_text = des.encryption_cbc(message, output_format="hex")
        des.log_with_timestamp(f"Cipher text sent: {cipher_text}")
        client_socket.sendall(bytes(cipher_text, 'utf-8'))

        # Terima pesan dari server
        data = client_socket.recv(1024)
        raw_message = data.decode('utf-8')
        des.log_with_timestamp(f"Cipher text received: {raw_message}")

        if raw_message.lower() == 'stop':
            # Jika menerima "stop" dari server, akhiri koneksi
            print("Stop signal received from receiver. Closing connection.")
            break  # Keluar dari loop

        # Dekripsi pesan yang diterima dan tampilkan
        plain_text = des.decryption_cbc(raw_message, output_format="text")
        des.log_with_timestamp(f"Plain text: {plain_text}")
        print(f'Plain Text: {plain_text}')

    # Menutup koneksi setelah keluar dari loop
    client_socket.close()
    print("Connection fully closed by both parties.")


# Menjalankan program client jika file ini dieksekusi secara langsung
if __name__ == '__main__':
    client_program()
