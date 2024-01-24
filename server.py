import socket
import logging
import threading
import rsa

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%m-%Y %H:%M:%S')


# Function to listen for incoming messages and relay them to the other client
def listen_for_messages_in_background(socket, client_name, other_client_socket):
    try:
        while True:
            data = socket.recv(4096)
            if data:
                print(f"Received from {client_name} (Encrypted): {data}")
                other_client_socket.sendall(data)
                print(f"Relayed message from {client_name} to {1 if other_client_socket.fileno() == 4 else 2}")
    except Exception as e:
        print(f"Error receiving/sending message: {e}")


# Main function to start the server
def start_server():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Bind the socket to a specific address and port and start listening for connections
            s.bind(('127.0.0.1', 65432))
            s.listen()
            logging.info(f"Server started. Waiting for connections...")

            # Accept connections from two clients
            client1_socket, addr1 = s.accept()
            client2_socket, addr2 = s.accept()

            # Receive the public keys from the clients
            pub_key1 = rsa.PublicKey.load_pkcs1(client1_socket.recv(4096))
            pub_key2 = rsa.PublicKey.load_pkcs1(client2_socket.recv(4096))

            # Send the public keys to the other client
            client1_socket.sendall(pub_key2.save_pkcs1())
            client2_socket.sendall(pub_key1.save_pkcs1())

            # Start two new threads to listen for messages from each client
            listen_thread1 = threading.Thread(target=listen_for_messages_in_background, args=(
                client1_socket, "Client 1", client2_socket))
            listen_thread2 = threading.Thread(target=listen_for_messages_in_background, args=(
                client2_socket, "Client 2", client1_socket))

            listen_thread1.start()
            listen_thread2.start()

            listen_thread1.join()
            listen_thread2.join()

    except Exception as e:
        logging.error(f"Server terminated. Closing connections. {e}")


def main():
    start_server()


if __name__ == "__main__":
    main()
