import socket
import logging
import threading
import rsa

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d-%m-%Y %H:%M:%S')


# Function to send an encrypted message over a socket
def send_encrypted_message(socket, message):
    try:
        socket.sendall(message)
    except Exception as e:
        print(f"Error sending message: {e}")


# Function to listen for incoming messages and decrypt them
def listen_for_messages(socket, priv_key):
    try:
        while True:
            data = socket.recv(4096)
            if data:
                decrypted_message = rsa.decrypt(data, priv_key)
                print(f"Received message: {decrypted_message.decode()}")
    except Exception as e:
        print(f"Error receiving message: {e}")


# Main function to start the client
def start_client():
    # Generate a new pair of RSA keys
    pub_key, priv_key = rsa.newkeys(2048)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Connect to the server
            s.connect(('127.0.0.1', 65432))
            logging.info(f"Connected to 127.0.0.1 on port: 65432")

            # Send the public key to the server
            s.sendall(pub_key.save_pkcs1())

            # Receive the public key of the other client from the server
            other_pub_key = rsa.PublicKey.load_pkcs1(s.recv(4096))

            # Start a new thread to listen for messages
            listen_thread = threading.Thread(target=listen_for_messages, args=(s, priv_key))
            listen_thread.start()

            try:
                while True:
                    # Get the message from the user
                    message = input("Message: ")
                    if message.lower() == 'exit':
                        break
                    # Encrypt the message with the other client's public key and send it
                    encrypted_message = rsa.encrypt(message.encode(), other_pub_key)
                    send_encrypted_message(s, encrypted_message)

            except KeyboardInterrupt:
                # If the user presses Ctrl+C, close the connection and stop the thread
                logging.info("Client terminated. Closing connection.")
                s.close()
                listen_thread.join(1)

    except Exception as e:
        logging.error(f"Connection error: {e}")


def main():
    start_client()


if __name__ == "__main__":
    main()
