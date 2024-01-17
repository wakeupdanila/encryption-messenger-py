import datetime
import rsa
import json

HOST = '127.0.0.1'
PORT = 65432


def get_current_time():
    return datetime.datetime.now()


def create_json_dumped_message(text):
    now = get_current_time()
    message_detail = {
        "Time": now.strftime("%H:%M:%S"),
        "Date": now.strftime("%Y-%m-%d"),
        "Message": text,
    }
    json_message = json.dumps(message_detail)
    return json_message.encode()


def encrypt_message(text, public_key):
    if isinstance(text, str):
        text = text.encode()
    encrypted_message = rsa.encrypt(text, public_key)
    return encrypted_message


def decrypt_message(encrypted_message, private_key):
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    return decrypted_message.decode()


def exchange_pub_rsa(socket, public_key_export):
    try:
        socket.sendall(public_key_export)
        other_party_pub_key_data = socket.recv(4096)
        other_party_pub_key = rsa.PublicKey.load_pkcs1(other_party_pub_key_data, format='PEM')
        return other_party_pub_key
    except Exception as ex:
        print(f"Error during key exchange: {ex}")
        return None


def listen_for_messages_in_background(socket, client_name, other_client_socket):
    try:
        while True:
            encrypted_message = listen_for_message(socket)
            if encrypted_message:
                peer_name = get_peer_name(socket)
                print(f"Received from {peer_name} (Encrypted): {encrypted_message}")

                if peer_name != client_name:
                    send_encrypted_message(other_client_socket, encrypted_message)
                    print(f"Relayed message from {client_name} to {get_peer_name(other_client_socket)}")
    except Exception as e:
        print(f"Error receiving/sending message: {e}")


def get_peer_name(socket):
    return f"Client {1 if socket.fileno() == 4 else 2}"


def send_encrypted_message(socket, encrypted_message):
    try:
        socket.sendall(encrypted_message)
    except Exception as send_error:
        print(f"Send error: {send_error}")


def listen_for_message(socket):
    try:
        data = socket.recv(4096)
        if data:
            return data
        else:
            return None
    except Exception as receive_error:
        print(f"Receive error: {receive_error}")
        return None
