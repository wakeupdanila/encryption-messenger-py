import datetime
import rsa
import json

HOST = '127.0.0.1'
import socket


def listen_for_messages_in_background(socket, client_name, other_client_socket, pub_key):
    try:
        while True:
            data = socket.recv(4096)
            if data:
                print(f"Received from {client_name} (Encrypted): {data}")
                encrypted_message = rsa.encrypt(data, pub_key)
                other_client_socket.sendall(encrypted_message)
                print(f"Relayed message from {client_name} to {1 if other_client_socket.fileno() == 4 else 2}")
    except Exception as e:
        print(f"Error receiving/sending message: {e}")


def send_encrypted_message(socket, encrypted_message):
    try:
        socket.sendall(encrypted_message)
    except Exception as send_error:
        print(f"Send error: {send_error}")


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


def send_encrypted_message(socket, encrypted_message):
    try:
        socket.sendall(encrypted_message)
    except Exception as send_error:
        print(f"Send error: {send_error}")
