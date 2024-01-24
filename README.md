# Encryption Messenger (encryption-messenger-py)

Encryption Messenger is a simple encrypted messaging system implemented in Python, utilizing RSA encryption for secure communication between clients and a server.

## Overview

This project consists of two main scripts:

1. **client.py**: The client-side script responsible for generating RSA key pairs, establishing a connection with the server, sending and receiving encrypted messages.
2. **server.py**: The server-side script managing connections from multiple clients, relaying encrypted messages between clients, and facilitating secure communication.

## Getting Started

### Prerequisites

- Ensure Python is installed on your system.
- Clone the repository:

    ```bash
    git clone https://github.com/fafa194/encryption-messenger-py.git
    cd encryption-messenger-py
    ```

- Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

### Running the scripts:

1. Start the server:

    ```bash
    python server.py
    ```

2. Start two clients (in two separate terminals):

    ```bash
    python client.py
    ```

3. Follow the prompts to send and receive encrypted messages. Type 'exit' in the client to terminate.

## Project Structure

- **client.py**: The client-side script for the Encryption Messenger.
- **server.py**: The server-side script for the Encryption Messenger.

## Features

- End-to-end encryption using RSA.
- Simple command-line interface.
- Secure communication between clients through a central server.

## Dependencies

- `socket`: Python standard library for socket programming.
- `logging`: Python standard library for logging.
- `threading`: Python standard library for multi-threading.
- `rsa`: Third-party library for RSA encryption.

## License

This project is licensed under the MIT License.

## Acknowledgments

- Inspired by the need for secure communication in various applications.
- Built for educational purposes and practical understanding of cryptography.
