import datetime, rsa, socket, logging
import json
from json import dumps

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HOST = socket.gethostname()  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

pubKey, privKey = rsa.newkeys(512)
pubKey_export = pubKey.save_pkcs1(format="DER")

print(pubKey_export)

message = "lolol"

## Managing the messenger.
messages = []
date_time_now = datetime.datetime.now()
date_time_now_timestamp = date_time_now.strftime("%H:%M")


def encryptMessage(text):
    encryptedMessage = rsa.encrypt(message.encode(), pubKey)
    return encryptedMessage


def decryptMessage(encryptMessage):
    decryptedMessage = rsa.decrypt(encryptMessage, privKey).decode()
    return decryptedMessage


def createJsonDumpedMessage(sender, message, timestamp):
    message_detail = {
        "Sender": sender,
        "Message": message,
        "Timestamp": timestamp
    }
    json_dumped_message = dumps(message_detail)
    return json_dumped_message


message_encrypted = encryptMessage(createJsonDumpedMessage)
json_deserilised = json.loads(createJsonDumpedMessage("X", "22", "10"))
print(decryptMessage(message_encrypted))


def exchangePubRSA():  # Function that exchanges the RSA key with server
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))  # Establish connection
            s.sendall(pubKey_export)  # Export the public key

            logging.info("Waiting for response")
            rsa_pubkey_import = s.recv(1024)
            logging.info(f"Got the key! {rsa_pubkey_import}")
    except Exception as ex:
        print(f"Error on exchange: {ex}")


exchangePubRSA()

# After exchanging RSA, the messenger establishes a new connection and starts.
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Configuring multi-usage of socket
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((HOST, PORT))
        while True:
            try:
                # Sending the encrypted message to server.
                s.sendall(message_encrypted)

                # Waiting for data from server
                data = s.recv(1024)
                logging.info(f"Received: {data.decode()}")
            except Exception as messageError:
                logging.error(f"Message error: {messageError}")
                break
except Exception as e:
    logging.error(f"Connection error: {e}")
