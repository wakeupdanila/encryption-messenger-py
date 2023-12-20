import datetime, rsa, socket
import json
from json import dumps



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
    encryptedMessage = rsa.encrypt(message.encode(),pubKey)
    return encryptedMessage

def decryptMessage(encryptMessage):
    decryptedMessage = rsa.decrypt(encryptMessage,privKey).decode()
    return decryptedMessage

def createJsonDumpedMessage(sender,message,timestamp):
    message_detail = {
    "Sender" : sender,
    "Message" : message,
    "Timestamp" : timestamp
}
    json_dumped_message = dumps(message_detail)
    return json_dumped_message

message_encrypted = encryptMessage(createJsonDumpedMessage)

json_deserilised = json.loads(createJsonDumpedMessage("X","22","10"))
#print(json_deserilised, type(message_encrypted))
#print(pubKey, type(pubKey_export))

## Exchange the pubkey with server

def exchangePubRSA():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST,PORT))  # Establish connection
            s.sendall(pubKey_export) # Export the public key

            print("Waiting for response")
            rsa_pubKey_import = s.recv(1024)
            print(rsa_pubKey_import,type(rsa_pubKey_import))
    except Exception as ex:
        print(f"Error on exchange: {ex}")


### SOCKET CLIENT STARTS
exchangePubRSA()
PORT = 65431
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        while True:
            message = input("Message:")
            s.sendall(message_encrypted)
            data = s.recv(1024)
    print(f"Received {data!r}")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    s.close()
