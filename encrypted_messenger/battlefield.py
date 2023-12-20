import datetime, rsa, socket
from json import dumps

HOST = socket.gethostname()  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

pubKey, privKey = rsa.newkeys(512)
message = "lolol"


## Managing the messenger.
messages = []
date_time_now = datetime.datetime.now()
date_time_now_timestamp = date_time_now.strftime("%H:%M")

def encryptMessage(message):
    encryptedMessage = rsa.encrypt(message.encode(),pubKey)
    return encryptedMessage

def decryptMessage(encryptMessage):
    decryptedMessage = rsa.decrypt(encryptMessage,privKey).decode()
    return decryptedMessage


message_detail = {
        "Sender" : "123",
        "EncMess" : message,
        "Timestamp" : date_time_now_timestamp
}

json_dumped = dumps(message_detail)

print(message_detail, type(message_detail))
print(json_dumped, type(json_dumped))


