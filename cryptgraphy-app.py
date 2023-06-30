from flask import Flask, request, send_file
from cryptography.fernet import Fernet
from dotenv import load_dotenv, set_key
import os
import glob

# Load the environment variables from the .env file
load_dotenv()

# Check if the SECRET_KEY is in environment variables
if "SECRET_KEY" in os.environ:
    secret_key = os.getenv("SECRET_KEY").encode()
else:
    # If not, generate a new key
    secret_key = Fernet.generate_key()
    
    # Save the new key to the .env file
    with open('.env', 'a') as f: # 'a' stands for 'append'
        f.write(f'\nSECRET_KEY={secret_key.decode()}')
    
# Initialize the Fernet encryption/decryption suite with the secret key
cipher_suite = Fernet(secret_key)

# Initialize a new Flask application
app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    encrypted_data = cipher_suite.encrypt(file.read())
    new_file_name = file.filename + ".enc"
    with open(new_file_name, 'wb') as enc_file:
        enc_file.write(encrypted_data)
    return {"status": "file uploaded and encrypted successfully"}

@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        with open(filename + ".enc", 'rb') as enc_file:
            encrypted_data = enc_file.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        with open(filename, 'wb') as dec_file:
            dec_file.write(decrypted_data)
        return send_file(filename, as_attachment=True)
    except FileNotFoundError:
        return {"status": "file not found"}

@app.route('/form', methods=['GET'])
def form():
    form_html = """
    <!DOCTYPE html>
    <html>
    <body>

    <h2>Upload File</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
      Select file to upload:
      <input type="file" name="file" id="file">
      <br>
      <input type="submit" value="Upload File" name="submit">
    </form>

    </body>
    </html>
    """
    return form_html

@app.route('/files', methods=['GET'])
def list_files():
    files = glob.glob('*.enc')
    files = [file[:-4] for file in files]
    files_str = '\n'.join(files)
    return files_str

if __name__ == "__main__":
    app.run(port=5000)
