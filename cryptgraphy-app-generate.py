from dotenv import load_dotenv, set_key
import os
from cryptography.fernet import Fernet

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
    
# Continue with the rest of your script...
cipher_suite = Fernet(secret_key)
