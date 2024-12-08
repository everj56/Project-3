from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os
import uuid
import bcrypt
from cryptography.hazmat.primitives import hashes

# AES encryption environment variable
AES_KEY = os.getenv("NOT_MY_KEY").encode()


#sets hostname and server port
hostName = "localhost"
serverPort = 8080
# path for the database file
db_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "totally_not_my_privateKeys.db")

# check and initialize the database
if not os.path.isfile(db_file_path):
    with open(db_file_path, 'w') as db_file:
        pass

# initialize the databases for keys, users, and authentication logs
def initialize_database(db_file):
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            # Creates table for keys
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            """)
            # Creates table for users
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            # Creates table for authentication logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_ip TEXT NOT NULL,
                    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error initializing database: {e}")

# Encrypt private keys with AES
def encrypt_with_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return iv + encrypted_data

# Decrypt private keys with AES
def decrypt_with_aes(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode()

# User registration endpoint
def register_user(username, email, db_file):
    password = str(uuid.uuid4())  
    # Hash password with bcrypt
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())  

    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password_hash, email)
                VALUES (?, ?, ?)
            """, (username, password_hash, email))
            conn.commit()
        return password
    except sqlite3.Error as e:
        print(f"Error registering user: {e}")
        return None

# Logs authentication requests
def log_auth_request(user_id, request_ip, db_file):
    try:
        with sqlite3.connect(db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO auth_logs (user_id, request_ip)
                VALUES (?, ?)
            """, (user_id, request_ip))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging authentication request: {e}")


# Stores timestamps for user IPs
auth_requests = {}  
# Rate-limiting function
def rate_limit(request_ip):
    current_time = datetime.datetime.now()
    if request_ip not in auth_requests:
        auth_requests[request_ip] = [current_time]
        return True
    else:
        requests = auth_requests[request_ip]
        # Keeps requests within 1 second
        requests = [t for t in requests if (current_time - t).seconds < 1]  
        auth_requests[request_ip] = requests
        if len(requests) < 10:
            requests.append(current_time)
            return True
        else:
            return False

# Helper function to convert int to base64
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')  
    return encoded.decode('utf-8')

# Initialize database
initialize_database(db_file_path)

# MyServer class
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)

            username = data.get("username")
            email = data.get("email")
            
            # Call the register_user function to create the user and generate a password
            password = register_user(username, email, db_file_path)
            if password:
                self.send_response(201)  # Created
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"password": password}).encode())
            else:
                self.send_response(500)  # Internal Server Error
                self.end_headers()

        elif parsed_path.path == "/auth":
            # Handle the authentication logic
            if rate_limit(self.client_address[0]):  # Check for rate limiting
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Authenticated successfully!")
                # Log the authentication request
                log_auth_request(user_id=1, request_ip=self.client_address[0], db_file=db_file_path)
            else:
                self.send_response(429)  # Too Many Requests
                self.end_headers()

        else:
            self.send_response(405)  # Method Not Allowed
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            vkeys = get_keys(db_file_path)
            jwks_keys = []
            for key_data in vkeys:
                try:
                    # Ensure key_data is in bytes
                    if isinstance(key_data, bytes): 
                        pkey = serialization.load_pem_private_key(key_data, password=None)
                        numbers = pkey.private_numbers()
                        jwks_keys.append({
                            "alg": "RS256",
                            "kty": "RSA",
                            "use": "sig",
                            "kid": "goodKID",
                            "n": int_to_base64(numbers.public_numbers.n),
                            "e": int_to_base64(numbers.public_numbers.e),
                        })
                    else:
                        print("Key data is not in bytes:", type(key_data))
                except Exception as e:
                    print(f"Error processing key data: {e}")
            keys = {
                "keys": jwks_keys
            }
                
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Server running on {hostName}:{serverPort}...")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

