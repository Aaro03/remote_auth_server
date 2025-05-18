import base64
import hashlib
import hmac
import json
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from dotenv import load_dotenv

load_dotenv()

# Read encryption and HMAC keys from environment variables and decode from base64
ENCRYPTION_KEY = base64.b64decode(os.getenv("ENCRYPTION_KEY"))
HMAC_KEY = base64.b64decode(os.getenv("HMAC_KEY"))

class TokenManager:
    """
    Manages authentication tokens with encryption, decryption, and verification.
    Uses AES-256 for encryption and HMAC for integrity verification.
    """
    
    def __init__(self, encryption_key=ENCRYPTION_KEY, hmac_key=HMAC_KEY):
        """
        Initialize with encryption and HMAC keys.
        
        Args:
            encryption_key (bytes): Key for AES-256 encryption (32 bytes)
            hmac_key (bytes): Key for HMAC verification (32 bytes)
        """
        self.encryption_key = encryption_key
        self.hmac_key = hmac_key
    
    def create_token(self, user_id, expiration_hours=24):
        """
        Create an encrypted and signed token with expiration time.
        
        Args:
            user_id (str): User identifier
            expiration_hours (int): Hours until token expires
            
        Returns:
            str: Base64 encoded encrypted token
        """
        expiration = int(time.time()) + (expiration_hours * 3600)
        token_id = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        payload = {
            'user_id': user_id,
            'exp': expiration,
            'token_id': token_id
        }
        
        payload_str = json.dumps(payload)
        
        iv = os.urandom(16)
        
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        encrypted_payload = cipher.encrypt(pad(payload_str.encode('utf-8'), AES.block_size))
        
        data = iv + encrypted_payload
        
        signature = hmac.new(self.hmac_key, data, hashlib.sha256).digest()
        
        token = base64.b64encode(data + signature).decode('utf-8')
        
        return token
    
    def verify_token(self, token):
        """
        Verify token integrity and expiration.
        
        Args:
            token (str): Base64 encoded token
            
        Returns:
            dict or None: Token payload if valid, None otherwise
        """
        try:
            binary_token = base64.b64decode(token)
            
            iv = binary_token[:16]
            hmac_signature = binary_token[-32:]
            encrypted_payload = binary_token[16:-32]
            
            expected_hmac = hmac.new(self.hmac_key, iv + encrypted_payload, hashlib.sha256).digest()
            if not hmac.compare_digest(hmac_signature, expected_hmac):
                print("HMAC verification failed")
                return None
            
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            decrypted_payload = unpad(cipher.decrypt(encrypted_payload), AES.block_size)
            
            payload = json.loads(decrypted_payload.decode('utf-8'))
            
            if payload['exp'] < time.time():
                print("Token expired")
                return None
            
            return payload
            
        except Exception as e:
            print(f"Token verification error: {e}")
            return None
