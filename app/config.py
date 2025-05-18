import os
import base64
from dotenv import load_dotenv

load_dotenv()

def get_config():
    return {
        'ENCRYPTION_KEY': base64.b64decode(os.getenv('ENCRYPTION_KEY')),
        'HMAC_KEY': base64.b64decode(os.getenv('HMAC_KEY')),
        'FLASK_ENV': os.getenv('FLASK_ENV', 'development'),
        # add other config values as needed
    }
