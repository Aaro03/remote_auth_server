import os
from dotenv import load_dotenv

load_dotenv()

def get_config():
    return {
        'ENCRYPTION_KEY': os.getenv('ENCRYPTION_KEY'),
        'HMAC_KEY': os.getenv('HMAC_KEY'),
        'FLASK_ENV': os.getenv('FLASK_ENV', 'development'),
        # add other config values as needed
    }