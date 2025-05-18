from flask import Flask
from app.auth_routes import auth_bp
from app.config import get_config  # Make sure this imports your config with decoded keys

def create_app():
    app = Flask(__name__)

    # Load configuration (including keys from environment)
    app.config.update(get_config())

    # Register authentication routes under /auth
    app.register_blueprint(auth_bp, url_prefix='/auth')

    @app.route("/")
    def index():
        return {"message": "Remote Auth Server is running!"}

    return app
