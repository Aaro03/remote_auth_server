from flask import Flask
from app.auth_routes import auth_bp
# from app.config import get_config  # Uncomment if using config.py

def create_app():
    app = Flask(__name__)

    # Load configuration if needed
    # app.config.from_object(get_config())

    # Register authentication routes under /auth
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Root route for status check
    @app.route("/")
    def index():
        return {"message": "Remote Auth Server is running!"}

    return app

