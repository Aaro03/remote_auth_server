from flask import Blueprint, request, jsonify
from app.token_manager import TokenManager
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__)
token_manager = TokenManager()

# In-memory user store (can be replaced with DB)
users = {}

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = data.get("user_id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({"error": "Missing user_id or password"}), 400

    if user_id in users:
        return jsonify({"error": "User already exists"}), 400

    users[user_id] = generate_password_hash(password)
    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user_id = data.get("user_id")
    password = data.get("password")

    if not user_id or not password:
        return jsonify({"error": "Missing user_id or password"}), 400

    stored_hash = users.get(user_id)
    if not stored_hash or not check_password_hash(stored_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = token_manager.create_token(user_id)
    return jsonify({"token": token}), 200

@auth_bp.route('/verify', methods=['POST'])
def verify_token():
    data = request.get_json()
    token = data.get("token")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    payload = token_manager.verify_token(token)

    if payload:
        return jsonify({"message": "Token is valid", "user_id": payload.get("user_id")})
    else:
        return jsonify({"error": "Invalid or expired token"}), 400
