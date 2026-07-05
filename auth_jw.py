import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, current_app, g

# pip install PyJWT

app = Flask(__name__)


app.config["SECRET_KEY"] = "sanan_super_secret_123"

def jwt_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({"message": "Token missing"}), 401

        try:
            token = auth_header.split(" ")[1]

            payload = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"]
            )

            # Store current user information
            g.user_id = payload["user_id"]
            g.username = payload["username"]
            g.role = payload["role"]

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401

        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        return func(*args, **kwargs)

    return wrapper

def generate_access_token(user):
    expire_time = datetime.utcnow() + timedelta(minutes=30)
    payload = {
        "user_id": user['id'],
        "username": user['username'],
        "role": user['role'],
        "exp": expire_time
    }
    print(f"token generation start for user {user}")
    token = jwt.encode(
        payload,
        current_app.config["SECRET_KEY"],
        algorithm="HS256"
    )
    print("token generated")
    return token, expire_time

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    # Validate user
    # user = User.query.filter_by(username=data["username"]).first()

    # if not user or user.password != data["password"]:
    #     return jsonify({"message": "Invalid credentials"}), 401
    user = {"id":data["id"], "username": data["username"], "role":data["role"]}
    access_token, expires_at = generate_access_token(user)
    print (f"access_token is {access_token} & expire at {expires_at}")
    #   =========== token store
    query = ("""
    INSERT INTO access_tokens (
        user_id,
        access_token,
        expires_at
    )
    VALUES (?, ?, ?)
    """, (
        user['id'],
        access_token,
        expires_at
    ))
    print(f"text query to store token is {query}")
    return jsonify({
        "access_token": access_token,
        "user": {
            "id": user['id'],
            "username": user['username'],
            "role": user['role']
        }
    }), 200


@app.route("/projects", methods=["GET"])
@jwt_required
def get_projects():

    return {
        "message": "Success",
        "user_id": g.user_id,
        "username": g.username,
        "role": g.role
    }

if __name__ == "__main__":
    app.run(debug=True)