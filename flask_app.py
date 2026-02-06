# vulnerable_demo.py
# WARNING: intentionally insecure. Run only on localhost for testing/learning.

from flask import Flask, request, redirect, url_for, jsonify, make_response
import jwt
import time

app = Flask(__name__)

# --- Insecure: hard-coded credentials (never do this in real apps) ---
HARDCODED_USER = "admin"
HARDCODED_PASS = "Password123!"

# --- Insecure: a "secret" used incorrectly (publicly visible here) ---
INSECURE_JWT_SECRET = "not_a_secret"

# Helper: create a JWT WITHOUT any expiry check on decode (simulating broken verification)
def create_token(username):
    payload = {"sub": username, "iat": int(time.time())}
    token = jwt.encode(payload, INSECURE_JWT_SECRET, algorithm="HS256")
    return token

@app.route("/")
def index():
    return """
    <h2>Vulnerable Demo (local only)</h2>
    <p>POST /login or GET /login?user=...&pass=... (we accept both — bad)</p>
    <p>GET /transfer?to=alice&amount=100 will perform a transfer via GET (bad)</p>
    <p>GET /profile returns user info using JWT but we do a weak decode (bad)</p>
    """

# --- Insecure: Accepts GET for login and does not use CSRF tokens ---
@app.route("/login", methods=["GET", "POST"])
def login():
    # Accept credentials via GET querystring OR POST form (bad practice)
    user = request.values.get("user")
    passwd = request.values.get("pass")
    if user == HARDCODED_USER and passwd == HARDCODED_PASS:
        token = create_token(user)
        resp = make_response(f"Welcome {user}. Your token: {token}")
        # Insecure: putting token in a cookie without Secure/HttpOnly flags
        resp.set_cookie("vuln_token", token)
        return resp
    return "Invalid credentials", 401

# --- Insecure: performs state change via GET (should be POST/PUT with CSRF protection) ---
@app.route("/transfer", methods=["GET"])
def transfer():
    # vulnerable: no auth check, no CSRF protection, GET performs state change
    to = request.args.get("to")
    amount = request.args.get("amount")
    # naive: pretend to move money (just an example)
    if not to or not amount:
        return "Missing parameters", 400
    return f"Transferred {amount} to {to} (this is a simulation).", 200

# --- Insecure JWT handling: decode WITHOUT verifying signature or expiry ---
@app.route("/profile", methods=["GET"])
def profile():
    token = request.cookies.get("vuln_token") or request.headers.get("Authorization")
    if not token:
        return "No token provided", 401
    # Many broken implementations: they decode without verifying signature or expiry.
    # Here we intentionally bypass verification to show what a BAD decode looks like.
    try:
        # WARNING: options={"verify_signature": False} disables signature verification.
        payload = jwt.decode(token, options={"verify_signature": False})
        return jsonify({"profile": {"username": payload.get("sub"), "payload": payload}})
    except Exception as e:
        return f"Token error: {e}", 400

if __name__ == "__main__":
    # Run only on localhost
    app.run(host="127.0.0.1", port=5000, debug=True)
