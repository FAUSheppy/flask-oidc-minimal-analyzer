# app.py
import sys
import json
import os
import tempfile
import requests
from flask import Flask, jsonify, redirect, url_for
from flask_oidc import OpenIDConnect

"""
Required env vars:
  OIDC_CLIENT_ID      -> your OAuth/OIDC client_id
  OIDC_CLIENT_SECRET  -> your OAuth/OIDC client_secret
  OIDC_ISSUER         -> your IdP Issuer URL (e.g., https://example.com/realms/myrealm)
"""

CLIENT_ID = os.environ.get("OIDC_CLIENT_ID")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET")
ISSUER = os.environ.get("OIDC_ISSUER")

if not all([CLIENT_ID, CLIENT_SECRET, ISSUER]):
    raise SystemExit("Set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER in the environment.")

disco_url = ISSUER.rstrip("/") + "/.well-known/openid-configuration"
resp = requests.get(disco_url, timeout=10)
resp.raise_for_status()
disco = resp.json()

AUTH_URI = disco["authorization_endpoint"]
TOKEN_URI = disco["token_endpoint"]
USERINFO_URI = disco.get("userinfo_endpoint") 

client_secrets_payload = {
    "web": {
        "issuer": ISSUER,
        "auth_uri": AUTH_URI,
        "token_uri": TOKEN_URI,
        "userinfo_uri": USERINFO_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uris": ["http://localhost:5000/oidc_callback"],
        "token_introspection_uri": disco.get("introspection_endpoint"),
        "jwks_uri": disco.get("jwks_uri"),
    }
}

tmp = tempfile.NamedTemporaryFile(prefix="client_secrets_", suffix=".json", delete=False)
with open(tmp.name, "w") as f:
    json.dump(client_secrets_payload, f)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", os.urandom(16)),
    OIDC_CLIENT_SECRETS=tmp.name,
    OIDC_SCOPES=["openid", "profile", "email"],
    OIDC_INTROSPECTION_AUTH_METHOD="client_secret_post",
    OIDC_ID_TOKEN_COOKIE_SECURE=False,   # set True when serving over HTTPS
)

oidc = OpenIDConnect(app)


@app.route("/")
def index():
    if oidc.user_loggedin:
        return redirect(url_for("me"))
    return jsonify({"status": "ok", "login": url_for("login", _external=True)})


@app.route("/login")
@oidc.require_login
def login():
    return redirect(url_for("me"))


@app.route("/me")
@oidc.require_login
def me():

    access_token = oidc.get_access_token()
    try:
        id_token = oidc.get_id_token()
    except AttributeError as e:
        id_token = None
        print("id-token not exposed, going directly to userinfo", file=sys.stderr)

    basic_info = oidc.user_getinfo(["sub", "email", "email_verified", "name", "preferred_username"])

    userinfo = {}
    if USERINFO_URI and access_token:
        r = requests.get(
            USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )

        if r.ok:
            userinfo = r.json()

    return jsonify(
        {
            "tokens": {
                "access_token": access_token,
                "id_token": id_token,
                "token_type": "Bearer",
            },
            "userinfo_basic": basic_info,
            "userinfo_full": userinfo,
        }
    )


@app.route("/logout")
def logout():
    oidc.logout()
    return jsonify({"status": "logged_out"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
