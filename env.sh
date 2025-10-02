export OIDC_CLIENT_ID=""
export OIDC_CLIENT_SECRET=""
export OIDC_ISSUER="https://keycloak.atlantishq.de/realms/master"
export FLASK_SECRET_KEY="$(python -c 'import os;print(os.urandom(16))')"
