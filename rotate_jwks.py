#!/usr/bin/env python3
import os, json, base64, hashlib
from jwcrypto import jwk
from datetime import datetime
from uuid import uuid4

# Paths
REPO_DIR = os.path.abspath(os.path.dirname(__file__))
KEY_DIR  = os.path.join(REPO_DIR, "..", "jwks-keys")  # outside repo
os.makedirs(KEY_DIR, exist_ok=True)

# Generate RSA key
kid = str(uuid4())
key = jwk.JWK.generate(kty="RSA", size=2048, use="sig", alg="RS256", kid=kid)

# Export and save private key (PEM)
priv_pem = key.export_to_pem(private_key=True, password=None)
with open(os.path.join(KEY_DIR, f"private-{kid}.pem"), "wb") as f:
    f.write(priv_pem)

# Export public key (DER) for thumbprint
pub_der = key.export_to_pem(private_key=False)
der_bytes = jwk.JWK.from_pem(pub_der.encode()).export_to_der(public_only=True)

# Compute x5t (SHA-1 thumbprint, then Base64URL)
thumb = base64.urlsafe_b64encode(hashlib.sha1(der_bytes).digest()).rstrip(b"=").decode()

# Build public JWK
public_jwk = json.loads(key.export_public())

# Attach thumbprint
public_jwk["x5t"] = thumb

# Wrap into JWKS
jwks = {"keys": [public_jwk]}

# Write jwks.json
out_path = os.path.join(REPO_DIR, "jwks.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(jwks, f, indent=2)
print(f"Generated new JWKS with kid={kid}, x5t={thumb}")
