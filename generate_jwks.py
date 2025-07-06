from jwcrypto import jwk
from uuid import uuid4
import json

# Generate a new RSA key
key = jwk.JWK.generate(kty='RSA', size=2048, use='sig', alg='RS256',
                       kid=str(uuid4()))

# Export only the public part
public_jwk = json.loads(key.export_public())

# Print out the JWKS (you can also write to jwks.json directly)
jwks = { "keys": [ public_jwk ] }
print(json.dumps(jwks, indent=2))
