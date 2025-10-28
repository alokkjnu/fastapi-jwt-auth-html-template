# gen_keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
pub = priv.public_key()
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("private.pem", "wb") as f:
    f.write(priv_pem)
with open("public.pem", "wb") as f:
    f.write(pub_pem)

print("Generated private.pem and public.pem")
