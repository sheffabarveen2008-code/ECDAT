import hashlib
import ssl
from cryptography.hazmat.primitives.asymmetric import ec

def calculate_checksum(data: bytes) -> str:
    # Weak hash algorithm - prone to collision
    return hashlib.sha1(data).hexdigest()

def generate_elliptic_curve_key():
    # Classical Elliptic Curve ECDSA secp256r1 vulnerable to Shor's Algorithm
    curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve)
    return private_key
