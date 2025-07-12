import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import logging
import threading

logger = logging.getLogger(__name__)


class EdwardsCurveOperations:
    """Edwards Curve (Ed25519) cryptographic operations"""
    
    _lock = threading.Lock()
    
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Generate Ed25519 key pair.
        Returns: (private_key_bytes, public_key_bytes)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return private_bytes, public_bytes
    
    @staticmethod
    def sign_data(private_key_bytes: bytes, data: bytes) -> bytes:
        """
        Sign data using Ed25519 private key.
        
        Args:
            private_key_bytes: Raw private key bytes
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        signature = private_key.sign(data)
        return signature
    
    @staticmethod
    def verify_signature(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
        """
        Verify Ed25519 signature.
        
        Args:
            public_key_bytes: Raw public key bytes
            data: Original data that was signed
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            return False
    
    @staticmethod
    def encode_public_key(public_key_bytes: bytes) -> str:
        """
        Encode public key to base64 string for storage/transmission.
        
        Args:
            public_key_bytes: Raw public key bytes
            
        Returns:
            Base64 encoded public key string
        """
        return base64.b64encode(public_key_bytes).decode('utf-8')
    
    @staticmethod
    def decode_public_key(public_key_b64: str) -> bytes:
        """
        Decode public key from base64 string.
        
        Args:
            public_key_b64: Base64 encoded public key
            
        Returns:
            Raw public key bytes
        """
        return base64.b64decode(public_key_b64)
    
    @staticmethod
    def encode_signature(signature_bytes: bytes) -> str:
        """
        Encode signature to base64 string.
        
        Args:
            signature_bytes: Raw signature bytes
            
        Returns:
            Base64 encoded signature string
        """
        return base64.b64encode(signature_bytes).decode('utf-8')
    
    @staticmethod
    def decode_signature(signature_b64: str) -> bytes:
        """
        Decode signature from base64 string.
        
        Args:
            signature_b64: Base64 encoded signature
            
        Returns:
            Raw signature bytes
        """
        return base64.b64decode(signature_b64)
    
    @staticmethod
    def public_key_to_pem(public_key_bytes: bytes) -> str:
        """
        Convert public key bytes to PEM format.
        
        Args:
            public_key_bytes: Raw public key bytes
            
        Returns:
            PEM formatted public key string
        """
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    @staticmethod
    def pem_to_public_key(pem_string: str) -> bytes:
        """
        Convert PEM formatted public key to raw bytes.
        
        Args:
            pem_string: PEM formatted public key
            
        Returns:
            Raw public key bytes
        """
        public_key = serialization.load_pem_public_key(
            pem_string.encode('utf-8'),
            backend=default_backend()
        )
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError("Invalid Ed25519 public key")
        
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )