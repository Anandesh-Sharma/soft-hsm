"""
Alternative HSM Manager using SoftHSM without problematic digest operations
"""
import os
import uuid
import logging
import base64
import json
from typing import Optional, Dict, Any, List, Tuple
from contextlib import contextmanager
import threading

from app.config import settings
from app.hsm.exceptions import (
    HSMConnectionError, HSMAuthenticationError, HSMKeyNotFoundError,
    HSMOperationError, HSMSlotError, HSMSessionError
)

logger = logging.getLogger(__name__)


class SoftHSMManager:
    """Alternative HSM manager that bypasses BoringSSL issues"""
    
    def __init__(self):
        self.keys = {}  # In-memory key storage for testing
        self._lock = threading.Lock()
        self.initialized = False
        self.keys_file = os.path.join(os.getcwd(), 'softhsm_keys.json')
        self._load_keys()
    
    def _load_keys(self):
        """Load keys from persistent storage"""
        try:
            if os.path.exists(self.keys_file):
                with open(self.keys_file, 'r') as f:
                    stored_keys = json.load(f)
                    # Convert base64 strings back to bytes
                    for key_id, key_data in stored_keys.items():
                        self.keys[key_id] = {
                            'private': base64.b64decode(key_data['private']),
                            'public': base64.b64decode(key_data['public'])
                        }
                    logger.info(f"Loaded {len(self.keys)} keys from persistent storage")
        except Exception as e:
            logger.warning(f"Failed to load keys from storage: {str(e)}")
            self.keys = {}
    
    def _save_keys(self):
        """Save keys to persistent storage"""
        try:
            # Convert bytes to base64 strings for JSON serialization
            serializable_keys = {}
            for key_id, key_data in self.keys.items():
                serializable_keys[key_id] = {
                    'private': base64.b64encode(key_data['private']).decode('utf-8'),
                    'public': base64.b64encode(key_data['public']).decode('utf-8')
                }
            
            with open(self.keys_file, 'w') as f:
                json.dump(serializable_keys, f, indent=2)
            
            logger.debug(f"Saved {len(self.keys)} keys to persistent storage")
        except Exception as e:
            logger.error(f"Failed to save keys to storage: {str(e)}")
        
    def initialize(self):
        """Initialize soft HSM"""
        try:
            logger.info("Initializing SoftHSM manager (BoringSSL bypass mode)")
            self.initialized = True
            logger.info("SoftHSM manager initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SoftHSM: {str(e)}")
            raise HSMConnectionError(f"Failed to initialize SoftHSM: {str(e)}")
    
    def generate_key_pair(self, key_id: Optional[str] = None) -> Tuple[str, str]:
        """
        Generate Ed25519 key pair in software.
        
        Returns:
            Tuple of (key_id, public_key_base64)
        """
        if not key_id:
            key_id = str(uuid.uuid4())
        
        with self._lock:
            try:
                # Use pure Python Ed25519 implementation
                from cryptography.hazmat.primitives.asymmetric import ed25519
                
                # Generate key pair
                private_key = ed25519.Ed25519PrivateKey.generate()
                public_key = private_key.public_key()
                
                # Get raw bytes
                public_bytes = public_key.public_bytes_raw()
                private_bytes = private_key.private_bytes_raw()
                
                # Store in memory
                self.keys[key_id] = {
                    'private': private_bytes,
                    'public': public_bytes
                }
                
                # Save to persistent storage
                self._save_keys()
                
                # Encode public key
                public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
                
                logger.info(f"Generated Ed25519 key pair with ID: {key_id} (SoftHSM)")
                return key_id, public_key_b64
                
            except Exception as e:
                logger.error(f"Failed to generate key pair: {str(e)}")
                raise HSMOperationError("generate_key_pair", str(e))
    
    def sign_data(self, key_id: str, data: bytes) -> bytes:
        """
        Sign data using Ed25519 key.
        
        Args:
            key_id: Key identifier
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        with self._lock:
            try:
                if key_id not in self.keys:
                    raise HSMKeyNotFoundError(key_id)
                
                from cryptography.hazmat.primitives.asymmetric import ed25519
                
                # Get private key
                private_bytes = self.keys[key_id]['private']
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
                
                # Sign data
                signature = private_key.sign(data)
                
                return signature
                
            except Exception as e:
                logger.error(f"Failed to sign data: {str(e)}")
                raise HSMOperationError("sign_data", str(e))
    
    def delete_key_pair(self, key_id: str) -> bool:
        """
        Delete key pair from memory.
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if successful
        """
        with self._lock:
            try:
                if key_id in self.keys:
                    del self.keys[key_id]
                    self._save_keys()
                    logger.info(f"Deleted key pair with ID: {key_id} (SoftHSM)")
                    return True
                else:
                    raise HSMKeyNotFoundError(key_id)
                
            except Exception as e:
                logger.error(f"Failed to delete key pair: {str(e)}")
                raise HSMOperationError("delete_key_pair", str(e))
    
    def get_hsm_info(self) -> Dict[str, Any]:
        """Get HSM information and status"""
        return {
            "connected": self.initialized,
            "type": "SoftHSM (BoringSSL bypass)",
            "key_count": len(self.keys),
            "note": "Running in software mode due to BoringSSL issues"
        }
    
    def list_keys(self) -> List[Dict[str, str]]:
        """List all keys in memory"""
        with self._lock:
            return [
                {
                    "key_id": key_id,
                    "label": f"ED25519_{key_id}"
                }
                for key_id in self.keys.keys()
            ]


# Create a wrapper that can switch between implementations
class HSMManagerWrapper:
    """Wrapper that can switch between PyKCS11 and SoftHSM implementations"""
    
    def __init__(self):
        self.use_softhsm = os.getenv("USE_SOFTHSM", "false").lower() == "true"
        self.manager = None
        
    def initialize(self):
        """Initialize appropriate HSM manager"""
        if self.use_softhsm:
            from app.hsm.softhsm_manager import SoftHSMManager
            self.manager = SoftHSMManager()
        else:
            try:
                from app.hsm.manager import HSMManager
                self.manager = HSMManager()
            except Exception as e:
                logger.warning(f"Failed to initialize PyKCS11, falling back to SoftHSM: {str(e)}")
                from app.hsm.softhsm_manager import SoftHSMManager
                self.manager = SoftHSMManager()
        
        self.manager.initialize()
    
    def __getattr__(self, name):
        """Proxy all calls to the underlying manager"""
        if self.manager is None:
            raise RuntimeError("HSM manager not initialized")
        return getattr(self.manager, name)