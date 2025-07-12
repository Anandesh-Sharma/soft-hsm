import os
import uuid
import logging
from typing import Optional, Dict, Any, List, Tuple
from contextlib import contextmanager
import PyKCS11
from PyKCS11 import CKA_CLASS, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKA_KEY_TYPE, CKK_EC_EDWARDS
from PyKCS11 import CKA_LABEL, CKA_ID, CKA_TOKEN, CKA_PRIVATE, CKA_SIGN, CKA_VERIFY
from PyKCS11 import CKA_EC_PARAMS, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA
import threading

from app.config import settings
from app.hsm.exceptions import (
    HSMConnectionError, HSMAuthenticationError, HSMKeyNotFoundError,
    HSMOperationError, HSMSlotError, HSMSessionError
)
from app.hsm.crypto import EdwardsCurveOperations

logger = logging.getLogger(__name__)


class HSMManager:
    """Manager class for HSM operations using PKCS#11 interface"""
    
    def __init__(self):
        self.pkcs11 = None
        self.session = None
        self.slot = None
        self._lock = threading.Lock()
        self._session_lock = threading.Lock()
        self.crypto_ops = EdwardsCurveOperations()
        
    def initialize(self):
        """Initialize PKCS#11 library and connect to HSM"""
        try:
            # Load PKCS#11 library
            self.pkcs11 = PyKCS11.PyKCS11Lib()
            self.pkcs11.load(settings.HSM_LIBRARY_PATH)
            
            # Get available slots
            slots = self.pkcs11.getSlotList(tokenPresent=True)
            if not slots:
                raise HSMSlotError(settings.HSM_SLOT_ID)
            
            # Find the specified slot
            if settings.HSM_SLOT_ID not in slots:
                raise HSMSlotError(settings.HSM_SLOT_ID)
            
            self.slot = settings.HSM_SLOT_ID
            logger.info(f"HSM initialized successfully with slot {self.slot}")
            
        except Exception as e:
            logger.error(f"Failed to initialize HSM: {str(e)}")
            raise HSMConnectionError(f"Failed to initialize HSM: {str(e)}")
    
    @contextmanager
    def get_session(self):
        """Context manager for HSM sessions"""
        session = None
        try:
            with self._session_lock:
                # Open session
                session = self.pkcs11.openSession(self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
                
                # Login to session
                session.login(settings.HSM_PIN)
                
                yield session
                
        except PyKCS11.PyKCS11Error as e:
            if "CKR_USER_ALREADY_LOGGED_IN" in str(e):
                # Already logged in, proceed
                yield session
            else:
                logger.error(f"HSM session error: {str(e)}")
                raise HSMSessionError(f"Failed to create HSM session: {str(e)}")
        finally:
            if session:
                try:
                    session.logout()
                except:
                    pass  # Ignore logout errors
                try:
                    session.closeSession()
                except:
                    pass
    
    def generate_key_pair(self, key_id: Optional[str] = None) -> Tuple[str, str]:
        """
        Generate Ed25519 key pair in HSM.
        
        Returns:
            Tuple of (key_id, public_key_base64)
        """
        if not key_id:
            key_id = str(uuid.uuid4())
        
        key_label = f"ED25519_{key_id}"
        
        with self.get_session() as session:
            try:
                # Ed25519 OID: 1.3.101.112
                ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])
                
                # Define public key template
                public_template = [
                    (CKA_CLASS, CKO_PUBLIC_KEY),
                    (CKA_KEY_TYPE, CKK_EC_EDWARDS),
                    (CKA_LABEL, key_label + "_pub"),
                    (CKA_ID, key_id.encode()),
                    (CKA_TOKEN, True),
                    (CKA_VERIFY, True),
                    (CKA_EC_PARAMS, ed25519_oid)
                ]
                
                # Define private key template
                private_template = [
                    (CKA_CLASS, CKO_PRIVATE_KEY),
                    (CKA_KEY_TYPE, CKK_EC_EDWARDS),
                    (CKA_LABEL, key_label + "_priv"),
                    (CKA_ID, key_id.encode()),
                    (CKA_TOKEN, True),
                    (CKA_PRIVATE, True),
                    (CKA_SIGN, True)
                ]
                
                # Generate key pair
                (public_key, private_key) = session.generateKeyPair(
                    public_template, 
                    private_template,
                    mecha=PyKCS11.Mechanism(CKM_EC_EDWARDS_KEY_PAIR_GEN)
                )
                
                # Get public key value
                public_key_value = session.getAttributeValue(public_key, [PyKCS11.CKA_EC_POINT])[0]
                
                # Extract the actual public key bytes (remove DER encoding if present)
                if len(public_key_value) > 32:
                    # Skip DER encoding bytes
                    public_key_bytes = bytes(public_key_value[-32:])
                else:
                    public_key_bytes = bytes(public_key_value)
                
                # Encode public key with error handling for BoringSSL issues
                try:
                    public_key_b64 = self.crypto_ops.encode_public_key(public_key_bytes)
                except Exception as e:
                    logger.error(f"Failed to encode public key: {str(e)}")
                    # Fallback to direct base64 encoding
                    import base64
                    public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
                
                logger.info(f"Generated Ed25519 key pair with ID: {key_id}")
                return key_id, public_key_b64
                
            except PyKCS11.PyKCS11Error as e:
                logger.error(f"Failed to generate key pair: {str(e)}")
                raise HSMOperationError("generate_key_pair", str(e))
    
    def sign_data(self, key_id: str, data: bytes) -> bytes:
        """
        Sign data using Ed25519 key in HSM.
        
        Args:
            key_id: Key identifier in HSM
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        with self.get_session() as session:
            try:
                # Find private key
                template = [
                    (CKA_CLASS, CKO_PRIVATE_KEY),
                    (CKA_ID, key_id.encode())
                ]
                
                keys = session.findObjects(template)
                if not keys:
                    raise HSMKeyNotFoundError(key_id)
                
                private_key = keys[0]
                
                # Sign data using EdDSA
                mechanism = PyKCS11.Mechanism(CKM_EDDSA)
                signature = session.sign(private_key, data, mechanism)
                
                return bytes(signature)
                
            except PyKCS11.PyKCS11Error as e:
                logger.error(f"Failed to sign data: {str(e)}")
                raise HSMOperationError("sign_data", str(e))
    
    def delete_key_pair(self, key_id: str) -> bool:
        """
        Delete key pair from HSM.
        
        Args:
            key_id: Key identifier in HSM
            
        Returns:
            True if successful
        """
        with self.get_session() as session:
            try:
                # Find and delete both public and private keys
                for key_class in [CKO_PRIVATE_KEY, CKO_PUBLIC_KEY]:
                    template = [
                        (CKA_CLASS, key_class),
                        (CKA_ID, key_id.encode())
                    ]
                    
                    keys = session.findObjects(template)
                    for key in keys:
                        session.destroyObject(key)
                
                logger.info(f"Deleted key pair with ID: {key_id}")
                return True
                
            except PyKCS11.PyKCS11Error as e:
                logger.error(f"Failed to delete key pair: {str(e)}")
                raise HSMOperationError("delete_key_pair", str(e))
    
    def get_hsm_info(self) -> Dict[str, Any]:
        """Get HSM information and status"""
        try:
            info = self.pkcs11.getInfo()
            token_info = self.pkcs11.getTokenInfo(self.slot)
            
            return {
                "connected": True,
                "slot_id": self.slot,
                "token_label": token_info.label.strip(),
                "manufacturer": info.manufacturerID.strip(),
                "model": token_info.model.strip(),
                "serial_number": token_info.serialNumber.strip(),
                "library_version": f"{info.libraryVersion[0]}.{info.libraryVersion[1]}",
                "total_slots": len(self.pkcs11.getSlotList()),
                "available_slots": len(self.pkcs11.getSlotList(tokenPresent=True))
            }
        except Exception as e:
            logger.error(f"Failed to get HSM info: {str(e)}")
            return {
                "connected": False,
                "error": str(e)
            }
    
    def list_keys(self) -> List[Dict[str, str]]:
        """List all Ed25519 keys in HSM"""
        keys_info = []
        
        with self.get_session() as session:
            try:
                # Find all Ed25519 public keys
                template = [
                    (CKA_CLASS, CKO_PUBLIC_KEY),
                    (CKA_KEY_TYPE, CKK_EC_EDWARDS)
                ]
                
                keys = session.findObjects(template)
                
                for key in keys:
                    attrs = session.getAttributeValue(key, [CKA_ID, CKA_LABEL])
                    key_id = bytes(attrs[0]).decode('utf-8')
                    label = attrs[1]
                    
                    keys_info.append({
                        "key_id": key_id,
                        "label": label
                    })
                
                return keys_info
                
            except PyKCS11.PyKCS11Error as e:
                logger.error(f"Failed to list keys: {str(e)}")
                raise HSMOperationError("list_keys", str(e))


# Global HSM manager instance
# Check if we should use SoftHSM to bypass BoringSSL issues
import os
if os.getenv("USE_SOFTHSM", "false").lower() == "true":
    from app.hsm.softhsm_manager import SoftHSMManager
    hsm_manager = SoftHSMManager()
else:
    hsm_manager = HSMManager()