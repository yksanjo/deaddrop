"""
NaCl-based encryption for DeadDrop messages
"""

import base64
import os
from typing import Tuple

import nacl.public
import nacl.secret
import nacl.utils


class CryptoManager:
    """
    Manages NaCl encryption for DeadDrop messages.
    
    Uses ephemeral key exchange for forward secrecy.
    """
    
    def __init__(self, private_key: bytes = None):
        """
        Initialize crypto manager with optional private key.
        
        If no key provided, generates a new one.
        """
        if private_key:
            self.private_key = nacl.public.PrivateKey(private_key)
        else:
            self.private_key = nacl.public.PrivateKey.generate()
        
        self.public_key = self.private_key.public_key
    
    @property
    def public_key_bytes(self) -> bytes:
        """Get public key bytes for sharing"""
        return bytes(self.public_key)
    
    @property
    def public_key_b64(self) -> str:
        """Get base64-encoded public key"""
        return base64.b64encode(self.public_key_bytes).decode()
    
    def encrypt_message(
        self,
        recipient_public_key: bytes,
        plaintext: bytes | str
    ) -> Tuple[str, str]:
        """
        Encrypt a message for a recipient.
        
        Args:
            recipient_public_key: Recipient's public key bytes
            plaintext: Message to encrypt (bytes or string)
            
        Returns:
            Tuple of (encrypted_payload_b64, nonce_b64)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate ephemeral key pair for this message
        ephemeral_private = nacl.public.PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key
        
        # Create shared secret with recipient
        recipient_key = nacl.public.PublicKey(recipient_public_key)
        box = nacl.public.Box(ephemeral_private, recipient_key)
        
        # Encrypt with random nonce
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        encrypted = box.encrypt(plaintext, nonce)
        
        # Prepend ephemeral public key for recipient to decrypt
        full_payload = bytes(ephemeral_public) + encrypted
        
        return (
            base64.b64encode(full_payload).decode(),
            base64.b64encode(nonce).decode()
        )
    
    def decrypt_message(
        self,
        encrypted_payload_b64: str,
        nonce_b64: str
    ) -> bytes:
        """
        Decrypt a message.
        
        Args:
            encrypted_payload_b64: Base64-encoded encrypted payload
            nonce_b64: Base64-encoded nonce
            
        Returns:
            Decrypted plaintext bytes
        """
        encrypted_payload = base64.b64decode(encrypted_payload_b64)
        nonce = base64.b64decode(nonce_b64)
        
        # Extract sender's ephemeral public key (first 32 bytes)
        ephemeral_public = nacl.public.PublicKey(encrypted_payload[:32])
        ciphertext = encrypted_payload[32:]
        
        # Decrypt using our private key and sender's ephemeral public key
        box = nacl.public.Box(self.private_key, ephemeral_public)
        plaintext = box.decrypt(ciphertext, nonce)
        
        return plaintext
    
    def decrypt_message_str(
        self,
        encrypted_payload_b64: str,
        nonce_b64: str
    ) -> str:
        """Decrypt message and return as UTF-8 string"""
        return self.decrypt_message(encrypted_payload_b64, nonce_b64).decode('utf-8')
    
    @classmethod
    def generate_keypair(cls) -> Tuple[bytes, bytes]:
        """Generate a new keypair, return (private_key, public_key)"""
        private_key = nacl.public.PrivateKey.generate()
        return (bytes(private_key), bytes(private_key.public_key))
    
    @staticmethod
    def load_private_key(key_b64: str) -> bytes:
        """Load private key from base64 string"""
        return base64.b64decode(key_b64)
    
    @staticmethod
    def save_private_key(key_bytes: bytes) -> str:
        """Save private key to base64 string"""
        return base64.b64encode(key_bytes).decode()


class SecretBoxCrypto:
    """
    Alternative symmetric encryption using SecretBox.
    Useful for encrypting to self or with pre-shared keys.
    """
    
    def __init__(self, key: bytes = None):
        """Initialize with optional key (generates new one if not provided)"""
        if key:
            self.key = key
        else:
            self.key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        
        self.box = nacl.secret.SecretBox(self.key)
    
    def encrypt(self, plaintext: bytes | str) -> Tuple[str, str]:
        """Encrypt plaintext, return (ciphertext_b64, nonce_b64)"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        encrypted = self.box.encrypt(plaintext, nonce)
        
        return (
            base64.b64encode(encrypted.ciphertext).decode(),
            base64.b64encode(nonce).decode()
        )
    
    def decrypt(self, ciphertext_b64: str, nonce_b64: str) -> bytes:
        """Decrypt ciphertext"""
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        
        return self.box.decrypt(ciphertext, nonce)
