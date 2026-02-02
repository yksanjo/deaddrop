"""
DeadDrop Client SDK - Zero-knowledge agent mailbox client
"""

from .client import DeadDropClient
from .crypto import CryptoManager

__version__ = "1.0.0"
__all__ = ["DeadDropClient", "CryptoManager"]
