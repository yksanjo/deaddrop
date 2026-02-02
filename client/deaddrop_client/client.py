"""
DeadDrop HTTP Client - Async client for the DeadDrop server
"""

import asyncio
import json
import logging
from typing import AsyncIterator, Callable, Optional

import httpx
from .crypto import CryptoManager

logger = logging.getLogger("deaddrop.client")


class DeadDropClient:
    """
    Async client for DeadDrop mailbox server.
    
    Handles encryption, HTTP polling, and message delivery.
    """
    
    def __init__(
        self,
        server_url: str,
        agent_id: str,
        crypto_manager: CryptoManager,
        api_key: Optional[str] = None,
        poll_interval: float = 5.0,
        timeout: float = 30.0
    ):
        """
        Initialize DeadDrop client.
        
        Args:
            server_url: DeadDrop server URL (e.g., "http://localhost:8000")
            agent_id: Unique agent identifier
            crypto_manager: CryptoManager instance for encryption
            api_key: Optional API key for authentication
            poll_interval: Seconds between poll requests
            timeout: HTTP request timeout
        """
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id
        self.crypto = crypto_manager
        self.api_key = api_key or agent_id  # Fallback to agent_id
        self.poll_interval = poll_interval
        self.timeout = timeout
        
        self._client: Optional[httpx.AsyncClient] = None
        self._running = False
        self._message_handlers: list[Callable] = []
        self._last_poll_id = "0"
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
            )
        return self._client
    
    async def close(self):
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def send_message(
        self,
        to_agent: str,
        recipient_public_key: bytes,
        message: str | dict | bytes
    ) -> dict:
        """
        Send encrypted message to another agent.
        
        Args:
            to_agent: Recipient agent ID
            recipient_public_key: Recipient's public key bytes
            message: Message to send (string, dict, or bytes)
            
        Returns:
            Server response with message_id
        """
        client = await self._get_client()
        
        # Serialize message if needed
        if isinstance(message, dict):
            message = json.dumps(message)
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Encrypt
        encrypted_payload, nonce = self.crypto.encrypt_message(
            recipient_public_key,
            message
        )
        
        # Send to server
        response = await client.post(
            f"{self.server_url}/send",
            json={
                "to_agent": to_agent,
                "encrypted_payload": encrypted_payload,
                "nonce": nonce
            }
        )
        response.raise_for_status()
        
        return response.json()
    
    async def poll_messages(
        self,
        last_id: str = "0",
        timeout: int = 30
    ) -> list[dict]:
        """
        Poll for new messages.
        
        Args:
            last_id: Last message ID received
            timeout: Long-polling timeout in seconds
            
        Returns:
            List of encrypted messages
        """
        client = await self._get_client()
        
        response = await client.get(
            f"{self.server_url}/poll",
            params={
                "last_id": last_id,
                "timeout": timeout
            }
        )
        response.raise_for_status()
        
        data = response.json()
        return data.get("messages", [])
    
    async def poll_and_decrypt(
        self,
        last_id: str = "0",
        timeout: int = 30
    ) -> list[dict]:
        """
        Poll for messages and automatically decrypt them.
        
        Returns:
            List of decrypted messages with original metadata
        """
        encrypted_messages = await self.poll_messages(last_id, timeout)
        
        decrypted = []
        for msg in encrypted_messages:
            try:
                plaintext = self.crypto.decrypt_message_str(
                    msg["encrypted_payload"],
                    msg["nonce"]
                )
                
                # Try to parse as JSON
                try:
                    content = json.loads(plaintext)
                except json.JSONDecodeError:
                    content = plaintext
                
                decrypted.append({
                    "message_id": msg["message_id"],
                    "from_agent": msg["from_agent"],
                    "to_agent": msg["to_agent"],
                    "content": content,
                    "timestamp": msg["timestamp"],
                    "expires_at": msg["expires_at"]
                })
            except Exception as e:
                logger.error(f"Failed to decrypt message {msg.get('message_id')}: {e}")
                # Include encrypted version if decryption fails
                decrypted.append({
                    "message_id": msg["message_id"],
                    "from_agent": msg["from_agent"],
                    "error": str(e),
                    "encrypted": True
                })
        
        return decrypted
    
    async def stream_messages(self) -> AsyncIterator[dict]:
        """
        Stream messages using Server-Sent Events.
        
        Yields decrypted messages as they arrive.
        """
        client = await self._get_client()
        
        async with client.stream(
            "GET",
            f"{self.server_url}/poll/stream"
        ) as response:
            response.raise_for_status()
            
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data = line[6:]
                    if data == "":
                        continue
                    
                    try:
                        msg = json.loads(data)
                        
                        # Decrypt
                        try:
                            plaintext = self.crypto.decrypt_message_str(
                                msg["encrypted_payload"],
                                msg["nonce"]
                            )
                            
                            # Try JSON parse
                            try:
                                content = json.loads(plaintext)
                            except json.JSONDecodeError:
                                content = plaintext
                            
                            yield {
                                "message_id": msg["message_id"],
                                "from_agent": msg["from_agent"],
                                "content": content,
                                "timestamp": msg["timestamp"]
                            }
                        except Exception as e:
                            logger.error(f"Stream decrypt error: {e}")
                            
                    except json.JSONDecodeError:
                        continue
    
    def on_message(self, handler: Callable):
        """Register a message handler callback"""
        self._message_handlers.append(handler)
        return handler
    
    async def start_polling(self):
        """Start background polling loop"""
        self._running = True
        logger.info(f"Starting polling loop for agent {self.agent_id}")
        
        while self._running:
            try:
                messages = await self.poll_and_decrypt(
                    last_id=self._last_poll_id,
                    timeout=30
                )
                
                for msg in messages:
                    self._last_poll_id = msg.get("message_id", self._last_poll_id)
                    
                    # Notify handlers
                    for handler in self._message_handlers:
                        try:
                            if asyncio.iscoroutinefunction(handler):
                                await handler(msg)
                            else:
                                handler(msg)
                        except Exception as e:
                            logger.error(f"Handler error: {e}")
                
                # Short delay if no messages
                if not messages:
                    await asyncio.sleep(self.poll_interval)
                    
            except Exception as e:
                logger.error(f"Polling error: {e}")
                await asyncio.sleep(self.poll_interval)
    
    def stop_polling(self):
        """Stop background polling"""
        self._running = False
    
    async def get_stats(self) -> dict:
        """Get mailbox statistics"""
        client = await self._get_client()
        response = await client.get(f"{self.server_url}/stats")
        response.raise_for_status()
        return response.json()
    
    async def delete_message(self, message_id: str) -> dict:
        """Delete a message"""
        client = await self._get_client()
        response = await client.delete(f"{self.server_url}/messages/{message_id}")
        response.raise_for_status()
        return response.json()
    
    async def cleanup(self) -> dict:
        """Trigger cleanup of expired messages"""
        client = await self._get_client()
        response = await client.post(f"{self.server_url}/cleanup")
        response.raise_for_status()
        return response.json()
