#!/usr/bin/env python3
"""
DeadDrop MCP Server - Model Context Protocol integration

Exposes DeadDrop messaging capabilities as MCP tools.
"""

import asyncio
import json
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from mcp.server.fastmcp import FastMCP, Context
from deaddrop_client import DeadDropClient, CryptoManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("deaddrop.mcp")

# Environment
DEADDROP_SERVER_URL = os.getenv("DEADDROP_SERVER_URL", "http://localhost:8000")
MCP_AGENT_ID = os.getenv("MCP_AGENT_ID", "mcp-server")
MCP_API_KEY = os.getenv("MCP_API_KEY", "mcp-secret")


class DeadDropMCPServer:
    """MCP Server for DeadDrop integration"""
    
    def __init__(self):
        self.mcp = FastMCP("deaddrop")
        self.client: DeadDropClient | None = None
        self.crypto: CryptoManager | None = None
        self._setup_tools()
    
    def _setup_tools(self):
        """Register MCP tools"""
        
        @self.mcp.tool()
        async def send_message(
            to_agent: str,
            recipient_public_key: str,
            message: str,
            ctx: Context
        ) -> str:
            """
            Send an encrypted message to another agent.
            
            Args:
                to_agent: Recipient agent ID
                recipient_public_key: Base64-encoded public key
                message: Message content (will be encrypted)
            """
            if not self.client:
                return json.dumps({"error": "Server not initialized"})
            
            try:
                import base64
                recipient_key = base64.b64decode(recipient_public_key)
                
                result = await self.client.send_message(
                    to_agent=to_agent,
                    recipient_public_key=recipient_key,
                    message=message
                )
                
                return json.dumps({
                    "success": True,
                    "message_id": result.get("message_id"),
                    "status": result.get("status"),
                    "expires_at": result.get("expires_at")
                })
                
            except Exception as e:
                logger.error(f"Send error: {e}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.tool()
        async def receive_messages(
            timeout: int = 10,
            ctx: Context = None
        ) -> str:
            """
            Poll for and receive encrypted messages.
            
            Args:
                timeout: Polling timeout in seconds
            
            Returns:
                JSON array of decrypted messages
            """
            if not self.client:
                return json.dumps({"error": "Server not initialized"})
            
            try:
                messages = await self.client.poll_and_decrypt(timeout=timeout)
                
                return json.dumps({
                    "success": True,
                    "count": len(messages),
                    "messages": messages
                })
                
            except Exception as e:
                logger.error(f"Receive error: {e}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.tool()
        async def get_public_key(ctx: Context = None) -> str:
            """Get this agent's public key for sharing with others."""
            if not self.crypto:
                return json.dumps({"error": "Crypto not initialized"})
            
            return json.dumps({
                "success": True,
                "agent_id": MCP_AGENT_ID,
                "public_key": self.crypto.public_key_b64
            })
        
        @self.mcp.tool()
        async def get_mailbox_stats(ctx: Context = None) -> str:
            """Get mailbox statistics."""
            if not self.client:
                return json.dumps({"error": "Server not initialized"})
            
            try:
                stats = await self.client.get_stats()
                return json.dumps({
                    "success": True,
                    "stats": stats
                })
            except Exception as e:
                return json.dumps({"error": str(e)})
        
        @self.mcp.tool()
        async def delete_message(
            message_id: str,
            ctx: Context = None
        ) -> str:
            """
            Delete a message from the mailbox.
            
            Args:
                message_id: ID of message to delete
            """
            if not self.client:
                return json.dumps({"error": "Server not initialized"})
            
            try:
                result = await self.client.delete_message(message_id)
                return json.dumps({
                    "success": True,
                    "result": result
                })
            except Exception as e:
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("deaddrop://status")
        async def get_status() -> str:
            """Get DeadDrop connection status"""
            return json.dumps({
                "connected": self.client is not None,
                "agent_id": MCP_AGENT_ID,
                "server_url": DEADDROP_SERVER_URL
            })
        
        @self.mcp.resource("deaddrop://agent-info")
        async def get_agent_info() -> str:
            """Get agent information"""
            return json.dumps({
                "agent_id": MCP_AGENT_ID,
                "public_key": self.crypto.public_key_b64 if self.crypto else None,
                "server_url": DEADDROP_SERVER_URL
            })
    
    async def initialize(self):
        """Initialize crypto and client"""
        # Generate or load keypair
        private_key_env = os.getenv("MCP_PRIVATE_KEY")
        
        if private_key_env:
            import base64
            private_key = base64.b64decode(private_key_env)
            self.crypto = CryptoManager(private_key)
            logger.info("Loaded existing keypair")
        else:
            self.crypto = CryptoManager()
            logger.info("Generated new keypair")
            logger.info(f"Public Key: {self.crypto.public_key_b64}")
        
        # Create client
        self.client = DeadDropClient(
            server_url=DEADDROP_SERVER_URL,
            agent_id=MCP_AGENT_ID,
            crypto_manager=self.crypto,
            api_key=MCP_API_KEY
        )
        
        logger.info(f"MCP Server initialized for agent: {MCP_AGENT_ID}")
    
    async def run(self):
        """Run the MCP server"""
        await self.initialize()
        
        logger.info("Starting DeadDrop MCP Server...")
        await self.mcp.run_stdio_async()
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.client:
            await self.client.close()


async def main():
    """Main entry point"""
    server = DeadDropMCPServer()
    
    try:
        await server.run()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        await server.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
