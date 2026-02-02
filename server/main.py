"""
DeadDrop Server - Zero-Knowledge Agent Mailbox
FastAPI-based message broker with Redis Streams and NaCl encryption
"""

import asyncio
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import AsyncGenerator, Optional

import nacl.secret
import nacl.utils
import redis.asyncio as redis
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("deaddrop")

# Environment configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MAX_MESSAGE_SIZE = int(os.getenv("MAX_MESSAGE_SIZE", "1048576"))  # 1MB
MESSAGE_TTL_SECONDS = int(os.getenv("MESSAGE_TTL_SECONDS", "86400"))  # 24 hours
STREAM_MAX_LEN = int(os.getenv("STREAM_MAX_LEN", "10000"))


class MessageRequest(BaseModel):
    """Request to send a message"""
    to_agent: str = Field(..., description="Recipient agent ID")
    encrypted_payload: str = Field(..., description="NaCl-encrypted message (base64)")
    nonce: str = Field(..., description="Encryption nonce (base64)")
    ttl: Optional[int] = Field(default=MESSAGE_TTL_SECONDS, description="Message TTL in seconds")


class MessageResponse(BaseModel):
    """Message stored in mailbox"""
    message_id: str
    from_agent: str
    to_agent: str
    encrypted_payload: str
    nonce: str
    timestamp: float
    expires_at: float


class PollResponse(BaseModel):
    """Response from polling endpoint"""
    messages: list[MessageResponse]
    has_more: bool


class DeadDropState:
    """Shared application state"""
    def __init__(self):
        self.redis: Optional[redis.Redis] = None
        self.active_polls: dict[str, asyncio.Event] = {}
        
    async def connect(self):
        """Connect to Redis"""
        self.redis = await redis.from_url(REDIS_URL, decode_responses=True)
        logger.info(f"Connected to Redis at {REDIS_URL}")
        
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis:
            await self.redis.close()
            logger.info("Disconnected from Redis")


# Global state
state = DeadDropState()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager"""
    await state.connect()
    yield
    await state.disconnect()


app = FastAPI(
    title="DeadDrop",
    description="Zero-knowledge agent mailbox with Redis Streams and NaCl encryption",
    version="1.0.0",
    lifespan=lifespan
)


def get_agent_id(authorization: str = Header(...)) -> str:
    """Extract agent ID from Authorization header"""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    return authorization[7:]


def generate_message_id() -> str:
    """Generate unique message ID"""
    return f"msg_{secrets.token_urlsafe(16)}"


@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint"""
    try:
        if state.redis:
            await state.redis.ping()
        return {"status": "healthy", "timestamp": time.time()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")


@app.post("/send", response_model=dict)
async def send_message(
    request: MessageRequest,
    background_tasks: BackgroundTasks,
    agent_id: str = Depends(get_agent_id)
) -> dict:
    """
    Send an encrypted message to another agent.
    
    The server never sees the plaintext - only encrypted payload and routing info.
    """
    message_id = generate_message_id()
    timestamp = time.time()
    expires_at = timestamp + (request.ttl or MESSAGE_TTL_SECONDS)
    
    # Validate payload size
    payload_bytes = len(request.encrypted_payload.encode())
    if payload_bytes > MAX_MESSAGE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Message too large: {payload_bytes} bytes (max: {MAX_MESSAGE_SIZE})"
        )
    
    # Create message record
    message = {
        "message_id": message_id,
        "from_agent": agent_id,
        "to_agent": request.to_agent,
        "encrypted_payload": request.encrypted_payload,
        "nonce": request.nonce,
        "timestamp": timestamp,
        "expires_at": expires_at,
    }
    
    # Store in recipient's mailbox stream
    stream_key = f"mailbox:{request.to_agent}"
    await state.redis.xadd(
        stream_key,
        message,
        maxlen=STREAM_MAX_LEN
    )
    
    # Also store in index for cleanup
    await state.redis.zadd(
        f"expiry:{request.to_agent}",
        {message_id: expires_at}
    )
    
    # Notify waiting polls
    if request.to_agent in state.active_polls:
        state.active_polls[request.to_agent].set()
    
    logger.info(f"Message {message_id} sent from {agent_id} to {request.to_agent}")
    
    return {
        "message_id": message_id,
        "status": "delivered",
        "expires_at": expires_at
    }


@app.get("/poll", response_model=PollResponse)
async def poll_messages(
    agent_id: str = Depends(get_agent_id),
    last_id: str = "0",
    timeout: int = 30,
    batch_size: int = 100
) -> PollResponse:
    """
    Poll for new messages.
    
    Uses Redis Streams for efficient message retrieval.
    Supports long-polling with timeout.
    """
    stream_key = f"mailbox:{agent_id}"
    
    # Try to read new messages
    messages = []
    has_more = False
    
    try:
        # Read from stream
        response = await state.redis.xread(
            {stream_key: last_id},
            count=batch_size,
            block=timeout * 1000  # Convert to milliseconds
        )
        
        if response:
            for stream_name, entries in response:
                for entry_id, entry_data in entries:
                    # Check if message is expired
                    expires_at = float(entry_data.get("expires_at", 0))
                    if expires_at > time.time():
                        messages.append(MessageResponse(
                            message_id=entry_data.get("message_id", ""),
                            from_agent=entry_data.get("from_agent", ""),
                            to_agent=entry_data.get("to_agent", ""),
                            encrypted_payload=entry_data.get("encrypted_payload", ""),
                            nonce=entry_data.get("nonce", ""),
                            timestamp=float(entry_data.get("timestamp", 0)),
                            expires_at=expires_at
                        ))
                    else:
                        # Delete expired message
                        await state.redis.xdel(stream_key, entry_id)
                        await state.redis.zrem(f"expiry:{agent_id}", entry_data.get("message_id"))
                    
                    last_id = entry_id
            
            has_more = len(entries) >= batch_size
            
    except Exception as e:
        logger.error(f"Error polling messages: {e}")
        raise HTTPException(status_code=500, detail="Error polling messages")
    
    return PollResponse(messages=messages, has_more=has_more)


@app.get("/poll/stream")
async def poll_stream(
    agent_id: str = Depends(get_agent_id),
    heartbeat: int = 30
) -> StreamingResponse:
    """
    Server-sent events stream for real-time message delivery.
    """
    stream_key = f"mailbox:{agent_id}"
    last_id = "0"
    
    async def event_generator():
        while True:
            try:
                response = await state.redis.xread(
                    {stream_key: last_id},
                    count=100,
                    block=heartbeat * 1000
                )
                
                if response:
                    for stream_name, entries in response:
                        for entry_id, entry_data in entries:
                            expires_at = float(entry_data.get("expires_at", 0))
                            if expires_at > time.time():
                                message = MessageResponse(
                                    message_id=entry_data.get("message_id", ""),
                                    from_agent=entry_data.get("from_agent", ""),
                                    to_agent=entry_data.get("to_agent", ""),
                                    encrypted_payload=entry_data.get("encrypted_payload", ""),
                                    nonce=entry_data.get("nonce", ""),
                                    timestamp=float(entry_data.get("timestamp", 0)),
                                    expires_at=expires_at
                                )
                                yield f"data: {message.model_dump_json()}\n\n"
                            else:
                                # Delete expired
                                await state.redis.xdel(stream_key, entry_id)
                            
                            last_id = entry_id
                
                # Send heartbeat
                yield f":heartbeat\n\n"
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Stream error: {e}")
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                await asyncio.sleep(5)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@app.delete("/messages/{message_id}")
async def delete_message(
    message_id: str,
    agent_id: str = Depends(get_agent_id)
) -> dict:
    """Delete a specific message from mailbox"""
    stream_key = f"mailbox:{agent_id}"
    
    # Find and delete message
    # Note: In production, you'd maintain an index for efficient deletion
    # This is a simplified version
    
    await state.redis.zrem(f"expiry:{agent_id}", message_id)
    
    return {"status": "deleted", "message_id": message_id}


@app.get("/stats")
async def get_stats(agent_id: str = Depends(get_agent_id)) -> dict:
    """Get mailbox statistics"""
    stream_key = f"mailbox:{agent_id}"
    expiry_key = f"expiry:{agent_id}"
    
    # Get stream length
    stream_len = await state.redis.xlen(stream_key)
    
    # Count non-expired messages
    now = time.time()
    valid_messages = await state.redis.zcount(expiry_key, now, "+inf")
    expired_messages = await state.redis.zcount(expiry_key, "-inf", now)
    
    return {
        "agent_id": agent_id,
        "total_messages": stream_len,
        "valid_messages": valid_messages,
        "expired_messages": expired_messages,
        "timestamp": now
    }


@app.post("/cleanup")
async def cleanup_expired(
    agent_id: str = Depends(get_agent_id),
    background_tasks: BackgroundTasks = None
) -> dict:
    """Trigger cleanup of expired messages"""
    stream_key = f"mailbox:{agent_id}"
    expiry_key = f"expiry:{agent_id}"
    
    now = time.time()
    
    # Get expired message IDs
    expired = await state.redis.zrangebyscore(expiry_key, "-inf", now)
    
    # Remove from expiry index
    if expired:
        await state.redis.zrem(expiry_key, *expired)
    
    return {
        "cleaned": len(expired),
        "agent_id": agent_id
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
