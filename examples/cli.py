#!/usr/bin/env python3
"""
DeadDrop CLI - Command-line interface for the mailbox
"""

import argparse
import asyncio
import base64
import json
import os
import sys
from pathlib import Path

# Add client to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from deaddrop_client import DeadDropClient, CryptoManager


CONFIG_DIR = Path.home() / ".deaddrop"
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    """Load CLI configuration"""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(config):
    """Save CLI configuration"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def init_agent(agent_id: str, server_url: str):
    """Initialize a new agent with keypair"""
    config = load_config()
    
    if agent_id in config:
        print(f"Agent {agent_id} already exists!")
        return
    
    # Generate keypair
    crypto = CryptoManager()
    
    config[agent_id] = {
        "server_url": server_url,
        "private_key": CryptoManager.save_private_key(crypto.private_key.encode()),
        "public_key": crypto.public_key_b64,
        "api_key": agent_id  # Default to agent_id
    }
    
    save_config(config)
    
    print(f"✅ Agent '{agent_id}' initialized!")
    print(f"   Server: {server_url}")
    print(f"   Public Key: {crypto.public_key_b64}")
    print(f"\nShare your public key with other agents to receive messages.")


def get_client(agent_id: str) -> tuple[DeadDropClient, CryptoManager]:
    """Get client for an agent"""
    config = load_config()
    
    if agent_id not in config:
        print(f"Agent '{agent_id}' not found. Run 'init' first.")
        sys.exit(1)
    
    agent_config = config[agent_id]
    
    # Load crypto
    private_key = CryptoManager.load_private_key(agent_config["private_key"])
    crypto = CryptoManager(private_key)
    
    # Create client
    client = DeadDropClient(
        server_url=agent_config["server_url"],
        agent_id=agent_id,
        crypto_manager=crypto,
        api_key=agent_config.get("api_key", agent_id)
    )
    
    return client, crypto


async def send_message(agent_id: str, to_agent: str, recipient_key: str, message: str):
    """Send a message"""
    client, crypto = get_client(agent_id)
    
    try:
        # Load recipient public key
        recipient_key_bytes = base64.b64decode(recipient_key)
        
        result = await client.send_message(
            to_agent=to_agent,
            recipient_public_key=recipient_key_bytes,
            message=message
        )
        
        print(f"✅ Message sent!")
        print(f"   Message ID: {result.get('message_id')}")
        print(f"   Expires: {result.get('expires_at')}")
        
    finally:
        await client.close()


async def receive_messages(agent_id: str, stream: bool = False):
    """Receive messages"""
    client, crypto = get_client(agent_id)
    
    try:
        if stream:
            print("🔌 Streaming messages (Ctrl+C to stop)...")
            async for msg in client.stream_messages():
                print(f"\n📨 From: {msg['from_agent']}")
                print(f"   Content: {msg['content']}")
                print(f"   Time: {msg['timestamp']}")
                print("-" * 40)
        else:
            print("📬 Polling for messages...")
            messages = await client.poll_and_decrypt(timeout=10)
            
            if not messages:
                print("No new messages.")
                return
            
            print(f"\n📨 Received {len(messages)} message(s):\n")
            
            for msg in messages:
                if "error" in msg:
                    print(f"❌ Failed to decrypt message {msg['message_id']}: {msg['error']}")
                else:
                    print(f"From: {msg['from_agent']}")
                    print(f"Content: {msg['content']}")
                    print(f"Time: {msg['timestamp']}")
                    print("-" * 40)
                    
    except KeyboardInterrupt:
        print("\n👋 Stopping...")
    finally:
        await client.close()


async def show_stats(agent_id: str):
    """Show mailbox stats"""
    client, _ = get_client(agent_id)
    
    try:
        stats = await client.get_stats()
        print(f"📊 Mailbox Stats for {agent_id}:")
        print(f"   Total messages: {stats.get('total_messages', 0)}")
        print(f"   Valid messages: {stats.get('valid_messages', 0)}")
        print(f"   Expired messages: {stats.get('expired_messages', 0)}")
    finally:
        await client.close()


def show_public_key(agent_id: str):
    """Display agent's public key"""
    config = load_config()
    
    if agent_id not in config:
        print(f"Agent '{agent_id}' not found.")
        return
    
    print(f"🔑 Public Key for {agent_id}:")
    print(config[agent_id]["public_key"])
    print("\nShare this with other agents to receive messages.")


def list_agents():
    """List all configured agents"""
    config = load_config()
    
    if not config:
        print("No agents configured. Run 'init' first.")
        return
    
    print("📋 Configured agents:")
    for agent_id, agent_config in config.items():
        print(f"   {agent_id} -> {agent_config.get('server_url', 'unknown')}")


async def main():
    parser = argparse.ArgumentParser(description="DeadDrop CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # init command
    init_parser = subparsers.add_parser("init", help="Initialize new agent")
    init_parser.add_argument("agent_id", help="Unique agent identifier")
    init_parser.add_argument("--server", default="http://localhost:8000", help="Server URL")
    
    # send command
    send_parser = subparsers.add_parser("send", help="Send a message")
    send_parser.add_argument("agent_id", help="Your agent ID")
    send_parser.add_argument("to", help="Recipient agent ID")
    send_parser.add_argument("recipient_key", help="Recipient public key (base64)")
    send_parser.add_argument("message", help="Message to send")
    
    # receive command
    recv_parser = subparsers.add_parser("receive", help="Receive messages")
    recv_parser.add_argument("agent_id", help="Your agent ID")
    recv_parser.add_argument("--stream", action="store_true", help="Stream messages")
    
    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show mailbox stats")
    stats_parser.add_argument("agent_id", help="Your agent ID")
    
    # key command
    key_parser = subparsers.add_parser("key", help="Show public key")
    key_parser.add_argument("agent_id", help="Your agent ID")
    
    # list command
    subparsers.add_parser("list", help="List configured agents")
    
    args = parser.parse_args()
    
    if args.command == "init":
        init_agent(args.agent_id, args.server)
    
    elif args.command == "send":
        asyncio.run(send_message(args.agent_id, args.to, args.recipient_key, args.message))
    
    elif args.command == "receive":
        asyncio.run(receive_messages(args.agent_id, args.stream))
    
    elif args.command == "stats":
        asyncio.run(show_stats(args.agent_id))
    
    elif args.command == "key":
        show_public_key(args.agent_id)
    
    elif args.command == "list":
        list_agents()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
