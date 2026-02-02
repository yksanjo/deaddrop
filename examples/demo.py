#!/usr/bin/env python3
"""
DeadDrop Demo - Two agents exchanging messages
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'client'))

from deaddrop_client import DeadDropClient, CryptoManager


async def demo():
    """Demonstrate DeadDrop messaging between two agents"""
    
    print("🦞 DeadDrop Demo - Zero-Knowledge Agent Mailbox")
    print("=" * 60)
    
    # Create two agents with their own keypairs
    print("\n1️⃣ Creating two agents...")
    
    alice_crypto = CryptoManager()
    bob_crypto = CryptoManager()
    
    alice_id = "alice-agent"
    bob_id = "bob-agent"
    
    print(f"   Alice: {alice_id}")
    print(f"   Bob: {bob_id}")
    
    # Create clients
    server_url = "http://localhost:8000"
    
    alice = DeadDropClient(
        server_url=server_url,
        agent_id=alice_id,
        crypto_manager=alice_crypto
    )
    
    bob = DeadDropClient(
        server_url=server_url,
        agent_id=bob_id,
        crypto_manager=bob_crypto
    )
    
    print(f"   Server: {server_url}")
    
    try:
        # Alice sends message to Bob
        print("\n2️⃣ Alice sends encrypted message to Bob...")
        
        message = {
            "type": "hello",
            "content": "Hey Bob! This is a secret message.",
            "timestamp": asyncio.get_event_loop().time()
        }
        
        result = await alice.send_message(
            to_agent=bob_id,
            recipient_public_key=bob_crypto.public_key_bytes,
            message=message
        )
        
        print(f"   ✅ Sent! Message ID: {result['message_id']}")
        
        # Bob receives message
        print("\n3️⃣ Bob polls for messages...")
        
        messages = await bob.poll_and_decrypt(timeout=5)
        
        if messages:
            for msg in messages:
                print(f"   📨 From: {msg['from_agent']}")
                print(f"   Content: {msg['content']}")
                print(f"   Decrypted successfully! ✅")
        else:
            print("   No messages received")
        
        # Bob replies
        print("\n4️⃣ Bob replies to Alice...")
        
        reply = {
            "type": "reply",
            "content": "Hi Alice! Got your secret message. Here's my reply.",
            "original_id": result['message_id']
        }
        
        await bob.send_message(
            to_agent=alice_id,
            recipient_public_key=alice_crypto.public_key_bytes,
            message=reply
        )
        
        print(f"   ✅ Reply sent!")
        
        # Alice receives reply
        print("\n5️⃣ Alice receives Bob's reply...")
        
        alice_messages = await alice.poll_and_decrypt(timeout=5)
        
        if alice_messages:
            for msg in alice_messages:
                print(f"   📨 From: {msg['from_agent']}")
                print(f"   Content: {msg['content']}")
        
        # Show stats
        print("\n6️⃣ Checking mailbox stats...")
        
        alice_stats = await alice.get_stats()
        bob_stats = await bob.get_stats()
        
        print(f"   Alice mailbox: {alice_stats.get('total_messages', 0)} messages")
        print(f"   Bob mailbox: {bob_stats.get('total_messages', 0)} messages")
        
        print("\n" + "=" * 60)
        print("✅ Demo complete! Zero-knowledge messaging works!")
        print("\nKey points:")
        print("• Server never sees plaintext")
        print("• Ephemeral keys for forward secrecy")
        print("• Redis Streams for reliable delivery")
        print("• Automatic encryption/decryption")
        
    finally:
        await alice.close()
        await bob.close()


if __name__ == "__main__":
    try:
        asyncio.run(demo())
    except KeyboardInterrupt:
        print("\n\n👋 Demo interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
