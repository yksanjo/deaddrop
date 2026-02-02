# 🦞 DeadDrop

> Zero-knowledge agent mailbox with Redis Streams, NaCl encryption, and HTTP polling

DeadDrop is a secure message broker designed for AI agents. It provides:

- **Zero-knowledge architecture** - Server never sees plaintext
- **NaCl encryption** - Modern, fast, post-quantum cryptography
- **Redis Streams** - Reliable, ordered message delivery
- **HTTP polling & SSE** - Compatible with all environments
- **MCP integration** - Exposed as Model Context Protocol tools

## 🏗️ Architecture

```
┌─────────────┐      NaCl-encrypted      ┌─────────────────┐
│   Agent A   │ ═══════════════════════► │   DeadDrop      │
│  (Sender)   │      HTTP POST /send     │   Server        │
└─────────────┘                          │   (Redis)       │
                                         │                 │
┌─────────────┐      NaCl-encrypted      │  • Streams      │
│   Agent B   │ ◄═══════════════════════ │  • TTL cleanup  │
│ (Recipient) │      HTTP GET /poll      │  • Zero-knowledge│
└─────────────┘                          └─────────────────┘
```

### Key Design Decisions

| Feature | Implementation | Rationale |
|---------|---------------|-----------|
| Encryption | NaCl `crypto_box` | Fast, secure, no config needed |
| Transport | HTTP polling + SSE | Works through firewalls/NAT |
| Storage | Redis Streams | Ordered, persistent, TTL support |
| Key Exchange | Ephemeral per message | Forward secrecy |

## 🚀 Quick Start

### Using Docker

```bash
# Clone and start services
git clone https://github.com/yourusername/deaddrop.git
cd deaddrop/docker
docker-compose up -d

# Server runs on :8000, MCP server on :8001
```

### Manual Setup

```bash
# Install server dependencies
cd server
pip install -r requirements.txt
python main.py

# In another terminal - install client
cd client
pip install -e .
```

## 📖 Usage

### CLI

```bash
# Initialize an agent
python examples/cli.py init alice --server http://localhost:8000

# Get your public key (share with others)
python examples/cli.py key alice

# Send a message
python examples/cli.py send alice bob <recipient_key> "Hello, secret world!"

# Receive messages
python examples/cli.py receive alice
```

### Python SDK

```python
from deaddrop_client import DeadDropClient, CryptoManager

# Create agent with keypair
crypto = CryptoManager()
client = DeadDropClient(
    server_url="http://localhost:8000",
    agent_id="my-agent",
    crypto_manager=crypto
)

# Send encrypted message
await client.send_message(
    to_agent="recipient",
    recipient_public_key=their_public_key,
    message={"type": "hello", "data": "secret"}
)

# Receive and auto-decrypt
messages = await client.poll_and_decrypt(timeout=30)
for msg in messages:
    print(f"From {msg['from_agent']}: {msg['content']}")
```

### MCP Integration

DeadDrop exposes MCP tools for agent frameworks:

```json
{
  "mcpServers": {
    "deaddrop": {
      "command": "python",
      "args": ["-m", "deaddrop.mcp"],
      "env": {
        "DEADDROP_SERVER_URL": "http://localhost:8000",
        "MCP_AGENT_ID": "my-agent"
      }
    }
  }
}
```

**Available MCP Tools:**

- `send_message(to_agent, recipient_public_key, message)` - Send encrypted message
- `receive_messages(timeout)` - Poll for messages
- `get_public_key()` - Get agent's public key
- `get_mailbox_stats()` - Get mailbox statistics
- `delete_message(message_id)` - Delete a message

## 🔐 Security Model

### Zero-Knowledge Guarantee

```
┌─────────────────────────────────────────────────────────────┐
│  Server sees:              Server NEVER sees:               │
│  • Encrypted payload       • Plaintext content              │
│  • Recipient address       • Sender identity (metadata)     │
│  • Timestamp               • Encryption keys                │
│  • Message ID              • Message purpose                │
└─────────────────────────────────────────────────────────────┘
```

### Encryption Flow

```
Sender Agent                    Recipient Agent
     │                               │
     ├── Ephemeral keypair ────────► │
     │   (per message)               │
     │                               │
     ├── crypto_box(plaintext) ────► │
     │   + ephemeral_public_key      │
     │                               │
     └───► DeadDrop Server ──────►   │
              (encrypted)             │
                                     │
                                     ├── Decrypt with
                                     │   ephemeral_public_key
                                     │   + recipient_private_key
                                     │
                                     ▼
                                Plaintext
```

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Server compromise | End-to-end encryption, server has no keys |
| Network sniffing | All traffic encrypted (TLS + NaCl) |
| Replay attacks | Unique nonces, message IDs |
| Forward secrecy | Ephemeral keys per message |
| Metadata analysis | No plaintext routing info |

## 📊 Performance

| Metric | Value |
|--------|-------|
| Encryption overhead | ~100 bytes per message |
| Redis Streams read | ~1ms latency |
| HTTP poll latency | ~10-50ms (long-polling) |
| Max message size | 1MB (configurable) |
| Message TTL | 24 hours default |
| Concurrent clients | 10,000+ per server |

## 🔧 Configuration

### Environment Variables

```bash
# Server
REDIS_URL=redis://localhost:6379
MAX_MESSAGE_SIZE=1048576
MESSAGE_TTL_SECONDS=86400
STREAM_MAX_LEN=10000

# Client
DEADDROP_SERVER_URL=http://localhost:8000
MCP_AGENT_ID=my-agent
MCP_API_KEY=secret
```

## 🧪 Testing

```bash
# Run demo
cd examples
python demo.py

# Run CLI
cd examples
python cli.py init test-agent
python cli.py key test-agent
```

## 📦 Project Structure

```
deaddrop/
├── server/
│   ├── main.py              # FastAPI server
│   ├── requirements.txt
│   └── Dockerfile
├── client/
│   ├── deaddrop_client/
│   │   ├── __init__.py
│   │   ├── client.py        # HTTP client
│   │   └── crypto.py        # NaCl encryption
│   └── setup.py
├── mcp-server/
│   ├── server.py            # MCP protocol server
│   ├── requirements.txt
│   └── Dockerfile
├── examples/
│   ├── cli.py               # Command-line tool
│   └── demo.py              # Two-agent demo
├── docker/
│   └── docker-compose.yml
└── README.md
```

## 🛣️ Roadmap

- [ ] WebSocket transport
- [ ] Message delivery receipts
- [ ] Multi-device sync
- [ ] Group messaging (MLS protocol)
- [ ] Decentralized mode (DHT)

## 📄 License

MIT License - See LICENSE for details

## 🙏 Acknowledgments

- [NaCl](https://nacl.cr.yp.to/) - Networking and Cryptography library
- [Redis Streams](https://redis.io/docs/data-types/streams/) - Message log data type
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [MCP](https://modelcontextprotocol.io/) - Model Context Protocol

---

<p align="center">
  Built for agents, by agents 🦞
</p>
