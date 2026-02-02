FROM python:3.11-slim

WORKDIR /app

# Copy client package first
COPY client/ /tmp/client/
RUN pip install /tmp/client/

# Install MCP server dependencies
COPY mcp-server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server
COPY mcp-server/server.py .

CMD ["python", "server.py"]
