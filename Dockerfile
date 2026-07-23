# Unified Dockerfile for SentinelAI
# Build Frontend React static assets
FROM node:20-alpine AS frontend-builder
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Final Python backend container
FROM python:3.11-slim
WORKDIR /app

# Install system dependencies (e.g. for scapy / build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy built frontend assets
COPY --from=frontend-builder /frontend/dist /frontend/dist

# Copy backend files
COPY backend/app/ ./backend/app/
COPY backend/scripts/ ./backend/scripts/
COPY .env ./

# Train AI model during build so it's ready out of the box
RUN python -m backend.scripts.train_ai

# Expose admin port and honeypot listener ports
# Admin API/Web Dashboard
EXPOSE 8000
# SSH Emulator
EXPOSE 2222
# HTTP Emulator
EXPOSE 8080
# FTP Emulator
EXPOSE 2121
# Telnet Emulator
EXPOSE 2323

# Start the FastAPI backend
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
