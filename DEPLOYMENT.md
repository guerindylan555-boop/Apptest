# Deployment Guide

## Prerequisites

- Docker and Docker Compose installed on your VPS
- Dokploy installed and running on your VPS
- Port forwarding configured (ports 3001, 5173, 8000, 5555)

## Local Development

### Running with Docker Compose

The docker-compose.yml now runs the backend (API + emulator + ws-scrcpy) and the frontend together. Hardware acceleration is enabled automatically when `/dev/kvm` is available on the host.

```bash
docker-compose up --build
```

Services will be available at:
- Frontend: http://localhost:5173
- Backend API: http://localhost:3001
- Stream (ws-scrcpy): http://localhost:8000
- ADB (TCP): localhost:5555

## Deploying with Dokploy

### Method 1: Docker Compose Deployment

1. **Add Project to Dokploy**
   - Log into your Dokploy dashboard
   - Click "New Project"
   - Select "Docker Compose"
   - Connect your Git repository or upload the project

2. **Configure Environment Variables**
   Add these environment variables in Dokploy if you need to override defaults:
   ```
   WS_SCRCPY_PORT=8000
   WS_SCRCPY_PLAYER=webcodecs
   ADB_SERVER_PORT=5555
   EMULATOR_CONSOLE_PORT=5554
   EMULATOR_ADB_PORT=5555
   ```

3. **Configure Domains**
   Set up domains for each service:
   - Frontend: `app.yourdomain.com`
   - Backend: `api.yourdomain.com`

4. **Deploy**
   - Click "Deploy" in Dokploy
   - Dokploy will build and start your containers
   - SSL certificates will be automatically provisioned

### Note about ws-scrcpy

The backend container now bundles ws-scrcpy and manages it automatically. No host-level process is required. The streamer listens on port 8000 inside the container and is exposed through Docker Compose for the frontend to embed.

## Accessing from Local Machine

### Option 1: Direct Access (if VPS has public IP)

Access services directly via your VPS IP or domain:
- Frontend: `http://your-vps-ip:5173`
- Backend: `http://your-vps-ip:3001`
- Stream: `http://your-vps-ip:8000`

### Option 2: SSH Tunnel (secure access)

If you want secure access without exposing ports publicly:

```bash
# Forward all ports at once
ssh -L 5173:localhost:5173 \
    -L 3001:localhost:3001 \
    -L 8000:localhost:8000 \
    user@your-vps-ip
```

Then access locally:
- Frontend: `http://localhost:5173`
- Backend: `http://localhost:3001`
- Stream: `http://localhost:8000`

### Option 3: Domain with SSL (recommended)

Set up domains in Dokploy and access via HTTPS:
- Frontend: `https://app.yourdomain.com`
- Backend: `https://api.yourdomain.com`
- Stream: `https://stream.yourdomain.com`

## Firewall Configuration

If using UFW on your VPS:

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow application ports (if not using reverse proxy)
sudo ufw allow 3001/tcp
sudo ufw allow 5173/tcp
sudo ufw allow 5555/tcp
sudo ufw allow 8000/tcp

# Enable firewall
sudo ufw enable
```

## Troubleshooting

### Check running containers
```bash
docker ps
```

### View logs
```bash
docker-compose logs -f
# or for specific service
docker-compose logs -f backend
```

### Restart services
```bash
docker-compose restart
```

### Rebuild after changes
```bash
docker-compose down
docker-compose up --build -d
```

### Check if ports are listening
```bash
netstat -tuln | grep -E '3001|5037|5173|8000'
```

## Android Emulator Notes

The backend Docker image now ships with just the Android platform-tools so it can talk to an externally managed emulator. To stream successfully:

1. Start your Android emulator on a host or VM that has network access to the backend container.
2. Run `ws-scrcpy` on the same host and point it at the backend's ADB server (`ADB_SERVER_SOCKET=tcp:<backend-host>:5037`).
3. Set `WS_SCRCPY_HOST`, `WS_SCRCPY_PORT`, and `EMULATOR_SERIAL` in the backend environment so stream tickets point to the external streamer.
4. From the host running ws-scrcpy, verify connectivity: `adb connect <backend-host>:5555` (if needed) and `nc -zv <backend-host> 5037`.

## Production Considerations

- Use environment variables for sensitive configuration
- Set up proper logging and monitoring
- Configure backups for Android data volume
- Use a reverse proxy (Nginx/Traefik) for SSL termination
- Enable rate limiting and security headers
- Keep Docker images updated

## Updating the Application

```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose up --build -d
```

In Dokploy, you can set up automatic deployments on Git push.
