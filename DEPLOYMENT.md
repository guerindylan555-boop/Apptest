# Deployment Guide

## Prerequisites

- Docker and Docker Compose installed on your VPS
- Dokploy installed and running on your VPS
- Port forwarding configured (ports 3001, 5173, 8000)

## Local Development

To run the app locally on your VPS:

```bash
docker-compose up --build
```

Services will be available at:
- Frontend: http://localhost:5173
- Backend API: http://localhost:3001
- ws-scrcpy: http://localhost:8000

## Deploying with Dokploy

### Method 1: Docker Compose Deployment

1. **Add Project to Dokploy**
   - Log into your Dokploy dashboard
   - Click "New Project"
   - Select "Docker Compose"
   - Connect your Git repository or upload the project

2. **Configure Environment Variables**
   Add these environment variables in Dokploy:
   ```
   NODE_ENV=production
   PORT=3001
   HOST=0.0.0.0
   LOG_LEVEL=info
   WS_SCRCPY_HOST=ws-scrcpy
   WS_SCRCPY_PORT=8000
   WS_SCRCPY_PLAYER=mse
   EMULATOR_SERIAL=emulator-5555
   ```

3. **Configure Domains**
   Set up domains for each service:
   - Frontend: `app.yourdomain.com`
   - Backend: `api.yourdomain.com`
   - ws-scrcpy: `stream.yourdomain.com`

4. **Deploy**
   - Click "Deploy" in Dokploy
   - Dokploy will build and start your containers
   - SSL certificates will be automatically provisioned

### Method 2: Individual Service Deployment

If you prefer to deploy services separately:

1. **Backend Service**
   - Create a new "Docker" application in Dokploy
   - Point to `backend/Dockerfile`
   - Expose port 3001
   - Add environment variables

2. **Frontend Service**
   - Create a new "Docker" application
   - Point to `frontend/Dockerfile`
   - Expose port 80
   - No environment variables needed

3. **ws-scrcpy Service**
   - Use the pre-built image: `ghcr.io/netrisai/ws-scrcpy:latest`
   - Expose port 8000
   - Enable privileged mode
   - Mount `/dev/kvm` device

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
netstat -tuln | grep -E '3001|5173|8000'
```

## Android Emulator Notes

The backend includes Android SDK and emulator support. To use:

1. Create an AVD (Android Virtual Device):
```bash
docker exec -it apptest-backend bash
avdmanager create avd -n test -k "system-images;android-33;google_apis;x86_64"
```

2. Start the emulator:
```bash
emulator -avd test -no-window -no-audio
```

3. The ws-scrcpy service will stream the emulator screen to the frontend.

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
