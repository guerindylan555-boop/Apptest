#!/bin/bash

# Start Networked MaynDrive Development Stack
# Includes emulator with proper internet connectivity

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== MaynDrive Networked Development Stack ===${NC}"
echo

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check Docker
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${RED}✗ Docker is not installed or not in PATH${NC}"
        exit 1
    fi

    # Check Docker Compose
    if ! command -v docker-compose >/dev/null 2>&1; then
        echo -e "${RED}✗ Docker Compose is not installed or not in PATH${NC}"
        exit 1
    fi

    # Check ADB
    if ! command -v adb >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ ADB not found - install Android SDK tools for full functionality${NC}"
    fi

    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        echo -e "${RED}✗ Docker daemon is not running${NC}"
        echo "Please start Docker and try again"
        exit 1
    fi

    echo -e "${GREEN}✓ Prerequisites checked${NC}"
    echo
}

# Function to setup Android SDK if needed
setup_android_sdk() {
    if command -v adb >/dev/null 2>&1; then
        echo -e "${GREEN}✓ ADB found: $(which adb)${NC}"
        return 0
    fi

    echo -e "${YELLOW}⚠ ADB not found. Would you like to install Android SDK tools? (y/N)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "Please install Android SDK tools and run this script again."
        echo "Visit: https://developer.android.com/studio"
        exit 1
    fi
}

# Function to create necessary directories
setup_directories() {
    echo -e "${YELLOW}Setting up directories...${NC}"

    mkdir -p backend/var/captures
    mkdir -p backend/var/uploads
    mkdir -p scripts
    mkdir -p orchestrator

    echo -e "${GREEN}✓ Directories created${NC}"
}

# Function to build and start services
start_services() {
    echo -e "${YELLOW}Building and starting services...${NC}"

    # Stop any existing containers
    docker-compose -f docker-compose.networked.yml down --remove-orphans 2>/dev/null || true

    # Build and start core services
    echo "Starting core services (backend, emulator, frontend)..."
    docker-compose -f docker-compose.networked.yml up --build -d

    echo -e "${GREEN}✓ Services starting...${NC}"
}

# Function to wait for emulator and show status
wait_for_emulator() {
    echo -e "${YELLOW}Waiting for emulator to be ready...${NC}"

    local max_attempts=60
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if docker-compose -f docker-compose.networked.yml exec -T emulator adb devices | grep -q "emulator-5556.*device"; then
            echo -e "${GREEN}✓ Emulator is ready!${NC}"
            return 0
        fi

        attempt=$((attempt + 1))
        echo -n "."
        sleep 3
    done

    echo
    echo -e "${RED}✗ Timeout waiting for emulator${NC}"
    return 1
}

# Function to show service URLs and commands
show_service_info() {
    echo
    echo -e "${BLUE}=== Service Information ===${NC}"
    echo

    echo -e "${GREEN}🌐 Frontend:${NC}"
    echo "  URL: http://localhost:5173"
    echo "  Vite dev server with hot reload"
    echo

    echo -e "${GREEN}🔧 Backend API:${NC}"
    echo "  URL: http://localhost:3001"
    echo "  Health: http://localhost:3001/api/health"
    echo "  API docs: http://localhost:3001/api/docs"
    echo

    echo -e "${GREEN}📱 Emulator:${NC}"
    echo "  ADB port: localhost:5555"
    echo "  Console: localhost:5554"
    echo "  Device ID: emulator-5556"
    echo

    echo -e "${GREEN}🔌 Port Forwarding:${NC}"
    echo "  Backend (3001) → Emulator (localhost:3001)"
    echo "  Orchestrator (8000) → Emulator (localhost:8000)"
    echo

    echo -e "${BLUE}=== Useful Commands ===${NC}"
    echo
    echo "Check emulator status:"
    echo "  docker-compose -f docker-compose.networked.yml exec emulator adb devices"
    echo
    echo "Test internet from emulator:"
    echo "  docker-compose -f docker-compose.networked.yml exec emulator adb -s emulator-5556 shell am start -a android.intent.action.VIEW -d 'http://connectivitycheck.gstatic.com/generate_204'"
    echo
    echo "Check network validation:"
    echo "  docker-compose -f docker-compose.networked.yml exec emulator adb -s emulator-5556 shell dumpsys connectivity | grep -E '(everValidated|VALIDATED)'"
    echo
    echo "View logs:"
    echo "  docker-compose -f docker-compose.networked.yml logs -f emulator"
    echo "  docker-compose -f docker-compose.networked.yml logs -f backend"
    echo "  docker-compose -f docker-compose.networked.yml logs -f frontend"
    echo
    echo "Stop services:"
    echo "  docker-compose -f docker-compose.networked.yml down"
    echo
}

# Function to verify everything is working
verify_stack() {
    echo -e "${YELLOW}Verifying stack...${NC}"

    # Check backend health
    if curl -s http://localhost:3001/api/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend API is responding${NC}"
    else
        echo -e "${RED}✗ Backend API is not responding${NC}"
    fi

    # Check frontend
    if curl -s http://localhost:5173 >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Frontend is accessible${NC}"
    else
        echo -e "${YELLOW}⚠ Frontend may still be starting${NC}"
    fi

    # Check emulator connectivity
    if docker-compose -f docker-compose.networked.yml exec -T emulator adb devices | grep -q "emulator-5556.*device"; then
        echo -e "${GREEN}✓ Emulator is connected${NC}"

        # Check network validation
        if docker-compose -f docker-compose.networked.yml exec -T emulator adb -s emulator-5556 shell dumpsys connectivity 2>/dev/null | grep -q "VALIDATED"; then
            echo -e "${GREEN}✓ Emulator network is validated${NC}"
        else
            echo -e "${YELLOW}⚠ Emulator network validation in progress${NC}"
        fi
    else
        echo -e "${RED}✗ Emulator is not connected${NC}"
    fi
}

# Main execution
main() {
    case "${1:-start}" in
        "start"|"up")
            check_prerequisites
            setup_android_sdk
            setup_directories
            start_services
            wait_for_emulator
            show_service_info
            verify_stack
            ;;
        "stop"|"down")
            echo -e "${YELLOW}Stopping services...${NC}"
            docker-compose -f docker-compose.networked.yml down
            echo -e "${GREEN}✓ Services stopped${NC}"
            ;;
        "restart")
            echo -e "${YELLOW}Restarting services...${NC}"
            docker-compose -f docker-compose.networked.yml restart
            wait_for_emulator
            verify_stack
            ;;
        "logs")
            docker-compose -f docker-compose.networked.yml logs -f
            ;;
        "status")
            docker-compose -f docker-compose.networked.yml ps
            verify_stack
            ;;
        "shell"|"sh")
            echo "Opening shell in emulator container..."
            docker-compose -f docker-compose.networked.yml exec emulator /bin/bash
            ;;
        "adb")
            shift
            docker-compose -f docker-compose.networked.yml exec emulator adb "$@"
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [command]"
            echo
            echo "Commands:"
            echo "  start      Start all services (default)"
            echo "  stop       Stop all services"
            echo "  restart    Restart all services"
            echo "  logs       Show logs for all services"
            echo "  status     Show service status"
            echo "  shell      Open shell in emulator container"
            echo "  adb [cmd]  Run adb command in emulator container"
            echo "  help       Show this help"
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            echo "Use '$0 help' for available commands"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"