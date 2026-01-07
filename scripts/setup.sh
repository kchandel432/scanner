#!/bin/bash

# Cyber Risk Intelligence Platform Setup Script

set -e

echo "🚀 Setting up Cyber Risk Intelligence Platform..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
python3 --version || { echo -e "${RED}Python 3.8+ is required${NC}"; exit 1; }

# Create virtual environment
echo -e "${YELLOW}Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Create necessary directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p uploads
mkdir -p ml/models
mkdir -p ml/data
mkdir -p ml/features
mkdir -p backend/frontend/static/assets/{fonts,images,icons}
mkdir -p backend/frontend/static/{css,js}
mkdir -p database/migrations/versions

# Copy environment file
if [ ! -f .env ]; then
    echo -e "${YELLOW}Creating .env file...${NC}"
    cp .env.example .env
    echo -e "${GREEN}Please update .env file with your configuration${NC}"
fi

# Initialize git pre-commit hooks
echo -e "${YELLOW}Setting up pre-commit hooks...${NC}"
pre-commit install

# Run database migrations
echo -e "${YELLOW}Running database migrations...${NC}"
alembic upgrade head || echo -e "${YELLOW}No migrations found, skipping...${NC}"

# Download sample ML models (if available)
echo -e "${YELLOW}Downloading sample ML models...${NC}"
# Add ML model download logic here

echo -e "${GREEN}Setup complete! 🎉${NC}"
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Update .env file with your configuration"
echo "2. Run 'python backend/app/main.py' to start the server"
echo "3. Visit http://localhost:8000 in your browser"
