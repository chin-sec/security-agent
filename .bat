@echo off
echo Building Docker Image...
docker build -t security-agent:v1 .

echo Starting Container...
docker run -d ^
  --name sec-agent-prod ^
  -p 8000:8000 ^
  --env-file .env ^
  -v %cd%\data:/app/data ^
  -v %cd%\reports:/app/reports ^
  --restart unless-stopped ^
  security-agent:v1

echo Done! Access API at http://localhost:8000
pause
