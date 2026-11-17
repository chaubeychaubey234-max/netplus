FROM python:3.13-alpine
WORKDIR /app
COPY backend ./backend
COPY frontend ./frontend
COPY config ./config
COPY deploy ./deploy
CMD ["python3", "backend/server.py", "--config", "deploy/server.json"]
