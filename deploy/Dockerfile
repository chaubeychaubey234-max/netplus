FROM node:22-bookworm-slim AS dashboard
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends snmp \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
COPY agent ./agent
COPY config ./config
COPY deploy ./deploy
COPY --from=dashboard /app/frontend/dist ./frontend/dist
EXPOSE 8765
CMD ["uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8765"]
