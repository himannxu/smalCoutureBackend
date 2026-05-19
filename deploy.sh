#!/usr/bin/env bash
# Rebuild website-backend and restart backend-container on port 4000.
# Keeps .env and uploads/ on the host (image upload APIs keep working).

set -euo pipefail

APP_DIR="${APP_DIR:-$HOME/websiteBackend}"
CONTAINER_NAME="${CONTAINER_NAME:-backend-container}"
IMAGE_NAME="${IMAGE_NAME:-website-backend}"
HOST_PORT="${HOST_PORT:-4000}"
CONTAINER_PORT="${CONTAINER_PORT:-4000}"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env}"
UPLOADS_DIR="${UPLOADS_DIR:-$APP_DIR/uploads}"
BUNDLE_DIR="${BUNDLE_DIR:-$APP_DIR/deploy-bundle}"

cd "$APP_DIR"

if [ -d "$BUNDLE_DIR/build" ]; then
  echo "Applying deploy bundle from CI..."
  rm -rf "$APP_DIR/build"
  cp -a "$BUNDLE_DIR/build" "$APP_DIR/build"
  cp -f "$BUNDLE_DIR/Dockerfile" "$APP_DIR/Dockerfile"
  cp -f "$BUNDLE_DIR/deploy.sh" "$APP_DIR/deploy.sh"
  chmod +x "$APP_DIR/deploy.sh"
fi

if [ ! -d "$APP_DIR/build" ] || [ ! -f "$APP_DIR/build/index.js" ]; then
  echo "Missing $APP_DIR/build — run: npm run build:deploy"
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE — create it on the server before deploying."
  exit 1
fi

mkdir -p "$UPLOADS_DIR"

echo "Building Docker image: $IMAGE_NAME:latest"
docker build -t "$IMAGE_NAME:latest" "$APP_DIR"

echo "Restarting container: $CONTAINER_NAME (${HOST_PORT}:${CONTAINER_PORT})"
docker stop "$CONTAINER_NAME" 2>/dev/null || true
docker rm "$CONTAINER_NAME" 2>/dev/null || true

docker run -d \
  --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p "${HOST_PORT}:${CONTAINER_PORT}" \
  --env-file "$ENV_FILE" \
  -e PORT="$CONTAINER_PORT" \
  -e HOST=0.0.0.0 \
  -v "${UPLOADS_DIR}:/app/uploads" \
  "$IMAGE_NAME:latest"

docker image prune -f >/dev/null 2>&1 || true

echo "Deploy complete."
docker ps --filter "name=$CONTAINER_NAME"
