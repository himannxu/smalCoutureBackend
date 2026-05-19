FROM node:18-alpine

WORKDIR /app

# Install production dependencies first (better layer cache)
COPY build/package.json build/package-lock.json ./
RUN npm ci --omit=dev

# Copy only the deploy build (no node_modules, .env, or local uploads)
COPY build/ ./

RUN mkdir -p uploads

ENV NODE_ENV=production
ENV PORT=4000
ENV HOST=0.0.0.0

EXPOSE 4000

CMD ["node", "index.js"]
