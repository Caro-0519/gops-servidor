FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json server.js ./
ENV NODE_ENV=production PORT=3000 DB_PATH=/data/gops.db
VOLUME ["/data"]
EXPOSE 3000
CMD ["node", "server.js"]
