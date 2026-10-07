# 22: better-sqlite3 needs it, and Node 20 is past end of life.

# ---- deps: install node_modules, compiling better-sqlite3 ----
# better-sqlite3 is a native module and builds from source on install,
# which needs a compiler and Python. They live in this stage only; the
# image that runs copies the finished node_modules and nothing else.
FROM node:22-alpine AS deps
WORKDIR /app
RUN apk add --no-cache python3 make g++
COPY package*.json ./
# ci, not install: exactly what package-lock.json says.
RUN npm ci --omit=dev
# npm has been seen to crash halfway through and still exit 0, which
# builds an image that can't start. Opening a database here makes a
# broken install fail the build instead of the deploy.
RUN node -e "new (require('better-sqlite3'))(':memory:').prepare('select 1').get()"

# ---- runtime ----
FROM node:22-alpine
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/app/data

# Persist this path with a Coolify volume: the database (account.db),
# its daily snapshots and profile photos all live here.
VOLUME ["/app/data"]

EXPOSE 3000

CMD ["node", "server.js"]
