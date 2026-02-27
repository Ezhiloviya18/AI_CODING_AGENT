FROM oven/bun:1

WORKDIR /app

# Install deps (better cache layer)
COPY . .
RUN bun install


CMD ["bun", "run", "dev"]