# Kiro Worker Dashboard

Cloudflare Workers-based credential manager with a simple Web UI.

## Features

- Setup flow with admin password, encryption key, and shell token
- Web UI for credentials, settings, and stats
- API endpoint for shell to fetch encrypted credentials

## Project Structure

- `wrangler.toml`
- `package.json`
- `src/index.js`
- `src/auth.js`
- `src/api.js`
- `src/ui.js`

## Development

```bash
npm install
npm run dev
```

## Deploy

```bash
# Create KV namespace
wrangler kv:namespace create "KV"
# Update `wrangler.toml` with the KV namespace ID

npm install
npm run deploy
```

## Initialize

1. Visit the deployed Worker URL
2. Complete setup (admin password, encryption key, shell token)
3. Log in and add credentials

## Shell Config

Set these environment variables in your shell runtime:

- `WORKER_URL`
- `AUTH_TOKEN`
- `ENCRYPTION_KEY`
- `API_KEY`
