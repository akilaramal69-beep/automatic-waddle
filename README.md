# 🚀 Pump.fun Solana Sniper Bot

High-speed algorithmic trading bot for new token launches on [Pump.fun](https://pump.fun). Detects tokens in real-time via Helius WebSocket, scores them with a Dev Trust engine, and executes trades using Jito MEV bundles.

## Features

- **Real-time Detection** — Subscribes to Helius WebSocket (`logsSubscribe`) for instant new token alerts
- **Dev Trust Scoring** — Filters honeypots and pump-and-dump tokens before buying
- **Jito Bundles** — Dynamic priority fees + MEV-protected transaction submission
- **Smart Exit Strategy** — Sell 50% at +50% profit, trailing stop-loss on the rest
- **Simulation Mode** — Full paper trading using real token data, zero real funds
- **Telegram Alerts** — Live notifications and commands via bot

## Architecture

```
┌─────────────────────────────────────────────┐
│               TELEGRAM BOT                  │
│  /start | /status | /simulate | /trades     │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│               MAIN (Orchestrator)           │
│  Health-check HTTP server (port 8000)       │
└────────┬──────────────────┬─────────────────┘
         │                  │
┌────────▼───────┐  ┌───────▼───────┐
│   SCANNER      │  │    TRADE      │
│  Helius WS     │  │   EXECUTOR    │
│  logsSubscribe │  │  Jito / Sim   │
└────────┬───────┘  └───────┬───────┘
         │                  │
┌────────▼──────────────────▼───────┐
│              ALGO                  │
│  • Mint Authority check            │
│  • Dev Buy % check                 │
│  • Creator history (coins/hour)    │
└────────────────────────────────────┘
```

## Scoring Logic

| Check | Condition | Result |
|---|---|---|
| Mint Authority | Present | **Score = 0** (Honeypot) |
| Dev Buy % | > 15% | **Score -= 50** (High Risk) |
| Creator History | > 3 coins/hour | **Score = 0** (Dumper) |

Only tokens with **score > 0** are traded.

## Exit Strategy

```
Step 1: Sell 50% at +50% profit
Step 2: Sell remaining 50% when price drops -20% from peak (trailing stop)
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `HELIUS_API_KEY` | ✅ Always | Helius RPC/WebSocket API key |
| `TELEGRAM_BOT_TOKEN` | ✅ | Telegram bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | ✅ | Your Telegram chat/user ID |
| `WALLET_PRIVATE_KEY` | Live only | Solana wallet private key (Base58) |
| `SIMULATION_MODE` | ❌ | Set `true` for paper trading (default: false) |
| `TRADE_AMOUNT_SOL` | ❌ | SOL per trade (default: 0.065) |
| `RPC_URL` | ❌ | Custom RPC endpoint |
| `WSS_URL` | ❌ | Custom WebSocket endpoint |

> **Note:** In simulation mode `WALLET_PRIVATE_KEY` is not required. The bot uses the real Helius WebSocket to detect and score real tokens — only trade execution is simulated.

## Installation

```bash
# 1. Clone
git clone https://github.com/your-username/pump-sniper.git
cd pump-sniper

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env and fill in your keys

# 4. Run (simulation mode recommended first)
SIMULATION_MODE=true python main.py
```

## Docker

```bash
# Build and run
docker compose up -d

# View logs
docker compose logs -f
```

## Koyeb Deployment

1. Push this repo to GitHub
2. Go to [app.koyeb.com](https://app.koyeb.com) → **Create App** → **GitHub**
3. Select your repo, branch `main`
4. Set environment variables in the Koyeb dashboard:
   - `HELIUS_API_KEY`
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   - `WALLET_PRIVATE_KEY`
   - `PYTHONUNBUFFERED=1`
5. Deploy — free tier (0.1 vCPU, 512 MB RAM) is sufficient

## Telegram Commands

| Command | Description |
|---|---|
| `/start` | Show balance, stats, and win rate |
| `/status` | Bot health and connection status |
| `/simulate` | Toggle simulation mode on/off |
| `/trades` | View trade history |

## File Structure

```
├── main.py          # Orchestrator + HTTP health server
├── config.py        # All settings (env-variable driven)
├── scanner.py       # Helius WebSocket token detection
├── algo.py          # Dev Trust scoring engine
├── trade.py         # Buy/sell execution + simulation
├── bot.py           # Telegram alerts and commands
├── wallet.py        # Solana keypair management
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── koyeb.yaml
└── .env.example
```

## Dependencies

- `solana` / `solders` — Solana Python SDK
- `aiohttp` — Async WebSocket + HTTP
- `asyncpg` — Async database (optional future use)

## ⚠️ Disclaimer

This bot trades real cryptocurrency. Use at your own risk. Always test in **simulation mode** first. The authors are not responsible for financial losses. Crypto trading involves significant risk of loss.

## License

MIT
