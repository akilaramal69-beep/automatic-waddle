#!/usr/bin/env python3
"""
Main Entry Point
Coordinates all components for the Pump.fun Sniper Bot
"""

import asyncio
import logging
import signal
import sys
import os
from datetime import datetime
from aiohttp import web

from config import config
from scanner import Scanner
from algo import AlgoScorer
from trade import TradeExecutor, TradeStatus
from bot import TelegramBot
from wallet import Wallet

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimal HTTP server — Koyeb requires the process to bind to a port.
# Without this the health check fails and the container is silently restarted.
# ---------------------------------------------------------------------------
async def health_handler(request):
    return web.Response(text="OK")

async def start_health_server():
    port = int(os.getenv("PORT", "8000"))
    app = web.Application()
    app.router.add_get("/", health_handler)
    app.router.add_get("/health", health_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logger.info(f"Health-check server listening on port {port}")

class SniperBot:
    def __init__(self):
        self.wallet = Wallet(config.WALLET_PRIVATE_KEY)
        self.algo = AlgoScorer()
        self.trade = TradeExecutor(self.wallet)
        self.scanner = Scanner(self.algo)
        self.telegram = TelegramBot(self.trade)
        self.running = False

        self.trade.simulation_mode = config.SIMULATION_MODE
        self.trade.simulated_balance = config.SIMULATION_BALANCE_SOL
        self.telegram.simulation_mode = config.SIMULATION_MODE

    async def start(self):
        mode = "🎮 SIMULATION" if self.trade.simulation_mode else "💰 LIVE"
        logger.info("=" * 50)
        logger.info(f"PUMP.FUN SNIPER BOT STARTING - {mode}")
        logger.info(f"Wallet: {self.wallet.address[:8]}...{self.wallet.address[-4:]}")
        logger.info(f"Trade Amount: {config.TRADE_AMOUNT_SOL} SOL")
        logger.info("=" * 50)

        self.running = True

        mode_text = "🎮 SIMULATION MODE" if self.trade.simulation_mode else "💰 LIVE MODE"
        await self.telegram.send_alert(
            f"🤖 *Bot Started*\n"
            f"Mode: {mode_text}\n"
            f"Wallet: {self.wallet.address[:8]}...\n"
            f"Trade Size: {config.TRADE_AMOUNT_SOL} SOL"
        )

        await self.scanner.start()
        self.scanner.token_callback = self.handle_token

        asyncio.create_task(self._scanner_loop())
        asyncio.create_task(self._status_reporter())
        asyncio.create_task(self.telegram.poll_updates())

        while self.running:
            await asyncio.sleep(1)

    async def _scanner_loop(self):
        logger.info("Scanner loop started")

        while self.running:
            try:
                await self.scanner.process_logs()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scanner error: {e}")
                await asyncio.sleep(5)

    async def _status_reporter(self):
        while self.running:
            await asyncio.sleep(300)

            if self.trade.positions:
                balance = await self.trade.get_sol_balance()
                logger.info(f"Status: {balance:.4f} SOL | {len(self.trade.positions)} positions")

    async def handle_token(self, pump_token):
        mode = "[SIM]" if self.trade.simulation_mode else ""
        logger.info(
            f"{mode} Token Scored: {pump_token.mint[:8]}... "
            f"Score: {pump_token.score}/100 "
            f"Dev: {pump_token.dev_holding_pct:.1f}%"
        )

        if pump_token.score > 0:
            status = "SIM BUYING..." if self.trade.simulation_mode else "BUYING..."
            await self.telegram.handle_new_token(
                pump_token.mint,
                pump_token.score,
                pump_token.dev_holding_pct,
                status
            )

            position = await self.trade.execute_buy(
                pump_token.mint,
                pump_token.bonding_curve
            )

            if position:
                self.telegram.update_stats(
                    total_trades=self.telegram.stats['total_trades'] + 1,
                    active_positions=len(self.trade.positions)
                )

                if self.trade.simulation_mode:
                    asyncio.create_task(
                        self.trade.monitor_and_exit_sim(
                            pump_token.mint,
                            self.telegram.handle_profit_taken
                        )
                    )
                else:
                    asyncio.create_task(
                        self.trade.monitor_and_exit(
                            pump_token.mint,
                            self.telegram.handle_profit_taken
                        )
                    )
            else:
                await self.telegram.handle_trade_failed(
                    pump_token.mint,
                    "Transaction failed"
                )
                self.telegram.update_stats(
                    failed_trades=self.telegram.stats['failed_trades'] + 1
                )
        else:
            logger.info(f"{mode} Token rejected: {pump_token.mint[:8]}... - {pump_token.risk_factors}")

    async def stop(self):
        logger.info("Shutting down...")
        self.running = False

        await self.scanner.stop()
        await self.algo.close()
        await self.trade.close()
        await self.telegram.stop()

        logger.info("Bot stopped")

async def main():
    # Start HTTP health-check server first so Koyeb sees an open port right away
    await start_health_server()

    bot = SniperBot()

    def signal_handler(sig, frame):
        asyncio.create_task(bot.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await bot.start()
    except KeyboardInterrupt:
        pass
    finally:
        await bot.stop()

if __name__ == "__main__":
    if not config.HELIUS_API_KEY:
        print("ERROR: HELIUS_API_KEY not set")
        sys.exit(1)

    if not config.WALLET_PRIVATE_KEY:
        print("ERROR: WALLET_PRIVATE_KEY not set")
        sys.exit(1)

    asyncio.run(main())
