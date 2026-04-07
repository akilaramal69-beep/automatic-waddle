#!/usr/bin/env python3
"""
Solana Pump.fun Sniper Bot
High-speed algorithmic trading for new Pump.fun tokens
"""

import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Optional
import json

import aiohttp
from solders.pubkey import Pubkey

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Config:
    HELIUS_API_KEY: str = os.getenv("HELIUS_API_KEY", "")
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")
    WALLET_PRIVATE_KEY: str = os.getenv("WALLET_PRIVATE_KEY", "")
    RPC_URL: str = os.getenv("RPC_URL", "https://mainnet.helius-rpc.com")
    WSS_URL: str = os.getenv("WSS_URL", "wss://mainnet.helius-rpc.com")
    
    TRADE_AMOUNT_SOL: float = float(os.getenv("TRADE_AMOUNT_SOL", "0.065"))
    MIN_PRIORITY_FEE: float = 0.0001
    MAX_PRIORITY_FEE: float = 0.005
    
    PUMP_FUN_PROGRAM: str = "6EF8rrecthR5Dkzon8NwuxeK7YMMvV35R885yFmK8Y9"
    PUMP_FUN_GLOBAL: str = "4wTVyH7jzP7qbBq9V73ZS3qZv6YvY8PzVjQjVjQjVjQj"
    PUMP_FUN_FEE_RECIPIENT: str = "CebN5WGCcP97GrS9bde96Xy2uB7rFpDMYhDMTWCH1nN5"
    PUMP_FUN_CREATE_PREFIX: bytes = bytes.fromhex("507270466d7359")
    
    SIMULATION_BALANCE_SOL: float = 0.15
    SIMULATION_MODE: bool = os.getenv("SIMULATION_MODE", "false").lower() == "true"
    
    JITO_ENDPOINTS: list = field(default_factory=lambda: [
        "https://ny.mainnet.block-engine.jito.wtf/api/v1/bundles",
        "https://mainnet.block-engine.jito.wtf/api/v1/bundles"
    ])
    
    DNS_RESOLVER: dict = field(default_factory=lambda: {
        "quote-api.jup.ag": "104.16.123.96",
        "api.jup.ag": "104.16.123.96"
    })
    
    STABLECOIN_WHITELIST: list = field(default_factory=lambda: [
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # USDC
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"   # USDT
    ])

    MAX_CREATOR_COINS_PER_HOUR: int = 3
    DEV_BUY_THRESHOLD: float = 0.15
    
    PROFIT_TARGET_1: float = float(os.getenv("PROFIT_TARGET_1", "0.50"))      # 50%
    SELL_PORTION_1: float = float(os.getenv("SELL_PORTION_1", "0.50"))       # Sell 50% at target 1
    TRAILING_STOP_LOSS: float = float(os.getenv("TRAILING_STOP_LOSS", "-0.20")) # -20% from peak
    STOP_LOSS_THRESHOLD: float = float(os.getenv("STOP_LOSS_THRESHOLD", "-0.30")) # -30% hard stop

config = Config()
