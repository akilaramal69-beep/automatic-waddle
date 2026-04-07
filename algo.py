#!/usr/bin/env python3
"""
Algorithmic Scoring Module
Dev Trust scoring and risk assessment for Pump.fun tokens
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import aiohttp
from solders.pubkey import Pubkey

from config import config

logger = logging.getLogger(__name__)

@dataclass
class ScoringResult:
    score: int
    risk_factors: List[str] = field(default_factory=list)
    has_mint_authority: bool = False
    dev_holding_pct: float = 0.0
    creator_history: Dict[str, Any] = field(default_factory=dict)

class AlgoScorer:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.creator_cache: Dict[str, List[Dict]] = {}
        self.cache_ttl = 300

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def score_token(self, pump_token) -> Dict[str, Any]:
        session = await self._get_session()

        has_mint_auth = await self._check_mint_authority(pump_token.mint, session)
        if has_mint_auth:
            return {
                "score": 0,
                "risk_factors": ["Mint authority detected - honeypot risk"],
                "has_mint_authority": True,
                "dev_holding_pct": 0
            }

        dev_buy_pct = await self._calculate_dev_buy_percentage(
            pump_token.mint, 
            pump_token.creator,
            session
        )

        creator_history = await self._check_creator_history(
            pump_token.creator,
            pump_token.timestamp,
            session
        )

        score = self._calculate_final_score(
            dev_buy_pct,
            creator_history,
            pump_token
        )

        return {
            "score": score,
            "risk_factors": self._get_risk_factors(dev_buy_pct, creator_history),
            "has_mint_authority": has_mint_auth,
            "dev_holding_pct": dev_buy_pct,
            "creator_history": creator_history
        }

    async def _check_mint_authority(self, mint: str, session: aiohttp.ClientSession) -> bool:
        try:
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"
            async with session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [
                    mint,
                    {"encoding": "base64"}
                ]
            }) as resp:
                data = await resp.json()
                if "result" in data and data["result"]:
                    account = data["result"]["data"][0]
                    if len(account) > 32:
                        return False
        except Exception as e:
            logger.debug(f"Mint authority check failed: {e}")
        return False

    async def _calculate_dev_buy_percentage(
        self, 
        mint: str, 
        creator: str,
        session: aiohttp.ClientSession
    ) -> float:
        try:
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"
            async with session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSignaturesForAddress",
                "params": [
                    creator,
                    {"limit": 5}
                ]
            }) as resp:
                data = await resp.json()

                if "result" not in data:
                    return 0.0

                total_dev_buys = 0
                tx_count = 0

                for sig_info in data["result"][:5]:
                    tx_data = await self._get_transaction_details(
                        sig_info["signature"],
                        session
                    )

                    if tx_data:
                        dev_buy = self._extract_dev_buy_from_tx(tx_data, mint, creator)
                        total_dev_buys += dev_buy
                        tx_count += 1

                if tx_count > 0:
                    return min(total_dev_buys / tx_count, 1.0)

        except Exception as e:
            logger.debug(f"Dev buy calculation error: {e}")
        return 0.0

    async def _get_transaction_details(self, signature: str, session: aiohttp.ClientSession) -> Optional[Dict]:
        try:
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"
            async with session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [
                    signature,
                    {"encoding": "jsonParsed"}
                ]
            }) as resp:
                data = await resp.json()
                return data.get("result")
        except Exception:
            return None

    def _extract_dev_buy_from_tx(self, tx_data: Dict, mint: str, creator: str) -> float:
        if not tx_data or "transaction" not in tx_data:
            return 0.0

        try:
            message = tx_data["transaction"]["message"]
            instructions = message.get("instructions", [])

            for ix in instructions:
                if isinstance(ix, dict):
                    if ix.get("program") == "system" or ix.get("parsed", {}).get("type") == "transfer":
                        return 0.05

            return 0.0
        except Exception:
            return 0.0

    async def _check_creator_history(
        self, 
        creator: str, 
        current_time: float,
        session: aiohttp.ClientSession
    ) -> Dict[str, Any]:
        cache_key = creator
        if cache_key in self.creator_cache:
            cached_result: Dict = self.creator_cache[cache_key]
            cached_data = cached_result["data"]
            cached_time: float = cached_result["time"]
            if current_time - cached_time < self.cache_ttl:
                return cached_data

        try:
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"
            async with session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSignaturesForAddress",
                "params": [
                    creator,
                    {"limit": 20}
                ]
            }) as resp:
                data = await resp.json()

                if "result" not in data:
                    return {"coins_per_hour": 0, "recent_coins": []}

                recent_coins = []
                hour_ago = current_time - 3600

                for sig_info in data["result"]:
                    block_time = sig_info.get("blockTime", 0)
                    if block_time > hour_ago:
                        recent_coins.append({
                            "signature": sig_info["signature"],
                            "time": block_time
                        })

                coins_per_hour = len(recent_coins)

                result = {
                    "coins_per_hour": coins_per_hour,
                    "recent_coins": recent_coins
                }

                self.creator_cache[cache_key] = {"data": result, "time": float(current_time)}
                return result

        except Exception as e:
            logger.debug(f"Creator history check error: {e}")
            return {"coins_per_hour": 0, "recent_coins": []}

    def _calculate_final_score(
        self, 
        dev_buy_pct: float,
        creator_history: Dict[str, Any],
        pump_token
    ) -> int:
        score = 100

        if dev_buy_pct > config.DEV_BUY_THRESHOLD:
            score -= 50
            logger.warning(f"High dev buy percentage: {dev_buy_pct:.1%}")

        coins_per_hour = creator_history.get("coins_per_hour", 0)
        if coins_per_hour > config.MAX_CREATOR_COINS_PER_HOUR:
            score = 0
            logger.warning(f"Creator launched {coins_per_hour} coins in 1 hour")

        if pump_token.has_mint_authority:
            score = 0

        return max(0, score)

    def _get_risk_factors(
        self, 
        dev_buy_pct: float,
        creator_history: Dict[str, Any]
    ) -> List[str]:
        factors = []

        if dev_buy_pct > config.DEV_BUY_THRESHOLD:
            factors.append(f"High Dev Buy: {dev_buy_pct:.1%}")

        coins_per_hour = creator_history.get("coins_per_hour", 0)
        if coins_per_hour > config.MAX_CREATOR_COINS_PER_HOUR:
            factors.append(f"Creator launched {coins_per_hour} coins/hour")

        return factors

    async def close(self):
        if self.session:
            await self.session.close()
