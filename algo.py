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

    async def score_token(self, pump_token, tx_data: Optional[Dict] = None) -> Dict[str, Any]:
        session = await self._get_session()
        logger.info(f"📊 [SCORING] Token: {pump_token.mint[:10]}... | Dev: {pump_token.creator[:10]}...")

        # 1. Authority Check
        has_mint_auth = await self._check_mint_authority(pump_token.mint, session)
        if has_mint_auth:
            return {
                "score": 0,
                "risk_factors": ["Mint authority detected - honeypot risk"],
                "has_mint_authority": True,
                "dev_holding_pct": 0,
                "creator_history": {"coins_per_hour": 0, "recent_coins": []}
            }

        # 2. Dev Buy Check (Launch Block vs Current)
        dev_buy_pct = 0.0
        if tx_data:
            dev_buy_pct = self._extract_dev_buy_from_tx(tx_data, pump_token.mint, pump_token.creator)
        
        # Fallback/Supplemental: Direct balance check
        current_holding = await self._check_dev_token_balance(
            pump_token.mint,
            pump_token.creator,
            session
        )
        # Take the maximum — if they bought in block 0 and still hold it, or bought more
        dev_holding_pct = max(dev_buy_pct, current_holding)

        # 3. Creator History Check (Previous coins)
        creator_history = await self._check_creator_history(
            pump_token.creator,
            pump_token.timestamp,
            session
        )

        # 4. Final Scoring Logic
        score = self._calculate_final_score(
            dev_holding_pct,
            creator_history,
            pump_token
        )

        return {
            "score": score,
            "risk_factors": self._get_risk_factors(dev_holding_pct, creator_history),
            "has_mint_authority": has_mint_auth,
            "dev_holding_pct": dev_holding_pct,
            "creator_history": creator_history
        }

    async def _check_mint_authority(self, mint: str, session: aiohttp.ClientSession) -> bool:
        """
        Checks if the SPL mint authority is still present (not renounced).
        Standard SPL Mint layout: first 36 bytes contains COption (4 bytes) + Pubkey (32 bytes).
        If COption is 0, authority is None (renounced).
        """
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
                if "result" in data and data["result"] and data["result"]["value"]:
                    account_data = data["result"]["value"]["data"][0]
                    import base64
                    raw_data = base64.b64decode(account_data)
                    
                    if len(raw_data) >= 36:
                        # First 4 bytes is COption (u32)
                        import struct
                        option = struct.unpack("<I", raw_data[:4])[0]
                        return option == 1 # 1 means authority exists
        except Exception as e:
            logger.debug(f"Mint authority check failed: {e}")
        return False

    async def _check_dev_token_balance(
        self, 
        mint: str, 
        creator: str,
        session: aiohttp.ClientSession
    ) -> float:
        """
        Checks the creator's current balance of the token using getParsedTokenAccountsByOwner.
        Returns percentage of total supply (assumed 1B for Pump.fun tokens).
        """
        try:
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"
            async with session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTokenAccountsByOwner",
                "params": [
                    creator,
                    {"mint": mint},
                    {"encoding": "jsonParsed"}
                ]
            }) as resp:
                data = await resp.json()
                if "result" in data and data["result"]["value"]:
                    total_amount = 0
                    for account in data["result"]["value"]:
                        info = account["account"]["data"]["parsed"]["info"]
                        token_amount = info["tokenAmount"]
                        total_amount += float(token_amount["uiAmount"])
                    
                    # Pump.fun tokens typically have 1B total supply
                    return total_amount / 1_000_000_000
                    
        except Exception as e:
            logger.debug(f"Dev balance check failed: {e}")
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
        """
        Parses postTokenBalances from the launch transaction to identify 
        exactly how much the creator bought in the first block.
        """
        if not tx_data:
            return 0.0

        try:
            meta = tx_data.get("meta", {})
            if not meta:
                return 0.0

            post_balances = meta.get("postTokenBalances", [])
            total_dev_tokens = 0.0

            for entry in post_balances:
                entry_mint = entry.get("mint")
                entry_owner = entry.get("owner")
                
                if entry_mint == mint and entry_owner == creator:
                    amount_info = entry.get("uiTokenAmount", {})
                    total_dev_tokens += float(amount_info.get("uiAmount", 0) or 0)

            # Pump.fun: 1B supply
            buy_pct = total_dev_tokens / 1_000_000_000
            if buy_pct > 0.01:
                logger.info(f"📊 [LAUNCH BUY] Creator bought {buy_pct:.2%} in the launch block")
            
            return buy_pct
        except Exception as e:
            logger.debug(f"Error extracting dev buy from tx balance metadata: {e}")
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

                if coins_per_hour > 1:
                    logger.info(f"🚩 [HISTORY] Dev {creator[:10]}... launched {coins_per_hour} coins in 1h")
                
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
