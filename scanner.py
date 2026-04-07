#!/usr/bin/env python3
"""
Scanner Component - Real-time Pump.fun token detection
Uses Helius WebSocket for high-speed log subscription
"""

import asyncio
import base64
import logging
import re
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any
import aiohttp
from solders.pubkey import Pubkey

from config import config

logger = logging.getLogger(__name__)

class PumpToken:
    def __init__(self, mint: str, creator: str, bonding_curve: str, timestamp: float,
                 initial_supply: float = 0, dev_holding_pct: float = 0,
                 has_mint_authority: bool = False, score: int = 100, risk_factors: list = None):
        self.mint = mint
        self.creator = creator
        self.bonding_curve = bonding_curve
        self.timestamp = timestamp
        self.initial_supply = initial_supply
        self.dev_holding_pct = dev_holding_pct
        self.has_mint_authority = has_mint_authority
        self.score = score
        self.risk_factors = risk_factors or []

class Scanner:
    def __init__(self, algo_module, callback=None):
        self.algo = algo_module
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.running = False
        self.scanned_tokens: Dict[str, PumpToken] = {}
        self.token_callback = callback

    async def start(self):
        await self._connect_websocket()
        self.running = True
        asyncio.create_task(self._heartbeat())

    async def _connect_websocket(self):
        headers = {"x-api-key": config.HELIUS_API_KEY}
        self.session = aiohttp.ClientSession()

        ws_url = f"{config.WSS_URL}?api-key={config.HELIUS_API_KEY}"
        self.ws = await self.session.ws_connect(ws_url)

        subscribe_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "logsSubscribe",
            "params": {
                "filter": {
                    "mentions": [config.PUMP_FUN_PROGRAM]
                }
            }
        }
        await self.ws.send_json(subscribe_msg)

        response = await self.ws.receive_json()
        logger.info(f"Sub response: {response}")
        logger.info("WebSocket connected to Helius logsSubscribe")

    async def _heartbeat(self):
        while self.running:
            await asyncio.sleep(30)
            if self.ws and not self.ws.closed:
                await self.ws.ping()

    async def _parse_create_instruction(self, log_data: str) -> Optional[Dict[str, Any]]:
        try:
            data_b64 = log_data.get("data", {})
            if isinstance(data_b64, dict):
                data_b64 = data_b64.get("parsed", "")

            if isinstance(data_b64, str):
                data_bytes = base64.b64decode(data_b64)
            else:
                data_bytes = data_b64

            if len(data_bytes) >= 8 and data_bytes[:8] == config.PUMP_FUN_CREATE_PREFIX:
                mint_bytes = data_bytes[8:40]
                if len(mint_bytes) == 32:
                    mint = str(Pubkey(mint_bytes))

                    instruction_data = data_bytes[40:]
                    if len(instruction_data) >= 32:
                        creator_bytes = instruction_data[:32]
                        creator = str(Pubkey(creator_bytes))

                        return {
                            "mint": mint,
                            "creator": creator,
                            "bonding_curve": self._derive_bonding_curve(mint)
                        }
        except Exception as e:
            logger.debug(f"Parse error: {e}")
        return None

    def _derive_bonding_curve(self, mint: str) -> str:
        seeds = [
            b"bonding-curve",
            bytes(Pubkey.from_string(mint))
        ]
        return str(Pubkey.__new__(Pubkey, seeds[1]))

    async def _extract_from_transaction(self, signature: str, logs_hint: list = None) -> Optional[Dict[str, Any]]:
        try:
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"
            async with self.session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransaction",
                "params": [
                    signature,
                    {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}
                ]
            }) as resp:
                data = await resp.json()
                if "result" in data and data["result"]:
                    tx = data["result"]
                    message = tx.get("transaction", {}).get("message", {})

                    accounts = []
                    account_keys = message.get("accountKeys", [])
                    for ak in account_keys:
                        if isinstance(ak, dict):
                            accounts.append(ak.get("pubkey", str(ak)))
                        else:
                            accounts.append(str(ak))

                    instructions = message.get("instructions", [])

                    for ix in instructions:
                        if isinstance(ix, dict):
                            program_id_idx = ix.get("programIdIndex", ix.get("programId"))

                            if isinstance(program_id_idx, int) and program_id_idx < len(accounts):
                                program_id = accounts[program_id_idx]
                            else:
                                program_id = str(program_id_idx) if program_id_idx else ""

                            if "6EF8" in str(program_id):
                                accts = ix.get("accounts", [])
                                if isinstance(accts, list) and len(accts) >= 2:
                                    mint = str(accts[0]) if len(str(accts[0])) >= 32 else None
                                    creator = str(accts[1]) if len(str(accts[1])) >= 32 else None

                                    if mint and (creator or len(accts) > 1):
                                        if not creator:
                                            creator = str(accts[2]) if len(accts) > 2 else signature[:44]
                                        return {
                                            "mint": mint,
                                            "creator": creator,
                                            "bonding_curve": str(accts[3]) if len(accts) > 3 else None
                                        }

        except Exception as e:
            logger.error(f"Failed to extract tx data: {e}")
        logger.warning(f"Could not extract mint from tx: {signature[:20]}...")
        return None

    def _extract_mint_from_logs(self, logs: list) -> Optional[str]:
        for log in logs:
            if isinstance(log, str):
                if "MintTo" in log or "mint" in log.lower():
                    addrs = re.findall(r'[1-9A-HJ-NP-Za-km-z]{32,44}', log)
                    for addr in addrs:
                        if len(addr) >= 32:
                            return addr
        return None

    async def _parse_ix_data(self, ix: Dict, account_keys: list) -> Optional[Dict[str, Any]]:
        try:
            data = ix.get("data", {})
            parsed = data.get("parsed", {}) if isinstance(data, dict) else {}
            ix_type = parsed.get("type", "")

            if ix_type == "create" or ix_type == "initialize":
                info = parsed.get("info", {})
                mint = info.get("mint")
                creator = info.get("authority")

                if mint and creator:
                    return {
                        "mint": mint,
                        "creator": creator,
                        "bonding_curve": None
                    }
        except Exception as e:
            logger.debug(f"Ix parse error: {e}")
        return None

    async def process_logs(self):
        last_heartbeat = time.time()
        last_token_log = time.time()
        while self.running:
            try:
                msg = await self.ws.receive()

                if time.time() - last_heartbeat > 60:
                    logger.info(f"[SCANNER] Still alive...")
                    last_heartbeat = time.time()

                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = msg.json()

                    if "params" in data and "result" in data["params"]:
                        result_value = data["params"]["result"]
                        if isinstance(result_value, dict) and "value" in result_value:
                            value_data = result_value["value"]
                            if isinstance(value_data, dict):
                                logs = value_data.get("logs", [])
                                signature = value_data.get("signature", "")

                                if logs and signature and time.time() - last_token_log > 5:
                                    create_count = sum(1 for l in logs if "Create" in str(l))
                                    pump_count = sum(1 for l in logs if "6EF8" in str(l))

                                    if pump_count > 2 and create_count > 0:
                                        logger.info(f"Potential new token! pump_logs:{pump_count} create:{create_count}")
                                        last_token_log = time.time()

                                        token_info = await self._extract_from_transaction(signature, logs)
                                        if token_info and token_info.get("mint"):
                                            logger.info(f"Extracted mint: {token_info['mint'][:20]}...")
                                            await self._handle_new_token(token_info)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Log processing error: {e}")
                await asyncio.sleep(1)

    async def _handle_new_token(self, token_info):
        mint = token_info["mint"]
        creator = token_info["creator"]

        if mint in self.scanned_tokens:
            existing = self.scanned_tokens[mint]
            logger.info(f"Token already scanned: {mint[:20]} Score:{existing.score} Factors:{existing.risk_factors}")
            return None

        logger.info(f"Scoring token: {mint[:20]}...")

        try:
            pump_token = PumpToken(
                mint=mint,
                creator=creator,
                bonding_curve=token_info.get("bonding_curve", ""),
                timestamp=time.time()
            )

            logger.info(f"Calling algo.score_token for {mint[:20]}...")
            score_result = await self.algo.score_token(pump_token)
            logger.info(f"Score result: {score_result}")

            pump_token.score = score_result["score"]
            pump_token.risk_factors = score_result["risk_factors"]
            pump_token.has_mint_authority = score_result["has_mint_authority"]
            pump_token.dev_holding_pct = score_result["dev_holding_pct"]

            self.scanned_tokens[mint] = pump_token

            if pump_token.score > 0:
                logger.info(f"Token PASSED scoring: {mint[:20]} Score: {pump_token.score}")

                if self.token_callback:
                    asyncio.create_task(self.token_callback(pump_token))

                return pump_token
            else:
                logger.info(f"Token FAILED scoring: {mint[:20]} - {pump_token.risk_factors}")

        except Exception as e:
            logger.error(f"Error scoring token: {e}")

        return None

    async def stop(self):
        self.running = False
        if self.ws:
            await self.ws.close()
        if self.session:
            await self.session.close()
