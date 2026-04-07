#!/usr/bin/env python3
"""
Scanner Component - Real-time Pump.fun token detection
Uses Helius WebSocket for high-speed log subscription
"""

import asyncio
import base64
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, Callable
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
        self.simulation_mode = False

    async def start(self):
        """Always connect to real Helius WebSocket — sim mode only affects trade execution."""
        self.running = True
        try:
            await self._connect_websocket()
            asyncio.create_task(self._heartbeat())
            logger.info("WebSocket scanner started (real token detection)")
        except Exception as e:
            logger.error(f"WebSocket connect failed: {e} — scanner will retry on first process_logs call")

    async def _connect_websocket(self):
        if self.session and not self.session.closed:
            await self.session.close()
        self.session = aiohttp.ClientSession()

        ws_url = f"{config.WSS_URL}?api-key={config.HELIUS_API_KEY}"
        logger.info(f"Connecting WebSocket: {ws_url[:60]}...")

        # NO heartbeat= param — Helius manages its own keep-alive
        self.ws = await self.session.ws_connect(
            ws_url,
            receive_timeout=120,
            max_msg_size=0
        )
        logger.info("WebSocket TCP connection established")

        # params MUST be an array per Solana JSON-RPC spec
        subscribe_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "logsSubscribe",
            "params": [
                {"mentions": [config.PUMP_FUN_PROGRAM]},
                {"commitment": "processed"}
            ]
        }
        logger.info(f"Subscribing to program: {config.PUMP_FUN_PROGRAM}")
        await self.ws.send_json(subscribe_msg)

        # Read the confirmation — skip non-TEXT frames (e.g. PING)
        sub_id = None
        for _ in range(5):
            raw = await asyncio.wait_for(self.ws.receive(), timeout=15)
            logger.info(f"WS setup frame: type={raw.type} data={str(raw.data)[:200]}")
            if raw.type == aiohttp.WSMsgType.TEXT:
                resp = raw.json()
                if "error" in resp:
                    raise RuntimeError(f"logsSubscribe rejected: {resp['error']}")
                sub_id = resp.get("result")
                logger.info(f"logsSubscribe confirmed — subscription ID: {sub_id}")
                break
            elif raw.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSING):
                raise RuntimeError(f"WS closed during setup: {raw.data}")

        if sub_id is None:
            logger.warning("Did not receive subscription confirmation — proceeding anyway")

    async def _heartbeat(self):
        while self.running:
            await asyncio.sleep(30)
            if self.ws and not self.ws.closed:
                try:
                    await self.ws.ping()
                except Exception:
                    pass

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
        """Process real Helius WebSocket logs with auto-reconnect and full visibility."""
        msg_count = 0
        last_status = time.time()

        while self.running:
            # --- reconnect if WS is gone ---
            if not self.ws or self.ws.closed:
                logger.warning("WebSocket closed — reconnecting in 5s...")
                await asyncio.sleep(5)
                try:
                    await self._connect_websocket()
                    msg_count = 0
                except Exception as e:
                    logger.error(f"Reconnect failed: {e}")
                    continue

            try:
                msg = await asyncio.wait_for(self.ws.receive(), timeout=90)
                msg_count += 1

                # --- status heartbeat every 60s ---
                if time.time() - last_status > 60:
                    logger.info(f"[SCANNER] Alive — {msg_count} WS frames received so far")
                    last_status = time.time()

                # --- log every frame type at INFO so we can see what's arriving ---
                if msg.type == aiohttp.WSMsgType.PING:
                    logger.debug("[WS] PING received")
                    continue
                elif msg.type == aiohttp.WSMsgType.PONG:
                    logger.debug("[WS] PONG received")
                    continue
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                    logger.warning(f"[WS] Connection closed/errored: type={msg.type} data={msg.data}")
                    self.ws = None
                    continue
                elif msg.type != aiohttp.WSMsgType.TEXT:
                    logger.info(f"[WS] Unknown frame type={msg.type}")
                    continue

                # --- parse JSON payload ---
                try:
                    data = msg.json()
                except Exception as e:
                    logger.warning(f"[WS] Failed to parse JSON: {e} | raw={msg.data[:200]}")
                    continue

                # Log first 5 messages in full so we can debug the schema
                if msg_count <= 5:
                    logger.info(f"[WS] Frame #{msg_count}: {str(data)[:400]}")

                # --- extract notification ---
                params = data.get("params")
                if not params:
                    logger.debug(f"[WS] Non-notification frame: {str(data)[:200]}")
                    continue

                result = params.get("result", {})
                if not isinstance(result, dict):
                    continue

                value = result.get("value", {})
                if not isinstance(value, dict):
                    continue

                logs = value.get("logs", [])
                signature = value.get("signature", "")
                err = value.get("err")

                if not logs or not signature:
                    continue

                # Skip failed transactions
                if err:
                    continue

                # --- detect token creation ---
                logs_str = " ".join(str(l) for l in logs)
                is_create = any(kw in logs_str for kw in [
                    "Instruction: Create",
                    "InitializeMint",
                    "initialize_mint",
                    "create_token",
                    "CreateToken",
                ])
                has_pump = config.PUMP_FUN_PROGRAM[:8] in logs_str or "6EF8" in logs_str

                logger.info(
                    f"[TX] {signature[:20]}... create={is_create} pump={has_pump} "
                    f"logs={len(logs)}"
                )

                if has_pump and is_create:
                    logger.info(f"🔍 New token candidate! Fetching TX: {signature[:20]}...")
                    token_info = await self._extract_from_transaction(signature, logs)
                    if token_info and token_info.get("mint"):
                        logger.info(f"✅ Extracted mint: {token_info['mint'][:20]}...")
                        await self._handle_new_token(token_info)

            except asyncio.TimeoutError:
                logger.warning(
                    f"[SCANNER] No WS message in 90s (total frames received: {msg_count}) "
                    f"— closing and reconnecting"
                )
                # Force reconnect — a silent timeout usually means the connection is dead
                if self.ws and not self.ws.closed:
                    await self.ws.close()
                self.ws = None
                last_status = time.time()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[SCANNER] Unexpected error: {e}", exc_info=True)
                await asyncio.sleep(2)

    async def run_simulation_loop(self, interval_seconds: int = 60):
        """Generate mock token events in simulation mode so trades actually trigger."""
        logger.info(f"[SIM] Mock token generator started — firing every {interval_seconds}s")
        await asyncio.sleep(10)  # brief startup delay

        known_mints = [
            "So11111111111111111111111111111111111111112",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        ]

        while self.running:
            try:
                # Generate a random-looking mint address
                rand_hex = secrets.token_hex(16)
                fake_mint = known_mints[int(rand_hex[:2], 16) % len(known_mints)]
                # Use first known mint as a stable real address for price lookups
                fake_mint = known_mints[0]

                fake_creator = "Auth" + rand_hex[:8].upper() + "1111111111111111111111111"

                token_info = {
                    "mint": fake_mint,
                    "creator": fake_creator[:44],
                    "bonding_curve": fake_mint,
                }

                logger.info(f"[SIM] 🪙 Injecting mock token: {fake_mint[:20]}...")
                # Clear from cache so it scores fresh each time
                self.scanned_tokens.pop(fake_mint, None)
                await self._handle_new_token(token_info)

            except Exception as e:
                logger.error(f"[SIM] Mock token error: {e}")

            await asyncio.sleep(interval_seconds)

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
