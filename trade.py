#!/usr/bin/env python3
"""
Trade Execution Component
Handles buying and selling with dynamic fees and Jito bundles
"""

import asyncio
import base64
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum
import aiohttp
from solders.transaction import VersionedTransaction
from solders.pubkey import Pubkey
from solders.message import Message
from solders.instruction import Instruction, AccountMeta
from solders.system_program import TransferParams, transfer

from config import config

logger = logging.getLogger(__name__)

class TradeStatus(Enum):
    PENDING = "pending"
    BUYING = "buying"
    BOUGHT = "bought"
    SELLING = "selling"
    SOLD = "sold"
    FAILED = "failed"

@dataclass
class TradePosition:
    mint: str
    entry_price: float
    amount_sol: float
    amount_tokens: float
    status: TradeStatus = TradeStatus.PENDING
    sold_portion_1: bool = False
    trailing_high: float = 0.0
    created_at: float = field(default_factory=time.time)
    signature: str = ""

class TradeExecutor:
    def __init__(self, wallet):
        self.wallet = wallet
        self.session: Optional[aiohttp.ClientSession] = None
        self.positions: Dict[str, TradePosition] = {}
        self.current_fees: float = config.MIN_PRIORITY_FEE
        self.last_fee_update: float = 0
        self.simulation_mode = False
        self.simulated_balance = config.SIMULATION_BALANCE_SOL
        self.simulated_positions: Dict[str, dict] = {}

    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def _update_dynamic_fees(self):
        current_time = time.time()
        if current_time - self.last_fee_update < 10:
            return

        try:
            session = await self._get_session()
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"

            async with session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getRecentPrioritizedFees"
            }) as resp:
                data = await resp.json()

                if "result" in data:
                    avg_fee = data["result"].get("median", config.MIN_PRIORITY_FEE)
                    self.current_fees = min(
                        max(avg_fee, config.MIN_PRIORITY_FEE),
                        config.MAX_PRIORITY_FEE
                    )

            self.last_fee_update = current_time

        except Exception as e:
            logger.debug(f"Fee update failed: {e}")
            self.current_fees = config.MIN_PRIORITY_FEE

    async def execute_buy(
        self, 
        mint: str, 
        bonding_curve: str,
        amount_sol: float = None
    ) -> Optional[TradePosition]:
        if amount_sol is None:
            amount_sol = config.TRADE_AMOUNT_SOL

        if self.simulation_mode:
            return await self._simulate_buy(mint, amount_sol)

        await self._update_dynamic_fees()

        position = TradePosition(
            mint=mint,
            entry_price=0,
            amount_sol=amount_sol,
            amount_tokens=0,
            status=TradeStatus.BUYING
        )
        self.positions[mint] = position

        try:
            swap_ix = await self._build_swap_instruction(
                mint,
                bonding_curve,
                amount_sol,
                is_buy=True
            )

            priority_fee_ix = self._build_priority_fee_instruction()

            recent_blockhash = await self._get_recent_blockhash()

            instructions = [priority_fee_ix, swap_ix]

            tx = self._create_transaction(instructions, recent_blockhash)

            position.signature = await self._send_via_jito(tx)

            if position.signature:
                await self._confirm_transaction(position.signature)

                position.status = TradeStatus.BOUGHT
                position.entry_price = await self._get_token_price(mint)
                position.amount_tokens = amount_sol / position.entry_price if position.entry_price > 0 else 0

                logger.info(f"Buy executed: {mint} @ {position.entry_price}")
                return position

        except Exception as e:
            logger.error(f"Buy failed: {e}")
            position.status = TradeStatus.FAILED

        return None

    async def _build_swap_instruction(
        self,
        mint: str,
        bonding_curve: str,
        amount: float,
        is_buy: bool
    ) -> Instruction:
        pump_fun_program = Pubkey.from_string(config.PUMP_FUN_PROGRAM)
        
        # Correct Pump.fun discriminators (8 bytes)
        BUY_DISC = bytes([102, 6, 61, 18, 1, 218, 235, 234])
        SELL_DISC = bytes([51, 230, 133, 164, 1, 127, 131, 210])
        
        disc = BUY_DISC if is_buy else SELL_DISC
        
        # Amount in decimal to lamports/tokens
        # For simplify: use estimated tokens for buy, and raw tokens for sell
        if is_buy:
            # amount = SOL to spend
            amount_lamports = int(amount * 1_000_000_000)
            # In a real bot, we'd calculate tokens. Here we send a robust estimated swap.
            # Most snipers use a specific "buy" instruction that accepts (amount_tokens, max_sol)
            # or a wrapper. To keep it "foolproof" and similar to original:
            data = disc + amount_lamports.to_bytes(8, "little") + (amount_lamports * 2).to_bytes(8, "little")
        else:
            # amount = Tokens to sell
            token_amount = int(amount)
            data = disc + token_amount.to_bytes(8, "little") + int(0).to_bytes(8, "little")

        accounts = [
            AccountMeta(pubkey=Pubkey.from_string(config.PUMP_FUN_GLOBAL), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(config.PUMP_FUN_FEE_RECIPIENT), is_signer=False, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string(mint), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string(bonding_curve), is_signer=False, is_writable=True),
            AccountMeta(pubkey=self._derive_associated_bonding_curve(mint, bonding_curve), is_signer=False, is_writable=True),
            AccountMeta(pubkey=self._derive_associated_token_account(self.wallet.public_key, mint), is_signer=False, is_writable=True),
            AccountMeta(pubkey=self.wallet.public_key, is_signer=True, is_writable=True),
            AccountMeta(pubkey=Pubkey.from_string("11111111111111111111111111111111"), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string("SysvarRent111111111111111111111111111111111"), is_signer=False, is_writable=False),
            AccountMeta(pubkey=Pubkey.from_string("Ce6scACALvCneWNBqy2htvDzhUmJ6TuU1BSBvVE9N2pZ"), is_signer=False, is_writable=False), # Event Authority
            AccountMeta(pubkey=pump_fun_program, is_signer=False, is_writable=False),
        ]

        return Instruction(pump_fun_program, data, accounts)

    def _derive_associated_token_account(self, owner: Pubkey, mint: str) -> Pubkey:
        from solders.pubkey import Pubkey
        mint_pubkey = Pubkey.from_string(mint)
        token_program = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        ata_program = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
        
        seeds = [bytes(owner), bytes(token_program), bytes(mint_pubkey)]
        res, _ = Pubkey.find_program_address(seeds, ata_program)
        return res

    def _derive_associated_bonding_curve(self, mint: str, bonding_curve: str) -> Pubkey:
        return self._derive_associated_token_account(Pubkey.from_string(bonding_curve), mint)

    def _build_priority_fee_instruction(self) -> Instruction:
        return transfer(TransferParams(
            from_pubkey=self.wallet.public_key,
            to_pubkey=self.wallet.public_key,
            lamports=int(self.current_fees * 1_000_000_000)
        ))

    async def _get_recent_blockhash(self) -> str:
        session = await self._get_session()
        url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"

        async with session.post(url, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash"
        }) as resp:
            data = await resp.json()
            return data["result"]["value"]["blockhash"]

    def _create_transaction(self, instructions: List[Instruction], blockhash: str) -> str:
        message = Message.new_with_blockhash(
            instructions,
            self.wallet.public_key,
            blockhash
        )

        tx = VersionedTransaction(message, [])

        return base64.b64encode(bytes(tx)).decode()

    async def _send_via_jito(self, tx_base64: str) -> Optional[str]:
        bundle = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendBundle",
            "params": [[tx_base64]]
        }

        for endpoint in config.JITO_ENDPOINTS:
            try:
                session = await self._get_session()
                async with session.post(endpoint, json=bundle) as resp:
                    result = await resp.json()

                    if "result" in result:
                        logger.info(f"Bundle sent via Jito: {endpoint}")
                        return result["result"][0]

            except Exception as e:
                logger.debug(f"Jito send failed ({endpoint}): {e}")

        return await self._send_via_rpc(tx_base64)

    async def _send_via_rpc(self, tx_base64: str) -> Optional[str]:
        session = await self._get_session()
        url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"

        async with session.post(url, json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                tx_base64,
                {"skipPreflight": True, "maxRetries": 3}
            ]
        }) as resp:
            data = await resp.json()
            if "result" in data:
                return data["result"]
        return None

    async def _confirm_transaction(self, signature: str, timeout: int = 30) -> bool:
        start = time.time()

        while time.time() - start < timeout:
            try:
                session = await self._get_session()
                url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"

                async with session.post(url, json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getSignatureStatuses",
                    "params": [[signature]]
                }) as resp:
                    data = await resp.json()

                    if "result" in data:
                        status = data["result"]["value"][0]
                        if status:
                            return status.get("confirmationStatus") == "finalized" or status.get("slot")

            except Exception as e:
                logger.debug(f"Confirmation check failed: {e}")

            await asyncio.sleep(0.5)

        return False

    async def _get_token_price(self, mint: str) -> float:
        try:
            session = await self._get_session()
            url = f"https://quote-api.jup.ag/v6/price?ids={mint}"

            async with session.get(url) as resp:
                data = await resp.json()
                if mint in data:
                    return float(data[mint]["price"])
        except Exception:
            pass
        return 0.000001

    async def execute_sell(self, mint: str, percentage: float = 1.0) -> bool:
        position = self.positions.get(mint)
        if not position or position.status != TradeStatus.BOUGHT:
            return False

        if self.simulation_mode:
            return await self._simulate_sell(mint, percentage)

        try:
            amount_tokens = position.amount_tokens * percentage

            swap_ix = await self._build_swap_instruction(
                mint,
                position.mint,
                amount_tokens,
                is_buy=False
            )

            priority_fee_ix = self._build_priority_fee_instruction()

            recent_blockhash = await self._get_recent_blockhash()

            tx = self._create_transaction([priority_fee_ix, swap_ix], recent_blockhash)

            signature = await self._send_via_jito(tx)

            if signature:
                await self._confirm_transaction(signature)
                logger.info(f"Sell executed: {mint} ({percentage*100:.0f}%)")
                return True

        except Exception as e:
            logger.error(f"Sell failed: {e}")

        return False

    async def monitor_and_exit(self, mint: str, bot_callback=None):
        position = self.positions.get(mint)
        if not position:
            return

        while position.status == TradeStatus.BOUGHT:
            try:
                current_price = await self._get_token_price(mint)

                if current_price > position.trailing_high:
                    position.trailing_high = current_price

                pnl_pct = (current_price - position.entry_price) / position.entry_price if position.entry_price > 0 else 0

                # 1. Take Profit
                if not position.sold_portion_1 and pnl_pct >= config.PROFIT_TARGET_1:
                    await self.execute_sell(mint, config.SELL_PORTION_1)
                    position.sold_portion_1 = True
                    logger.info(f"Take Profit Hit: {mint} (+{pnl_pct*100:.1f}%)")

                    if bot_callback:
                        await bot_callback(
                            mint,
                            pnl_pct * 100,
                            pnl_pct * position.amount_sol * current_price
                        )

                # 2. Hard Stop Loss
                if pnl_pct <= config.STOP_LOSS_THRESHOLD:
                    logger.warning(f"Hard Stop Loss Hit: {mint} ({pnl_pct*100:.1f}%)")
                    await self.execute_sell(mint, 1.0 if not position.sold_portion_1 else 1.0 - config.SELL_PORTION_1)
                    position.status = TradeStatus.SOLD
                    break

                # 3. Trailing Stop Loss (only active after trailing_high has moved or after TP1)
                trailing_stop_val = position.trailing_high * (1 + config.TRAILING_STOP_LOSS)
                if current_price <= trailing_stop_val and (position.sold_portion_1 or position.trailing_high > position.entry_price * 1.2):
                    logger.warning(f"Trailing Stop Hit: {mint} @ {current_price:.9f} (Peak: {position.trailing_high:.9f})")
                    await self.execute_sell(mint, 1.0 if not position.sold_portion_1 else 1.0 - config.SELL_PORTION_1)
                    position.status = TradeStatus.SOLD
                    break

            except Exception as e:
                logger.error(f"Monitor error: {e}")

            await asyncio.sleep(2)

    async def get_sol_balance(self) -> float:
        if self.simulation_mode:
            return self.simulated_balance
        try:
            session = await self._get_session()
            url = f"{config.RPC_URL}?api-key={config.HELIUS_API_KEY}"

            async with session.post(url, json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [str(self.wallet.public_key)]
            }) as resp:
                data = await resp.json()
                if "result" in data:
                    return data["result"]["value"] / 1_000_000_000
        except Exception as e:
            logger.error(f"Balance check failed: {e}")
        return 0.0

    async def _simulate_buy(self, mint: str, amount_sol: float) -> Optional[TradePosition]:
        if self.simulated_balance < amount_sol:
            logger.warning(f"[SIM] Insufficient balance: {self.simulated_balance:.4f} SOL")
            return None

        self.simulated_balance -= amount_sol

        entry_price = await self._get_token_price(mint)
        if entry_price == 0:
            entry_price = 0.000001

        tokens_bought = amount_sol / entry_price

        position = TradePosition(
            mint=mint,
            entry_price=entry_price,
            amount_sol=amount_sol,
            amount_tokens=tokens_bought,
            status=TradeStatus.BOUGHT,
            signature=f"[SIM]{mint[:8]}"
        )

        self.positions[mint] = position
        self.simulated_positions[mint] = {
            "entry_price": entry_price,
            "amount_sol": amount_sol,
            "tokens": tokens_bought,
            "sold_portion_1": False,
            "trailing_high": entry_price,
            "entry_time": time.time()
        }

        logger.info(f"[SIM] BUY executed: {mint[:8]}... @ {entry_price:.9f} | {tokens_bought:.0f} tokens")

        return position

    async def _simulate_sell(self, mint: str, percentage: float = 1.0) -> bool:
        if mint not in self.simulated_positions:
            return False

        sim_pos = self.simulated_positions[mint]
        amount_tokens = sim_pos["tokens"] * percentage

        current_price = await self._get_token_price(mint)
        if current_price == 0:
            current_price = sim_pos["entry_price"]

        sol_received = amount_tokens * current_price

        if percentage >= 1.0:
            del self.simulated_positions[mint]
        else:
            sim_pos["tokens"] -= amount_tokens

        self.simulated_balance += sol_received

        pnl_pct = ((sol_received - sim_pos["amount_sol"]) / sim_pos["amount_sol"]) * 100 if sim_pos["amount_sol"] > 0 else 0
        logger.info(f"[SIM] SELL executed: {mint[:8]}... @ {current_price:.9f} | PnL: {pnl_pct:+.1f}%")

        return True

    async def monitor_and_exit_sim(self, mint: str, bot_callback=None):
        if mint not in self.simulated_positions:
            return

        sim_pos = self.simulated_positions[mint]
        logger.info(f"[SIM] Started monitoring {mint[:20]}... Entry: {sim_pos['entry_price']:.9f}")

        while mint in self.simulated_positions:
            try:
                current_price = await self._get_token_price(mint)
                if current_price == 0:
                    current_price = sim_pos["entry_price"]

                if current_price > sim_pos["trailing_high"]:
                    sim_pos["trailing_high"] = current_price

                pnl_pct = ((current_price - sim_pos["entry_price"]) / sim_pos["entry_price"]) * 100 if sim_pos["entry_price"] > 0 else 0

                # Log price every ~30s or on significant move
                logger.info(f"[SIM] Pos {mint[:8]}: PnL {pnl_pct:+.1f}% | Price {current_price:.9f} | Peak {sim_pos['trailing_high']:.9f}")

                # 1. Take Profit
                if not sim_pos["sold_portion_1"] and pnl_pct >= config.PROFIT_TARGET_1 * 100:
                    logger.info(f"[SIM] TP1 Hit at {pnl_pct:.1f}%! Selling {config.SELL_PORTION_1*100}%")
                    await self._simulate_sell(mint, config.SELL_PORTION_1)
                    sim_pos["sold_portion_1"] = True

                    if bot_callback:
                        await bot_callback(
                            mint,
                            pnl_pct,
                            pnl_pct * sim_pos["amount_sol"] / 100
                        )

                # 2. Hard Stop Loss
                if pnl_pct <= config.STOP_LOSS_THRESHOLD * 100:
                    logger.warning(f"[SIM] Hard Stop Hit at {pnl_pct:.1f}%! Selling ALL")
                    await self._simulate_sell(mint, 1.0)
                    break

                # 3. Trailing Stop Loss
                trailing_stop_val = sim_pos["trailing_high"] * (1 + config.TRAILING_STOP_LOSS)
                if current_price <= trailing_stop_val and (sim_pos["sold_portion_1"] or sim_pos["trailing_high"] > sim_pos["entry_price"] * 1.2):
                    logger.warning(f"[SIM] Trailing Stop Hit! Peak {sim_pos['trailing_high']:.9f} -> Current {current_price:.9f}")
                    await self._simulate_sell(mint, 1.0)
                    break

            except Exception as e:
                logger.error(f"[SIM] Monitor error: {e}")

            await asyncio.sleep(5)

    def toggle_simulation(self, enabled: bool):
        self.simulation_mode = enabled
        if enabled:
            self.simulated_balance = config.SIMULATION_BALANCE_SOL
            self.simulated_positions = {}
            logger.info(f"[SIM] Simulation mode ENABLED | Balance: {self.simulated_balance:.4f} SOL")
        else:
            logger.info(f"[SIM] Simulation mode DISABLED | Final PnL: {self.simulated_balance - config.SIMULATION_BALANCE_SOL:.4f} SOL")

    async def close(self):
        if self.session:
            await self.session.close()
