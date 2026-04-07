#!/usr/bin/env python3
"""
Wallet Module
Secure key management for Solana transactions
"""

import base64
import os
from solders.keypair import Keypair
from solders.pubkey import Pubkey

class Wallet:
    def __init__(self, private_key_b58: str = None):
        if private_key_b58:
            self.keypair = Keypair.from_base58_string(private_key_b58)
        else:
            self.keypair = Keypair.from_json(os.getenv("WALLET_PRIVATE_KEY", ""))
            
        self.public_key: Pubkey = self.keypair.pubkey()
        
    def sign(self, message: bytes) -> bytes:
        return bytes(self.keypair.sign_message(message))
        
    @property
    def address(self) -> str:
        return str(self.public_key)
