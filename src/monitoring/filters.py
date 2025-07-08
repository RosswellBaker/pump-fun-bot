from typing import Optional, Tuple, Dict
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import struct
import os
import asyncio
from collections import deque
from time import time

# Configure RPC endpoint
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

# Pump.fun constants
CREATOR_BUY_AMOUNT_THRESHOLD = 50000000  # 50 million tokens
TOKEN_DECIMALS = 6  # Pump.fun uses 6 decimals
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

BUY_DISCRIMINATOR_BYTES = bytes([102, 6, 61, 18, 1, 218, 235, 234])  # global:buy

# Rate Limiter
class RateLimiter:
    def __init__(self, max_requests: int, time_window: float):
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_times = deque()

    async def acquire(self):
        while len(self.request_times) >= self.max_requests:
            now = time()
            if now - self.request_times[0] > self.time_window:
                self.request_times.popleft()
            else:
                await asyncio.sleep(self.time_window - (now - self.request_times[0]))
        self.request_times.append(time())

rate_limiter = RateLimiter(max_requests=8, time_window=1.0)

async def fetch_transaction_data(signature: str, max_retries: int = 5, retry_delay: float = 0.5) -> Optional[Dict]:
    """
    Fetch transaction data using the configured RPC endpoint.
    
    Args:
        signature: Transaction signature as a string.
        max_retries: Maximum number of retry attempts.
        retry_delay: Delay between retries in seconds.
        
    Returns:
        Decoded transaction data if found, otherwise None.
    """
    await rate_limiter.acquire()
    
    for attempt in range(max_retries):
        try:
            # Critical fix: Add maxSupportedTransactionVersion parameter
            transaction_response = await rpc_client.get_transaction(
                Signature.from_string(signature),
                encoding="jsonParsed",
                commitment="confirmed",
                maxSupportedTransactionVersion=0  # Required for newer Solana transactions
            )
            
            if transaction_response and transaction_response.value:
                return transaction_response.value
                
            await asyncio.sleep(retry_delay)
            
        except Exception:
            await asyncio.sleep(retry_delay)
            
    return None

def extract_buy_instruction_amount(txn: Dict) -> Optional[float]:
    """
    Extracts the buy() instruction amount encoded within innerInstructions of a Pump.fun mint transaction.
    """
    for entry in txn.get("meta", {}).get("innerInstructions", []):
        for ix in entry.get("instructions", []):
            if ix.get("programId") != PUMP_PROGRAM_ID:
                continue
            data = ix.get("data")  # always base64
            if not data:
                continue
            try:
                raw = base64.b64decode(data)
            except Exception:
                continue
            if len(raw) < 16 or raw[:8] != BUY_DISCRIMINATOR_BYTES:
                continue
            amount_raw = struct.unpack("<Q", raw[8:16])[0]
            return amount_raw / (10 ** TOKEN_DECIMALS)
    return None

async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    """
    Determines whether a token should be processed based on the creator's initial buy amount.
    """
    transaction_data = await fetch_transaction_data(signature)
    if not transaction_data:
        return False, 0.0

    creator_buy_amount = extract_buy_instruction_amount(transaction_data)
    
    # FIXED: If no buy instruction found, treat as 0 (creator didn't buy = PERFECT TARGET)
    if creator_buy_amount is None:
        creator_buy_amount = 0.0

    # Return True if amount is below or equal to threshold, False otherwise
    return creator_buy_amount <= CREATOR_BUY_AMOUNT_THRESHOLD, creator_buy_amount