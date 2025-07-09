from typing import Optional, Tuple, Dict
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import struct
import os
import asyncio
from collections import deque
from time import time

# RPC setup
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

# Pump.fun program constants
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
BUY_DISCRIMINATOR_BYTES = bytes([102, 6, 61, 18, 1, 218, 235, 234])
CREATOR_BUY_AMOUNT_THRESHOLD = 50_000_000  # 50 million tokens
TOKEN_DECIMALS = 6

# Rate limiter
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

# Transaction fetch
async def fetch_transaction_data(signature: str, max_retries: int = 5, retry_delay: float = 0.5) -> Optional[Dict]:
    await rate_limiter.acquire()

    for _ in range(max_retries):
        try:
            response = await rpc_client.get_transaction(
                Signature.from_string(signature),
                encoding="jsonParsed",
                commitment="confirmed",
                max_supported_transaction_version=0
            )
            if response and response.value:
                return response.value
        except Exception:
            pass
        await asyncio.sleep(retry_delay)

    return None

# Buy amount extractor
def extract_buy_instruction_amount(transaction_data: Dict) -> Optional[float]:
    """
    Extracts the buy amount from inner instructions only.
    """
    try:
        inner_ix_lists = transaction_data["meta"].get("innerInstructions", [])
        for ix_block in inner_ix_lists:
            for ix in ix_block.get("instructions", []):
                if ix.get("programId") != PUMP_PROGRAM_ID:
                    continue

                encoded = ix.get("data")
                if not encoded:
                    continue

                try:
                    raw = base64.b64decode(encoded)
                except Exception:
                    continue

                if len(raw) < 16:
                    continue

                if raw[:8] == BUY_DISCRIMINATOR_BYTES:
                    amount_raw = struct.unpack("<Q", raw[8:16])[0]
                    return amount_raw / (10 ** TOKEN_DECIMALS)
    except Exception:
        pass

    return None

# Filter decision
async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    transaction_data = await fetch_transaction_data(signature)
    if not transaction_data:
        return False, 0.0

    creator_buy_amount = extract_buy_instruction_amount(transaction_data)

    if creator_buy_amount is None:
        creator_buy_amount = 0.0

    return creator_buy_amount <= CREATOR_BUY_AMOUNT_THRESHOLD, creator_buy_amount
