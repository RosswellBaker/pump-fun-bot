from typing import Optional, Tuple, Dict, List
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import struct
import os
import asyncio
from collections import deque
from time import time

# RPC config
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

# Constants
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
BUY_DISCRIMINATOR_BYTES = bytes([102, 6, 61, 18, 1, 218, 235, 234])  # global:buy
CREATOR_BUY_AMOUNT_THRESHOLD = 50_000_000  # 50 million
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

# Fetch tx from Solana RPC
async def fetch_transaction_data(signature: str, retries: int = 5, delay: float = 0.5) -> Optional[Dict]:
    await rate_limiter.acquire()

    for _ in range(retries):
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
        await asyncio.sleep(delay)

    return None

# Extract buy amount from innerInstructions
def extract_buy_instruction_amount(transaction_data: Dict) -> Optional[float]:
    try:
        inner_ix = transaction_data.get("meta", {}).get("innerInstructions", [])
        for item in inner_ix:
            for ix in item.get("instructions", []):
                if ix.get("programId") != PUMP_PROGRAM_ID:
                    continue

                data_b64 = ix.get("data")
                if not data_b64:
                    continue

                try:
                    raw = base64.b64decode(data_b64)
                except Exception:
                    continue

                if len(raw) < 16 or raw[:8] != BUY_DISCRIMINATOR_BYTES:
                    continue

                amount_raw = struct.unpack("<Q", raw[8:16])[0]
                return amount_raw / (10 ** TOKEN_DECIMALS)

    except Exception:
        pass

    return None

# ✅ This function now takes BOTH logs and signature as required
async def should_process_token(logs: List[str], signature: str) -> Tuple[bool, float]:
    transaction_data = await fetch_transaction_data(signature)
    if not transaction_data:
        return False, 0.0

    amount = extract_buy_instruction_amount(transaction_data)
    if amount is None:
        amount = 0.0

    return amount <= CREATOR_BUY_AMOUNT_THRESHOLD, amount
