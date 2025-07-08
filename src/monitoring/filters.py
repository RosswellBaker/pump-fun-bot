from typing import Optional, Tuple, Dict, List
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64
import struct
import os
import asyncio
from collections import deque
from time import time

# ————————————— INITIAL SETUP —————————————
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)
RATE_LIMIT = 8  # per second
TOKEN_DECIMALS = 6
CREATOR_BUY_AMOUNT_THRESHOLD = 50_000_000  # raw units (50M base tokens)
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
BUY_DISCRIMINATOR = 16927863322537952870  # u64 LE for Anchor global:buy

# ————————————— RATE LIMITER —————————————
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

rate_limiter = RateLimiter(max_requests=RATE_LIMIT, time_window=1.0)

# ————————————— FETCH TRANSACTION —————————————
async def fetch_transaction_data(signature: str, max_retries: int = 5, retry_delay: float = 0.5) -> Optional[Dict]:
    await rate_limiter.acquire()
    for _ in range(max_retries):
        try:
            resp = await rpc_client.get_transaction(
                Signature.from_string(signature),
                encoding="base64",  # blockSubscribe uses base64 encoding
                commitment="confirmed",
                transaction_details="full",
                max_supported_transaction_version=0
            )
        except Exception:
            await asyncio.sleep(retry_delay)
            continue
        value = getattr(resp, "value", None)
        if value:
            return value
        await asyncio.sleep(retry_delay)
    return None

# ————————————— PARSE BUY INSTRUCTION —————————————
def extract_buy_amount_from_raw(raw: bytes) -> Optional[float]:
    if len(raw) < 16:
        return None
    if struct.unpack("<Q", raw[:8])[0] != BUY_DISCRIMINATOR:
        return None
    amount_raw = struct.unpack("<Q", raw[8:16])[0]
    return amount_raw / (10 ** TOKEN_DECIMALS)

def extract_buy_instruction_amount(txn: Dict) -> Optional[float]:
    # Explore top-level instructions
    for ix in txn["transaction"]["message"].get("instructions", []):
        if ix.get("programId") == PUMP_PROGRAM_ID and isinstance(ix.get("data"), str):
            try:
                raw = base64.b64decode(ix["data"])
            except Exception:
                continue
            amt = extract_buy_amount_from_raw(raw)
            if amt is not None:
                return amt

    # Explore nested instructions
    for inner in txn["meta"].get("innerInstructions", []):
        for ix in inner.get("instructions", []):
            if ix.get("programId") == PUMP_PROGRAM_ID and isinstance(ix.get("data"), str):
                try:
                    raw = base64.b64decode(ix["data"])
                except Exception:
                    continue
                amt = extract_buy_amount_from_raw(raw)
                if amt is not None:
                    return amt
    return None