# filters.py — FINAL VERIFIED for Pump.fun mint detection + dev buy amount filtering

from typing import Optional, Tuple, Dict, List
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64, struct, os, asyncio
from collections import deque
from time import time

# --- CONFIGURATION ---
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT not set")

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

# Constants matching Anchor/Pump.fun specs
CREATOR_BUY_AMOUNT_THRESHOLD = 50_000_000
TOKEN_DECIMALS = 6
PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
BUY_DISCRIMINATOR_BYTES = bytes([102, 6, 61, 18, 1, 218, 235, 234])

CREATE_TAG = "Program log: Instruction: Create"
SKIP_TAG = "Program log: Instruction: CreateTokenAccount"
DATA_TAG = "Program data:"

# --- RATE LIMITER ---
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

# --- VALIDATION FUNCTIONS ---
def is_valid_pumpfun_create(logs: List[str]) -> bool:
    return (
        any(CREATE_TAG in log for log in logs)
        and not any(SKIP_TAG in log for log in logs)
        and any(log.startswith(DATA_TAG) for log in logs)
    )

async def fetch_transaction_data(signature: str) -> Optional[Dict]:
    await rate_limiter.acquire()
    try:
        res = await rpc_client.get_transaction(
            Signature.from_string(signature),
            encoding="jsonParsed",
            commitment="confirmed",
            max_supported_transaction_version=0
        )
        return res.value.to_json() if res and res.value else None
    except:
        return None

def extract_buy_instruction_amount(txn: Dict) -> Optional[float]:
    def decode(data_b64: str) -> Optional[float]:
        try:
            raw = base64.b64decode(data_b64)
            if raw[:8] == BUY_DISCRIMINATOR_BYTES:
                return struct.unpack("<Q", raw[8:16])[0] / (10 ** TOKEN_DECIMALS)
        except:
            pass
        return None

    for entry in txn.get("meta", {}).get("innerInstructions", []):
        for ix in entry.get("instructions", []):
            if ix.get("programId") == PUMP_PROGRAM_ID:
                amt = decode(ix.get("data", ""))
                if amt is not None:
                    return amt

    for ix in txn.get("transaction", {}).get("message", {}).get("instructions", []):
        if ix.get("programId") == PUMP_PROGRAM_ID:
            amt = decode(ix.get("data", ""))
            if amt is not None:
                return amt

    return None

# --- MAIN ENTRY POINT ---
async def should_process_token(signature: str, logs: List[str]) -> Tuple[bool, Optional[float]]:
    if not is_valid_pumpfun_create(logs):
        return False, None

    txn = await fetch_transaction_data(signature)
    if not txn:
        return False, 0.0

    creator_buy_amount = extract_buy_instruction_amount(txn)
    if creator_buy_amount is None:
        creator_buy_amount = 0.0

    return creator_buy_amount <= CREATOR_BUY_AMOUNT_THRESHOLD, creator_buy_amount
