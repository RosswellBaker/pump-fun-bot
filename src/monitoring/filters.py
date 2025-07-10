from typing import Optional, Tuple, List, Dict
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64, struct, os, asyncio, json
from collections import deque
from time import time

# Setup
FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")
rpc = AsyncClient(FILTER_RPC_ENDPOINT)

# Constants
THRESHOLD = 50_000_000
DECIMALS = 6
PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
BUY_DISC = bytes([102, 6, 61, 18, 1, 218, 235, 234])
CREATE_LOG = "Program log: Instruction: Create"
SKIP_LOG = "Program log: Instruction: CreateTokenAccount"
DATA_LOG = "Program data:"

# Rate limiter
class RateLimiter:
    def __init__(self):
        self.times = deque()
        self.max = 8
        self.win = 1

    async def acquire(self):
        now = time()
        while len(self.times) >= self.max and now - self.times[0] < self.win:
            await asyncio.sleep(self.win - (now - self.times[0]))
            now = time()
        self.times.append(now)

lim = RateLimiter()

def valid_create(logs: List[str]) -> bool:
    return any(CREATE_LOG in l for l in logs) \
        and not any(SKIP_LOG in l for l in logs) \
        and any(l.startswith(DATA_LOG) for l in logs)

async def fetch_tx(sig: str) -> Optional[Dict]:
    await lim.acquire()
    try:
        res = await rpc.get_transaction(Signature.from_string(sig),
                                        encoding="jsonParsed", commitment="confirmed",
                                        max_supported_transaction_version=0)
        if res and res.value:
            js = res.value.to_json()
            return json.loads(js) if isinstance(js, str) else js
    except Exception as e:
        print(f"[ERROR] fetch_tx: {e}")
    return None

def parse_buy_amount(tx: Dict) -> Optional[float]:
    def decode(b64: str) -> Optional[float]:
        try:
            raw = base64.b64decode(b64)
            if raw[:8] == BUY_DISC:
                val = struct.unpack("<Q", raw[8:16])[0]
                return val / (10 ** DECIMALS)
        except Exception as e:
            print(f"[ERROR] decode: {e}")
        return None

    for entry in tx.get("meta", {}).get("innerInstructions", []):
        for ix in entry.get("instructions", []):
            if ix.get("programId") == PROGRAM_ID:
                amt = decode(ix.get("data", ""))
                if amt is not None:
                    return amt

    for ix in tx.get("transaction", {}).get("message", {}).get("instructions", []):
        if ix.get("programId") == PROGRAM_ID:
            amt = decode(ix.get("data", ""))
            if amt is not None:
                return amt

    return None

async def should_process_token(signature: str, logs: List[str]) -> Tuple[bool, Optional[float]]:
    if not valid_create(logs):
        return False, None
    tx = await fetch_tx(signature)
    if not tx:
        return False, 0.0
    amt = parse_buy_amount(tx)
    if amt is None:
        amt = 0.0
    return amt <= THRESHOLD, amt
