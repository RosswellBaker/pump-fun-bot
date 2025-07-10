from typing import Optional, Tuple, List, Dict
from solders.signature import Signature
from solana.rpc.async_api import AsyncClient
import base64, struct, os, asyncio, json, aiohttp
from collections import deque
from time import time
import logging

logger = logging.getLogger(__name__)

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
        headers = {"Content-Type": "application/json"}
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                sig,
                {
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0,
                    "commitment": "confirmed"
                }
            ]
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(FILTER_RPC_ENDPOINT, headers=headers, json=body) as resp:
                js = await resp.json()
                return js.get("result", None)
    except Exception as e:
        logger.error(f"fetch_tx error for {sig}: {e}")
        return None

def parse_buy_amount(tx: Dict) -> Optional[float]:
    def decode(b64: str) -> Optional[float]:
        try:
            b64 = b64 + '=' * (-len(b64) % 4)
            raw = base64.b64decode(b64, validate=True)
            if raw[:8] != BUY_DISC:
                return None
            val = struct.unpack("<Q", raw[8:16])[0]
            return val / (10 ** DECIMALS)
        except Exception as e:
            logger.error(f"decode error: {e}")
        return None

    for entry in tx.get("meta", {}).get("innerInstructions", []):
        for ix in entry.get("instructions", []):
            if ix.get("programId") == PROGRAM_ID:
                b64 = ix.get("data", "")
                if len(b64) % 4 != 0:
                    continue
                amt = decode(b64)
                if amt is not None:
                    return amt

    for ix in tx.get("transaction", {}).get("message", {}).get("instructions", []):
        if ix.get("programId") == PROGRAM_ID:
            b64 = ix.get("data", "")
            if len(b64) % 4 != 0:
                continue
            amt = decode(b64)
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
        logger.warning(f"Transaction {signature} had no buy amount")
        return False, 0.0
    logger.info(f"Transaction {signature} passed filter: Buy amount = {amt:.6f}")
    return amt <= THRESHOLD, amt
