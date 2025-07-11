# monitoring/filters.py

import os
import asyncio
import base64
import struct
from collections import deque
from time import time
from typing import Optional, Tuple, Dict, Any

from solana.rpc.async_api import AsyncClient
from solders.signature import Signature

# ─── CONFIGURATION ─────────────────────────────────────────────────────────────

FILTER_RPC_ENDPOINT = os.getenv("FILTER_RPC_ENDPOINT")
if not FILTER_RPC_ENDPOINT:
    raise ValueError("FILTER_RPC_ENDPOINT environment variable not set")

PUMP_PROGRAM_ID = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"

# The exact numeric discriminator used in LogsEventProcessor for CreateEvent
CREATE_EVENT_DISCRIMINATOR: int = 8530921459188068891

# Numeric discriminator for global:buy from calculate_discriminator.py
BUY_INSTRUCTION_DISCRIMINATOR: int = 16927863322537952870

TOKEN_DECIMALS = 6
CREATOR_BUY_THRESHOLD = 50_000_000  # in whole tokens

# ─── RPC CLIENT & RATE LIMITER ────────────────────────────────────────────────

rpc_client = AsyncClient(FILTER_RPC_ENDPOINT)

class RateLimiter:
    """Throttle to ~8 RPC calls/sec to avoid Helius free-tier 429s."""
    def __init__(self, max_requests: int = 8, per_seconds: float = 1.0):
        self.max_requests = max_requests
        self.per_seconds = per_seconds
        self.timestamps = deque()

    async def acquire(self):
        now = time()
        # drop any timestamps older than the window
        while self.timestamps and now - self.timestamps[0] > self.per_seconds:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.max_requests:
            await asyncio.sleep(self.per_seconds - (now - self.timestamps[0]))
        self.timestamps.append(now)

rate_limiter = RateLimiter()

# ─── CORE FILTER LOGIC ─────────────────────────────────────────────────────────

async def fetch_transaction(sig_str: str) -> Optional[Dict[str, Any]]:
    """
    Fetch a confirmed transaction with jsonParsed encoding so that we get:
      - logMessages (including "Program data: <base64>")
      - innerInstructions (for buy parsing)
    """
    try:
        sig = Signature.from_string(sig_str)
        for _ in range(5):
            await rate_limiter.acquire()
            resp = await rpc_client.get_transaction(
                sig,
                encoding="jsonParsed",
                commitment="confirmed",
                max_supported_transaction_version=0
            )
            if resp and resp.value:
                return resp.value  # type: ignore
            await asyncio.sleep(0.5)
    except Exception:
        pass
    return None

def is_create_event(txn: Dict[str, Any]) -> bool:
    """
    Scans the RPC-fetched logMessages for any Anchor 'CreateEvent' CPI log:
      - looks for lines starting with "Program data: "
      - base64-decodes the payload
      - unpacks the first 8 bytes as a u64
      - checks against CREATE_EVENT_DISCRIMINATOR
    """
    for log in txn.get("meta", {}).get("logMessages", []):
        if not log.startswith("Program data: "):
            continue
        encoded = log.split("Program data: ", 1)[1]
        try:
            raw = base64.b64decode(encoded)
        except Exception:
            continue
        if len(raw) < 8:
            continue
        disc = struct.unpack("<Q", raw[:8])[0]
        if disc == CREATE_EVENT_DISCRIMINATOR:
            return True
    return False

def extract_buy_amount(txn: Dict[str, Any]) -> Optional[float]:
    """
    Scans `meta.innerInstructions` for the Pump​.fun `global:buy` call,
    decodes the next 8 bytes as a u64 amount, and normalizes by 10**TOKEN_DECIMALS.
    """
    for grp in txn.get("meta", {}).get("innerInstructions", []):
        for ix in grp.get("instructions", []):
            if ix.get("programId") != PUMP_PROGRAM_ID:
                continue
            data_b64 = ix.get("data", "")
            if not data_b64:
                continue
            try:
                raw = base64.b64decode(data_b64)
            except Exception:
                continue
            if len(raw) < 16:
                continue
            disc = struct.unpack("<Q", raw[:8])[0]
            if disc != BUY_INSTRUCTION_DISCRIMINATOR:
                continue
            amount_raw = struct.unpack("<Q", raw[8:16])[0]
            return amount_raw / (10 ** TOKEN_DECIMALS)
    return None

async def should_process_token(signature: str) -> Tuple[bool, Optional[float]]:
    """
    Gatekeeper filter:
      1) Fetch the full txn.
      2) Verify it's a real Pump​.fun mint by decoding the on-chain CreateEvent.
      3) Extract the buy() amount from innerInstructions.
      4) Return (True, amount) if amount <= CREATOR_BUY_THRESHOLD,
         else (False, amount). On any error or missing data, (False, None).
    """
    txn = await fetch_transaction(signature)
    if not txn or not is_create_event(txn):
        return False, None

    amount = extract_buy_amount(txn)
    if amount is None:
        return False, None

    return (amount <= CREATOR_BUY_THRESHOLD), amount
